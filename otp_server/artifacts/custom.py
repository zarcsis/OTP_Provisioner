"""Custom OS images: an operator's own ``.img`` uploaded to the station and written at stage 3 instead of the
station's Raspberry Pi OS Lite (setting ``image.custom`` = the image's id).

The upload is a raw disk image with an MBR, a FAT boot partition and an ext4 root (:func:`diskimage.read_layout`
checks it as it arrives). A job then prepares two IDP sets from it with ``docker/scripts/custom-image.sh`` in
the tools image, one per scenario:

* ``clear`` (open): the image as it is, boot partition and root file system as sparse images, the image's own
  partition sizes and disk identifier;
* ``crypt`` (secure): a copy whose initramfs unlocks a LUKS2 root with the board's OTP key (packages from the
  image's own apt sources, see the script); stage 3 then encrypts its root per board exactly like the
  station image's (``ImageBuilder._station_luks``).

Layout, ``<work>/artifacts/custom/<id>/`` (id = the first 16 hex digits of the upload's sha256):
``source.img`` (the upload, kept: a changed script prepares it again), ``upload.json``, one directory per
prepared set (``<variant>-<fingerprint>[-rN]``: image.json, the pieces, ``custom.json`` from the script,
``manifest.json``, ``.complete``), ``current-<variant>.json`` naming the set stage 3 serves, and
``error-<variant>.json`` while the last preparation of that variant failed. A set is served only while its
fingerprint (tools image, the scripts, ``max_piece_size``) matches the station's.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Callable

from .. import diskimage, imagejson
from ..docker import Mount
from .common import (NotReady, commit_partial, fingerprint, fresh_partial, heavy_lock, is_complete, now_iso,
                     read_json, rmtree, write_json)

VARIANTS = ("clear", "crypt")
SCRIPT = "custom-image.sh"
#: Everything in docker/scripts a prepared set depends on.
SCRIPT_FILES = ("custom-image.sh", "ext4_sparse.py", "custom-crypt/otp-hwkey", "custom-crypt/otp-cryptroot.hook",
                "custom-crypt/otp-growroot", "custom-crypt/otp-growroot.service")
#: The dm-crypt mapping a prepared crypt image unlocks its root as (crypttab, fstab, cmdline.txt).
MAPPER = "cryptroot"
_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_NAME_RE = re.compile(r"[^A-Za-z0-9._+-]+")
#: Largest upload accepted (bytes).
MAX_UPLOAD = 64 * 1024 ** 3
#: Free space an upload must leave on the work disk (the two sets need room too).
UPLOAD_HEADROOM = 2 * 1024 ** 3


def check_id(cid: str) -> str:
    cid = str(cid or "").strip().lower()
    if not _ID_RE.fullmatch(cid):
        raise KeyError(f"no custom image {cid!r}")
    return cid


def display_name(name: str) -> str:
    """The file name the operator uploaded, reduced to something safe to show and to name files after."""
    base = re.split(r"[\\/]", str(name or ""))[-1].strip()
    base = _NAME_RE.sub("_", base).strip("._") or "custom.img"
    return base[:80]


def target(cid: str) -> str:
    """Job target of a custom image's preparation."""
    return f"custom:{cid}"


class Upload:
    """One upload being received: bytes go to a temporary file and into a sha256 as they arrive; :meth:`finish`
    checks the partition table and files the image under its id (an image uploaded before is not kept twice)."""

    def __init__(self, owner: "CustomImages", name: str, size: int):
        self.owner = owner
        self.name = display_name(name)
        self.size = int(size)
        owner.root.mkdir(parents=True, exist_ok=True)
        self.tmp = owner.root / f"upload-{uuid.uuid4().hex[:12]}.partial"
        self.f = open(self.tmp, "wb")
        self.h = hashlib.sha256()
        self.n = 0

    def write(self, data: bytes) -> None:
        if self.n + len(data) > self.size:
            raise ValueError(f"the upload is longer than announced ({self.size} bytes)")
        self.f.write(data)
        self.h.update(data)
        self.n += len(data)

    def abort(self) -> None:
        try:
            self.f.close()
        finally:
            try:
                self.tmp.unlink()
            except OSError:
                pass

    def finish(self) -> tuple[dict, bool]:
        """``(upload info, new)``; ValueError (the file is removed) when it is not an image the station takes."""
        self.f.close()
        try:
            if self.n != self.size:
                raise ValueError(f"the upload ended after {self.n} of {self.size} bytes")
            layout = diskimage.read_layout(self.tmp)
        except BaseException:
            self.abort()
            raise
        sha = self.h.hexdigest()
        cid = sha[:16]
        d = self.owner.dir(cid)
        if (d / "source.img").is_file() and (d / "upload.json").is_file():
            self.abort()
            return read_json(d / "upload.json"), False
        d.mkdir(parents=True, exist_ok=True)
        os.replace(self.tmp, d / "source.img")
        info = {"id": cid, "name": self.name, "size": self.n, "sha256": sha, "uploaded": now_iso(), "layout": layout}
        write_json(d / "upload.json", info)
        return info, True


class CustomImages:
    """The uploaded images, their preparation jobs and the sets stage 3 serves from them."""

    def __init__(self, cfg: Any, docker: Any, jobs: Any, tools: Any, hashes: Any):
        self.cfg = cfg
        self.docker = docker
        self.jobs = jobs
        self.tools = tools
        self.hashes = hashes

    # ------------------------------------------------------------------ paths / identity
    @property
    def root(self) -> Path:
        return Path(self.cfg.work_dir) / "artifacts" / "custom"

    def dir(self, cid: str) -> Path:
        return self.root / check_id(cid)

    def ids(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(d.name for d in self.root.iterdir()
                      if d.is_dir() and _ID_RE.fullmatch(d.name) and (d / "upload.json").is_file())

    def info(self, cid: str) -> dict | None:
        try:
            return read_json(self.dir(cid) / "upload.json")
        except (OSError, ValueError, KeyError):
            return None

    def fingerprint(self, variant: str) -> str:
        """Changes whenever a set prepared now would differ: the tools image, the scripts, the piece size."""
        return fingerprint("custom-image", variant, self.tools.hash(), self.tools.script_hash(*SCRIPT_FILES),
                           int(self.cfg.provisioning.max_piece_size))[:12]

    # ------------------------------------------------------------------ sets
    def published_set(self, cid: str, variant: str) -> tuple[Path, dict] | None:
        d = self.dir(cid)
        try:
            name = read_json(d / f"current-{variant}.json").get("set")
        except (OSError, ValueError, AttributeError):
            return None
        s = d / str(name or "")
        if not name or not is_complete(s) or not (s / "image.json").is_file():
            return None
        try:
            return s, read_json(s / "manifest.json")
        except (OSError, ValueError):
            return None

    def rebuild_reason(self, man: dict, variant: str) -> str | None:
        if man.get("variant") != variant:
            return f"set {man.get('set', '')} is a {man.get('variant')} set, not {variant}"
        if man.get("fingerprint") != self.fingerprint(variant):
            return ("the station's preparation scripts or the tools image changed since this image was prepared: "
                    "prepare it again")
        return None

    def current_set(self, cid: str, variant: str) -> tuple[Path, dict] | None:
        cur = self.published_set(cid, variant)
        if cur is None or self.rebuild_reason(cur[1], variant) is not None:
            return None
        return cur

    def servable_set(self, cid: str, variant: str) -> tuple[Path, dict]:
        """The set stage 3 writes, or NotReady (with the preparation job when one runs or was started)."""
        info = self.info(cid)
        if info is None:
            raise NotReady(f"custom image {cid} (setting image.custom) is not on this station: upload it on the page, "
                           "or clear image.custom to use the station image")
        cur = self.published_set(cid, variant)
        why = None if cur is None else self.rebuild_reason(cur[1], variant)
        if cur is not None and why is None:
            return cur
        job = self.jobs.active(target(cid))
        # A failed preparation is not started again by itself (the page asks every few seconds): Prepare does.
        if job is None and self.cfg.builds.auto and not self.errors(cid) and (self.dir(cid) / "source.img").is_file():
            job = self.start_prepare(cid)
        err = self.error(cid, variant)
        if err and job is None:
            raise NotReady(f"custom image {info.get('name', cid)}: preparing the {variant} variant failed: "
                           f"{err.get('error', '?')}", self.jobs.current(target(cid)))
        raise NotReady(f"custom image {info.get('name', cid)} is being prepared for the "
                       f"{'secure' if variant == 'crypt' else 'open'} scenario" if job else
                       f"custom image {info.get('name', cid)} is not prepared ({why or 'never prepared'}): "
                       "click Prepare on the page", job)

    def errors(self, cid: str) -> dict[str, dict]:
        """``{variant: {"error", "at", "job"}}`` of the variants whose last preparation failed."""
        return {v: e for v in VARIANTS if (e := self.error(cid, v))}

    def error(self, cid: str, variant: str) -> dict | None:
        try:
            return read_json(self.dir(cid) / f"error-{variant}.json")
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ upload
    def begin_upload(self, name: str, size: int) -> Upload:
        if size <= 0:
            raise ValueError("the upload is empty")
        if size > MAX_UPLOAD:
            raise ValueError(f"the upload has {size} bytes; the station takes images up to {MAX_UPLOAD} bytes")
        self.root.mkdir(parents=True, exist_ok=True)
        free = shutil.disk_usage(self.root).free
        if free < size + UPLOAD_HEADROOM:
            raise ValueError(f"not enough free space on the station's disk for a {size}-byte image "
                             f"({free} bytes free; it also needs room to prepare the image)")
        return Upload(self, name, size)

    def delete(self, cid: str) -> None:
        cid = check_id(cid)
        if self.info(cid) is None:
            raise KeyError(f"no custom image {cid!r}")
        if self.jobs.active(target(cid)) is not None:
            raise ValueError("the image is being prepared; wait for the job to end")
        if str(getattr(self.cfg.image, "custom", "") or "") == cid:
            raise ValueError("the image is the one stage 3 writes (image.custom): choose another image first")
        if not rmtree(self.dir(cid)):
            raise ValueError(f"could not remove {self.dir(cid)} (a file in use?)")

    # ------------------------------------------------------------------ preparation
    def missing(self, cid: str) -> list[str]:
        return [v for v in VARIANTS if self.current_set(cid, v) is None]

    def start_prepare(self, cid: str, force: bool = False) -> Any:
        cid = check_id(cid)
        info = self.info(cid)
        if info is None or not (self.dir(cid) / "source.img").is_file():
            raise KeyError(f"no custom image {cid!r}")
        return self.jobs.submit(target(cid), f"Prepare custom image {info.get('name', cid)}",
                                lambda job: self.prepare(job, cid, force=force), dedupe=True)

    def prepare(self, job: Any, cid: str, force: bool = False) -> None:
        """Job body: every variant that is not prepared for the current scripts (all with ``force``). A failed
        variant is recorded (``error-<variant>.json``) and the next one still runs; the job fails at the end."""
        info = self.info(cid)
        if info is None:
            raise RuntimeError(f"custom image {cid} is gone")
        failed = []
        with heavy_lock(self.cfg.work_dir, job.log):
            self.docker.ensure_daemon(job.log)
            self.tools.ensure(job.log)
            for variant in VARIANTS:
                if not force and self.current_set(cid, variant) is not None:
                    job.log(f"==> {info['name']} ({variant}) already prepared")
                    continue
                if variant == "crypt":
                    self.docker.ensure_arm64(job.log)
                try:
                    self._prepare_variant(job, cid, info, variant)
                except Exception as exc:
                    msg = str(exc) or exc.__class__.__name__
                    job.log(f"ERROR: {variant}: {msg}")
                    write_json(self.dir(cid) / f"error-{variant}.json", {"error": msg, "at": now_iso(), "job": job.id})
                    failed.append(f"{variant}: {msg}")
        if failed:
            raise RuntimeError("; ".join(failed))

    def _prepare_variant(self, job: Any, cid: str, info: dict, variant: str) -> Path:
        d = self.dir(cid)
        max_piece = int(self.cfg.provisioning.max_piece_size)
        fp = self.fingerprint(variant)
        env = {"VARIANT": variant, "MAX_PIECE": str(max_piece)}
        luks = None
        if variant == "crypt":
            luks = {"uuid": str(uuid.uuid4()), "mname": MAPPER}
            env.update(LUKS_UUID=luks["uuid"], MAPPER=MAPPER)
        job.log(f"==> custom image {info['name']} ({cid}): {variant} variant")
        part = fresh_partial(d / f"build-{job.id}-{variant}")
        try:
            self.tools.run_script(SCRIPT, mounts=[Mount.bind(d, "/in", readonly=True), Mount.bind(part, "/out")],
                                  env=env, log=job.log, privileged=True)
            facts = read_json(part / "custom.json")
            if facts.get("variant") != variant:
                raise RuntimeError(f"{SCRIPT} prepared a {facts.get('variant')!r} set, not {variant}")
            if variant == "crypt" and (facts.get("crypt") or {}).get("uuid") != luks["uuid"]:
                raise RuntimeError(f"{SCRIPT} reported another LUKS UUID than it was given")
            ij = imagejson.custom_image_json(facts, name=info["name"], version=f"custom-{cid[:8]}", luks=luks)
            write_json(part / "image.json", ij)
            simages: dict[str, list[dict]] = {}
            for key in ("boot", "root"):
                sec = facts.get(key) or {}
                simages[str(sec.get("simage"))] = [{"file": p["file"], "size": p["size"],
                                                    "sha256": self.hashes.sha256(part / str(p["file"]))}
                                                   for p in sec.get("pieces") or []]
            write_json(part / "collect.json", {"image_name": info["name"], "simages": {
                s: {"pieces": ps} for s, ps in simages.items()}})
            from .image import validate_collect
            collect = validate_collect(part, max_piece, self.hashes)
            name = f"{variant}-{fp}"
            final = d / name
            n = 2
            while final.exists():
                final = d / f"{name}-r{n}"
                n += 1
            manifest = {
                "name": info["name"], "variant": variant, "set": final.name, "built": now_iso(), "custom": cid,
                "source_sha256": info.get("sha256", ""), "version": f"custom-{cid[:8]}", "fingerprint": fp,
                "device_class": "pi5", "storage_type": "sd", "encrypted": variant == "crypt",
                "max_piece_size": max_piece, "os": facts.get("os") or {},
                "cloud_init": bool((facts.get("os") or {}).get("cloud_init")),
                "crypt": facts.get("crypt"),
                "image_json": {"name": "image.json", "size": (part / "image.json").stat().st_size,
                               "sha256": self.hashes.sha256(part / "image.json")},
                "simages": collect["simages_out"],
            }
            write_json(part / "manifest.json", manifest)
            commit_partial(part, final, {"set": final.name})
        except BaseException:
            job.log(f"preparation failed; the partial set is removed: {part.name}")
            rmtree(part)
            raise
        write_json(d / f"current-{variant}.json", {"set": final.name})
        try:
            (d / f"error-{variant}.json").unlink()
        except OSError:
            pass
        for old in d.iterdir():          # older sets of this variant (a few GB each)
            if old.is_dir() and old != final and old.name.startswith(f"{variant}-") and not old.name.endswith(".partial"):
                rmtree(old)
        job.log(f"==> {variant} set ready: {final}")
        return final

    # ------------------------------------------------------------------ status
    def status(self) -> list[dict]:
        """Every uploaded image, newest first: what it is and whether each variant is ready."""
        out = []
        selected = str(getattr(self.cfg.image, "custom", "") or "")
        for cid in self.ids():
            info = self.info(cid) or {}
            variants = {}
            os_info: dict = {}
            for v in VARIANTS:
                cur = self.published_set(cid, v)
                why = None if cur is None else self.rebuild_reason(cur[1], v)
                err = self.error(cid, v)
                st = {"ready": cur is not None and why is None, "set": cur[1].get("set", "") if cur else "",
                      "built": cur[1].get("built") if cur else None,
                      "detail": "" if cur is not None and why is None else (why or "not prepared"),
                      "error": (err or {}).get("error", "")}
                if cur is not None:
                    os_info = os_info or dict(cur[1].get("os") or {})
                variants[v] = st
            job = self.jobs.current(target(cid))
            out.append({"id": cid, "name": info.get("name", cid), "size": info.get("size"), "sha256": info.get("sha256", ""),
                        "uploaded": info.get("uploaded"), "layout": info.get("layout") or {}, "os": os_info,
                        "cloud_init": os_info.get("cloud_init") if os_info else None,
                        "variants": variants, "ready": all(s["ready"] for s in variants.values()),
                        "selected": cid == selected, "job": job.to_dict() if job is not None else None})
        out.sort(key=lambda x: str(x.get("uploaded") or ""), reverse=True)
        return out


__all__ = ["CustomImages", "Upload", "VARIANTS", "MAPPER", "check_id", "display_name", "target"]
