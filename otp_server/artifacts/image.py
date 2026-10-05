"""OS image build (rpi-image-gen in Docker), IDP collect, and the stage-3 fastboot manifest.

Build = ``image/build.sh --in-container`` in the builder image (``image/docker``): rpi-image-gen
(``image/rpi-image-gen``, a submodule) with the station layers (``image/layer``: Raspberry Pi OS Lite)
and a config (:mod:`otp_server.imageconfig`) mounted at ``/cfg``; the work volume keeps the image
output. Then ``image-collect.sh`` in the tools image copies ``image.json`` + the sparse partition images
(split to ``max_piece_size``) into ``<work>/artifacts/image/<set>/``; Python validates them and writes
``manifest.json`` + ``.complete`` and points ``current-<variant>.json`` at the set.

Two variants, one per provisioning mode: ``clear`` (``open``: plain root filesystem) and ``crypt``
(``secure``: LUKS2 root container), built with ``IGconf_image_pmap=<variant>``. Each has its own current
set, so switching the mode back and forth does not rebuild what is already there. A set is served only
while it matches the station: same rpi-image-gen revision, same image sources, image name, overrides
and partition map (``config_hash``).

The image is the same for every board. Stage 3 serves each board its own boot partition
(``boot-slot.sh``): the image's, with the board's first-boot files (:mod:`otp_server.firstboot`: account,
SSH, Wi-Fi, host name, time zone as cloud-init files) and, on a board locked to our key, re-signed.
"""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

from .. import firstboot
from .. import imageconfig
from .. import imagejson
from .. import sparse
from ..docker import Mount
from .common import (NotReady, StageFile, TempFiles, TempKeys, commit_partial, file_url, fingerprint, fresh_partial,
                     git_output, heavy_lock, is_complete, now_iso, read_json, require_quick_build, rmtree,
                     write_json)

WHY_FWCRYPTO = ("generates the board's device-unique private key in OTP (the key the LUKS root is bound to; "
                "a copy is exported to the station); it can never be changed or erased")
WHY_ERASE = "wipes the whole storage device before the image is written"
VARIANTS = ("clear", "crypt")
#: Where the build container sees the config dir (the config and any files next to it).
CFG_MOUNT = "/cfg"
#: The parts of ``image/`` an image depends on (rpi-image-gen itself is versioned by its commit).
SOURCES = ("build.sh", "docker", "layer")
#: Builds of one job before it gives up on settings that keep changing under it.
MAX_ROUNDS = 3
#: docker/scripts: a board's boot slot (first-boot files, re-signed on signed boards).
BOOT_SCRIPT = "boot-slot.sh"

#: Where the gadget's otp-keyexport helper leaves its output (docker/gadget-helpers/otp-keyexport).
KEY_EXPORT = {
    "dir": "/run/otp-keyexport",
    "key": "/run/otp-keyexport/key.der",
    "status": "/run/otp-keyexport/status",
    "request": "/run/otp-keyexport/request",
}


class ImageBuilder:
    """OS image sets (one current set per variant) and the stage-3 manifest."""

    def __init__(self, cfg: Any, docker: Any, jobs: Any, tools: Any, hashes: Any):
        self.cfg = cfg
        self.docker = docker
        self.jobs = jobs
        self.tools = tools
        self.hashes = hashes

    # ------------------------------------------------------------------ paths / identity
    @property
    def icfg(self) -> Any:
        return self.cfg.builds.image

    @property
    def root(self) -> Path:
        return Path(self.cfg.work_dir) / "artifacts" / "image"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    def current_json(self, variant: str) -> Path:
        return self.root / f"current-{check_variant(variant)}.json"

    @property
    def source_dir(self) -> Path:
        """``<repo>/image``: build.sh, docker/ (the builder image), layer/ (station layers), rpi-image-gen/."""
        return Path(self.cfg.image_dir)

    @property
    def rig_dir(self) -> Path:
        """The rpi-image-gen submodule."""
        return self.source_dir / "rpi-image-gen"

    def rendered(self) -> imageconfig.RenderedConfig:
        """The rpi-image-gen config of the station image (``image.name``)."""
        return imageconfig.render(self.cfg.image, mount=CFG_MOUNT)

    def overrides(self, variant: str) -> list[str]:
        """``builds.image.overrides`` plus the variant's provisioning map (``IGconf_image_pmap``, last)."""
        return [*self.icfg.overrides, f"IGconf_image_pmap={check_variant(variant)}"]

    SOURCES_TTL = 10.0

    def sources_hash(self) -> str:
        """sha256 over build.sh, docker/ and layer/ of ``image/`` (line endings normalised), cached briefly."""
        cached = getattr(self, "_sources_cache", None)
        now = time.monotonic()
        if cached is not None and now - cached[0] < self.SOURCES_TTL:
            return cached[1]
        h = hashlib.sha256()
        for rel in SOURCES:
            base = self.source_dir / rel
            files = [base] if base.is_file() else sorted((f for f in base.rglob("*") if f.is_file()), key=str)
            for f in files:
                try:
                    data = f.read_bytes().replace(b"\r\n", b"\n")
                except OSError:
                    data = b"<unreadable>"
                h.update(f.relative_to(self.source_dir).as_posix().encode("utf-8") + b"\0" + data + b"\0")
        value = h.hexdigest()[:16]
        self._sources_cache = (now, value)
        return value

    def _config_hash(self, rendered: imageconfig.RenderedConfig, variant: str) -> str:
        blob = "\n".join([rendered.digest(), self.sources_hash(), *self.overrides(variant)])
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8]

    def config_hash(self, variant: str) -> str:
        """sha256(image config + image sources + overrides of the variant)[:8] — part of the set name.
        Changes whenever the image built now would differ."""
        return self._config_hash(self.rendered(), variant)

    VERSION_TTL = 10.0   # status is polled every few seconds; git describe --dirty is not free on Windows

    def version(self, max_age: float | None = None) -> str:
        """``git describe --tags --always --dirty`` of the rpi-image-gen submodule (cached for a few seconds)."""
        ttl = self.VERSION_TTL if max_age is None else max_age
        cached = getattr(self, "_version_cache", None)
        now = time.monotonic()
        if cached is not None and now - cached[0] < ttl:
            return cached[1]
        v = git_output(self.rig_dir, "describe", "--tags", "--always", "--dirty") or "unknown"
        self._version_cache = (now, v)
        return v

    def build_args(self, variant: str) -> list[str]:
        """Arguments after the builder image (what build.sh --docker passes into its container)."""
        return ["--in-container", "-B", "/work", "-o", "/out", "-c", f"{CFG_MOUNT}/{imageconfig.CONFIG_NAME}",
                "--", *self.overrides(variant)]

    def write_config_dir(self, rendered: imageconfig.RenderedConfig, where: Path) -> Path:
        """``where`` (emptied) holding the config and its files, as the container sees them at /cfg."""
        rmtree(where)
        where.mkdir(parents=True)
        (where / imageconfig.CONFIG_NAME).write_text(rendered.text, encoding="utf-8", newline="\n")
        for rel, data in rendered.files.items():
            f = where / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        return where

    # ------------------------------------------------------------------ current sets
    def current_set(self, variant: str) -> tuple[Path, dict] | None:
        """(set dir, manifest) of the variant's image stage 3 serves, or None (also when it needs a rebuild)."""
        cur = self.published_set(variant)
        if cur is None or self.rebuild_reason(cur[1], variant) is not None:
            return None
        return cur

    def missing_variants(self) -> list[str]:
        """Variants without a servable set (not built, or a rebuild is needed)."""
        return [v for v in VARIANTS if self.current_set(v) is None]

    def rebuild_reason(self, man: dict, variant: str) -> str | None:
        """Why a published set cannot be served with the current settings (None when it can).

        Pieces are split to ``provisioning.max_piece_size`` at build time; a set split with a larger
        limit than the current one would hand the page pieces bigger than it was told to expect.

        The set must also come from the rpi-image-gen revision the submodule is at now and from the
        current image name, sources and overrides (``config_hash``): a board must never be flashed with
        another OS than the one the station is set up to provision. A mismatch makes stage 3 wait for a
        rebuild (the server rebuilds after the name changes and at start with ``builds.auto``, or via
        Build). The per-board settings (:mod:`otp_server.firstboot`) are not part of the image.
        """
        cur = int(self.cfg.provisioning.max_piece_size)
        built = int(man.get("max_piece_size") or 0)
        largest = max((int(p.get("size") or 0) for ps in (man.get("simages") or {}).values() for p in ps),
                      default=0)
        if built > cur or largest > cur:
            return (f"rebuild needed: image set {man.get('set', '')} was split into pieces of up to "
                    f"{max(built, largest)} bytes, more than provisioning.max_piece_size {cur}")
        if man.get("variant") and man.get("variant") != variant:
            return f"rebuild needed: image set {man.get('set', '')} is a {man.get('variant')} image, not {variant}"
        have_v = str(man.get("version") or "")
        if have_v:
            want_v = self.version()
            if want_v != "unknown" and want_v != have_v:      # unknown = git failed: cannot tell, keep serving
                return (f"rebuild needed: rpi-image-gen is at {want_v}, image set {man.get('set', '')} was "
                        f"built from {have_v}")
        have_c = str(man.get("config_hash") or "")
        if have_c and have_c != self.config_hash(variant):
            return (f"rebuild needed: the image name, builds.image.overrides or the station's image sources "
                    f"changed since image set {man.get('set', '')} was built")
        return None

    def published_set(self, variant: str) -> tuple[Path, dict] | None:
        """(set dir, manifest) named by current-<variant>.json when it is complete, whatever the settings."""
        try:
            name = read_json(self.current_json(variant)).get("set")
        except (OSError, ValueError, AttributeError):
            return None
        if not name:
            return None
        d = self.root / str(name)
        if not is_complete(d) or not (d / "image.json").is_file():
            return None
        try:
            return d, read_json(d / "manifest.json")
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ build job
    def build(self, job: Any, force: bool = False, variants: list[str] | None = None) -> None:
        """Job body "Build OS images": every variant that does not match the settings (all with ``force``).

        Settings saved while a variant builds make it stale at once; the job then builds it again (up to
        :data:`MAX_ROUNDS` rounds), so it ends with images of the settings in effect.
        """
        wanted = [check_variant(v) for v in (variants or VARIANTS)]
        forced = set(wanted) if force else set()
        for round_no in range(MAX_ROUNDS):
            todo = []
            for v in wanted:
                cur = None if v in forced else self.current_set(v)
                if cur is not None:
                    job.log(f"==> OS image ({v}) already built: {cur[0]}")
                else:
                    todo.append(v)
            if not todo:
                return
            if round_no:
                job.log(f"==> the image settings changed during the build: building {', '.join(todo)} again")
            if not (self.source_dir / "build.sh").is_file():
                raise RuntimeError(f"image sources not found at {self.source_dir} (image/build.sh)")
            if not (self.rig_dir / "rpi-image-gen").is_file():
                raise RuntimeError(f"rpi-image-gen is not checked out at {self.rig_dir}: "
                                   "git submodule update --init image/rpi-image-gen")
            with heavy_lock(self.cfg.work_dir, job.log):
                self._sweep_config_dirs(job)
                for v in todo:
                    cur = None if v in forced else self.current_set(v)
                    if cur is not None:      # built meanwhile (another process)
                        job.log(f"==> OS image ({v}) already built: {cur[0]}")
                        continue
                    self._build_locked(job, v)
                    forced.discard(v)
        stale = [v for v in wanted if self.current_set(v) is None]
        if stale:
            raise RuntimeError(f"the image settings changed during {MAX_ROUNDS} builds in a row; "
                               f"{', '.join(stale)} is still out of date: build again")

    def _sweep_config_dirs(self, job: Any) -> None:
        """Config dirs a killed build left behind; called under the heavy lock, when no
        other build can be using one."""
        base = self.root / "cfg"
        if not base.is_dir():
            return
        for d in base.iterdir():
            if rmtree(d):
                job.log(f"==> removed the config dir of an interrupted build: {d.name}")

    def _build_locked(self, job: Any, variant: str) -> None:
        self.docker.ensure_daemon(job.log)
        self.docker.ensure_arm64(job.log)
        self.tools.ensure(job.log)
        self.docker.build_image(self.icfg.builder_tag, self.source_dir / "docker" / "Dockerfile",
                                self.source_dir / "docker", log=job.log)
        version = self.version(max_age=0)
        commit = git_output(self.rig_dir, "rev-parse", "HEAD") or ""
        rendered = self.rendered()
        cfg_hash = self._config_hash(rendered, variant)
        cfg_dir = self.write_config_dir(rendered, self.root / "cfg" / f"{job.id}-{variant}")
        try:
            self.staging.mkdir(parents=True, exist_ok=True)
            mounts = [Mount.bind(self.source_dir, "/src", readonly=True),
                      Mount.volume(self.icfg.volume, "/work"),
                      Mount.bind(self.staging, "/out"),
                      Mount.bind(cfg_dir, CFG_MOUNT, readonly=True)]
            env = {"OTP_IMAGE_IN_CONTAINER": "1", "OTP_IMAGE_ROOT": "/src", "OTP_IMAGE_VERSION": version,
                   "OTP_IMAGE_CONFIG_ID": imageconfig.CONFIG_NAME}
            job.log(f"==> rpi-image-gen {version} ({variant}): {' '.join(self.overrides(variant))}")
            job.log(f"==> {imageconfig.CONFIG_NAME}:")
            for line in rendered.text.splitlines():
                job.log(f"    {line}")
            if rendered.files:
                job.log("==> files next to it: " + ", ".join(sorted(rendered.files)))
            self.docker.run(self.icfg.builder_tag, self.build_args(variant), mounts=mounts, env=env,
                            privileged=True, hostname="otp-image-builder", interactive=True, log=job.log,
                            check=True)
        finally:
            rmtree(cfg_dir)          # the config dir only lives as long as the build
        set_dir = self.collect(job, version=version, commit=commit, cfg_hash=cfg_hash, variant=variant,
                               settings=rendered.summary)
        job.log(f"==> image set ready: {set_dir}")

    def collect(self, job: Any, *, version: str, commit: str, cfg_hash: str, variant: str,
                settings: dict | None = None) -> Path:
        """Run image-collect.sh into a .partial dir, validate, write manifest.json, publish the set."""
        max_piece = int(self.cfg.provisioning.max_piece_size)
        self.root.mkdir(parents=True, exist_ok=True)
        part = fresh_partial(self.root / f"build-{job.id}")
        try:
            self.tools.run_script("image-collect.sh",
                                  mounts=[Mount.volume(self.icfg.volume, "/work", readonly=True),
                                          Mount.bind(part, "/out")],
                                  env={"MAX_PIECE": str(max_piece)}, log=job.log)
            job.log("==> validating collected pieces")
            collect = validate_collect(part, max_piece, self.hashes)
            ij = imagejson.load(part / "image.json")
            encrypted = imagejson.is_encrypted(ij)
            if encrypted != (variant == "crypt"):
                raise RuntimeError(f"the {variant} build produced an image that is "
                                   f"{'encrypted' if encrypted else 'not encrypted'} (IGconf_image_pmap ignored?)")
            name = safe_name(f"{collect['image_name']}-{variant}-{version}-{cfg_hash}")
            final = self.root / name
            n = 2
            while final.exists():
                final = self.root / f"{name}-r{n}"
                n += 1
            manifest = {
                "name": collect["image_name"],
                "variant": variant,
                "version": version,
                "set": final.name,
                "built": now_iso(),
                "rpi_image_gen_commit": commit,
                "sources_hash": self.sources_hash(),
                "image_settings": dict(settings or {}),
                "config_hash": cfg_hash,
                "overrides": self.overrides(variant),
                "image_version": collect.get("image_version", ""),
                "device_class": collect.get("device_class") or imagejson.meta(ij).get("IGconf_device_class", ""),
                "storage_type": collect.get("storage_type") or imagejson.storage_type(ij),
                "encrypted": encrypted,
                "max_piece_size": max_piece,
                "image_json": {"name": "image.json", "size": (part / "image.json").stat().st_size,
                               "sha256": self.hashes.sha256(part / "image.json")},
                "simages": collect["simages_out"],
            }
            write_json(part / "manifest.json", manifest)
            commit_partial(part, final, {"set": final.name})
        except BaseException:
            job.log(f"collect failed; partial set left for inspection: {part}")
            raise
        write_json(self.current_json(variant), {"set": final.name})
        if not self.icfg.keep_raw_image:
            for raw in self.staging.glob("*.img"):
                try:
                    raw.unlink()
                    job.log(f"==> removed raw image {raw.name} from staging (builds.image.keep_raw_image = false)")
                except OSError as exc:
                    job.log(f"warning: cannot remove {raw}: {exc}")
        return final

    def variant_status(self, variant: str) -> dict:
        """``{"ready", "set", "version", "path", "size", "built", "detail"}`` of one variant."""
        out = {"ready": False, "set": "", "version": "", "path": "", "size": None, "built": None, "detail": ""}
        cur = self.published_set(variant)
        if cur is None:
            out["detail"] = f"the {variant} image is not built yet"
            return out
        d, man = cur
        why = self.rebuild_reason(man, variant)
        if why is not None:
            out["detail"] = why
            return out
        total = int((man.get("image_json") or {}).get("size") or 0)
        for pieces in (man.get("simages") or {}).values():
            total += sum(int(p.get("size") or 0) for p in pieces)
        out.update(ready=True, set=str(man.get("set") or d.name), version=str(man.get("version", "")),
                   path=str(d), size=total, built=man.get("built"),
                   detail=f"{man.get('name', '')} ({man.get('device_class', '')}, {man.get('storage_type', '')}"
                          f"{', encrypted' if man.get('encrypted') else ''})")
        return out

    def status(self, job: Any = None) -> dict:
        """Artifact status dict (SPEC §8) for target ``image``: ready when every variant is.

        ``variants`` holds the per-variant status; the top-level fields describe the crypt set when it is
        ready, else the clear one.
        """
        variants = {v: self.variant_status(v) for v in VARIANTS}
        base = {"target": "image", "ready": all(s["ready"] for s in variants.values()), "source": None,
                "version": "", "path": "", "size": None, "built": None, "detail": "",
                "job": job.to_dict() if job is not None else None, "variants": variants}
        shown = next((variants[v] for v in ("crypt", "clear") if variants[v]["ready"]), None)
        if shown is not None:
            base.update(source="built", version=shown["version"], path=shown["path"], size=shown["size"],
                        built=shown["built"])
        base["detail"] = "; ".join(f"{v}: {s['detail']}" for v, s in variants.items())
        return base

    # ------------------------------------------------------------------ stage 3
    def _board_boot(self, record: dict, set_dir: Path, simage: str, pieces: list[dict], *, signed: bool,
                    seed: firstboot.Seed, secrets_fn) -> list[StageFile]:
        """The board's own boot slot pieces (boot-slot.sh), via a quick build: the image's boot partition
        with the board's first-boot files and cmdline additions, re-signed with the board key when
        ``signed``."""
        serial = str(record.get("serial") or "")
        if len(pieces) != 1:
            raise NotReady(f"boot partition image {simage} is split into {len(pieces)} pieces; "
                           "a split boot image is not supported")
        khash = str(record.get("customer_key_hash") or "") if signed else ""
        max_piece = int(self.cfg.provisioning.max_piece_size)
        fp = fingerprint("stage3-boot", set_dir.name, simage, [p.get("sha256") for p in pieces], signed, khash,
                         seed.digest(), self.tools.hash(), self.tools.script_hash(BOOT_SCRIPT), max_piece)
        out_dir = Path(self.cfg.work_dir) / "modules" / serial / "stage3" / fp
        seed_files = {f"files/{name}": data for name, data in seed.files.items()}
        seed_files["cmdline.append"] = (seed.cmdline + "\n").encode("utf-8")

        def build(job: Any) -> None:
            if is_complete(out_dir):
                return
            self.tools.ensure(job.log)
            part = fresh_partial(out_dir)
            env = {"SIMAGE": simage, "SIGN": "1" if signed else "0", "MAX_PIECE": str(max_piece)}
            mounts = [Mount.bind(set_dir, "/in", readonly=True), Mount.bind(part, "/out")]
            with TempFiles(self.cfg.work_dir, seed_files) as sdir:
                mounts.append(Mount.bind(sdir, "/seed", readonly=True))
                if signed:
                    secrets = secrets_fn()
                    with TempKeys(self.cfg.work_dir, secrets["rsa_private_pem"],
                                  secrets["rsa_public_pem"]) as kdir:
                        mounts.append(Mount.bind(kdir, "/keys", readonly=True))
                        self.tools.run_script(BOOT_SCRIPT, mounts=mounts, env=env, log=job.log)
                else:
                    self.tools.run_script(BOOT_SCRIPT, mounts=mounts, env=env, log=job.log)
            res = read_json(part / "slot.json")
            files = [part / str(p["file"]) for p in res.get("pieces") or []]
            if not files:
                raise RuntimeError(f"{BOOT_SCRIPT} reported no pieces")
            if bool(res.get("signed")) != signed:
                raise RuntimeError(f"{BOOT_SCRIPT} made a {'signed' if res.get('signed') else 'unsigned'} slot")
            if sorted(res.get("seed") or []) != sorted(seed.files):
                raise RuntimeError(f"{BOOT_SCRIPT} wrote first-boot files {res.get('seed')}, expected "
                                   f"{sorted(seed.files)}")
            for p, f in zip(res["pieces"], files):
                if not f.is_file() or f.stat().st_size != int(p.get("size", -1)):
                    raise RuntimeError(f"{BOOT_SCRIPT} piece {f.name} missing or size mismatch")
                if f.stat().st_size > max_piece:
                    raise RuntimeError(f"{f.name} is larger than max_piece_size")
            sparse.check_pieces(files)
            commit_partial(part, out_dir, {"stage": 3, "simage": simage})

        if not is_complete(out_dir):
            self.tools.require(self.jobs)
        require_quick_build(self.jobs, f"stage3:{serial}", f"Stage 3 boot partition for {serial}", build,
                            lambda: is_complete(out_dir), f"the boot partition of {serial} ({simage})")
        res = read_json(out_dir / "slot.json")
        what = (f"{simage} with this board's first-boot files"
                + (", re-signed with the board key (boot.img + boot.sig)" if signed else ""))
        return [self.hashes.stage_file(str(p["file"]), out_dir / str(p["file"]), what)
                for p in res.get("pieces") or []]

    def stage3(self, record: dict, *, secure: bool, signed: bool, secrets_fn,
               base_url: str) -> tuple[dict, dict[str, Path]]:
        """Stage-3 manifest (SPEC §8) and {name: path}.

        ``secure``: the crypt image, ``oem fwcrypto init`` and the OTP device key export; otherwise the
        clear image and nothing that touches OTP.
        """
        serial = str(record.get("serial") or "")
        variant = "crypt" if secure else "clear"
        scenario = "secure" if secure else "open"
        cur = self.published_set(variant)
        if cur is None:
            raise NotReady(f"the OS image for the {scenario} scenario ({variant}) is not built yet",
                           self.jobs.active("image"))
        set_dir, man = cur
        why = self.rebuild_reason(man, variant)
        if why is not None:
            raise NotReady(why, self.jobs.active("image"))
        ij = imagejson.load(set_dir / "image.json")
        disk = imagejson.storage_device(ij)
        encrypted = imagejson.is_encrypted(ij)
        if encrypted != secure:
            raise NotReady(f"image set {set_dir.name} is {'encrypted' if encrypted else 'not encrypted'}, the "
                           f"{scenario} scenario needs {'an encrypted' if secure else 'a clear'} image; rebuild it",
                           self.jobs.active("image"))
        prov = self.cfg.provisioning
        origin = f"image {man.get('set', set_dir.name)}"
        msim: dict = man.get("simages") or {}
        order = [s for s in imagejson.simages(ij) if s in msim] + [s for s in msim if s not in imagejson.simages(ij)]
        missing = [s for s in imagejson.simages(ij) if s not in msim]
        if missing:
            raise NotReady(f"image set {set_dir.name} lacks {', '.join(missing)}; rebuild the image")
        parts: dict[str, list[StageFile]] = {}
        for s in order:
            parts[s] = [StageFile(str(p["name"]), set_dir / str(p["name"]), int(p["size"]), str(p["sha256"]), origin)
                        for p in msim[s]]
        notes: list[str] = []
        boots = [b for b in imagejson.boot_simages(ij) if b in msim]
        if not boots:
            raise NotReady(f"image set {set_dir.name} has no boot partition image for the first-boot files; "
                           "rebuild the image")
        seed = firstboot.render(self.cfg.image, serial)
        for b in boots:
            parts[b] = self._board_boot(record, set_dir, b, msim[b], signed=signed, seed=seed, secrets_fn=secrets_fn)
        fb = seed.summary
        notes.append(f"first boot (cloud-init, files in the boot partition): host name {fb['hostname']}, "
                     + (f"user {fb['user']}" if fb["user"] else "the Raspberry Pi OS wizard asks for a user")
                     + f", SSH {'on' if fb['ssh'] else 'off'}, "
                     + (f"Wi-Fi {fb['wifi_ssid']!r}" if fb["wifi_ssid"] else "no Wi-Fi network")
                     + f" ({fb['wifi_country']}), {fb['timezone']}")
        if signed:
            notes.append("board OTP is locked to our key: boot partition re-signed for this board")
        ijm = man.get("image_json") or {}
        ij_path = set_dir / "image.json"
        ij_sf = StageFile("image.json", ij_path, int(ijm.get("size") or ij_path.stat().st_size),
                          str(ijm.get("sha256") or self.hashes.sha256(ij_path)), origin)
        crypt = []
        if secure and prov.recovery_passphrase:
            secrets = secrets_fn()
            dsec = secrets.get("device_secret") if secrets else None
            if not dsec:
                raise NotReady(f"module {serial} has no device secret; cannot derive the recovery passphrase")
            from ..secrets_gen import luks_passphrase
            for c in imagejson.crypt_containers(ij):
                crypt.append({"dev": imagejson.partition_name(disk, c["index"]), "mname": c["mname"],
                              "label": c["label"], "passphrase": luks_passphrase(dsec, c["mname"], serial)})
        irreversible = []
        if secure:
            irreversible.append({"key": "oem fwcrypto init", "value": "", "why": WHY_FWCRYPTO})
            notes.append("the OTP device key is exported to the station before the storage is erased")
        else:
            notes.append("open scenario: clear image, OTP is not touched")
        if prov.erase_storage:
            irreversible.append({"key": "erase", "value": disk, "why": WHY_ERASE})
        paths = {"image.json": ij_path}
        total = ij_sf.size
        for pl in parts.values():
            for f in pl:
                paths[f.name] = f.path
                total += f.size
        manifest = {
            "stage": 3,
            "kind": "fastboot-idp",
            "title": "Image",
            "ready": True,
            "mode": "signed" if signed else "unsigned",
            "scenario": scenario,
            "image": {"name": man.get("name", ""), "version": man.get("version", ""),
                      "set": man.get("set", set_dir.name), "built": man.get("built"),
                      "variant": variant, "device_class": man.get("device_class", ""),
                      "storage_type": man.get("storage_type", ""), "encrypted": encrypted},
            "storage_device": disk,
            "image_json": _entry(ij_sf, file_url(base_url, serial, 3, "image.json")),
            "parts": {s: [_entry(f, file_url(base_url, serial, 3, f.name)) for f in pl] for s, pl in parts.items()},
            "total_bytes": total,
            "max_piece_size": int(prov.max_piece_size),
            "fwcrypto_init": bool(secure),
            "key_export": dict(KEY_EXPORT) if secure else None,
            "erase": bool(prov.erase_storage),
            "crypt": crypt,
            "firstboot": seed.summary,
            "irreversible": irreversible,
            "notes": notes,
        }
        return manifest, paths


def _entry(f: StageFile, url: str) -> dict:
    """Stage-3 file entry: {"name", "size", "sha256", "url"} (SPEC §8)."""
    return {"name": f.name, "size": f.size, "sha256": f.sha256, "url": url}


def check_variant(variant: str) -> str:
    """``variant`` when it is one of :data:`VARIANTS` (ValueError otherwise)."""
    if variant not in VARIANTS:
        raise ValueError(f"image variant must be one of {', '.join(VARIANTS)}, got {variant!r}")
    return variant


def safe_name(name: str) -> str:
    """Directory-safe set name."""
    return re.sub(r"[^A-Za-z0-9._+-]", "_", name).strip("._") or "image"


def validate_collect(out_dir: Path, max_piece: int, hashes: Any) -> dict:
    """Validate image-collect.sh output in ``out_dir`` (collect.json, image.json, pieces).

    Checks: every simage named by image.json is present; pieces exist with the reported size and
    sha256, are ≤ ``max_piece``, are valid sparse files describing the same image, and do not expand
    beyond the partition. Returns collect.json plus ``simages_out`` = {simage: [{"name","size","sha256"}]}
    in image.json order.
    """
    out_dir = Path(out_dir)
    try:
        collect = read_json(out_dir / "collect.json")
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"image-collect.sh wrote no readable collect.json: {exc}") from exc
    if not (out_dir / "image.json").is_file():
        raise RuntimeError("image-collect.sh did not copy image.json")
    ij = imagejson.load(out_dir / "image.json")
    if not collect.get("image_name"):
        raise RuntimeError("collect.json has no image_name")
    got = collect.get("simages") or {}
    wanted = imagejson.simages(ij)
    if not wanted:
        raise RuntimeError("image.json names no sparse partition images (layout.partitionimages[*].simage)")
    out: dict[str, list[dict]] = {}
    for simage in wanted:
        entry = got.get(simage)
        if not entry or not entry.get("pieces"):
            raise RuntimeError(f"collect.json has no pieces for {simage}")
        files = []
        pieces = []
        for p in entry["pieces"]:
            f = out_dir / str(p["file"])
            if not f.is_file():
                raise RuntimeError(f"piece {f.name} is missing")
            size = f.stat().st_size
            if size != int(p.get("size", -1)):
                raise RuntimeError(f"piece {f.name}: size {size} != collect.json {p.get('size')}")
            if size > max_piece:
                raise RuntimeError(f"piece {f.name} ({size} bytes) exceeds max_piece_size {max_piece}")
            digest = hashes.sha256(f)
            if p.get("sha256") and str(p["sha256"]).lower() != digest:
                raise RuntimeError(f"piece {f.name}: sha256 mismatch")
            files.append(f)
            pieces.append({"name": f.name, "size": size, "sha256": digest})
        try:
            info = sparse.check_pieces(files)
        except sparse.SparseError as exc:
            raise RuntimeError(f"{simage}: {exc}") from exc
        psize = imagejson.simage_partition_size(ij, simage)
        if psize and info["expanded_size"] > psize:
            raise RuntimeError(f"{simage} expands to {info['expanded_size']} bytes, larger than its "
                               f"partition ({psize} bytes)")
        out[simage] = pieces
    collect["simages_out"] = out
    return collect
