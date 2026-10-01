"""droneos image build (rpi-image-gen in Docker), IDP collect, and the stage-3 fastboot manifest.

Build = ``droneos build.sh --in-container`` in the owner's builder image (work volume keeps the image
output), then ``image-collect.sh`` in the tools image copies ``image.json`` + the sparse partition images
(split to ``max_piece_size``) into ``<work>/artifacts/image/<set>/``; Python validates them and writes
``manifest.json`` + ``.complete`` and points ``current.json`` at the set.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .. import imagejson
from .. import sparse
from ..docker import Mount
from .common import (NotReady, StageFile, TempKeys, commit_partial, file_url, fingerprint, fresh_partial,
                     git_output, heavy_lock, is_complete, now_iso, read_json, require_quick_build, write_json)

WHY_FWCRYPTO = ("generates the board's device-unique private key in OTP (the key the LUKS root is bound to); "
                "it can never be changed or erased")
WHY_ERASE = "wipes the whole storage device before the image is written"


class ImageBuilder:
    """droneos image sets and the stage-3 manifest."""

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

    @property
    def current_json(self) -> Path:
        return self.root / "current.json"

    @property
    def droneos_dir(self) -> Path:
        return Path(self.cfg.droneos_dir)

    def config_path(self) -> Path:
        p = Path(self.icfg.config)
        return p if p.is_absolute() else self.droneos_dir / p

    def config_hash(self) -> str:
        """sha256(config text + overrides)[:8] — part of the set name."""
        try:
            text = self.config_path().read_bytes().replace(b"\r\n", b"\n").decode("utf-8", "replace")
        except OSError:
            text = ""
        blob = text + "\n" + "\n".join(self.icfg.overrides)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8]

    def version(self) -> str:
        return git_output(self.droneos_dir, "describe", "--tags", "--always", "--dirty") or "unknown"

    def container_config(self) -> tuple[str, list[Mount]]:
        """(-c argument, extra mounts): /src/<rel> inside the checkout, else /cfg/<name> with /cfg mounted."""
        cfgp = self.config_path().resolve()
        try:
            rel = cfgp.relative_to(self.droneos_dir.resolve())
            return "/src/" + rel.as_posix(), []
        except ValueError:
            return "/cfg/" + cfgp.name, [Mount.bind(cfgp.parent, "/cfg", readonly=True)]

    def build_args(self, cfg_arg: str) -> list[str]:
        """Arguments after the builder image (exactly what droneos build.sh --docker passes)."""
        args = ["--in-container", "-B", "/work", "-o", "/out", "-c", cfg_arg]
        if self.icfg.overrides:
            args += ["--", *self.icfg.overrides]
        return args

    # ------------------------------------------------------------------ current set
    def current_set(self) -> tuple[Path, dict] | None:
        """(set dir, manifest) of the image stage 3 serves, or None (also when it needs a rebuild)."""
        cur = self.published_set()
        if cur is None or self.rebuild_reason(cur[1]) is not None:
            return None
        return cur

    def rebuild_reason(self, man: dict) -> str | None:
        """Why a published set cannot be served with the current settings (None when it can).

        Pieces are split to ``provisioning.max_piece_size`` at build time; a set split with a larger
        limit than the current one would hand the page pieces bigger than it was told to expect.
        """
        cur = int(self.cfg.provisioning.max_piece_size)
        built = int(man.get("max_piece_size") or 0)
        largest = max((int(p.get("size") or 0) for ps in (man.get("simages") or {}).values() for p in ps),
                      default=0)
        if built > cur or largest > cur:
            return (f"rebuild needed: image set {man.get('set', '')} was split into pieces of up to "
                    f"{max(built, largest)} bytes, more than provisioning.max_piece_size {cur}")
        return None

    def published_set(self) -> tuple[Path, dict] | None:
        """(set dir, manifest) named by current.json when it is complete, whatever the settings."""
        try:
            name = read_json(self.current_json).get("set")
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
    def build(self, job: Any, force: bool = False) -> None:
        """Job body "Build droneos image" (SPEC §10.4)."""
        if not force and self.current_set() is not None:
            job.log(f"==> droneos image already built: {self.current_set()[0]}")
            return
        if not (self.droneos_dir / "build.sh").is_file():
            raise RuntimeError(f"droneos checkout not found at {self.droneos_dir} (paths.droneos)")
        cfgp = self.config_path()
        if not cfgp.is_file():
            raise RuntimeError(f"image config {cfgp} not found (builds.image.config)")
        with heavy_lock(self.cfg.work_dir, job.log):
            if not force and self.current_set() is not None:      # built meanwhile (another process)
                job.log(f"==> droneos image already built: {self.current_set()[0]}")
                return
            self._build_locked(job)

    def _build_locked(self, job: Any) -> None:
        self.docker.ensure_daemon(job.log)
        self.docker.ensure_arm64(job.log)
        self.tools.ensure(job.log)
        self.docker.build_image(self.icfg.builder_tag, self.droneos_dir / "docker" / "Dockerfile",
                                self.droneos_dir / "docker", log=job.log)
        version = self.version()
        commit = git_output(self.droneos_dir, "rev-parse", "HEAD") or ""
        cfg_hash = self.config_hash()
        cfg_arg, extra = self.container_config()
        self.staging.mkdir(parents=True, exist_ok=True)
        mounts = [Mount.bind(self.droneos_dir, "/src", readonly=True),
                  Mount.volume(self.icfg.volume, "/work"),
                  Mount.bind(self.staging, "/out"), *extra]
        env = {"DRONEOS_IN_CONTAINER": "1", "DRONEOS_ROOT": "/src", "DRONEOS_VERSION": version}
        job.log(f"==> droneos {version}: {cfg_arg} {' '.join(self.icfg.overrides)}")
        self.docker.run(self.icfg.builder_tag, self.build_args(cfg_arg), mounts=mounts, env=env,
                        privileged=True, hostname="droneos-builder", interactive=True, log=job.log,
                        check=True)
        set_dir = self.collect(job, version=version, commit=commit, cfg_hash=cfg_hash)
        job.log(f"==> image set ready: {set_dir}")

    def collect(self, job: Any, *, version: str, commit: str, cfg_hash: str) -> Path:
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
            name = safe_name(f"{collect['image_name']}-{version}-{cfg_hash}")
            final = self.root / name
            n = 2
            while final.exists():
                final = self.root / f"{name}-r{n}"
                n += 1
            ij = imagejson.load(part / "image.json")
            manifest = {
                "name": collect["image_name"],
                "version": version,
                "set": final.name,
                "built": now_iso(),
                "droneos_commit": commit,
                "config": str(self.config_path()),
                "config_hash": cfg_hash,
                "overrides": list(self.icfg.overrides),
                "image_version": collect.get("image_version", ""),
                "device_class": collect.get("device_class") or imagejson.meta(ij).get("IGconf_device_class", ""),
                "storage_type": collect.get("storage_type") or imagejson.storage_type(ij),
                "encrypted": imagejson.is_encrypted(ij),
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
        write_json(self.current_json, {"set": final.name})
        if not self.icfg.keep_raw_image:
            for raw in self.staging.glob("*.img"):
                try:
                    raw.unlink()
                    job.log(f"==> removed raw image {raw.name} from staging (builds.image.keep_raw_image = false)")
                except OSError as exc:
                    job.log(f"warning: cannot remove {raw}: {exc}")
        return final

    def status(self, job: Any = None) -> dict:
        """Artifact status dict (SPEC §8) for target ``image``."""
        base = {"target": "image", "ready": False, "source": None, "version": "", "path": "", "size": None,
                "built": None, "detail": "", "job": job.to_dict() if job is not None else None}
        cur = self.published_set()
        if cur is None:
            base["detail"] = "the droneos image is not built yet"
            return base
        d, man = cur
        why = self.rebuild_reason(man)
        if why is not None:
            base["detail"] = why
            return base
        total = int((man.get("image_json") or {}).get("size") or 0)
        for pieces in (man.get("simages") or {}).values():
            total += sum(int(p.get("size") or 0) for p in pieces)
        detail = f"{man.get('name', '')} ({man.get('device_class', '')}, {man.get('storage_type', '')}" \
                 f"{', encrypted' if man.get('encrypted') else ''})"
        if man.get("config_hash") and man.get("config_hash") != self.config_hash():
            detail += "; built from different builds.image settings than the current ones (rebuild to apply)"
        base.update(ready=True, source="built", version=str(man.get("version", "")), path=str(d), size=total,
                    built=man.get("built"), detail=detail)
        return base

    # ------------------------------------------------------------------ stage 3
    def _resign(self, record: dict, set_dir: Path, set_name: str, simage: str, pieces: list[dict],
                secrets_fn) -> list[StageFile]:
        """Per-board re-signed boot slot pieces (boot-resign.sh), via a quick build."""
        serial = str(record.get("serial") or "")
        if len(pieces) != 1:
            raise NotReady(f"boot partition image {simage} is split into {len(pieces)} pieces; "
                           "re-signing a split boot image is not supported")
        khash = str(record.get("customer_key_hash") or "")
        max_piece = int(self.cfg.provisioning.max_piece_size)
        fp = fingerprint("stage3", set_name, simage, [p.get("sha256") for p in pieces], khash,
                         self.tools.hash(), self.tools.script_hash("boot-resign.sh"), max_piece)
        out_dir = Path(self.cfg.work_dir) / "modules" / serial / "stage3" / fp

        def build(job: Any) -> None:
            if is_complete(out_dir):
                return
            self.tools.ensure(job.log)
            secrets = secrets_fn()
            part = fresh_partial(out_dir)
            with TempKeys(self.cfg.work_dir, secrets["rsa_private_pem"], secrets["rsa_public_pem"]) as kdir:
                self.tools.run_script("boot-resign.sh",
                                      mounts=[Mount.bind(set_dir, "/in", readonly=True),
                                              Mount.bind(kdir, "/keys", readonly=True),
                                              Mount.bind(part, "/out")],
                                      env={"SIMAGE": simage, "MAX_PIECE": str(max_piece)}, log=job.log)
            res = read_json(part / "resign.json")
            files = [part / str(p["file"]) for p in res.get("pieces") or []]
            if not files:
                raise RuntimeError("boot-resign.sh reported no pieces")
            for p, f in zip(res["pieces"], files):
                if not f.is_file() or f.stat().st_size != int(p.get("size", -1)):
                    raise RuntimeError(f"boot-resign.sh piece {f.name} missing or size mismatch")
                if f.stat().st_size > max_piece:
                    raise RuntimeError(f"{f.name} is larger than max_piece_size")
            sparse.check_pieces(files)
            commit_partial(part, out_dir, {"stage": 3, "simage": simage})

        if not is_complete(out_dir):
            self.tools.require(self.jobs)
        require_quick_build(self.jobs, f"stage3:{serial}", f"Stage 3 boot re-sign for {serial}", build,
                            lambda: is_complete(out_dir), f"re-signed {simage}")
        res = read_json(out_dir / "resign.json")
        return [self.hashes.stage_file(str(p["file"]), out_dir / str(p["file"]),
                                       f"{simage} re-signed with the board key (boot.img + boot.sig)")
                for p in res.get("pieces") or []]

    def stage3(self, record: dict, *, signed: bool, secrets_fn, base_url: str) -> tuple[dict, dict[str, Path]]:
        """Stage-3 manifest (SPEC §8) and {name: path}."""
        serial = str(record.get("serial") or "")
        cur = self.published_set()
        if cur is None:
            raise NotReady("the droneos image is not built yet", self.jobs.active("image"))
        set_dir, man = cur
        why = self.rebuild_reason(man)
        if why is not None:
            raise NotReady(why, self.jobs.active("image"))
        ij = imagejson.load(set_dir / "image.json")
        disk = imagejson.storage_device(ij)
        encrypted = imagejson.is_encrypted(ij)
        prov = self.cfg.provisioning
        origin = f"droneos {man.get('set', set_dir.name)}"
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
        if signed:
            for b in imagejson.boot_simages(ij):
                if b in msim:
                    parts[b] = self._resign(record, set_dir, set_dir.name, b, msim[b], secrets_fn)
            notes.append("board OTP is locked to our key: boot partition re-signed for this board")
        ijm = man.get("image_json") or {}
        ij_path = set_dir / "image.json"
        ij_sf = StageFile("image.json", ij_path, int(ijm.get("size") or ij_path.stat().st_size),
                          str(ijm.get("sha256") or self.hashes.sha256(ij_path)), origin)
        crypt = []
        if encrypted and prov.recovery_passphrase:
            secrets = secrets_fn()
            dsec = secrets.get("device_secret") if secrets else None
            if not dsec:
                raise NotReady(f"module {serial} has no device secret; cannot derive the recovery passphrase")
            from ..secrets_gen import luks_passphrase
            for c in imagejson.crypt_containers(ij):
                crypt.append({"dev": imagejson.partition_name(disk, c["index"]), "mname": c["mname"],
                              "label": c["label"], "passphrase": luks_passphrase(dsec, c["mname"], serial)})
        elif encrypted:
            notes.append("provisioning.recovery_passphrase is false: no server-held LUKS passphrase is added")
        irreversible = [{"key": "oem fwcrypto init", "value": "", "why": WHY_FWCRYPTO}]
        if prov.erase_storage:
            irreversible.append({"key": "erase", "value": disk, "why": WHY_ERASE})
        if man.get("config_hash") and man.get("config_hash") != self.config_hash():
            notes.append("the image was built from different builds.image settings than the current ones")
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
            "image": {"name": man.get("name", ""), "version": man.get("version", ""),
                      "set": man.get("set", set_dir.name), "built": man.get("built"),
                      "device_class": man.get("device_class", ""), "storage_type": man.get("storage_type", ""),
                      "encrypted": encrypted},
            "storage_device": disk,
            "image_json": _entry(ij_sf, file_url(base_url, serial, 3, "image.json")),
            "parts": {s: [_entry(f, file_url(base_url, serial, 3, f.name)) for f in pl] for s, pl in parts.items()},
            "total_bytes": total,
            "max_piece_size": int(prov.max_piece_size),
            "fwcrypto_init": True,
            "erase": bool(prov.erase_storage),
            "crypt": crypt,
            "irreversible": irreversible,
            "notes": notes,
        }
        return manifest, paths


def _entry(f: StageFile, url: str) -> dict:
    """Stage-3 file entry: {"name", "size", "sha256", "url"} (SPEC §8)."""
    return {"name": f.name, "size": f.size, "sha256": f.sha256, "url": url}


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
