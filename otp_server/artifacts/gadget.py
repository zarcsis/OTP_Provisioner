"""Fastboot gadget (pi-gen-micro ``fastboot`` configuration) and the stage-2 rpiboot directory.

Built gadget: ``<work>/artifacts/gadget/<key>[-r<N>]/fastboot-gadget-<targets>.img`` (+ build-info.json,
.complete), key = ``<pi-gen-micro commit>-<builder hash>-<targets>`` where the builder hash covers
docker/gadget.Dockerfile + gadget-entrypoint.sh. A forced rebuild of the same key goes to the next
``-r<N>`` directory instead of replacing one that may be being served; the newest complete one wins. Prebuilt fallback: rpi-sb-provisioner ``host-support/
fastboot-gadget-pi5-family.img`` (same configuration's output, only valid for ``pi5-family``).
Stage 2 = ``bootfiles.bin`` (usbboot firmware) + ``boot.img`` (the gadget) + ``config.txt``; for a board
locked to our key also ``boot.sig`` and a counter-signed ``bootfiles.bin`` from ``stage2-sign.sh``.
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path
from typing import Any

from ..docker import Mount
from .common import (NotReady, TempKeys, commit_partial, content_hash, file_url, fingerprint, fresh_partial,
                     git_output, heavy_lock, is_complete, now_iso, read_json, require_quick_build, rmtree,
                     write_json, write_text)

STAGE2_CONFIG = "boot_ramdisk=1\nuart_2ndstage=1\n"
PREBUILT_TARGETS = "pi5-family"


class GadgetBuilder:
    """Gadget build job, current-gadget selection and stage-2 files."""

    def __init__(self, cfg: Any, docker: Any, jobs: Any, tools: Any, hashes: Any):
        self.cfg = cfg
        self.docker = docker
        self.jobs = jobs
        self.tools = tools
        self.hashes = hashes
        self._commit: tuple[float, str] | None = None

    # ------------------------------------------------------------------ paths / identity
    @property
    def gcfg(self) -> Any:
        return self.cfg.builds.gadget

    @property
    def pgm_dir(self) -> Path:
        return Path(self.cfg.repo_root) / "external" / "pi-gen-micro"

    @property
    def prebuilt_path(self) -> Path:
        return (Path(self.cfg.repo_root) / "external" / "rpi-sb-provisioner" / "host-support"
                / "fastboot-gadget-pi5-family.img")

    @property
    def bootfiles_path(self) -> Path:
        # A real file in the usbboot checkout (never go through the firmware/2712/* git symlinks).
        return Path(self.cfg.repo_root) / "external" / "usbboot" / "firmware" / "bootfiles.bin"

    def commit(self) -> str:
        """Short (12) pi-gen-micro commit, cached for 30 s; "unknown" when git cannot tell."""
        now = time.monotonic()
        if self._commit and now - self._commit[0] < 30:
            return self._commit[1]
        c = git_output(self.pgm_dir, "rev-parse", "--short=12", "HEAD") or "unknown"
        self._commit = (now, c)
        return c

    @property
    def builder_files(self) -> list[Path]:
        d = Path(self.cfg.repo_root) / "docker"
        return [d / "gadget.Dockerfile", d / "gadget-entrypoint.sh"]

    def builder_hash(self) -> str:
        """Content hash of gadget.Dockerfile + gadget-entrypoint.sh (CRLF-normalised)."""
        return content_hash(self.builder_files)

    def key(self) -> str:
        return f"{self.commit()}-{self.builder_hash()[:8]}-{self.gcfg.targets}"

    @property
    def root(self) -> Path:
        return Path(self.cfg.work_dir) / "artifacts" / "gadget"

    def _versions(self) -> list[tuple[int, Path]]:
        """(revision, dir) of ``<key>`` (revision 1) and ``<key>-r<N>``, oldest first."""
        key = self.key()
        pat = re.compile(rf"^{re.escape(key)}(?:-r(\d+))?$")
        out = []
        if self.root.is_dir():
            for d in self.root.iterdir():
                m = pat.match(d.name)
                if m and d.is_dir():
                    out.append((int(m.group(1) or 1), d))
        return sorted(out)

    def built_dir(self) -> Path:
        """Newest complete build dir of the current key (``<root>/<key>`` when there is none)."""
        for _rev, d in reversed(self._versions()):
            if is_complete(d):
                return d
        return self.root / self.key()

    def next_build_dir(self) -> Path:
        """Where a new build of the current key is committed: never an existing directory."""
        versions = self._versions()
        if not versions:
            return self.root / self.key()
        return self.root / f"{self.key()}-r{max(2, versions[-1][0] + 1)}"

    def image_name(self) -> str:
        return f"fastboot-gadget-{self.gcfg.targets}.img"

    def built_image(self) -> Path | None:
        d = self.built_dir()
        p = d / self.image_name()
        return p if is_complete(d) and p.is_file() and p.stat().st_size > 0 else None

    def prebuilt_image(self) -> Path | None:
        p = self.prebuilt_path
        if self.gcfg.targets == PREBUILT_TARGETS and p.is_file() and p.stat().st_size > 0:
            return p
        return None

    def current(self) -> tuple[Path, str, str]:
        """(path, source "built"|"prebuilt", version) of the gadget stage 2 serves, per builds.gadget.source."""
        source = self.gcfg.source
        built = self.built_image() if source in ("build", "auto") else None
        if built is not None:
            return built, "built", built.parent.name
        if source in ("prebuilt", "auto"):
            pre = self.prebuilt_image()
            if pre is not None:
                sb = git_output(self.pgm_dir.parent / "rpi-sb-provisioner", "rev-parse", "--short=12", "HEAD")
                return pre, "prebuilt", f"rpi-sb-provisioner host-support ({sb or 'unknown'})"
        job = self.jobs.active("gadget")
        if source == "build":
            raise NotReady("the fastboot gadget is not built yet (builds.gadget.source = build)", job)
        if source == "prebuilt":
            raise NotReady(f"no prebuilt fastboot gadget for targets {self.gcfg.targets!r} "
                           f"(only {PREBUILT_TARGETS} ships in rpi-sb-provisioner host-support)", job)
        raise NotReady("no fastboot gadget: not built yet and no prebuilt image for "
                       f"targets {self.gcfg.targets!r}", job)

    # ------------------------------------------------------------------ build job
    def build(self, job: Any, force: bool = False) -> None:
        """Job body: build the gadget builder image and run it (SPEC §11)."""
        if not force and self.built_image() is not None:
            job.log(f"==> gadget already built: {self.built_dir()}")
            return
        if not (self.pgm_dir / "pi-gen-micro").is_file():
            raise RuntimeError(f"{self.pgm_dir} is not checked out (git submodule update --init external/pi-gen-micro)")
        with heavy_lock(self.cfg.work_dir, job.log):
            if not force and self.built_image() is not None:      # built meanwhile (another process)
                job.log(f"==> gadget already built: {self.built_dir()}")
                return
            self._build_locked(job)

    def _build_locked(self, job: Any) -> None:
        self.docker.ensure_daemon(job.log)
        self.docker.ensure_arm64(job.log)
        dockerfile = Path(self.cfg.repo_root) / "docker" / "gadget.Dockerfile"
        self.docker.build_image(self.gcfg.image_tag, dockerfile, Path(self.cfg.repo_root) / "docker",
                                platform="linux/arm64", log=job.log)
        commit = self.commit()
        targets = self.gcfg.targets
        final = self.next_build_dir()
        part = fresh_partial(final)
        mounts = [Mount.bind(self.pgm_dir, "/src", readonly=True),
                  Mount.volume(self.gcfg.volume, "/work"),
                  Mount.bind(part, "/out")]
        job.log(f"==> pi-gen-micro fastboot {targets} (commit {commit})")
        self.docker.run(self.gcfg.image_tag, [], mounts=mounts,
                        env={"PGM_TARGETS": targets, "PGM_COMMIT": commit},
                        platform="linux/arm64", log=job.log, check=True)
        img = part / self.image_name()
        if not img.is_file() or img.stat().st_size == 0:
            raise RuntimeError(f"the gadget build did not produce {img.name}")
        info_path = part / "build-info.json"
        try:
            info = read_json(info_path)
        except (OSError, ValueError):
            info = {}
        if not info:
            info = {"targets": targets, "built": now_iso(), "pi_gen_micro_commit": commit,
                    "fastbootd_deb": "", "size": img.stat().st_size}
            write_json(info_path, info)
        size = img.stat().st_size
        commit_partial(part, final, {"key": self.key(), "builder_hash": self.builder_hash()})
        job.log(f"==> gadget ready: {final / img.name} ({size} bytes)")

    def status(self, job: Any = None) -> dict:
        """Artifact status dict (SPEC §8) for target ``gadget``."""
        base = {"target": "gadget", "ready": False, "source": None, "version": "", "path": "", "size": None,
                "built": None, "detail": "", "job": job.to_dict() if job is not None else None}
        try:
            path, source, version = self.current()
        except NotReady as exc:
            base["detail"] = exc.reason
            return base
        base.update(ready=True, source=source, version=version, path=str(path), size=path.stat().st_size)
        if source == "built":
            try:
                base["built"] = read_json(path.parent / "build-info.json").get("built")
            except (OSError, ValueError, AttributeError):
                pass
            base["detail"] = f"pi-gen-micro fastboot {self.gcfg.targets}"
        else:
            detail = "prebuilt image from rpi-sb-provisioner host-support"
            if self.gcfg.source == "auto":
                detail += f"; no build for pi-gen-micro {self.commit()} yet"
            base["detail"] = detail
        return base

    # ------------------------------------------------------------------ stage 2
    def config_path(self) -> Path:
        p = Path(self.cfg.work_dir) / "artifacts" / "stage2" / "config.txt"
        try:
            if p.read_text(encoding="utf-8") == STAGE2_CONFIG:
                return p
        except OSError:
            pass
        write_text(p, STAGE2_CONFIG)
        return p

    def signed_dir(self, serial: str, boot_sha: str, bootfiles_sha: str, khash: str) -> tuple[Path, str]:
        fp = fingerprint("stage2", boot_sha, bootfiles_sha, khash, self.tools.hash(),
                         self.tools.script_hash("stage2-sign.sh"))
        return Path(self.cfg.work_dir) / "modules" / serial / "stage2" / fp, fp

    def sign_build(self, job: Any, out_dir: Path, boot_img: Path, secrets: dict) -> None:
        """Job body: stage2-sign.sh → boot.sig + counter-signed bootfiles.bin in ``out_dir``."""
        if is_complete(out_dir):
            job.log(f"==> signed stage-2 files already complete: {out_dir}")
            return
        self.tools.ensure(job.log)
        part = fresh_partial(out_dir)
        indir = Path(self.cfg.work_dir) / "tmp" / f"{out_dir.name}-in-{job.id}"
        rmtree(indir)
        indir.mkdir(parents=True)
        try:
            shutil.copyfile(boot_img, indir / "boot.img")
            shutil.copyfile(self.bootfiles_path, indir / "bootfiles.bin")
            with TempKeys(self.cfg.work_dir, secrets["rsa_private_pem"], secrets["rsa_public_pem"]) as kdir:
                self.tools.run_script("stage2-sign.sh",
                                      mounts=[Mount.bind(indir, "/in", readonly=True),
                                              Mount.bind(kdir, "/keys", readonly=True),
                                              Mount.bind(part, "/out")],
                                      log=job.log)
        finally:
            rmtree(indir)
        for n in ("boot.sig", "bootfiles.bin"):
            if not (part / n).is_file() or (part / n).stat().st_size == 0:
                raise RuntimeError(f"stage2-sign.sh did not produce {n}")
        sig = (part / "boot.sig").read_text(encoding="ascii", errors="replace")
        m = re.search(r"^rsa2048:\s*([0-9a-f]+)\s*$", sig, re.MULTILINE)
        if not m or len(m.group(1)) != 512:
            raise RuntimeError("boot.sig has no valid rsa2048: line")
        commit_partial(part, out_dir, {"stage": 2, "mode": "signed"})
        job.log(f"==> signed stage-2 files ready: {out_dir}")

    def stage2(self, record: dict, *, signed: bool, secrets_fn, base_url: str) -> tuple[dict, dict[str, Path]]:
        """Stage-2 manifest and {name: path}."""
        serial = str(record.get("serial") or "")
        boot_img, source, version = self.current()
        if not self.bootfiles_path.is_file():
            raise NotReady(f"{self.bootfiles_path} is missing (external/usbboot submodule not checked out?)")
        cfg_path = self.config_path()
        boot_sf = self.hashes.stage_file("boot.img", boot_img, f"fastboot gadget ({source}: {version})")
        notes: list[str] = []
        if signed:
            bootfiles_sha = self.hashes.sha256(self.bootfiles_path)
            khash = str(record.get("customer_key_hash") or "")
            out_dir, _fp = self.signed_dir(serial, boot_sf.sha256, bootfiles_sha, khash)
            if not is_complete(out_dir):
                self.tools.require(self.jobs)
                secrets = secrets_fn()
                require_quick_build(self.jobs, f"stage2:{serial}", f"Stage 2 signing for {serial}",
                                    lambda job: self.sign_build(job, out_dir, boot_img, secrets),
                                    lambda: is_complete(out_dir), "signed stage 2 files")
            files = [
                self.hashes.stage_file("bootfiles.bin", out_dir / "bootfiles.bin",
                                       "usbboot firmware/bootfiles.bin (2712/bootcode5.bin counter-signed)"),
                boot_sf,
                self.hashes.stage_file("boot.sig", out_dir / "boot.sig", "rpi-eeprom-digest -k <board key>"),
                self.hashes.stage_file("config.txt", cfg_path, "generated"),
            ]
            notes.append("board OTP is locked to our key: boot.img signed, bootcode5.bin counter-signed")
        else:
            files = [
                self.hashes.stage_file("bootfiles.bin", self.bootfiles_path, "usbboot firmware/bootfiles.bin"),
                boot_sf,
                self.hashes.stage_file("config.txt", cfg_path, "generated"),
            ]
        if source == "prebuilt":
            notes.append("using the prebuilt fastboot gadget from rpi-sb-provisioner host-support")
        manifest = {
            "stage": 2,
            "kind": "rpiboot",
            "title": "Fastboot gadget",
            "ready": True,
            "mode": "signed" if signed else "unsigned",
            "files": [f.to_dict(file_url(base_url, serial, 2, f.name)) for f in files],
            "config_txt": STAGE2_CONFIG,
            "irreversible": [],
            "expect": {"secure_boot_provision": False, "customer_key_hash": None},
            "notes": notes,
            "source": {"gadget": source, "version": version},
        }
        return manifest, {f.name: f.path for f in files}
