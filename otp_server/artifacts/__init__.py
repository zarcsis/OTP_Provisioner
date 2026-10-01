"""Artifacts facade used by the HTTP API: build status, build jobs, per-board stage manifests and files.

Signing rules (SPEC §10): a board whose OTP holds another key is refused (NotReady). Stage 1 is signed
when ``provisioning.secure_boot`` is set or the board is already locked to our key (``program_pubkey=1``
only when not locked yet; ``bootcode5.bin`` counter-signed only when locked). Stages 2 and 3 are signed
iff the board is locked to our key (a locked board only runs signed code).

File downloads are pinned to the manifest: ``stage_file`` serves the files the last manifest issued for
that board and stage named (path + sha256), never a re-resolved newer artifact. Superseded artifact
directories are kept (gadget builds are versioned, image sets and per-board dirs are content-keyed), so
a pinned path stays valid; if it changed or vanished anyway, the download is refused (NotReady) and the
page has to restart the stage.
"""
from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .common import HashCache, NotReady, StageFile, sweep_stale_temp
from .gadget import GadgetBuilder
from .image import ImageBuilder
from .stage1 import Stage1Builder
from .tools import TITLE as TOOLS_TITLE, ToolsImage

__all__ = ["Artifacts", "NotReady", "StageFile", "TARGETS"]

TARGETS = ("tools", "gadget", "image")
TITLES = {"tools": TOOLS_TITLE, "gadget": "Build fastboot gadget", "image": "Build droneos image"}
MAX_PINNED = 1024       # (board, stage) manifests remembered for downloads

log = logging.getLogger(__name__)


def _pin_key(serial: str, stage: int) -> tuple[str, int]:
    return str(serial).replace("\x00", "").strip().lower(), int(stage)


def _manifest_shas(manifest: dict) -> dict[str, str]:
    """{name: sha256} of every file entry a stage manifest lists (stage 1/2 ``files``, stage 3 parts)."""
    entries = list(manifest.get("files") or [])
    if isinstance(manifest.get("image_json"), dict):
        entries.append(manifest["image_json"])
    for pieces in (manifest.get("parts") or {}).values():
        entries.extend(pieces)
    return {str(e["name"]): str(e.get("sha256") or "") for e in entries if isinstance(e, dict) and "name" in e}


class Artifacts:
    """Everything the page downloads, and the jobs that produce it."""

    def __init__(self, cfg: Any, docker: Any, jobs: Any, modules: Any):
        self.cfg = cfg
        self.docker = docker
        self.jobs = jobs
        self.modules = modules
        self.hashes = HashCache(Path(cfg.work_dir))
        self.tools = ToolsImage(cfg, docker)
        self.stage1 = Stage1Builder(cfg, docker, jobs, self.tools, self.hashes)
        self.gadget = GadgetBuilder(cfg, docker, jobs, self.tools, self.hashes)
        self.image = ImageBuilder(cfg, docker, jobs, self.tools, self.hashes)
        self._pins: OrderedDict[tuple[str, int], dict[str, tuple[Path, str]]] = OrderedDict()
        self._pins_lock = threading.Lock()
        try:
            for p in sweep_stale_temp(Path(cfg.work_dir)):
                log.info("removed leftover %s", p)
        except OSError as exc:
            log.warning("could not sweep stale temporary files under %s: %s", cfg.work_dir, exc)

    # ------------------------------------------------------------------ builds
    def status(self) -> dict:
        """``{"tools": .., "gadget": .., "image": ..}`` (SPEC §8 Artifact status)."""
        return {
            "tools": self.tools.status(self.jobs.current("tools")),
            "gadget": self.gadget.status(self.jobs.current("gadget")),
            "image": self.image.status(self.jobs.current("image")),
        }

    def start_build(self, target: str, force: bool = False) -> Any:
        """Submit (deduplicated) the build job for ``target``; ValueError for an unknown target."""
        if target not in TARGETS:
            raise ValueError(f"unknown build target {target!r} (expected one of {', '.join(TARGETS)})")
        if target == "tools":
            fn = lambda job: self.tools.ensure(job.log, force=force)  # noqa: E731
        elif target == "gadget":
            fn = lambda job: self.gadget.build(job, force=force)  # noqa: E731
        else:
            fn = lambda job: self.image.build(job, force=force)  # noqa: E731
        return self.jobs.submit(target, TITLES[target], fn, dedupe=True)

    def auto_build(self) -> list:
        """Start what is missing: tools image, gadget (unless source is prebuilt), droneos image."""
        started = []
        if not self.tools.ready():
            started.append(self.start_build("tools"))
        if self.cfg.builds.gadget.source != "prebuilt" and self.gadget.built_image() is None:
            started.append(self.start_build("gadget"))
        if self.image.current_set() is None:
            started.append(self.start_build("image"))
        return started

    # ------------------------------------------------------------------ stages
    def _board(self, record: dict) -> bool:
        """Locked-to-our-key flag; NotReady when locked to a different key."""
        if self.modules.is_locked(record):
            if not self.modules.locked_to_our_key(record):
                raise NotReady("board OTP is locked to a different key (CUSTOMER_KEY_HASH "
                               f"{record.get('otp_key_hash', '')}, ours {record.get('customer_key_hash', '')}); "
                               "this server cannot sign code the board will run")
            return True
        return False

    def _stage(self, serial: str, stage: int, base_url: str) -> tuple[dict, dict[str, Path]]:
        record = self.modules.require(serial)
        serial = str(record.get("serial") or serial)
        ours = self._board(record)
        secrets_fn = lambda: self.modules.secrets_for(serial)  # noqa: E731
        if stage == 1:
            plan = self.stage1.plan(record, locked_to_ours=ours)
            self.stage1.ensure(plan, serial, secrets_fn)
            files = self.stage1.files(plan)
            return self.stage1.manifest(plan, record, files, base_url), {f.name: f.path for f in files}
        if stage == 2:
            return self.gadget.stage2(record, signed=ours, secrets_fn=secrets_fn, base_url=base_url)
        if stage == 3:
            return self.image.stage3(record, signed=ours, secrets_fn=secrets_fn, base_url=base_url)
        raise ValueError(f"stage must be 1, 2 or 3 (got {stage!r})")

    def stage_manifest(self, serial: str, stage: int, base_url: str = "") -> dict:
        """Stage manifest (SPEC §8). Raises NotReady, KeyError (unknown board), ValueError (bad stage).

        The files it names are remembered (path + sha256) for :meth:`stage_file`.
        """
        manifest, paths = self._stage(serial, int(stage), base_url)
        shas = _manifest_shas(manifest)
        pinned = {name: (Path(p), shas.get(name, "")) for name, p in paths.items()}
        key = _pin_key(serial, stage)
        with self._pins_lock:
            self._pins[key] = pinned
            self._pins.move_to_end(key)
            while len(self._pins) > MAX_PINNED:
                self._pins.popitem(last=False)
        return manifest

    def stage_file(self, serial: str, stage: int, name: str) -> Path:
        """Path of a file named in the last manifest issued for this board and stage.

        FileNotFoundError when the manifest does not name it; NotReady when that exact file changed or
        vanished since (restart the stage). Without an issued manifest (e.g. after a restart) the
        stage is resolved afresh.
        """
        with self._pins_lock:
            pinned = self._pins.get(_pin_key(serial, stage))
        if pinned is None:
            _manifest, paths = self._stage(serial, int(stage), "")
            p = paths.get(name)
            if p is None or not Path(p).is_file():
                raise FileNotFoundError(f"{name} is not part of stage {stage} for {serial}")
            return Path(p)
        entry = pinned.get(name)
        if entry is None:
            raise FileNotFoundError(f"{name} is not part of stage {stage} for {serial}")
        path, sha = entry
        try:
            same = path.is_file() and (not sha or self.hashes.sha256(path) == sha)
        except OSError:
            same = False
        if not same:
            raise NotReady(f"{name} of stage {stage} changed after its manifest was issued; restart the stage")
        return path
