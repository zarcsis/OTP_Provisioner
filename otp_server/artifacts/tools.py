"""The otp-tools image: official Raspberry Pi signing / EEPROM tools + our docker/scripts.

``docker build -t <tag> -f docker/tools.Dockerfile docker/`` labelled ``otp.tools.hash=<hash of
tools.Dockerfile + tools-entrypoint.sh>``; rebuilt when missing or when that hash changes. Scripts run as
``docker run --rm <mounts> [-e K=V] <tag> <script> [args]`` (image ENTRYPOINT ``otp-run``).
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Sequence

from ..docker import Mount
from .common import NotReady, content_hash

LABEL = "otp.tools.hash"
TITLE = "Build otp-tools image"
LogFn = Callable[[str], None]


class ToolsImage:
    """Builds and runs the otp-tools image."""

    def __init__(self, cfg: Any, docker: Any):
        self.cfg = cfg
        self.docker = docker
        self.docker_dir = Path(cfg.repo_root) / "docker"
        self.dockerfile = self.docker_dir / "tools.Dockerfile"
        self.entrypoint = self.docker_dir / "tools-entrypoint.sh"
        self.scripts_dir = self.docker_dir / "scripts"
        self._lock = threading.Lock()

    @property
    def tag(self) -> str:
        return self.cfg.builds.tools.image_tag

    def hash(self) -> str:
        """Content hash of tools.Dockerfile + tools-entrypoint.sh (CRLF-normalised)."""
        return content_hash([self.dockerfile, self.entrypoint])

    def script_hash(self, *names: str) -> str:
        """Content hash of docker/scripts/<names> (part of the per-board fingerprints)."""
        return content_hash([self.scripts_dir / n for n in names])

    def ready(self) -> bool:
        """True when the image exists and carries the current hash label."""
        return self.docker.image_label(self.tag, LABEL) == self.hash()

    def ensure(self, log: LogFn | None = None, force: bool = False) -> None:
        """Build the image when missing, outdated, or ``force``."""
        with self._lock:
            if not force and self.ready():
                if log:
                    log(f"==> tools image {self.tag} is up to date")
                return
            if not self.dockerfile.is_file():
                raise FileNotFoundError(f"{self.dockerfile} is missing")
            self.docker.ensure_daemon(log)
            if log:
                log(f"==> building tools image {self.tag}")
            self.docker.build_image(self.tag, self.dockerfile, self.docker_dir,
                                    labels={LABEL: self.hash()}, log=log)

    def require(self, jobs: Any) -> None:
        """Raise NotReady (starting the tools build job) unless the image is ready for a quick build."""
        if self.ready():
            return
        job = jobs.submit("tools", TITLE, lambda job: self.ensure(job.log), dedupe=True)
        raise NotReady("the otp-tools Docker image is being built (needed to prepare this board's files)", job)

    def standard_mounts(self) -> list[Mount]:
        """/scripts <- docker/scripts (ro), /ext <- external (ro)."""
        return [Mount.bind(self.scripts_dir, "/scripts", readonly=True),
                Mount.bind(Path(self.cfg.repo_root) / "external", "/ext", readonly=True)]

    def run_script(self, script: str, args: Sequence[str] = (), *, mounts: Sequence[Mount] = (),
                   env: dict[str, str] | None = None, log: LogFn | None = None) -> int:
        """Run ``otp-run <script> [args]`` in the tools image (raises DockerError on failure)."""
        return self.docker.run(self.tag, [script, *args], mounts=[*self.standard_mounts(), *mounts],
                               env=env, log=log, check=True)

    def status(self, job: Any = None) -> dict:
        """Artifact status dict (SPEC §8) for target ``tools``."""
        h = self.hash()
        st = self.docker.status()
        base = {"target": "tools", "ready": False, "source": None, "version": h[:12], "path": self.tag,
                "size": None, "built": None, "detail": "",
                "job": job.to_dict() if job is not None else None}
        if not st.get("ok"):
            base["detail"] = f"Docker is not available: {st.get('detail') or 'not running'}"
            return base
        label = self.docker.image_label(self.tag, LABEL)
        if label is None:
            base["detail"] = f"image {self.tag} is not built yet"
            return base
        info = self.docker.image_info(self.tag) or {}
        base["size"] = info.get("size")
        base["built"] = info.get("created")
        if label != h:
            base["detail"] = "image is out of date (docker/tools.Dockerfile or tools-entrypoint.sh changed)"
            return base
        base["ready"] = True
        base["source"] = "built"
        base["detail"] = f"Docker {st.get('version', '')}".strip()
        return base
