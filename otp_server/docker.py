"""Thin, fakeable wrapper around the docker CLI.

Every command runs through :mod:`subprocess` with an argv list (no shell). Output of long-running
commands (``build``, ``run``) is stdout+stderr merged, split on ``\\n`` and ``\\r`` and streamed line by
line to a ``log`` callback. A streamed command that prints nothing for ``idle_timeout`` seconds
(default 30 min, ``docker.idle_timeout`` when the config has it) is stopped: its named container is
removed (``docker rm -f``), the CLI is killed and :class:`DockerError` is raised. Tests replace
:class:`DockerRunner` with a fake that records calls.
"""
from __future__ import annotations

import codecs
import csv
import io
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

LogFn = Callable[[str], None]

# Small multi-arch image used for the arm64 emulation probe (also the tools image base).
PROBE_IMAGE = "debian:trixie-slim"
BINFMT_IMAGE = "tonistiigi/binfmt"
# Same test image/build.sh runs inside its builder container (binfmt_arm64_present).
BINFMT_CHECK = ("mountpoint -q /proc/sys/fs/binfmt_misc "
                "|| mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc; "
                "test -e /proc/sys/fs/binfmt_misc/qemu-aarch64")
DEFAULT_DESKTOP = Path(r"C:\Program Files\Docker\Docker\Docker Desktop.exe")
DEFAULT_IDLE_TIMEOUT = 30 * 60.0   # a streamed docker build/run silent this long is considered hung

_SECRET_ENV = re.compile(r"(KEY|PASS|SECRET|TOKEN|PRIVATE)", re.IGNORECASE)


class DockerError(RuntimeError):
    """A docker command failed. ``rc`` is the exit code when there was one."""

    def __init__(self, message: str, rc: int | None = None):
        super().__init__(message)
        self.rc = rc


def _csv_field(value: str) -> str:
    """Quote a --mount field the way docker's CSV parser expects when it contains , or "."""
    if "," in value or '"' in value:
        buf = io.StringIO()
        csv.writer(buf, lineterminator="").writerow([value])
        return buf.getvalue()
    return value


@dataclass
class Mount:
    """A ``--mount`` specification. ``source`` is a host path (bind) or a volume name (volume)."""

    source: str
    target: str
    type: str = "bind"
    readonly: bool = False

    def spec(self) -> str:
        """The value after ``--mount``: ``type=bind,source=...,target=/src[,readonly]``."""
        fields = [f"type={self.type}", f"source={self.source}", f"target={self.target}"]
        if self.readonly:
            fields.append("readonly")
        return ",".join(_csv_field(f) for f in fields)

    def arg(self) -> str:
        """Display form: ``--mount type=bind,source=C:\\...,target=/src,readonly``."""
        return f"--mount {self.spec()}"

    def argv(self) -> list[str]:
        """argv form: ``["--mount", spec]``."""
        return ["--mount", self.spec()]

    @classmethod
    def bind(cls, source: str | Path, target: str, readonly: bool = False) -> "Mount":
        return cls(str(Path(source)), target, "bind", readonly)

    @classmethod
    def volume(cls, name: str, target: str, readonly: bool = False) -> "Mount":
        return cls(name, target, "volume", readonly)


def _creationflags() -> int:
    if sys.platform == "win32":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return 0


def _display_argv(argv: Sequence[str]) -> str:
    """Command line for logs, with values of secret-looking -e variables masked."""
    out: list[str] = []
    prev = ""
    for a in argv:
        if prev in ("-e", "--env") and "=" in a:
            k, _, _v = a.partition("=")
            if _SECRET_ENV.search(k):
                a = f"{k}=***"
        out.append(f'"{a}"' if (" " in a and not a.startswith('"')) else a)
        prev = a
    return " ".join(out)


def _container_name() -> str:
    """Unique ``--name`` for a streamed run, so a hung container can be removed by name."""
    return f"otp-{uuid.uuid4().hex[:12]}"


class LineSplitter:
    """Incremental splitter on \\n and \\r (\\r\\n counts once); empty lines are dropped."""

    def __init__(self, emit: Callable[[str], None]):
        self._emit = emit
        self._buf = ""

    def feed(self, text: str) -> None:
        buf = self._buf + text
        # A trailing \r may be the first half of \r\n: hold it back until the next feed.
        keep_cr = buf.endswith("\r")
        if keep_cr:
            buf = buf[:-1]
        parts = re.split(r"\r\n|\r|\n", buf)
        self._buf = parts.pop() + ("\r" if keep_cr else "")
        for p in parts:
            p = p.rstrip()
            if p:
                self._emit(p)

    def close(self) -> None:
        rest = self._buf.rstrip("\r").rstrip()
        self._buf = ""
        if rest:
            self._emit(rest)


class DockerRunner:
    """docker CLI wrapper bound to a :class:`otp_server.config.Config` (uses ``cfg.docker``)."""

    def __init__(self, cfg: Any):
        dcfg = getattr(cfg, "docker", None)
        self.binary: str = getattr(dcfg, "binary", None) or "docker"
        self.start_desktop: bool = bool(getattr(dcfg, "start_desktop", True))
        dp = getattr(dcfg, "desktop_path", None)
        self.desktop_path: Path = Path(dp) if dp else DEFAULT_DESKTOP
        self._lock = threading.Lock()
        self._status: dict | None = None
        self._status_t = 0.0
        self._arm64: bool | None = None
        self._arm64_lock = threading.Lock()
        self._daemon_lock = threading.Lock()
        idle = getattr(dcfg, "idle_timeout", None)
        self.idle_timeout: float = float(idle) if idle is not None else DEFAULT_IDLE_TIMEOUT   # <= 0: off

    # ------------------------------------------------------------------ low level
    def _capture(self, args: Sequence[str], timeout: float = 30.0) -> tuple[int, str]:
        """Run ``docker <args>`` and return (rc, merged output). rc 127 when docker is missing."""
        argv = [self.binary, *args]
        try:
            cp = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, timeout=timeout,
                                creationflags=_creationflags())
        except FileNotFoundError:
            return 127, f"{self.binary}: not found on PATH (install Docker Desktop)"
        except subprocess.TimeoutExpired:
            return 124, f"{_display_argv(argv)}: timed out after {timeout:.0f} s"
        return cp.returncode, cp.stdout.decode("utf-8", "replace")

    def _stream(self, args: Sequence[str], log: LogFn | None, *, check: bool, what: str,
                container: str | None = None, idle_timeout: float | None = None) -> int:
        """Run ``docker <args>`` streaming merged output to ``log``; return the exit code.

        No output for ``idle_timeout`` s (default :attr:`idle_timeout`; <= 0 disables the watchdog)
        stops the command: ``docker rm -f <container>`` when the run was started with ``--name``, then
        the CLI process is killed, and DockerError (rc 124) is raised whatever ``check`` says.
        """
        argv = [self.binary, *args]
        emit = log or (lambda _l: None)
        emit(f"$ {_display_argv(argv)}")
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, creationflags=_creationflags())
        except FileNotFoundError as exc:
            raise DockerError(f"{self.binary}: not found on PATH (install Docker Desktop)") from exc
        limit = self.idle_timeout if idle_timeout is None else float(idle_timeout)
        splitter = LineSplitter(emit)
        assert proc.stdout is not None
        stdout = proc.stdout
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        chunks: queue.Queue = queue.Queue()

        def reader() -> None:
            try:
                while True:
                    chunk = stdout.read1(65536) if hasattr(stdout, "read1") else stdout.read(4096)
                    if not chunk:
                        break
                    chunks.put(chunk)
            except (OSError, ValueError):
                pass
            finally:
                chunks.put(None)

        t = threading.Thread(target=reader, name="docker-stream", daemon=True)
        t.start()
        last = time.monotonic()
        stalled = False
        while True:
            timeout = max(0.0, last + limit - time.monotonic()) if limit > 0 else None
            try:
                chunk = chunks.get(timeout=timeout)
            except queue.Empty:
                stalled = True
                break
            if chunk is None:
                break
            last = time.monotonic()
            splitter.feed(decoder.decode(chunk))
        splitter.feed(decoder.decode(b"", final=True))
        splitter.close()
        if stalled:
            emit(f"==> {what}: no output for {limit:.0f} s, stopping it")
            self._stop(proc, container, emit)
            t.join(10)
            raise DockerError(f"{what} produced no output for {limit:.0f} s and was stopped "
                              "(docker.idle_timeout)", 124)
        t.join(10)
        rc = proc.wait()
        if check and rc != 0:
            raise DockerError(f"{what} exited with {rc}", rc)
        return rc

    def _stop(self, proc: subprocess.Popen, container: str | None, emit: LogFn) -> None:
        """Remove ``container`` (killing the docker CLI alone leaves it running) and kill ``proc``."""
        if container:
            rc, out = self._capture(["rm", "-f", container], timeout=60)
            if rc != 0:
                lines = [ln for ln in out.splitlines() if ln.strip()]
                emit(f"warning: docker rm -f {container} failed: {lines[-1] if lines else f'rc {rc}'}")
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass

    # ------------------------------------------------------------------ daemon
    def status(self, max_age: float = 5.0) -> dict:
        """``{"ok", "version", "detail", "arm64"}``; cached for ``max_age`` seconds."""
        with self._lock:
            if self._status is not None and time.monotonic() - self._status_t < max_age:
                st = dict(self._status)
                st["arm64"] = self._arm64
                return st
        rc, out = self._capture(["version", "--format", "{{.Server.Version}}"], timeout=15)
        text = out.strip()
        if rc == 0 and text:
            st = {"ok": True, "version": text.splitlines()[-1].strip(), "detail": "", "arm64": self._arm64}
        else:
            lines = [ln for ln in text.splitlines() if ln.strip()]
            detail = lines[-1] if lines else f"docker exited with {rc}"
            st = {"ok": False, "version": "", "detail": detail, "arm64": self._arm64}
        with self._lock:
            self._status, self._status_t = dict(st), time.monotonic()
        return st

    def invalidate(self) -> None:
        """Drop the cached status (after starting the daemon, for instance)."""
        with self._lock:
            self._status = None

    def _info_ok(self) -> bool:
        rc, _ = self._capture(["info", "--format", "{{.ServerVersion}}"], timeout=20)
        return rc == 0

    def ensure_daemon(self, log: LogFn | None = None, timeout: float = 180.0) -> None:
        """Return when ``docker info`` works; on Windows start Docker Desktop and wait for it."""
        emit = log or (lambda _l: None)
        with self._daemon_lock:
            if self._info_ok():
                self.invalidate()
                return
            if sys.platform == "win32" and self.start_desktop:
                if not self.desktop_path.exists():
                    raise DockerError(f"Docker is not running and Docker Desktop was not found at {self.desktop_path}")
                emit(f"==> starting Docker Desktop ({self.desktop_path})")
                try:
                    subprocess.Popen([str(self.desktop_path)], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=_creationflags() | getattr(subprocess, "DETACHED_PROCESS", 0))
                except OSError as exc:
                    raise DockerError(f"cannot start Docker Desktop: {exc}") from exc
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    time.sleep(3.0)
                    if self._info_ok():
                        emit("==> Docker engine is up")
                        self.invalidate()
                        return
                raise DockerError(f"Docker Desktop did not come up within {timeout:.0f} s")
            rc, out = self._capture(["info"], timeout=20)
            lines = [ln for ln in out.splitlines() if ln.strip()]
            raise DockerError("Docker engine is not reachable: " + (lines[-1] if lines else f"rc {rc}"))

    def _probe_arm64(self) -> tuple[bool, str]:
        """True when linux/arm64 containers run AND the kernel has a ``qemu-aarch64`` binfmt entry.

        ``uname -m`` alone is not enough: Docker Desktop 29.x registers its own handler under the
        name ``aarch64``, which runs arm64 containers, but ``image/build.sh`` (rpi-image-gen runs
        arm64 chroots) checks for ``/proc/sys/fs/binfmt_misc/qemu-aarch64`` by name and refuses to
        build without it. ``tonistiigi/binfmt --install arm64`` adds that entry (flags POCF), which is
        what ``image/build.sh --docker`` does on the host.
        """
        rc, out = self._capture(["run", "--rm", "--platform", "linux/arm64", PROBE_IMAGE, "uname", "-m"],
                                timeout=600)
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if not (rc == 0 and lines and lines[-1] == "aarch64"):
            return False, (lines[-1] if lines else f"rc {rc}")
        rc, out = self._capture(["run", "--rm", "--privileged", "--entrypoint", "sh", PROBE_IMAGE, "-c",
                                 BINFMT_CHECK], timeout=120)
        if rc != 0:
            return False, "no qemu-aarch64 binfmt entry in the Docker VM (image/build.sh requires it)"
        return True, "aarch64"

    def ensure_arm64(self, log: LogFn | None = None) -> None:
        """Make sure linux/arm64 containers run and the ``qemu-aarch64`` binfmt entry exists.

        Registers the handler with ``tonistiigi/binfmt --install arm64`` when it is missing. The
        registration lives in the Docker VM kernel and is lost when Docker Desktop restarts, so this
        is re-checked before every arm64 build.
        """
        emit = log or (lambda _l: None)
        with self._arm64_lock:
            ok, detail = self._probe_arm64()
            if ok:
                self._arm64 = True
                return
            emit(f"==> arm64 emulation incomplete ({detail}); registering qemu binfmt")
            name = _container_name()
            self._stream(["run", "--rm", "--name", name, "--privileged", BINFMT_IMAGE, "--install", "arm64"], log,
                         check=False, what="binfmt install", container=name)
            ok, detail = self._probe_arm64()
            self._arm64 = ok
            if not ok:
                raise DockerError(f"arm64 emulation is not available in the Docker engine ({detail})")
            emit("==> arm64 emulation registered")

    # ------------------------------------------------------------------ images / volumes
    def image_exists(self, tag: str) -> bool:
        rc, _ = self._capture(["image", "inspect", "--format", "{{.Id}}", tag], timeout=30)
        return rc == 0

    def image_label(self, tag: str, label: str) -> str | None:
        """Value of an image label, '' when the label is absent, None when the image is missing."""
        rc, out = self._capture(["image", "inspect", "--format",
                                 '{{ index .Config.Labels "%s" }}' % label, tag], timeout=30)
        if rc != 0:
            return None
        v = out.strip()
        return "" if v == "<no value>" else v

    def image_info(self, tag: str) -> dict | None:
        """``{"id", "created", "size"}`` of a local image, or None."""
        rc, out = self._capture(["image", "inspect", "--format", "{{.Id}}|{{.Created}}|{{.Size}}", tag],
                                timeout=30)
        if rc != 0:
            return None
        parts = out.strip().splitlines()[-1].split("|") if out.strip() else []
        if len(parts) != 3:
            return None
        try:
            size = int(parts[2])
        except ValueError:
            size = 0
        return {"id": parts[0], "created": parts[1], "size": size}

    def build_image(self, tag: str, dockerfile: Path, context: Path, *, platform: str | None = None,
                    pull: bool = False, labels: dict[str, str] | None = None,
                    build_args: dict[str, str] | None = None, log: LogFn | None = None) -> None:
        """``docker build --progress=plain -t <tag> -f <dockerfile> [...] <context>``."""
        args = ["build", "--progress=plain", "-t", tag, "-f", str(Path(dockerfile))]
        if platform:
            args += ["--platform", platform]
        if pull:
            args.append("--pull")
        for k, v in (labels or {}).items():
            args += ["--label", f"{k}={v}"]
        for k, v in (build_args or {}).items():
            args += ["--build-arg", f"{k}={v}"]
        args.append(str(Path(context)))
        self._stream(args, log, check=True, what=f"docker build {tag}")

    def volume_exists(self, name: str) -> bool:
        rc, _ = self._capture(["volume", "inspect", name], timeout=30)
        return rc == 0

    # ------------------------------------------------------------------ run
    @staticmethod
    def run_argv(image: str, args: Iterable[str] = (), *, mounts: Iterable[Mount] = (),
                 env: dict[str, str] | None = None, privileged: bool = False, platform: str | None = None,
                 entrypoint: str | None = None, hostname: str | None = None,
                 interactive: bool = False, name: str | None = None) -> list[str]:
        """The docker argv (without the binary) :meth:`run` executes."""
        argv = ["run", "--rm"]
        if name:
            argv += ["--name", name]
        if interactive:
            argv.append("-i")
        if privileged:
            argv.append("--privileged")
        if platform:
            argv += ["--platform", platform]
        if hostname:
            argv += ["--hostname", hostname]
        if entrypoint is not None:
            argv += ["--entrypoint", entrypoint]
        for k, v in (env or {}).items():
            argv += ["-e", f"{k}={v}"]
        for m in mounts:
            argv += m.argv()
        argv.append(image)
        argv += list(args)
        return argv

    def run(self, image: str, args: Sequence[str] = (), *, mounts: Sequence[Mount] = (),
            env: dict[str, str] | None = None, privileged: bool = False, platform: str | None = None,
            entrypoint: str | None = None, hostname: str | None = None, log: LogFn | None = None,
            check: bool = True, interactive: bool = False) -> int:
        """``docker run --rm ...``; streams output to ``log``; returns the exit code.

        With ``check`` a non-zero exit raises :class:`DockerError`.
        """
        name = _container_name()
        argv = self.run_argv(image, args, mounts=mounts, env=env, privileged=privileged, platform=platform,
                             entrypoint=entrypoint, hostname=hostname, interactive=interactive, name=name)
        return self._stream(argv, log, check=check, what=f"docker run {image}", container=name)
