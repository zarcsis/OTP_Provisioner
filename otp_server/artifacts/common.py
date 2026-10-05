"""Shared pieces of the artifact builders: NotReady, StageFile, hashing, complete-dir handling."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

log = logging.getLogger(__name__)

COMPLETE = ".complete"
PARTIAL_SUFFIX = ".partial"
OLD_MARK = ".old-"              # <final>.old-<id>: a replaced dir moved aside by commit_partial
QUICK_BUILD_TIMEOUT = 300.0     # the manifest call waits this long for a per-board quick build
HEAVY_LOCK = threading.Lock()   # gadget and OS image builds are CPU-heavy: one at a time
HEAVY_LOCK_FILE = "heavy.lock"  # <work>/tmp/heavy.lock: the same rule across processes (server + CLI)
STALE_KEYS_AGE = 60.0           # a keys-* dir without its lock file is swept only when older than this


class NotReady(Exception):
    """An artifact cannot be served yet; ``job`` is the build that will produce it (if any)."""

    def __init__(self, reason: str, job: Any = None):
        super().__init__(reason)
        self.reason = reason
        self.job = job

    def to_dict(self) -> dict:
        job = self.job.to_dict() if self.job is not None and hasattr(self.job, "to_dict") else self.job
        return {"ready": False, "reason": self.reason, "job": job}


@dataclass
class StageFile:
    """One file of a stage manifest."""

    name: str
    path: Path
    size: int
    sha256: str
    origin: str

    def to_dict(self, url: str | None = None) -> dict:
        d = {"name": self.name, "size": self.size, "sha256": self.sha256}
        if url is not None:
            d["url"] = url
        d["origin"] = self.origin
        return d


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_url(base_url: str, serial: str, stage: int, name: str) -> str:
    return f"{base_url.rstrip('/')}/api/modules/{serial}/stage/{stage}/files/{name}"


# ---------------------------------------------------------------------- hashing
class HashCache:
    """sha256 of files, computed once per (path, size, mtime).

    Kept in memory; files under ``sidecar_root`` also get a ``<file>.sha256`` sidecar so the result
    survives a restart (files outside it, e.g. in the repo, never get sidecars).
    """

    def __init__(self, sidecar_root: Path | None = None):
        self.sidecar_root = Path(sidecar_root).resolve() if sidecar_root else None
        self._mem: dict[tuple[str, int, int], str] = {}
        self._lock = threading.Lock()

    def _may_sidecar(self, path: Path) -> bool:
        if self.sidecar_root is None:
            return False
        try:
            path.resolve().relative_to(self.sidecar_root)
            return True
        except ValueError:
            return False

    def sha256(self, path: Path) -> str:
        path = Path(path)
        st = path.stat()
        key = (str(path.resolve()), st.st_size, st.st_mtime_ns)
        with self._lock:
            hit = self._mem.get(key)
        if hit:
            return hit
        side = path.with_name(path.name + ".sha256")
        if self._may_sidecar(path) and side.is_file():
            try:
                parts = side.read_text(encoding="ascii").split()
                if len(parts) == 3 and int(parts[1]) == st.st_size and int(parts[2]) == st.st_mtime_ns:
                    with self._lock:
                        self._mem[key] = parts[0]
                    return parts[0]
            except (OSError, ValueError):
                pass
        digest = sha256_file(path)
        with self._lock:
            self._mem[key] = digest
        if self._may_sidecar(path):
            try:
                side.write_text(f"{digest} {st.st_size} {st.st_mtime_ns}\n", encoding="ascii")
            except OSError:
                pass
        return digest

    def stage_file(self, name: str, path: Path, origin: str) -> StageFile:
        path = Path(path)
        return StageFile(name=name, path=path, size=path.stat().st_size, sha256=self.sha256(path), origin=origin)


def sha256_file(path: Path, bufsize: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def text_bytes(path: Path) -> bytes:
    """File content with CRLF normalised to LF (so a Windows checkout hashes like a Linux one)."""
    return Path(path).read_bytes().replace(b"\r\n", b"\n")


def content_hash(paths: Iterable[Path]) -> str:
    """sha256 over the (CRLF-normalised) contents of the files, names included; missing files count."""
    h = hashlib.sha256()
    for p in paths:
        p = Path(p)
        h.update(p.name.encode() + b"\0")
        h.update(text_bytes(p) if p.is_file() else b"<missing>")
        h.update(b"\0")
    return h.hexdigest()


def fingerprint(*parts: Any) -> str:
    """Stable 16-hex fingerprint of JSON-serialisable parts."""
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


# ---------------------------------------------------------------------- files / dirs
def replace_retry(src: Path | str, dst: Path | str, attempts: int = 40, delay: float = 0.05) -> None:
    """``os.replace`` retried on PermissionError.

    Windows refuses to replace a file another thread or process holds open without FILE_SHARE_DELETE
    (a reader of current.json, an antivirus scanner, the indexer), and to rename a directory while a
    file inside it is open. Such holds are short, so retry for ``attempts * delay`` seconds.
    """
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)


def write_text(path: Path, text: str) -> None:
    """Atomic LF text write (tmp + os.replace, retried while a reader holds the target on Windows)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        replace_retry(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: Path, data: Any) -> None:
    write_text(path, json.dumps(data, indent=2, sort_keys=False) + "\n")


def read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_complete(d: Path) -> bool:
    return (Path(d) / COMPLETE).is_file()


def rmtree(path: Path, *, warn: bool = True) -> bool:
    """Remove a tree, tolerating read-only files (Windows). True when ``path`` is gone afterwards.

    Entries that cannot be removed (a file held open on Windows) are skipped; with ``warn`` the first
    one is logged (path and error only) so a leftover is never silent.
    """
    path = Path(path)
    if not path.exists():
        return True
    failed: list[tuple[str, BaseException]] = []

    def onerr(func, p, exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError as again:
            failed.append((str(p), again))

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=onerr)
    else:  # pragma: no cover
        shutil.rmtree(path, onerror=lambda func, p, ei: onerr(func, p, ei[1]))
    gone = not path.exists()
    if not gone and warn:
        first, exc = failed[0] if failed else (str(path), None)
        log.warning("could not remove %s (%d entries left; first: %s: %s)", path, len(failed), first,
                    exc.__class__.__name__ if exc is not None else "still exists")
    return gone


def remove_dir_retry(path: Path, attempts: int = 5, delay: float = 0.1) -> bool:
    """:func:`rmtree` retried with back-off (``delay``, doubled each time); True when ``path`` is gone."""
    path = Path(path)
    for attempt in range(attempts):
        if rmtree(path, warn=False):
            return True
        if attempt < attempts - 1:
            time.sleep(delay * (2 ** attempt))
    return not path.exists()


def partial_dir(final: Path) -> Path:
    final = Path(final)
    return final.with_name(final.name + PARTIAL_SUFFIX)


def fresh_partial(final: Path) -> Path:
    """Create an empty ``<final>.partial`` (removing leftovers)."""
    part = partial_dir(final)
    rmtree(part)
    part.mkdir(parents=True)
    return part


def commit_partial(part: Path, final: Path, info: dict | None = None) -> None:
    """Write ``.complete`` into ``part`` and rename it to ``final``.

    An existing ``final`` is never deleted in place (it may be being served): it is first renamed aside
    to ``<final>.old-<id>``; when that rename fails the old ``final`` is left untouched and the error is
    raised. The aside copy is removed afterwards (best effort, logged when it stays;
    :func:`sweep_stale_temp` removes leftovers at the next start).
    """
    marker = {"completed": now_iso()}
    if info:
        marker.update(info)
    write_json(Path(part) / COMPLETE, marker)
    final = Path(final)
    aside: Path | None = None
    if final.exists():
        aside = final.with_name(f"{final.name}{OLD_MARK}{uuid.uuid4().hex[:8]}")
        try:
            replace_retry(final, aside, attempts=10, delay=0.5)
        except OSError as exc:
            raise RuntimeError(f"cannot move the previous {final} aside to replace it ({exc}); "
                               "it was left as it was") from exc
    try:
        replace_retry(part, final, attempts=10, delay=0.5)
    except BaseException:
        if aside is not None:
            try:
                os.replace(aside, final)
            except OSError:
                log.warning("could not move %s back to %s", aside, final)
        raise
    if aside is not None and not remove_dir_retry(aside):
        log.warning("the replaced directory %s could not be removed; it will be removed at the next start", aside)


def git_output(repo: Path, *args: str, timeout: float = 20.0) -> str | None:
    """Output of ``git -C <repo> <args>`` (stripped) or None when git fails."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        cp = subprocess.run(["git", "-c", "safe.directory=*", "-C", str(repo), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                            timeout=timeout, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if cp.returncode != 0:
        return None
    out = cp.stdout.decode("utf-8", "replace").strip()
    return out or None


class FileLock:
    """Exclusive, non-inheritable OS lock on a lock file (msvcrt on Windows, fcntl.flock elsewhere).

    Held by the open handle, so it ends with the process; separate FileLock objects conflict even
    inside one process.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    @staticmethod
    def _try_lock(fd: int) -> bool:
        try:
            if sys.platform == "win32":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def acquire(self, blocking: bool = True, poll: float = 1.0, timeout: float | None = None) -> bool:
        """Take the lock; polls every ``poll`` s while blocking (up to ``timeout`` s, None = forever)."""
        if self._fd is not None:
            raise RuntimeError(f"{self.path} is already locked by this object")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOINHERIT", 0), 0o600)
            if self._try_lock(fd):
                self._fd = fd
                return True
            os.close(fd)
            if not blocking or (deadline is not None and time.monotonic() >= deadline):
                return False
            time.sleep(poll)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            os.close(fd)


@contextmanager
def heavy_lock(work_dir: Path, log_fn: Callable[[str], None] | None = None, poll: float = 2.0) -> Iterator[None]:
    """One heavy (gadget / OS image) build at a time, in this process and across processes.

    The in-process :data:`HEAVY_LOCK` is backed by an OS lock on ``<work>/tmp/heavy.lock``, so
    ``python -m otp_server build ...`` and a running server never build on the same Docker work volume
    at once. Waiting is logged to ``log_fn``.
    """
    emit = log_fn or (lambda _l: None)
    if not HEAVY_LOCK.acquire(blocking=False):
        emit("==> waiting for another image/gadget build to finish")
        HEAVY_LOCK.acquire()
    try:
        flock = FileLock(Path(work_dir) / "tmp" / HEAVY_LOCK_FILE)
        if not flock.acquire(blocking=False):
            emit(f"==> waiting for another image/gadget build to finish (another OTP_Provisioner process "
                 f"holds {flock.path})")
            flock.acquire(blocking=True, poll=poll)
        try:
            yield
        finally:
            flock.release()
    finally:
        HEAVY_LOCK.release()


class TempFiles:
    """Context manager: a temp dir under ``<work>/tmp`` holding secret files, always deleted.

    The directory is mounted read-only into a container. A sibling ``keys-<id>.lock`` is held while it is
    in use, so :func:`sweep_stale_temp` (run at start-up, possibly by another process) never removes a
    live directory. Removal is retried with back-off; a directory that still cannot be removed is logged
    (path only) and swept at the next start.

    ``files``: relative path (``/``-separated, may name a sub-directory) -> bytes.
    """

    def __init__(self, work_dir: Path, files: dict[str, bytes] | None = None):
        name = f"keys-{uuid.uuid4().hex}"
        self.dir = Path(work_dir) / "tmp" / name
        self._lock = FileLock(self.dir.with_name(name + ".lock"))
        self._files = dict(files or {})

    def _write(self) -> None:
        for rel, data in self._files.items():
            p = self.dir.joinpath(*rel.split("/"))
            if not p.resolve().is_relative_to(self.dir.resolve()) or p == self.dir:
                raise ValueError(f"temporary file name {rel!r} leaves its directory")
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)

    def __enter__(self) -> Path:
        self._lock.acquire(blocking=False)      # a fresh name: nobody else can hold it
        try:
            self.dir.mkdir(parents=True, exist_ok=False)
            try:
                os.chmod(self.dir, 0o700)
            except OSError:
                pass
            self._write()
        except BaseException:
            self._cleanup()
            raise
        return self.dir

    def __exit__(self, *exc) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        gone = remove_dir_retry(self.dir)
        self._lock.release()
        if gone:
            try:
                self._lock.path.unlink()
            except OSError:
                pass
        else:
            log.warning("temporary key directory %s could not be removed; it will be removed at the next start",
                        self.dir)


class TempKeys(TempFiles):
    """:class:`TempFiles` holding private.pem/public.pem, mounted read-only into the signing containers at
    /keys."""

    def __init__(self, work_dir: Path, private_pem: str, public_pem: str):
        super().__init__(work_dir)
        self._priv = private_pem
        self._pub = public_pem

    def _write(self) -> None:
        for name, text in (("private.pem", self._priv), ("public.pem", self._pub)):
            p = self.dir / name
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
                f.write(text if text.endswith("\n") else text + "\n")


def sweep_stale_temp(work_dir: Path, min_age: float = STALE_KEYS_AGE) -> list[Path]:
    """Remove leftovers of earlier runs; returns what was removed.

    * ``<work>/tmp/keys-*`` key directories whose lock file is not held by a live process (one without
      a lock file only when older than ``min_age`` s, so a directory being created right now survives),
      and orphaned ``keys-*.lock`` files;
    * ``*.old-*`` directories :func:`commit_partial` moved aside but could not delete
      (``<work>/artifacts/<kind>/`` and ``<work>/modules/<serial>/<stage>/``).

    Called by :class:`otp_server.artifacts.Artifacts` on construction; safe while another process
    runs jobs.
    """
    work = Path(work_dir)
    removed: list[Path] = []
    tmp = work / "tmp"
    keys_re = re.compile(r"^keys-[0-9a-f]+$")
    if tmp.is_dir():
        now = time.time()
        for d in sorted(tmp.iterdir()):
            if not (keys_re.match(d.name) and d.is_dir()):
                continue
            lock = FileLock(d.with_name(d.name + ".lock"))
            if lock.path.exists():
                if not lock.acquire(blocking=False):
                    continue                     # in use by a live process
                try:
                    gone = remove_dir_retry(d)
                finally:
                    lock.release()
                if gone:
                    try:
                        lock.path.unlink()
                    except OSError:
                        pass
            else:
                try:
                    if now - d.stat().st_mtime < min_age:
                        continue
                except OSError:
                    continue
                gone = remove_dir_retry(d)
            if gone:
                removed.append(d)
            else:
                log.warning("stale temporary key directory %s could not be removed", d)
        for lp in sorted(tmp.glob("keys-*.lock")):
            if lp.with_suffix("").exists():
                continue
            lock = FileLock(lp)
            if lock.acquire(blocking=False):
                lock.release()
                try:
                    lp.unlink()
                    removed.append(lp)
                except OSError:
                    pass
    for pattern in ("artifacts/*/*" + OLD_MARK + "*", "modules/*/*/*" + OLD_MARK + "*"):
        for d in sorted(work.glob(pattern)):
            if d.is_dir() and rmtree(d):
                removed.append(d)
    return removed


def require_quick_build(jobs: Any, target: str, title: str, fn: Callable, check: Callable[[], bool],
                        what: str, timeout: float = QUICK_BUILD_TIMEOUT) -> None:
    """Run a per-board quick build through ``jobs.run_sync`` until ``check()`` holds.

    A deduplicated job may be one started for other inputs; then it is run once more.
    Raises NotReady when the build fails or is still running after ``timeout``.
    """
    for _ in range(2):
        if check():
            return
        job = jobs.run_sync(target, title, fn, timeout=timeout)
        if not job.done:
            raise NotReady(f"{what} is still being prepared", job)
        if job.status == "failed":
            raise NotReady(f"{what} failed: {job.error}", job)
    if not check():
        raise NotReady(f"{what} could not be prepared (outputs missing after the build)", None)
