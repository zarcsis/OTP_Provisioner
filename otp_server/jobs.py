"""Background jobs (docker builds, per-board signing) with a line log and an SSE follower."""
from __future__ import annotations

import asyncio
import json
import secrets
import threading
import time
import traceback
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Callable

MAX_LINES = 50_000
MAX_JOBS = 200
STATUSES = ("queued", "running", "succeeded", "failed")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Job:
    """One unit of background work. ``lines`` keeps the last :data:`MAX_LINES` log lines."""

    def __init__(self, job_id: str, target: str, title: str, log_path: Path | None = None):
        self.id = job_id
        self.target = target
        self.title = title
        self.status = "queued"
        self.started: str | None = None
        self.finished: str | None = None
        self.rc: int | None = None
        self.error = ""
        self.lines: deque[str] = deque(maxlen=MAX_LINES)
        self.line_count = 0          # total lines ever logged (the deque may have dropped old ones)
        self.log_path = log_path
        self._cond = threading.Condition()
        self._done = threading.Event()
        self._file_lock = threading.Lock()
        self._fh = None                # log file, kept open while the job runs

    # ------------------------------------------------------------------ logging
    def log(self, line: str) -> None:
        """Append one or more lines (split on newlines) to the job log."""
        text = str(line).replace("\r\n", "\n").replace("\r", "\n")
        new = [ln.rstrip() for ln in text.split("\n")]
        if len(new) > 1 and new[-1] == "":
            new.pop()
        with self._cond:
            for ln in new:
                self.lines.append(ln)
            self.line_count += len(new)
            self._cond.notify_all()
        if self.log_path is not None:
            with self._file_lock:
                try:
                    if self._fh is None:
                        self._fh = open(self.log_path, "a", encoding="utf-8", newline="\n")
                    for ln in new:
                        self._fh.write(ln + "\n")
                    self._fh.flush()
                except OSError:
                    pass

    def lines_since(self, index: int) -> tuple[list[str], int]:
        """Lines with absolute index >= ``index`` still buffered, and the next index to ask for."""
        with self._cond:
            first = self.line_count - len(self.lines)
            start = max(index, first)
            if start >= self.line_count:
                return [], self.line_count
            buf = list(self.lines)
            return buf[start - first:], self.line_count

    # ------------------------------------------------------------------ state
    @property
    def done(self) -> bool:
        return self.status in ("succeeded", "failed")

    def wait(self, timeout: float | None = None) -> bool:
        """Block until the job finished; False on timeout."""
        return self._done.wait(timeout)

    def _set_running(self) -> None:
        with self._cond:
            self.status = "running"
            self.started = _now()
            self._cond.notify_all()

    def _finish(self, status: str, rc: int | None, error: str = "") -> None:
        with self._cond:
            self.status = status
            self.rc = rc
            self.error = error
            self.finished = _now()
            self._cond.notify_all()
        with self._file_lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
        self._done.set()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "title": self.title,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "rc": self.rc,
            "error": self.error,
            "lines": self.line_count,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Job {self.id} {self.target} {self.status}>"


class JobManager:
    """Runs jobs in daemon threads; one active job per target when ``dedupe`` is set."""

    def __init__(self, work_dir: Path):
        self.work_dir = Path(work_dir)
        self.jobs_dir = self.work_dir / "jobs"
        try:
            self.jobs_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}      # insertion order = submission order

    def _new_id(self) -> str:
        while True:
            jid = secrets.token_hex(4)
            if jid not in self._jobs:
                return jid

    def submit(self, target: str, title: str, fn: Callable[[Job], None], *, dedupe: bool = True) -> Job:
        """Start ``fn(job)`` in a daemon thread.

        With ``dedupe`` an already queued/running job for the same target is returned instead.
        ``fn`` may set ``job.rc``; an exception marks the job failed (``error = str(exc)``, the
        traceback goes to the job log, ``rc`` from ``exc.rc`` when present, else 1).
        """
        with self._lock:
            if dedupe:
                cur = self._active_locked(target)
                if cur is not None:
                    return cur
            jid = self._new_id()
            job = Job(jid, target, title, self.jobs_dir / f"{jid}.log" if self.jobs_dir.is_dir() else None)
            self._jobs[jid] = job
            self._prune_locked()
        t = threading.Thread(target=self._run, args=(job, fn), name=f"job-{target}-{jid}", daemon=True)
        t.start()
        return job

    def _run(self, job: Job, fn: Callable[[Job], None]) -> None:
        job._set_running()
        job.log(f"==> {job.title} (job {job.id}, {job.started})")
        t0 = time.monotonic()
        try:
            fn(job)
        except BaseException as exc:  # noqa: BLE001 - a job must never kill the server
            for ln in traceback.format_exc().splitlines():
                job.log(ln)
            msg = str(exc) or exc.__class__.__name__
            job.log(f"ERROR: {msg}")
            rc = getattr(exc, "rc", None)
            job._finish("failed", rc if isinstance(rc, int) and rc != 0 else 1, msg)
            return
        job.log(f"==> done in {time.monotonic() - t0:.1f} s")
        job._finish("succeeded", job.rc if isinstance(job.rc, int) else 0)

    def _prune_locked(self) -> None:
        if len(self._jobs) <= MAX_JOBS:
            return
        for jid in list(self._jobs):
            if len(self._jobs) <= MAX_JOBS:
                break
            if self._jobs[jid].done:
                del self._jobs[jid]

    def _active_locked(self, target: str) -> Job | None:
        for job in reversed(list(self._jobs.values())):
            if job.target == target and not job.done:
                return job
        return None

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        """All retained jobs, newest first."""
        with self._lock:
            return list(reversed(list(self._jobs.values())))

    def active(self, target: str) -> Job | None:
        """The queued/running job for ``target``, if any."""
        with self._lock:
            return self._active_locked(target)

    def last(self, target: str) -> Job | None:
        """The most recently submitted job for ``target`` (any status)."""
        with self._lock:
            for job in reversed(list(self._jobs.values())):
                if job.target == target:
                    return job
        return None

    def current(self, target: str) -> Job | None:
        """Running job for ``target``, else the last one."""
        return self.active(target) or self.last(target)

    def run_sync(self, target: str, title: str, fn: Callable[[Job], None],
                 timeout: float | None = None) -> Job:
        """Submit (deduplicated) and wait for the job; returns it whatever its outcome.

        On timeout the still running job is returned (``job.done`` is False).
        """
        job = self.submit(target, title, fn, dedupe=True)
        job.wait(timeout)
        return job

    async def sse(self, job_id: str, keepalive: float = 15.0, poll: float = 0.25) -> AsyncIterator[str]:
        """Server-sent events for a job log.

        Replays every buffered line, then follows new ones: ``data: {"line": "..."}\\n\\n`` per line,
        ``: keepalive\\n\\n`` after ``keepalive`` seconds of silence, and finally
        ``event: done\\ndata: {"status": ..., "rc": ...}\\n\\n``. Raises KeyError for an unknown id.
        """
        job = self.get(job_id)
        if job is None:
            raise KeyError(job_id)
        index = 0
        last_sent = time.monotonic()
        while True:
            done = job.done           # read before draining so no line logged before finish is lost
            lines, index = job.lines_since(index)
            for ln in lines:
                yield "data: " + json.dumps({"line": ln}) + "\n\n"
            if lines:
                last_sent = time.monotonic()
            if done:
                lines, index = job.lines_since(index)
                for ln in lines:
                    yield "data: " + json.dumps({"line": ln}) + "\n\n"
                yield "event: done\ndata: " + json.dumps({"status": job.status, "rc": job.rc}) + "\n\n"
                return
            if time.monotonic() - last_sent >= keepalive:
                yield ": keepalive\n\n"
                last_sent = time.monotonic()
            await asyncio.sleep(poll)
