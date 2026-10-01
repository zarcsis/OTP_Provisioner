"""JobManager / Job: threads, dedupe, logs, run_sync and the SSE generator."""
from __future__ import annotations

import asyncio
import json
import threading

import pytest

from otp_server import jobs as jobs_mod
from otp_server.jobs import JobManager


class RcError(RuntimeError):
    def __init__(self, msg, rc):
        super().__init__(msg)
        self.rc = rc


def collect_sse(jm, job_id, **kw):
    async def run():
        out = []
        async for ev in jm.sse(job_id, **kw):
            out.append(ev)
        return out
    return asyncio.run(asyncio.wait_for(run(), timeout=10))


def test_submit_success_and_log_file(tmp_path):
    jm = JobManager(tmp_path)

    def fn(job):
        job.log("hello")
        job.log("two\nlines")

    job = jm.submit("tools", "Build tools", fn)
    assert job.wait(5)
    d = job.to_dict()
    assert d["status"] == "succeeded" and d["rc"] == 0 and d["error"] == ""
    assert d["target"] == "tools" and d["title"] == "Build tools" and len(d["id"]) == 8
    assert d["started"].endswith("Z") and d["finished"].endswith("Z")
    assert "hello" in job.lines and "two" in job.lines and "lines" in job.lines
    assert d["lines"] == len(job.lines)
    text = (tmp_path / "jobs" / f"{job.id}.log").read_text(encoding="utf-8")
    assert "hello\n" in text and "two\nlines\n" in text


def test_failure_sets_error_rc_and_traceback(tmp_path):
    jm = JobManager(tmp_path)

    def fn(job):
        raise RcError("docker run otp-tools exited with 3", 3)

    job = jm.submit("image", "Build image", fn)
    job.wait(5)
    assert job.status == "failed" and job.rc == 3
    assert job.error == "docker run otp-tools exited with 3"
    assert any("Traceback" in ln for ln in job.lines)
    job2 = jm.submit("image", "again", lambda j: (_ for _ in ()).throw(ValueError("boom")))
    job2.wait(5)
    assert job2.status == "failed" and job2.rc == 1 and job2.error == "boom"


def test_dedupe_active_last(tmp_path):
    jm = JobManager(tmp_path)
    gate = threading.Event()
    job = jm.submit("gadget", "Build gadget", lambda j: gate.wait(5))
    same = jm.submit("gadget", "Build gadget", lambda j: None)
    assert same is job
    other = jm.submit("gadget", "forced", lambda j: None, dedupe=False)
    assert other is not job
    other.wait(5)
    assert jm.active("gadget") is job
    assert jm.active("image") is None
    gate.set()
    job.wait(5)
    assert jm.active("gadget") is None
    assert jm.last("gadget") is other          # most recently submitted
    assert jm.get(job.id) is job and jm.get("nope") is None
    assert [j.id for j in jm.list()][:2] == [other.id, job.id]


def test_run_sync_waits_and_times_out(tmp_path):
    jm = JobManager(tmp_path)
    job = jm.run_sync("stage1", "Stage 1", lambda j: j.log("x"))
    assert job.done and job.status == "succeeded"
    gate = threading.Event()
    slow = jm.run_sync("stage1:x", "slow", lambda j: gate.wait(5), timeout=0.2)
    assert not slow.done and slow.status == "running"
    gate.set()
    assert slow.wait(5)


def test_lines_since_with_dropped_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs_mod, "MAX_LINES", 5)
    jm = JobManager(tmp_path)

    def fn(job):
        for i in range(12):
            job.log(f"l{i}")

    job = jm.submit("t", "t", fn)
    job.wait(5)
    total = job.line_count
    assert len(job.lines) == 5
    lines, nxt = job.lines_since(0)
    assert nxt == total and lines == list(job.lines)
    assert job.lines_since(total) == ([], total)


def test_sse_replay_then_done(tmp_path):
    jm = JobManager(tmp_path)
    job = jm.submit("tools", "t", lambda j: j.log('say "hi"'))
    job.wait(5)
    events = collect_sse(jm, job.id)
    assert events[-1] == 'event: done\ndata: {"status": "succeeded", "rc": 0}\n\n'
    data = [json.loads(e[len("data: "):]) for e in events[:-1]]
    assert all(e.startswith("data: ") and e.endswith("\n\n") for e in events[:-1])
    assert {"line": 'say "hi"'} in data
    assert len(data) == job.line_count


def test_sse_follows_live_job_with_keepalive(tmp_path):
    jm = JobManager(tmp_path)
    gate = threading.Event()

    def fn(job):
        job.log("first")
        gate.wait(5)
        job.log("second")
        raise RcError("bad", 2)

    job = jm.submit("image", "t", fn)
    threading.Timer(0.6, gate.set).start()
    events = collect_sse(jm, job.id, keepalive=0.2, poll=0.05)
    assert ": keepalive\n\n" in events
    lines = [json.loads(e[6:])["line"] for e in events if e.startswith("data: ")]
    assert lines.index("first") < lines.index("second")
    assert events[-1] == 'event: done\ndata: {"status": "failed", "rc": 2}\n\n'


def test_sse_unknown_job(tmp_path):
    jm = JobManager(tmp_path)
    with pytest.raises(KeyError):
        collect_sse(jm, "deadbeef")
