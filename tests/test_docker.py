"""DockerRunner: argv building, mount specs, output streaming (python as a stand-in binary).

The real-engine smoke test runs only with OTP_DOCKER_TESTS=1 (needs a running Docker engine).
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from otp_server.docker import DockerError, DockerRunner, LineSplitter, Mount, _display_argv


def runner(binary: str = "docker") -> DockerRunner:
    cfg = SimpleNamespace(docker=SimpleNamespace(binary=binary, start_desktop=False, desktop_path=None))
    return DockerRunner(cfg)


def test_mount_specs():
    m = Mount.bind(Path("C:/Users/x/work"), "/src", readonly=True)
    assert m.type == "bind" and m.readonly
    assert m.spec() == f"type=bind,source={Path('C:/Users/x/work')},target=/src,readonly"
    assert m.arg() == "--mount " + m.spec()
    assert m.argv() == ["--mount", m.spec()]
    v = Mount.volume("otp-pgm-work", "/work")
    assert v.arg() == "--mount type=volume,source=otp-pgm-work,target=/work"
    comma = Mount("/tmp/a,b", "/out")
    assert comma.spec() == 'type=bind,"source=/tmp/a,b",target=/out'


def test_run_argv_order():
    argv = DockerRunner.run_argv(
        "droneos-builder:trixie", ["--in-container", "-B", "/work"],
        mounts=[Mount("/d", "/src", readonly=True), Mount("vol", "/work", "volume")],
        env={"DRONEOS_IN_CONTAINER": "1", "DRONEOS_VERSION": "v1"}, privileged=True,
        platform="linux/arm64", hostname="droneos-builder", interactive=True)
    assert argv == ["run", "--rm", "-i", "--privileged", "--platform", "linux/arm64",
                    "--hostname", "droneos-builder",
                    "-e", "DRONEOS_IN_CONTAINER=1", "-e", "DRONEOS_VERSION=v1",
                    "--mount", "type=bind,source=/d,target=/src,readonly",
                    "--mount", "type=volume,source=vol,target=/work",
                    "droneos-builder:trixie", "--in-container", "-B", "/work"]
    assert DockerRunner.run_argv("img") == ["run", "--rm", "img"]
    assert DockerRunner.run_argv("img", entrypoint="")[:4] == ["run", "--rm", "--entrypoint", ""]


def test_line_splitter():
    got = []
    s = LineSplitter(got.append)
    s.feed("step 1\r\nprogress 10%\rprogress 50%\r")
    s.feed("\nstep")
    s.feed(" 2\n\n\nlast")
    s.close()
    assert got == ["step 1", "progress 10%", "progress 50%", "step 2", "last"]


def test_display_argv_masks_secret_env():
    shown = _display_argv(["docker", "run", "-e", "MODE=signed", "-e", "API_TOKEN=abc", "-e", "PASSPHRASE=x"])
    assert "MODE=signed" in shown and "abc" not in shown and "PASSPHRASE=***" in shown


def test_stream_with_python_binary():
    r = runner(sys.executable)
    lines = []
    code = "import sys; print('a'); sys.stdout.write('b\\rc\\r\\n'); sys.stderr.write('err\\n'); sys.exit(0)"
    rc = r._stream(["-u", "-c", code], lines.append, check=True, what="py")
    assert rc == 0
    assert lines[0].startswith("$ ")
    assert lines[1:] == ["a", "b", "c", "err"]
    with pytest.raises(DockerError, match="py exited with 4") as ei:
        r._stream(["-c", "import sys; sys.exit(4)"], None, check=True, what="py")
    assert ei.value.rc == 4
    assert r._stream(["-c", "import sys; sys.exit(4)"], None, check=False, what="py") == 4


def test_missing_binary():
    r = runner("definitely-not-docker-" + uuid.uuid4().hex[:6])
    st = r.status()
    assert st["ok"] is False and "not found" in st["detail"] and st["arm64"] is None
    assert r.image_exists("x") is False
    with pytest.raises(DockerError, match="not found"):
        r.run("img", ["true"])


def test_status_is_cached():
    r = runner(sys.executable)          # "python version --format ..." fails -> ok False
    first = r.status()
    assert first["ok"] is False
    r.binary = "definitely-not-docker"  # a cached answer must not re-run the command
    assert r.status()["detail"] == first["detail"]
    r.invalidate()
    assert "not found" in r.status()["detail"]


@pytest.mark.skipif(os.environ.get("OTP_DOCKER_TESTS") != "1", reason="set OTP_DOCKER_TESTS=1 to use the real engine")
def test_real_engine_smoke(tmp_path):
    r = runner("docker")
    st = r.status()
    assert st["ok"], st
    assert r.image_exists("debian:trixie-slim") in (True, False)
    lines = []
    rc = r.run("debian:trixie-slim", ["uname", "-m"], platform="linux/arm64", log=lines.append)
    assert rc == 0 and lines[-1] == "aarch64"
    d = tmp_path / "bind"
    d.mkdir()
    r.run("debian:trixie-slim", ["sh", "-c", "echo from-container > /out/hello.txt"],
          mounts=[Mount.bind(d, "/out")], log=lines.append)
    assert (d / "hello.txt").read_text().strip() == "from-container"


# ---------------------------------------------------------------------- no-output watchdog (#8)
def test_stream_watchdog_stops_a_silent_command(monkeypatch):
    import time

    r = runner(sys.executable)
    removed = []
    monkeypatch.setattr(r, "_capture", lambda args, timeout=30.0: (removed.append(list(args)), (0, ""))[1])
    lines = []
    t0 = time.monotonic()
    with pytest.raises(DockerError, match="no output for") as ei:
        r._stream(["-u", "-c", "import time; print('started'); time.sleep(60)"], lines.append, check=False,
                  what="py", container="otp-test123", idle_timeout=0.5)
    assert time.monotonic() - t0 < 20
    assert ei.value.rc == 124
    assert "started" in lines and any("stopping it" in ln for ln in lines)
    assert removed == [["rm", "-f", "otp-test123"]]


def test_stream_watchdog_resets_on_output():
    r = runner(sys.executable)
    lines = []
    code = "import time\nfor i in range(8):\n    print(i, flush=True)\n    time.sleep(0.15)\n"
    assert r._stream(["-u", "-c", code], lines.append, check=True, what="py", idle_timeout=0.6) == 0
    assert lines[1:] == [str(i) for i in range(8)]


def test_run_names_its_container_and_idle_timeout_config(monkeypatch):
    r = runner()
    assert r.idle_timeout == 30 * 60
    seen = {}

    def fake_stream(args, log, *, check, what, container=None, idle_timeout=None):
        seen.update(args=list(args), container=container)
        return 0

    monkeypatch.setattr(r, "_stream", fake_stream)
    assert r.run("img", ["true"]) == 0
    name = seen["container"]
    assert name and name.startswith("otp-") and seen["args"][:4] == ["run", "--rm", "--name", name]
    assert seen["args"][-2:] == ["img", "true"]
    cfg = SimpleNamespace(docker=SimpleNamespace(binary="docker", start_desktop=False, desktop_path=None,
                                                 idle_timeout=5))
    assert DockerRunner(cfg).idle_timeout == 5.0
