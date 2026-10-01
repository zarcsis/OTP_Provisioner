"""CLI, launcher and Windows driver check tests."""

from __future__ import annotations

import ast
import json
import logging
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from memstore import MemoryStore

import otp_server.__main__ as cli
import otp_server.app as app_mod
from otp_server import __version__, winusb
from otp_server.app import Services
from otp_server.google_account import GoogleAccount
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.storage.base import StoreError

REPO = Path(__file__).resolve().parent.parent
OTP_ENV = ("OTP_CONFIG", "OTP_WORK_DIR", "OTP_STORAGE", "OTP_PORT")
NO_CLIENT = "no Google OAuth client"
SIGN_IN_FIRST = "sign in to Google first"


# ----------------------------------------------------------------------------------------------------
# argument parsing
# ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("argv, expect", [
    ([], {"command": "serve", "work": None, "host": None, "port": None, "browser": None, "no_browser": False,
          "no_auto_build": False}),
    (["serve"], {"command": "serve", "work": None}),
    (["--no-browser", "--no-auto-build"], {"command": "serve", "no_browser": True, "no_auto_build": True}),
    (["--host", "0.0.0.0", "--port", "8799"], {"command": "serve", "host": "0.0.0.0", "port": 8799}),
    (["--browser", "D:/portable/chrome.exe"], {"command": "serve", "browser": "D:/portable/chrome.exe"}),
    (["--work", "w"], {"command": "serve", "work": "w"}),
    (["--work", "w", "--port", "1"], {"command": "serve", "work": "w", "port": 1}),
    (["--work=w", "--port", "1"], {"command": "serve", "work": "w", "port": 1}),
    (["serve", "--work", "w", "--port", "9"], {"command": "serve", "work": "w", "port": 9}),
    (["--port", "9", "--work", "w"], {"command": "serve", "work": "w", "port": 9}),
    (["build", "gadget"], {"command": "build", "target": "gadget", "force": False, "work": None}),
    (["build", "image", "--force", "--work", "x"], {"command": "build", "target": "image", "force": True, "work": "x"}),
    (["--work", "x", "build", "tools"], {"command": "build", "target": "tools", "work": "x"}),
    (["modules"], {"command": "modules", "json": False, "work": None}),
    (["modules", "--json"], {"command": "modules", "json": True}),
    (["--work", "y", "status"], {"command": "status", "work": "y"}),
    (["status", "--work", "y"], {"command": "status", "work": "y"}),
    (["login"], {"command": "login", "work": None}),
])
def test_parse_args(argv, expect):
    ns = cli.parse_args(argv)
    for k, v in expect.items():
        assert getattr(ns, k) == v, (argv, k, getattr(ns, k))


@pytest.mark.parametrize("argv", [["build"], ["build", "firmware"], ["modules", "--xml"], ["--port", "abc"],
                                  ["frobnicate"], ["--work"],
                                  # there is no config file any more
                                  ["--config", "c.yaml"], ["status", "--config", "c.yaml"],
                                  # serve flags belong to serve
                                  ["status", "--port", "1"], ["build", "tools", "--browser", "x.exe"]])
def test_parse_args_errors(argv, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.parse_args(argv)
    assert ei.value.code == 2


def test_overrides_from_flags(tmp_path):
    ns = cli.parse_args(["--host", "::1", "--port", "9000", "--no-browser", "--no-auto-build"])
    assert cli._overrides(ns) == {"server": {"host": "::1", "port": 9000, "open_browser": False},
                                  "builds": {"auto": False}}
    ns = cli.parse_args(["--work", str(tmp_path / "w"), "--browser", str(tmp_path / "x" / "chrome.exe")])
    assert cli._overrides(ns) == {"server": {"browser": str((tmp_path / "x" / "chrome.exe").resolve())},
                                  "paths": {"work": str((tmp_path / "w").resolve())}}
    assert cli._overrides(cli.parse_args([])) == {}
    assert cli._overrides(cli.parse_args(["status"])) == {}


def test_flags_reach_config(tmp_path, monkeypatch):
    for n in OTP_ENV:
        monkeypatch.delenv(n, raising=False)
    exe = tmp_path / "Chromium" / "chrome.exe"
    ns = cli.parse_args(["--work", str(tmp_path / "w"), "--port", "8799", "--no-browser", "--no-auto-build",
                         "--browser", str(exe)])
    cfg = cli._load(ns)
    assert cfg.server.port == 8799 and cfg.server.open_browser is False and cfg.builds.auto is False
    assert cfg.work_dir == (tmp_path / "w").resolve()
    assert cfg.server.browser == exe
    # the flags are kept as the bootstrap layer that stays on top of the sheet settings
    assert cfg.bootstrap == cli._overrides(ns) and cfg.bootstrap["paths"] == {"work": str((tmp_path / "w").resolve())}
    # --work after the command
    cfg = cli._load(cli.parse_args(["status", "--work", str(tmp_path / "w2")]))
    assert cfg.work_dir == (tmp_path / "w2").resolve()
    assert cfg.server.port == 8765 and cfg.server.open_browser is True and cfg.server.browser is None
    assert cfg.bootstrap == {"paths": {"work": str((tmp_path / "w2").resolve())}}
    # the environment, then the flags on top of it
    monkeypatch.setenv("OTP_WORK_DIR", str(tmp_path / "envwork"))
    monkeypatch.setenv("OTP_PORT", "8800")
    cfg = cli._load(cli.parse_args(["status"]))
    assert cfg.work_dir == (tmp_path / "envwork").resolve() and cfg.server.port == 8800 and cfg.bootstrap == {}
    cfg = cli._load(cli.parse_args(["--work", str(tmp_path / "w3"), "--port", "8801"]))
    assert cfg.work_dir == (tmp_path / "w3").resolve() and cfg.server.port == 8801
    # a relative --work / --browser is relative to the current directory, not to the repository
    monkeypatch.delenv("OTP_WORK_DIR")
    monkeypatch.chdir(tmp_path)
    cfg = cli._load(cli.parse_args(["modules", "--work", "rel"]))
    assert cfg.work_dir == (tmp_path / "rel").resolve()
    cfg = cli._load(cli.parse_args(["--browser", "bin/chrome.exe"]))
    assert cfg.server.browser == (tmp_path / "bin" / "chrome.exe").resolve()


@pytest.mark.parametrize("host, url", [("127.0.0.1", "http://127.0.0.1:8765/"), ("0.0.0.0", "http://127.0.0.1:8765/"),
                                       ("localhost", "http://127.0.0.1:8765/"), ("::", "http://127.0.0.1:8765/"),
                                       ("192.168.1.5", "http://192.168.1.5:8765/"), ("fe80::1", "http://[fe80::1]:8765/")])
def test_page_url(host, url):
    assert cli.page_url(host, 8765) == url


def test_main_bad_values_are_exit_2(tmp_path, monkeypatch, capsys):
    """An invalid flag / environment value is a user error: exit 2 with the reason, no traceback."""
    for n in OTP_ENV:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setattr(cli, "cmd_serve", lambda ns, cfg: pytest.fail("must not get as far as serving"))
    monkeypatch.setattr(cli, "cmd_status", lambda ns, cfg: pytest.fail("must not get as far as the status"))
    monkeypatch.setenv("OTP_PORT", "eighty")
    assert cli.main(["status", "--work", str(tmp_path / "w")]) == 2
    err = capsys.readouterr().err
    assert "ERROR:" in err and "OTP_PORT" in err and "Traceback" not in err
    monkeypatch.delenv("OTP_PORT")
    assert cli.main(["--port", "70000", "--work", str(tmp_path / "w")]) == 2
    assert "server.port" in capsys.readouterr().err


# ----------------------------------------------------------------------------------------------------
# status / modules / build commands
# ----------------------------------------------------------------------------------------------------


class _FakeDocker:
    def __init__(self, cfg=None):
        pass

    def status(self, max_age=5.0):
        return {"ok": False, "version": "", "detail": "docker down", "arm64": None}


class _FakeArtifacts:
    def __init__(self, jobs, fn):
        self.jobs, self.fn, self.calls = jobs, fn, []
        self.auto_calls = 0

    def status(self):
        return {t: {"target": t, "ready": False, "source": None, "version": "", "path": "", "size": None,
                    "built": None, "detail": "", "job": None} for t in ("tools", "gadget", "image")}

    def start_build(self, target, force=False):
        self.calls.append((target, force))
        return self.jobs.submit(target, f"Build {target}", self.fn)

    def auto_build(self):
        self.auto_calls += 1
        return []


@pytest.fixture
def services(make_cfg, tmp_path, monkeypatch):
    """The real ``_services`` over injected services without a Google account (nothing gated)."""
    cfg = make_cfg(tmp_path)
    store = MemoryStore()
    jobs = JobManager(cfg.work_dir)
    svc = Services(cfg=cfg, store=store, modules=ModuleService(cfg, store), docker=_FakeDocker(), jobs=jobs)
    assert svc.account is None
    monkeypatch.setattr(app_mod, "create_services", lambda c, **kw: svc)
    monkeypatch.setattr(cli, "_load", lambda ns: cfg)
    # never talk to a real OTP_Provisioner that may be running on this machine's default port
    monkeypatch.setattr(cli, "_existing_server", lambda url: None)
    return svc


def test_cmd_status(services, capsys, monkeypatch):
    monkeypatch.setattr(winusb, "check_usb_driver", lambda *a, **k: None)
    services.artifacts = _FakeArtifacts(services.jobs, lambda j: None)
    assert cli.main(["status"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["version"] == __version__
    assert out["google"] is None and out["google_ready"] is True and out["settings"]["ok"] is True
    assert out["storage"]["backend"] == "memory"
    assert out["docker"]["detail"] == "docker down"
    assert set(out["artifacts"]) == {"tools", "gadget", "image"}
    assert out["usb_driver"] is None and out["jobs"] == []


def test_cmd_modules(services, capsys):
    assert cli.main(["modules"]) == 0
    assert "no modules" in capsys.readouterr().out
    services.modules.hello("a7eb274c", {"chip": "BCM2712"})
    services.modules.identify_fastboot("100000005e21c09a", {})
    assert cli.main(["modules"]) == 0
    out = capsys.readouterr().out
    assert "a7eb274c" in out and "5e21c09a" in out and "100000005e21c09a" in out and "SERIAL" in out
    assert "PRIVATE" not in out
    assert cli.main(["modules", "--json"]) == 0
    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert {m["serial"] for m in data} == {"a7eb274c", "5e21c09a"}
    assert "PRIVATE KEY" not in raw and "rsa_private_pem" not in raw and "device_secret\": \"" not in raw


def test_cmd_modules_store_unusable(services, capsys):
    services.modules = None
    services.store_error = "spreadsheet not shared"
    assert cli.main(["modules"]) == 1
    assert "spreadsheet not shared" in capsys.readouterr().err


def test_cmd_build_success_streams_log(services, capsys):
    def fn(job):
        for i in range(5):
            job.log(f"step {i}")

    arts = services.artifacts = _FakeArtifacts(services.jobs, fn)
    assert cli.main(["build", "gadget", "--force"]) == 0
    out = capsys.readouterr().out
    assert arts.calls == [("gadget", True)]
    lines = out.splitlines()
    assert lines[0].startswith("==> Build gadget")
    assert [ln for ln in lines if ln.startswith("step")] == [f"step {i}" for i in range(5)]
    assert lines[-1] == "==> Build gadget: succeeded"


def test_cmd_build_failure_exit_code(services, capsys):
    class Boom(RuntimeError):
        rc = 7

    def fn(job):
        job.log("working")
        raise Boom("docker build exited with 7")

    services.artifacts = _FakeArtifacts(services.jobs, fn)
    assert cli.main(["build", "image"]) == 7
    cap = capsys.readouterr()
    assert "working" in cap.out and "ERROR: docker build exited with 7" in cap.out
    assert "failed (rc 7): docker build exited with 7" in cap.err


def test_cmd_build_without_artifacts(services, capsys):
    services.artifacts = None
    services.artifacts_error = "broken"
    assert cli.main(["build", "tools"]) == 1


# ----------------------------------------------------------------------------------------------------
# serve (without starting uvicorn)
# ----------------------------------------------------------------------------------------------------


def test_serve_port_in_use_by_our_server_opens_browser(make_cfg, tmp_path, monkeypatch, capsys):
    cfg = make_cfg(tmp_path, server={"open_browser": True, "port": 8799})
    opened = []
    monkeypatch.setattr(cli, "_load", lambda ns: cfg)
    monkeypatch.setattr(cli, "_port_in_use", lambda h, p: True)
    monkeypatch.setattr(cli, "_existing_server", lambda url: "0.2.0")
    monkeypatch.setattr(cli, "open_browser", lambda url, configured=None: opened.append((url, configured)) or "test")
    assert cli.main([]) == 0
    assert opened == [("http://127.0.0.1:8799/", None)]
    assert "already running at http://127.0.0.1:8799/" in capsys.readouterr().out


def test_serve_browser_flag_reaches_open_browser(tmp_path, monkeypatch, capsys):
    """``--browser`` (and ``--work``/``--port``) through the real ``_load`` into ``open_browser``."""
    for n in OTP_ENV:
        monkeypatch.delenv(n, raising=False)
    exe = tmp_path / "Portable Chrome" / "chrome.exe"
    opened = []
    monkeypatch.setattr(cli, "_port_in_use", lambda h, p: True)
    monkeypatch.setattr(cli, "_existing_server", lambda url: "0.2.0")
    monkeypatch.setattr(cli, "open_browser", lambda url, configured=None: opened.append((url, configured)) or "test")
    assert cli.main(["--work", str(tmp_path / "w"), "--port", "8799", "--browser", str(exe)]) == 0
    assert opened == [("http://127.0.0.1:8799/", exe)]
    assert cli.main(["serve", "--work", str(tmp_path / "w"), "--port", "8799", "--no-browser"]) == 0
    assert len(opened) == 1  # --no-browser: nothing opened
    assert "already running" in capsys.readouterr().out


def test_serve_port_in_use_by_someone_else(make_cfg, tmp_path, monkeypatch, capsys):
    cfg = make_cfg(tmp_path, server={"port": 8799})
    monkeypatch.setattr(cli, "_load", lambda ns: cfg)
    monkeypatch.setattr(cli, "_port_in_use", lambda h, p: True)
    monkeypatch.setattr(cli, "_existing_server", lambda url: None)
    assert cli.main(["--no-browser"]) == 2
    assert "in use" in capsys.readouterr().err


def test_port_in_use_detects_listener():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert cli._port_in_use("127.0.0.1", port) is True
    assert cli._port_in_use("127.0.0.1", port) is False


def test_quiet_polls_filter():
    import logging

    f = cli._QuietPolls()

    def rec(method, path, status):
        return logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                                 ("127.0.0.1:1", method, path, "1.1", status), None)

    assert f.filter(rec("GET", "/api/status", 200)) is False
    assert f.filter(rec("GET", "/api/modules", 200)) is False
    assert f.filter(rec("GET", "/api/status", 500)) is True
    assert f.filter(rec("POST", "/api/modules/hello", 200)) is True
    assert f.filter(rec("GET", "/api/modules/a7eb274c/stage/1", 200)) is True


# ----------------------------------------------------------------------------------------------------
# browser selection
# ----------------------------------------------------------------------------------------------------


def _touch(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"")
    return p


@pytest.fixture
def fake_windows(tmp_path, monkeypatch):
    """``sys.platform == "win32"`` with Program Files / LOCALAPPDATA pointing at empty dirs under tmp_path,
    and a ``winreg`` that fails the test on any use."""

    class NoRegistry:
        def __getattr__(self, name):
            raise AssertionError(f"the Windows registry must not be read (winreg.{name})")

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "winreg", NoRegistry())
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "PF"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "PF86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LA"))
    return SimpleNamespace(
        chrome_pf=tmp_path / "PF" / "Google" / "Chrome" / "Application" / "chrome.exe",
        chrome_pf86=tmp_path / "PF86" / "Google" / "Chrome" / "Application" / "chrome.exe",
        chrome_local=tmp_path / "LA" / "Google" / "Chrome" / "Application" / "chrome.exe",
        edge_pf86=tmp_path / "PF86" / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        edge_pf=tmp_path / "PF" / "Microsoft" / "Edge" / "Application" / "msedge.exe",
    )


def test_find_browser_windows_program_files(fake_windows):
    w = fake_windows
    assert cli.find_browser() is None  # nothing installed, and no registry fallback
    for p in (w.edge_pf, w.edge_pf86, w.chrome_local, w.chrome_pf86, w.chrome_pf):
        _touch(p)
    # Chrome first (Program Files, Program Files (x86), per-user install), then Edge
    for p, name in ((w.chrome_pf, "chrome"), (w.chrome_pf86, "chrome"), (w.chrome_local, "chrome"),
                    (w.edge_pf86, "msedge"), (w.edge_pf, "msedge")):
        assert cli.find_browser() == (name, str(p))
        p.unlink()
    assert cli.find_browser() is None


def test_find_browser_never_reads_the_registry():
    assert not hasattr(cli, "_win_app_path")
    assert "winreg" not in vars(cli)
    tree = ast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"winreg", "_winreg"}


def test_find_browser_configured_wins(tmp_path, fake_windows):
    _touch(fake_windows.chrome_pf)
    portable = _touch(tmp_path / "Portable" / "Chromium.exe")
    assert cli.find_browser(portable) == ("chromium", str(portable))
    assert cli.find_browser(str(portable)) == ("chromium", str(portable))
    assert cli.find_browser(None) == ("chrome", str(fake_windows.chrome_pf))


def test_find_browser_missing_configured_falls_back(tmp_path, fake_windows, caplog):
    _touch(fake_windows.edge_pf86)
    missing = tmp_path / "gone" / "chrome.exe"
    with caplog.at_level(logging.WARNING, logger="otp_server"):
        assert cli.find_browser(missing) == ("msedge", str(fake_windows.edge_pf86))
    assert any(r.levelno == logging.WARNING and str(missing) in r.getMessage() for r in caplog.records)
    # a directory is not an executable either
    assert cli.find_browser(tmp_path) == ("msedge", str(fake_windows.edge_pf86))


def test_find_browser_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/usr/bin/chromium" if n == "chromium" else None)
    assert cli.find_browser() == ("chromium", "/usr/bin/chromium")
    configured = _touch(tmp_path / "bin" / "google-chrome-beta")
    assert cli.find_browser(configured) == ("google-chrome-beta", str(configured))
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert cli.find_browser() is None


def test_open_browser_falls_back_to_default(monkeypatch):
    opened, seen = [], []
    monkeypatch.setattr(cli, "find_browser", lambda configured=None: seen.append(configured))
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)
    assert "default browser" in cli.open_browser("http://127.0.0.1:1/")
    assert "default browser" in cli.open_browser("http://127.0.0.1:1/", Path("X:/nope/chrome.exe"))
    assert opened == ["http://127.0.0.1:1/"] * 2
    assert seen == [None, Path("X:/nope/chrome.exe")]  # the configured browser is handed to find_browser


def test_open_browser_windows_launches_exe(monkeypatch):
    launched = []

    class P:
        def __init__(self, argv, **kw):
            launched.append(argv)

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "find_browser", lambda configured=None: ("chrome", r"C:\c\chrome.exe"))
    monkeypatch.setattr(cli.subprocess, "Popen", P)
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: pytest.fail("the found browser must be used"))
    assert cli.open_browser("http://127.0.0.1:2/").startswith("chrome")
    assert launched == [[r"C:\c\chrome.exe", "http://127.0.0.1:2/"]]


def test_open_browser_windows_configured_exe(tmp_path, fake_windows, monkeypatch):
    launched = []

    class P:
        def __init__(self, argv, **kw):
            launched.append(argv)

    _touch(fake_windows.chrome_pf)
    portable = _touch(tmp_path / "Portable" / "chrome.exe")
    monkeypatch.setattr(cli.subprocess, "Popen", P)
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: pytest.fail("the configured browser must be used"))
    assert cli.open_browser("http://127.0.0.1:3/", portable) == f"chrome ({portable})"
    assert launched == [[str(portable), "http://127.0.0.1:3/"]]


def test_open_browser_windows_start_failure_falls_back(monkeypatch):
    opened = []

    def boom(argv, **kw):
        raise OSError("access denied")

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "find_browser", lambda configured=None: ("chrome", r"C:\c\chrome.exe"))
    monkeypatch.setattr(cli.subprocess, "Popen", boom)
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)
    assert "default browser" in cli.open_browser("http://127.0.0.1:4/")
    assert opened == ["http://127.0.0.1:4/"]


def test_open_browser_posix_uses_the_found_browser(monkeypatch):
    started, opened = [], []

    class Controller:
        ok = True

        def __init__(self, exe):
            self.exe = exe

        def open(self, url):
            started.append((self.exe, url))
            return Controller.ok

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "find_browser", lambda configured=None: ("chromium", "/usr/bin/chromium"))
    monkeypatch.setattr(cli.webbrowser, "BackgroundBrowser", Controller)
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)
    assert cli.open_browser("http://127.0.0.1:5/") == "chromium (/usr/bin/chromium)"
    assert started == [("/usr/bin/chromium", "http://127.0.0.1:5/")] and opened == []
    Controller.ok = False  # the browser did not start: the default one is used
    assert "default browser" in cli.open_browser("http://127.0.0.1:5/")
    assert opened == ["http://127.0.0.1:5/"]


# ----------------------------------------------------------------------------------------------------
# launcher script
# ----------------------------------------------------------------------------------------------------


def _run(args, **kw):
    env = {**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, *args], cwd=REPO, capture_output=True, text=True, timeout=60, env=env, **kw)


def test_server_py_help():
    cp = _run(["server.py", "--help"])
    assert cp.returncode == 0, cp.stderr
    for flag in ("--work", "--host", "--port", "--browser", "--no-browser", "--no-auto-build"):
        assert flag in cp.stdout
    assert "--config" not in cp.stdout
    assert "python server.py" in cp.stdout


def test_server_py_rejects_other_commands():
    cp = _run(["server.py", "status"])
    assert cp.returncode != 0 and "python -m otp_server" in cp.stderr


def test_module_help_and_version():
    cp = _run(["-m", "otp_server", "--help"])
    assert cp.returncode == 0 and "build" in cp.stdout and "modules" in cp.stdout and "status" in cp.stdout
    cp = _run(["-m", "otp_server", "--version"])
    assert cp.returncode == 0 and __version__ in cp.stdout


# ----------------------------------------------------------------------------------------------------
# Windows WinUSB driver check
# ----------------------------------------------------------------------------------------------------

RPI_INF = """; rpiboot-winusb.inf
[Version]
Signature   = "$Windows NT$"
Class       = USBDevice
[Manufacturer]
%Provider% = Devices, NTamd64, NTarm64, NT
[Devices.NTamd64]
%BCM2711%   = WinUSB_Install, USB\\VID_0A5C&PID_2711
%BCM2712%   = WinUSB_Install, USB\\VID_0A5C&PID_2712
%Fastboot%  = WinUSB_Install, USB\\VID_18D1&PID_4E40
[WinUSB_Install]
Include = winusb.inf
Needs   = WINUSB.NT
[WinUSB_Install.Services]
Include = winusb.inf
Needs   = WINUSB.NT.Services
"""

WDI_FASTBOOT_INF = """[Version]
Signature = "$Windows NT$"
[Devices.NTamd64]
"Raspberry Pi fastboot" = USB_Install, USB\\VID_18d1&PID_4e40
[USB_Install]
Include = winusb.inf
Needs   = WINUSB.NT
"""

LIBUSBK_INF = """[Version]
Signature = "$Windows NT$"
[Devices.NTamd64]
"BCM2712 Boot" = LUsbK_Device, USB\\VID_0A5C&PID_2712
[LUsbK_Device]
CopyFiles = libusbk_files_sys
[LUsbK_Device.Services]
AddService = libusbK, 0x00000002, libusbk_add_service
"""

OTHER_INF = """[Version]
Signature = "$Windows NT$"
[Devices.NTamd64]
"Some phone" = USB_Install, USB\\VID_18D1&PID_4EE0
[USB_Install]
Include = winusb.inf
Needs = WINUSB.NT
"""


def _write(d: Path, name: str, text: str, encoding: str = "ascii") -> None:
    data = text.replace("\n", "\r\n")
    if encoding == "utf-16":
        (d / name).write_bytes(b"\xff\xfe" + data.encode("utf-16-le"))
    else:
        (d / name).write_bytes(data.encode(encoding))


def test_winusb_rpiboot_setup_package(tmp_path):
    _write(tmp_path, "oem45.inf", RPI_INF)
    _write(tmp_path, "oem1.inf", OTHER_INF)
    r = winusb.scan(tmp_path)
    assert set(r) == {"platform", "rpiboot", "fastboot", "detail"}
    assert r["platform"] == "windows" and r["rpiboot"] is True and r["fastboot"] is True
    assert "oem45.inf" in r["detail"] and "oem1.inf" not in r["detail"]


def test_winusb_utf16_inf_and_wdi_package(tmp_path):
    _write(tmp_path, "oem7.inf", WDI_FASTBOOT_INF, "utf-16")
    r = winusb.scan(tmp_path)
    assert r["rpiboot"] is False and r["fastboot"] is True
    assert "0a5c:2712" in r["detail"] and "rpiboot_setup.exe" in r["detail"] and "rpiboot-winusb.inf" in r["detail"]
    assert "oem7.inf" in r["detail"]


def test_winusb_other_driver_is_not_winusb(tmp_path):
    _write(tmp_path, "oem3.inf", LIBUSBK_INF)
    _write(tmp_path, "oem4.inf", OTHER_INF)
    _write(tmp_path, "keyboard.inf", RPI_INF)  # not an oem*.inf: ignored
    r = winusb.scan(tmp_path)
    assert r["rpiboot"] is False and r["fastboot"] is False
    assert "rpiboot_setup.exe" in r["detail"]


def test_winusb_missing_dir(tmp_path):
    r = winusb.scan(tmp_path / "nope")
    assert r["rpiboot"] is False and r["fastboot"] is False


def test_winusb_platform_gate_and_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(winusb.sys, "platform", "linux")
    assert winusb.check_usb_driver(tmp_path) is None
    assert winusb.check_usb_driver(tmp_path, force_platform=True)["rpiboot"] is False
    _write(tmp_path, "oem45.inf", RPI_INF)
    assert winusb.check_usb_driver(tmp_path, force_platform=True)["rpiboot"] is False  # cached
    assert winusb.check_usb_driver(tmp_path, force_platform=True, max_age=0)["rpiboot"] is True


def test_inf_binds_winusb_rev_suffix():
    text = "[D]\nx = I, USB\\VID_0A5C&PID_2712&REV_0000\n[I]\nNeeds = WINUSB.NT\n"
    assert winusb.inf_binds_winusb(text, winusb.RPIBOOT_HWID) is True
    assert winusb.inf_binds_winusb(text.replace("2712", "27120"), winusb.RPIBOOT_HWID) is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows driver store")
def test_winusb_real_driver_store_does_not_raise():
    r = winusb.scan()
    assert r["platform"] == "windows" and isinstance(r["rpiboot"], bool) and r["detail"]


# ----------------------------------------------------------------------------------------------------
# modules mark-locked / mark-unlocked, login
# ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("argv, expect", [
    (["modules", "mark-locked", "a7eb274c"], {"command": "modules", "modules_action": "mark-locked",
                                              "serial": "a7eb274c", "yes": False}),
    (["--work", "x", "modules", "mark-unlocked", "A7EB274C", "--yes"],
     {"command": "modules", "modules_action": "mark-unlocked", "serial": "A7EB274C", "yes": True, "work": "x"}),
    (["modules", "mark-locked", "a7eb274c", "--work", "y"], {"modules_action": "mark-locked", "work": "y"}),
    (["modules", "--json"], {"modules_action": None, "json": True}),
    (["login"], {"command": "login", "work": None}),
    (["login", "--work", "z"], {"command": "login", "work": "z"}),
    (["--work", "z", "login"], {"command": "login", "work": "z"}),
])
def test_parse_args_new_commands(argv, expect):
    ns = cli.parse_args(argv)
    for k, v in expect.items():
        assert getattr(ns, k) == v, (argv, k, getattr(ns, k))


@pytest.mark.parametrize("argv", [["modules", "mark-locked"], ["modules", "mark-bogus", "a7eb274c"]])
def test_parse_args_new_commands_errors(argv, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.parse_args(argv)
    assert ei.value.code == 2


def test_cmd_mark_locked_with_yes(services, capsys):
    rec, _ = services.modules.hello("a7eb274c")
    assert cli.main(["modules", "mark-locked", "A7EB274C", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "locked to our key" in out and "PRIVATE" not in out
    rec = services.modules.get("a7eb274c")
    assert rec["otp_key_hash"] == rec["customer_key_hash"] and rec["secure_boot_provisioned"] is True
    assert rec["events"][-1]["kind"] == "otp_override"

    assert cli.main(["modules", "mark-unlocked", "a7eb274c", "--yes"]) == 0
    rec = services.modules.get("a7eb274c")
    assert rec["otp_key_hash"] == "" and rec["secure_boot_provisioned"] is False
    assert "not locked" in capsys.readouterr().out


def test_cmd_mark_locked_typed_confirmation(services, capsys, monkeypatch):
    services.modules.hello("a7eb274c")
    answers = iter(["nope", "", " A7EB274C "])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert cli.main(["modules", "mark-locked", "a7eb274c"]) == 1  # wrong text
    assert cli.main(["modules", "mark-locked", "a7eb274c"]) == 1  # empty
    assert "aborted" in capsys.readouterr().err
    assert services.modules.get("a7eb274c")["otp_key_hash"] == ""
    assert cli.main(["modules", "mark-locked", "a7eb274c"]) == 0  # the serial, typed
    assert services.modules.locked_to_our_key(services.modules.get("a7eb274c"))

    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert cli.main(["modules", "mark-unlocked", "a7eb274c"]) == 1  # no terminal: nothing changes
    assert services.modules.locked_to_our_key(services.modules.get("a7eb274c"))


def test_cmd_mark_errors(services, capsys):
    assert cli.main(["modules", "mark-locked", "bbbbbbbb", "--yes"]) == 1
    assert "unknown module" in capsys.readouterr().err
    assert cli.main(["modules", "mark-locked", "Broadcom", "--yes"]) == 2
    assert "no usable USB serial" in capsys.readouterr().err
    services.modules = None
    services.store_error = "spreadsheet not shared"
    assert cli.main(["modules", "mark-unlocked", "a7eb274c", "--yes"]) == 1
    assert "spreadsheet not shared" in capsys.readouterr().err


# ----------------------------------------------------------------------------------------------------
# Google: the real _load / _services / GoogleAccount wiring (fake repo root; no network, no browser)
# ----------------------------------------------------------------------------------------------------


@pytest.fixture
def gcli(tmp_path, monkeypatch):
    """The real ``_load`` (``--work``) and ``create_services`` with a fake repository root (no OAuth client
    unless a test writes one), fake Docker / artifacts and a fake ``settings`` worksheet. Google itself is
    never contacted: without a token the account stops before any request, and the settings sheet is fake."""
    import otp_server.artifacts as artifacts_mod
    import otp_server.config as config_mod
    import otp_server.docker as docker_mod
    import otp_server.settings as settings_mod

    for n in OTP_ENV:
        monkeypatch.delenv(n, raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    work = tmp_path / "work"
    monkeypatch.setattr(config_mod, "REPO_ROOT", repo)
    monkeypatch.setattr(docker_mod, "DockerRunner", _FakeDocker)
    made: list[_FakeArtifacts] = []

    def make_artifacts(cfg, docker, jobs, modules):
        made.append(_FakeArtifacts(jobs, lambda job: job.log("building")))
        return made[-1]

    monkeypatch.setattr(artifacts_mod, "Artifacts", make_artifacts)
    sheet = SimpleNamespace(rows={"builds.auto": "false"}, error=None, reads=0)

    class Sheet:
        def __init__(self, account, **kw):
            self.account = account

        def read(self):
            sheet.reads += 1
            if sheet.error:
                raise StoreError(sheet.error)
            return dict(sheet.rows)

    monkeypatch.setattr(settings_mod, "SettingsSheet", Sheet)

    def no_network(self):
        raise StoreError("tests: Google is never contacted")

    monkeypatch.setattr(GoogleAccount, "client", no_network)  # the registry store connects lazily through it
    monkeypatch.setattr(winusb, "check_usb_driver", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_existing_server", lambda url: None)
    monkeypatch.setattr(cli.webbrowser, "open", lambda *a, **k: pytest.fail("no browser may be opened in tests"))
    monkeypatch.setattr(cli.webbrowser, "open_new", lambda *a, **k: pytest.fail("no browser may be opened in tests"))
    return SimpleNamespace(repo=repo, work=work, argv=["--work", str(work)], sheet=sheet, artifacts=made,
                           client_file=repo / "google-oauth-client.json",
                           token_file=work.resolve() / "google" / "token.json",
                           sheet_file=work.resolve() / "google" / "spreadsheet.json")


def _write_client(g) -> None:
    g.client_file.write_text(json.dumps({"installed": {
        "client_id": "station.apps.googleusercontent.com", "client_secret": "not-secret",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"]}}), encoding="utf-8")


def _sign_in(g, spreadsheet_id: str = "") -> None:
    """An OAuth client and a saved token (as after an earlier login)."""
    _write_client(g)
    g.token_file.parent.mkdir(parents=True, exist_ok=True)
    g.token_file.write_text(json.dumps({"token": "t", "refresh_token": "r"}), encoding="utf-8")
    if spreadsheet_id:
        g.sheet_file.write_text(json.dumps({"id": spreadsheet_id}), encoding="utf-8")


def test_status_works_without_google(gcli, capsys):
    assert cli.main(["status", *gcli.argv]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["version"] == __version__
    assert out["google"]["client"] is False and out["google"]["signed_in"] is False
    assert out["google"]["client_file"] == str(gcli.client_file)
    assert out["google_ready"] is False
    assert out["settings"]["ok"] is False and out["settings"]["error"] == "not signed in to Google"
    assert out["storage"]["backend"] == "gsheets" and out["storage"]["ok"] is False
    assert out["config"]["work_dir"] == str(gcli.work.resolve())
    assert gcli.sheet.reads == 0
    # --work before the command, and signed in (the sheet is read)
    _sign_in(gcli, "1AbC")
    assert cli.main([*gcli.argv, "status"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["google"]["signed_in"] is True and out["google_ready"] is True
    assert out["google"]["spreadsheet_url"] == "https://docs.google.com/spreadsheets/d/1AbC/edit"
    assert out["settings"]["ok"] is True and gcli.sheet.reads >= 1


def test_services_exits_2_when_google_is_not_usable(gcli, capsys):
    cfg = cli._load(cli.parse_args(["modules", *gcli.argv]))
    with pytest.raises(SystemExit) as ei:
        cli._services(cfg)
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert err.startswith("ERROR: ") and NO_CLIENT in err and str(gcli.client_file) in err
    _write_client(gcli)
    with pytest.raises(SystemExit) as ei:
        cli._services(cfg)
    assert ei.value.code == 2 and SIGN_IN_FIRST in capsys.readouterr().err
    # signed in, but the settings sheet cannot be used: refused with the reason
    _sign_in(gcli)
    gcli.sheet.error = "worksheet 'settings': row 1 must be: key | value | description"
    with pytest.raises(SystemExit) as ei:
        cli._services(cfg)
    assert ei.value.code == 2 and "row 1 must be" in capsys.readouterr().err
    gcli.sheet.error = None
    gcli.sheet.rows = {"provisioning.default_mode": "maybe"}
    with pytest.raises(SystemExit) as ei:
        cli._services(cfg)
    assert ei.value.code == 2 and "invalid value in the settings sheet" in capsys.readouterr().err
    # need_google=False never refuses
    gcli.client_file.unlink()
    gcli.token_file.unlink()
    svc = cli._services(cfg, need_google=False)
    assert svc.google_ready() is False and svc.account.client_configured() is False


def test_services_applies_the_sheet_settings(gcli):
    _sign_in(gcli)
    gcli.sheet.rows = {"provisioning.erase_storage": "false", "provisioning.default_mode": "secure",
                       "builds.auto": "false"}
    cfg = cli._load(cli.parse_args(["build", "tools", *gcli.argv]))
    assert cfg.provisioning.erase_storage is True  # the default, until the sheet is read
    svc = cli._services(cfg)
    assert isinstance(svc.account, GoogleAccount) and svc.store.backend == "gsheets"
    assert svc.google_ready() is True and gcli.sheet.reads >= 1
    assert svc.cfg is cfg and cfg.provisioning.erase_storage is False and cfg.provisioning.default_mode == "secure"
    assert cfg.work_dir == gcli.work.resolve()  # the --work flag stays on top of the sheet


@pytest.mark.parametrize("argv", [["modules"], ["modules", "--json"], ["build", "tools"], ["build", "image", "--force"],
                                  ["modules", "mark-locked", "a7eb274c", "--yes"]])
def test_modules_and_build_refuse_without_google(gcli, capsys, argv):
    with pytest.raises(SystemExit) as ei:
        cli.main([*argv, *gcli.argv])
    assert ei.value.code == 2
    assert NO_CLIENT in capsys.readouterr().err
    _write_client(gcli)
    with pytest.raises(SystemExit) as ei:
        cli.main([*gcli.argv, *argv])
    assert ei.value.code == 2
    cap = capsys.readouterr()
    assert SIGN_IN_FIRST in cap.err and "PRIVATE" not in cap.out
    assert all(a.calls == [] for a in gcli.artifacts)  # no build was started


def test_build_runs_once_google_is_ready(gcli, capsys):
    _sign_in(gcli)
    assert cli.main(["build", "gadget", "--force", *gcli.argv]) == 0
    out = capsys.readouterr().out
    assert gcli.artifacts[-1].calls == [("gadget", True)]
    assert "building" in out and out.splitlines()[-1] == "==> Build gadget: succeeded"


def test_cmd_login(gcli, monkeypatch, capsys):
    _write_client(gcli)
    gcli.sheet_file.parent.mkdir(parents=True, exist_ok=True)
    gcli.sheet_file.write_text(json.dumps({"id": "1AbC"}), encoding="utf-8")
    gcli.sheet.rows = {"provisioning.erase_storage": "false", "builds.auto": "false"}
    calls = []

    class Creds:
        def to_json(self):
            return json.dumps({"token": "t", "refresh_token": "r"})

    def fake_login(self, **kw):
        calls.append(kw)
        self.save_credentials(Creds())

    monkeypatch.setattr(GoogleAccount, "login_interactive", fake_login)
    assert not gcli.token_file.exists()
    assert cli.main(["login", *gcli.argv]) == 0
    cap = capsys.readouterr()
    assert calls == [{}]
    assert gcli.token_file.is_file()
    assert gcli.sheet.reads >= 1  # the settings were read right after the login
    assert "signed in to Google" in cap.out
    # a new login may be another account: the station's last spreadsheet is not shown as this account's
    # until the server has connected with it (the fake settings sheet here never opens the spreadsheet)
    assert "https://docs.google.com/spreadsheets/d/1AbC/edit" not in cap.out
    assert "station spreadsheet: (found or created when the station connects)" in cap.out
    # --work before the command
    assert cli.main([*gcli.argv, "login"]) == 0 and len(calls) == 2


def test_cmd_login_failures(gcli, monkeypatch, capsys):
    # no OAuth client: the real login_interactive refuses before anything is opened
    assert cli.main(["login", *gcli.argv]) == 1
    err = capsys.readouterr().err
    assert "no OAuth client" in err and str(gcli.client_file) in err
    assert not gcli.token_file.exists()

    _write_client(gcli)

    def fails(self, **kw):
        raise StoreError("no answer from the browser within 300 s; run 'python -m otp_server login' again")

    monkeypatch.setattr(GoogleAccount, "login_interactive", fails)
    assert cli.main(["login", *gcli.argv]) == 1
    assert "no answer from the browser" in capsys.readouterr().err

    def interrupted(self, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(GoogleAccount, "login_interactive", interrupted)
    assert cli.main(["login", *gcli.argv]) == 130
    assert "interrupted" in capsys.readouterr().err

    # signed in, but the settings sheet is broken: reported, exit 1
    def ok(self, **kw):
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        self.token_file.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(GoogleAccount, "login_interactive", ok)
    gcli.sheet.error = "Google Sheets API error: quota exceeded"
    assert cli.main(["login", *gcli.argv]) == 1
    err = capsys.readouterr().err
    assert "signed in, but" in err and "quota exceeded" in err


def test_server_py_rejects_login():
    cp = _run(["server.py", "login"])
    assert cp.returncode != 0 and "python -m otp_server" in cp.stderr


def test_module_help_lists_new_commands():
    cp = _run(["-m", "otp_server", "--help"])
    assert cp.returncode == 0 and "login" in cp.stdout
    cp = _run(["-m", "otp_server", "modules", "--help"])
    assert cp.returncode == 0 and "mark-locked" in cp.stdout and "mark-unlocked" in cp.stdout


def test_cmd_mark_locked_goes_through_a_running_server(services, capsys, monkeypatch):
    """With a server answering, the override is POSTed to it (its store cache), not written directly."""
    services.modules.hello("a7eb274c")
    monkeypatch.setattr(cli, "_existing_server", lambda url: "0.2.0")
    sent = []

    def fake_post(url, key, locked):
        sent.append((url, key, locked))
        return {"otp": {"locked_to_our_key": locked, "customer_key_hash": "ab" * 32 if locked else ""}}

    monkeypatch.setattr(cli, "_post_otp_override", fake_post)
    assert cli.main(["modules", "mark-locked", "a7eb274c", "--yes"]) == 0
    assert sent == [("http://127.0.0.1:8765/", "a7eb274c", True)]
    assert "running server" in capsys.readouterr().out
    assert services.modules.get("a7eb274c")["otp_key_hash"] == ""   # the CLI did not write the store itself

    def refused(url, key, locked):
        raise RuntimeError("the running server refused the change (HTTP 400): nope")

    monkeypatch.setattr(cli, "_post_otp_override", refused)
    assert cli.main(["modules", "mark-unlocked", "a7eb274c", "--yes"]) == 1
    assert "refused" in capsys.readouterr().err


def test_api_otp_override_endpoint(make_cfg, tmp_path):
    from fastapi.testclient import TestClient

    from otp_server.app import create_app

    cfg = make_cfg(tmp_path)
    c = TestClient(create_app(cfg, store=MemoryStore(), docker=_FakeDocker(), jobs=JobManager(cfg.work_dir),
                              artifacts=None, auto_build=False), base_url="http://127.0.0.1:8765")
    assert c.post("/api/modules/hello", json={"serial": "a7eb274c"}).status_code == 200
    r = c.post("/api/modules/a7eb274c/otp", json={"action": "mark-locked", "note": "CLI"})
    assert r.status_code == 200 and r.json()["module"]["otp"]["locked_to_our_key"] is True
    r = c.post("/api/modules/a7eb274c/otp", json={"action": "mark-unlocked"})
    assert r.status_code == 200 and r.json()["module"]["otp"]["locked"] is False
    assert c.post("/api/modules/a7eb274c/otp", json={"action": "burn"}).status_code == 400
    assert c.post("/api/modules/deadbeef/otp", json={"action": "mark-locked"}).status_code == 404
    # a foreign page cannot trigger it
    assert c.post("/api/modules/a7eb274c/otp", json={"action": "mark-locked"},
                  headers={"origin": "http://attacker.example"}).status_code == 403
