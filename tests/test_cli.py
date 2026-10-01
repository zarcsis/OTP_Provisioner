"""CLI, launcher and Windows driver check tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import otp_server.__main__ as cli
from otp_server import __version__, winusb
from otp_server.app import Services
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.storage.local import LocalJsonStore

REPO = Path(__file__).resolve().parent.parent


# ----------------------------------------------------------------------------------------------------
# argument parsing
# ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("argv, expect", [
    ([], {"command": "serve", "config": None, "host": None, "port": None, "no_browser": False, "no_auto_build": False}),
    (["serve"], {"command": "serve", "config": None}),
    (["--no-browser", "--no-auto-build"], {"command": "serve", "no_browser": True, "no_auto_build": True}),
    (["--config", "c.yaml", "--host", "0.0.0.0", "--port", "8799"],
     {"command": "serve", "config": "c.yaml", "host": "0.0.0.0", "port": 8799}),
    (["--config=c.yaml", "--port", "1"], {"command": "serve", "config": "c.yaml", "port": 1}),
    (["serve", "--config", "c.yaml", "--port", "9"], {"command": "serve", "config": "c.yaml", "port": 9}),
    (["build", "gadget"], {"command": "build", "target": "gadget", "force": False, "config": None}),
    (["build", "image", "--force", "--config", "x"], {"command": "build", "target": "image", "force": True, "config": "x"}),
    (["--config", "x", "build", "tools"], {"command": "build", "target": "tools", "config": "x"}),
    (["modules"], {"command": "modules", "json": False}),
    (["modules", "--json"], {"command": "modules", "json": True}),
    (["--config", "y", "status"], {"command": "status", "config": "y"}),
])
def test_parse_args(argv, expect):
    ns = cli.parse_args(argv)
    for k, v in expect.items():
        assert getattr(ns, k) == v, (argv, k, getattr(ns, k))


@pytest.mark.parametrize("argv", [["build"], ["build", "firmware"], ["modules", "--xml"], ["--port", "abc"],
                                  ["frobnicate"]])
def test_parse_args_errors(argv, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.parse_args(argv)
    assert ei.value.code == 2


def test_overrides_from_flags():
    ns = cli.parse_args(["--host", "::1", "--port", "9000", "--no-browser", "--no-auto-build"])
    assert cli._overrides(ns) == {"server": {"host": "::1", "port": 9000, "open_browser": False},
                                  "builds": {"auto": False}}
    assert cli._overrides(cli.parse_args([])) == {}
    assert cli._overrides(cli.parse_args(["status"])) == {}


def test_flags_reach_config(make_cfg, tmp_path, monkeypatch):
    for n in ("OTP_CONFIG", "OTP_WORK_DIR", "OTP_STORAGE", "OTP_PORT"):
        monkeypatch.delenv(n, raising=False)
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(f"paths: {{work: '{(tmp_path / 'w').as_posix()}'}}\nserver: {{port: 8111}}\n", encoding="utf-8")
    cfg = cli._load(cli.parse_args(["--config", str(cfg_file), "--port", "8799", "--no-browser", "--no-auto-build"]))
    assert cfg.server.port == 8799 and cfg.server.open_browser is False and cfg.builds.auto is False
    assert cfg.work_dir == tmp_path / "w"
    cfg = cli._load(cli.parse_args(["--config", str(cfg_file)]))
    assert cfg.server.port == 8111 and cfg.server.open_browser is True


@pytest.mark.parametrize("host, url", [("127.0.0.1", "http://127.0.0.1:8765/"), ("0.0.0.0", "http://127.0.0.1:8765/"),
                                       ("localhost", "http://127.0.0.1:8765/"), ("::", "http://127.0.0.1:8765/"),
                                       ("192.168.1.5", "http://192.168.1.5:8765/"), ("fe80::1", "http://[fe80::1]:8765/")])
def test_page_url(host, url):
    assert cli.page_url(host, 8765) == url


def test_main_missing_config_is_exit_2(tmp_path, capsys):
    rc = cli.main(["status", "--config", str(tmp_path / "missing.yaml")])
    assert rc == 2
    assert "config file not found" in capsys.readouterr().err


def test_main_invalid_config_is_exit_2(tmp_path, capsys):
    p = tmp_path / "bad.yaml"
    p.write_text("storage: {backend: floppy}\n", encoding="utf-8")
    assert cli.main(["modules", "--config", str(p)]) == 2
    assert "storage.backend" in capsys.readouterr().err


# ----------------------------------------------------------------------------------------------------
# status / modules / build commands
# ----------------------------------------------------------------------------------------------------


class _FakeDocker:
    def status(self, max_age=5.0):
        return {"ok": False, "version": "", "detail": "docker down", "arm64": None}


class _FakeArtifacts:
    def __init__(self, jobs, fn):
        self.jobs, self.fn, self.calls = jobs, fn, []

    def status(self):
        return {t: {"target": t, "ready": False, "source": None, "version": "", "path": "", "size": None,
                    "built": None, "detail": "", "job": None} for t in ("tools", "gadget", "image")}

    def start_build(self, target, force=False):
        self.calls.append((target, force))
        return self.jobs.submit(target, f"Build {target}", self.fn)


@pytest.fixture
def services(make_cfg, tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    store = LocalJsonStore(cfg.storage.local_dir)
    jobs = JobManager(cfg.work_dir)
    svc = Services(cfg=cfg, store=store, modules=ModuleService(cfg, store), docker=_FakeDocker(), jobs=jobs)
    monkeypatch.setattr(cli, "_services", lambda c: svc)
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
    monkeypatch.setattr(cli, "open_browser", lambda url: opened.append(url) or "test")
    assert cli.main([]) == 0
    assert opened == ["http://127.0.0.1:8799/"]
    assert "already running at http://127.0.0.1:8799/" in capsys.readouterr().out


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


def test_find_browser_windows_program_files(tmp_path, monkeypatch):
    chrome = tmp_path / "PF" / "Google" / "Chrome" / "Application" / "chrome.exe"
    chrome.parent.mkdir(parents=True)
    chrome.write_bytes(b"")
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_win_app_path", lambda exe: None)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "PF"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "PF86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LA"))
    assert cli.find_browser() == ("chrome", str(chrome))
    chrome.unlink()
    edge = tmp_path / "PF86" / "Microsoft" / "Edge" / "Application" / "msedge.exe"
    edge.parent.mkdir(parents=True)
    edge.write_bytes(b"")
    assert cli.find_browser() == ("msedge", str(edge))
    edge.unlink()
    assert cli.find_browser() is None


def test_find_browser_windows_app_paths_first(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "_win_app_path", lambda exe: r"D:\chrome\chrome.exe" if exe == "chrome.exe" else None)
    assert cli.find_browser() == ("chrome", r"D:\chrome\chrome.exe")


def test_find_browser_linux(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.shutil, "which", lambda n: "/usr/bin/chromium" if n == "chromium" else None)
    assert cli.find_browser() == ("chromium", "/usr/bin/chromium")
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    assert cli.find_browser() is None


def test_open_browser_falls_back_to_default(monkeypatch):
    opened = []
    monkeypatch.setattr(cli, "find_browser", lambda: None)
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)
    assert "default browser" in cli.open_browser("http://127.0.0.1:1/")
    assert opened == ["http://127.0.0.1:1/"]


def test_open_browser_windows_launches_exe(monkeypatch):
    launched = []

    class P:
        def __init__(self, argv, **kw):
            launched.append(argv)

    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli, "find_browser", lambda: ("chrome", r"C:\c\chrome.exe"))
    monkeypatch.setattr(cli.subprocess, "Popen", P)
    assert cli.open_browser("http://127.0.0.1:2/").startswith("chrome")
    assert launched == [[r"C:\c\chrome.exe", "http://127.0.0.1:2/"]]


# ----------------------------------------------------------------------------------------------------
# launcher script
# ----------------------------------------------------------------------------------------------------


def _run(args, **kw):
    env = {**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, *args], cwd=REPO, capture_output=True, text=True, timeout=60, env=env, **kw)


def test_server_py_help():
    cp = _run(["server.py", "--help"])
    assert cp.returncode == 0, cp.stderr
    for flag in ("--config", "--host", "--port", "--no-browser", "--no-auto-build"):
        assert flag in cp.stdout
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
    (["--config", "x", "modules", "mark-unlocked", "A7EB274C", "--yes"],
     {"command": "modules", "modules_action": "mark-unlocked", "serial": "A7EB274C", "yes": True, "config": "x"}),
    (["modules", "mark-locked", "a7eb274c", "--config", "y"], {"modules_action": "mark-locked", "config": "y"}),
    (["modules", "--json"], {"modules_action": None, "json": True}),
    (["login"], {"command": "login", "config": None}),
    (["login", "--config", "z"], {"command": "login", "config": "z"}),
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


def _login_cfg(monkeypatch, backend):
    from types import SimpleNamespace

    cfg = SimpleNamespace(storage=SimpleNamespace(backend=backend))
    monkeypatch.setattr(cli, "_load", lambda ns: cfg)
    return cfg


def test_cmd_login_local_needs_none(monkeypatch, capsys):
    _login_cfg(monkeypatch, "local")
    monkeypatch.setattr(cli, "_make_store", lambda cfg: pytest.fail("no store for the local backend"))
    assert cli.main(["login"]) == 0
    assert "backend local needs no login" in capsys.readouterr().out


@pytest.mark.parametrize("backend", ["gsheets", "gdrive"])
def test_cmd_login_google(monkeypatch, capsys, backend):
    from otp_server.storage.base import StoreError

    _login_cfg(monkeypatch, backend)

    class WithLogin:
        calls = 0

        def login(self):
            WithLogin.calls += 1
            return f"signed in; token saved for {backend}"

    monkeypatch.setattr(cli, "_make_store", lambda cfg: WithLogin())
    assert cli.main(["login"]) == 0
    assert WithLogin.calls == 1 and f"signed in; token saved for {backend}" in capsys.readouterr().out

    monkeypatch.setattr(cli, "_make_store", lambda cfg: object())
    assert cli.main(["login"]) == 0
    assert f"backend {backend} needs no login" in capsys.readouterr().out

    class Failing:
        def login(self):
            raise StoreError("credentials file not found: x.json")

    monkeypatch.setattr(cli, "_make_store", lambda cfg: Failing())
    assert cli.main(["login"]) == 1
    assert "credentials file not found" in capsys.readouterr().err

    def bad_cfg(cfg):
        raise StoreError("storage.gsheets.spreadsheet is not set")

    monkeypatch.setattr(cli, "_make_store", bad_cfg)
    assert cli.main(["login"]) == 1
    assert "spreadsheet is not set" in capsys.readouterr().err


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
    c = TestClient(create_app(cfg, docker=_FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False),
                   base_url="http://127.0.0.1:8765")
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
