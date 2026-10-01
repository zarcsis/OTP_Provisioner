"""Command line: ``python -m otp_server <command>`` (``python server.py`` is ``serve``).

Commands::

    serve   [--host H] [--port N] [--no-browser] [--no-auto-build]   run the server (default command)
    build   tools|gadget|image [--force]                             run one build, stream its log, exit with its result
    modules [--json]                                                 list the registry (public view, no secrets)
    modules mark-locked <serial> [--yes]                             record that the board OTP holds our key hash
    modules mark-unlocked <serial> [--yes]                           undo mark-locked (clear the OTP lock state)
    status                                                           print the /api/status document as JSON
    login                                                            sign in to / check the Google storage backend

``--config PATH`` (before or after the command) selects the config file (SPEC section 4 search order
otherwise).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Sequence

from . import __version__

log = logging.getLogger("otp_server")

COMMANDS = ("serve", "build", "modules", "status", "login")
BUILD_TARGETS = ("tools", "gadget", "image")


# ----------------------------------------------------------------------------------------------------
# argument parsing
# ----------------------------------------------------------------------------------------------------


def _add_common(p: argparse.ArgumentParser, *, top: bool) -> None:
    # The sub-parsers use SUPPRESS so a --config given before the command is not reset to None.
    p.add_argument("--config", metavar="PATH", default=None if top else argparse.SUPPRESS,
                   help="config file (default: $OTP_CONFIG, <repo>/config.yaml, <work>/config.yaml)")


def _add_serve_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default=None, help="listen address (default: server.host, 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="listen port (default: server.port, 8765)")
    p.add_argument("--no-browser", action="store_true", help="do not open the page in Chrome")
    p.add_argument("--no-auto-build", action="store_true", help="do not start missing builds at startup")


def build_parser(prog: str = "python -m otp_server") -> argparse.ArgumentParser:
    """The CLI parser (``serve`` is the default command)."""
    parser = argparse.ArgumentParser(prog=prog, description="OTP_Provisioner server and tools")
    parser.add_argument("--version", action="version", version=f"OTP_Provisioner {__version__}")
    _add_common(parser, top=True)
    sub = parser.add_subparsers(dest="command", metavar="command")

    ps = sub.add_parser("serve", help="run the web server (default)")
    _add_common(ps, top=False)
    _add_serve_args(ps)

    pb = sub.add_parser("build", help="run one build and stream its log")
    _add_common(pb, top=False)
    pb.add_argument("target", choices=BUILD_TARGETS)
    pb.add_argument("--force", action="store_true", help="rebuild even when the artifact is up to date")

    pm = sub.add_parser("modules", help="list the module registry (no secrets)")
    _add_common(pm, top=False)
    pm.add_argument("--json", action="store_true", help="print the public module JSON")
    msub = pm.add_subparsers(dest="modules_action", metavar="action")
    for name, text in (("mark-locked", "record that the board OTP holds this module's key hash (the stage-1 "
                                       "report was lost after the OTP was programmed)"),
                       ("mark-unlocked", "clear the recorded OTP lock (undo a wrong mark-locked)")):
        pa = msub.add_parser(name, help=text, description=text)
        _add_common(pa, top=False)
        pa.add_argument("serial", help="board serial (8 hex digits)")
        pa.add_argument("--yes", action="store_true", help="do not ask for the typed confirmation")

    pt = sub.add_parser("status", help="print the server status document")
    _add_common(pt, top=False)

    pl = sub.add_parser("login", help="sign in to the Google storage backend (OAuth) or check its access")
    _add_common(pl, top=False)
    return parser


def parse_args(argv: Sequence[str] | None = None, *, prog: str = "python -m otp_server") -> argparse.Namespace:
    """Parse ``argv``; with no command (or only serve options) the command is ``serve``."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser(prog)
    # Default command: insert "serve" before the first argument that is not a global option.
    if not any(a in COMMANDS for a in args_list) and not any(a in ("-h", "--help", "--version") for a in args_list):
        args_list = _insert_serve(args_list)
    ns = parser.parse_args(args_list)
    if ns.command is None:
        ns = parser.parse_args([*args_list, "serve"])
    return ns


def _insert_serve(args: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--config" and i + 1 < len(args):
            out += [a, args[i + 1]]
            i += 2
            continue
        if a.startswith("--config="):
            out.append(a)
            i += 1
            continue
        break
    return [*out, "serve", *args[i:]]


def _overrides(ns: argparse.Namespace) -> dict:
    ov: dict[str, Any] = {}
    if getattr(ns, "host", None):
        ov.setdefault("server", {})["host"] = ns.host
    if getattr(ns, "port", None) is not None:
        ov.setdefault("server", {})["port"] = ns.port
    if getattr(ns, "no_browser", False):
        ov.setdefault("server", {})["open_browser"] = False
    if getattr(ns, "no_auto_build", False):
        ov.setdefault("builds", {})["auto"] = False
    return ov


def _load(ns: argparse.Namespace):
    from .config import load_config

    return load_config(getattr(ns, "config", None), overrides=_overrides(ns) or None)


# ----------------------------------------------------------------------------------------------------
# browser
# ----------------------------------------------------------------------------------------------------


def _win_app_path(exe: str) -> str | None:
    """``App Paths`` registry entry of ``exe`` (HKCU, then HKLM)."""
    try:
        import winreg
    except ImportError:
        return None
    key = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, key) as k:
                val, _ = winreg.QueryValueEx(k, "")
        except OSError:
            continue
        if val:
            p = Path(os.path.expandvars(str(val).strip().strip('"')))
            if p.is_file():
                return str(p)
    return None


def find_browser() -> tuple[str, str] | None:
    """``(name, executable)`` of Chrome (else Edge on Windows), or ``None``."""
    if sys.platform == "win32":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        local = os.environ.get("LOCALAPPDATA", "")
        for name, exe, candidates in (
            ("chrome", "chrome.exe", [Path(pf, "Google", "Chrome", "Application", "chrome.exe"),
                                      Path(pf86, "Google", "Chrome", "Application", "chrome.exe"),
                                      Path(local, "Google", "Chrome", "Application", "chrome.exe") if local else None]),
            ("msedge", "msedge.exe", [Path(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
                                      Path(pf, "Microsoft", "Edge", "Application", "msedge.exe")]),
        ):
            found = _win_app_path(exe)
            if found:
                return name, found
            for c in candidates:
                if c is not None and c.is_file():
                    return name, str(c)
        return None
    if sys.platform == "darwin":
        app = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        return ("chrome", str(app)) if app.is_file() else None
    for exe in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        p = shutil.which(exe)
        if p:
            return exe, p
    return None


def open_browser(url: str) -> str:
    """Open ``url`` in Chrome/Chromium (WebUSB), else Edge (Windows), else the default browser.

    :returns: a short description of what was launched.
    """
    found = find_browser()
    if found is not None:
        name, exe = found
        if sys.platform == "win32":
            try:
                flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                subprocess.Popen([exe, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=flags, close_fds=True)
                return f"{name} ({exe})"
            except OSError as exc:
                log.warning("cannot start %s: %s", exe, exc)
        else:
            try:
                controller = webbrowser.BackgroundBrowser(exe)
                if controller.open(url):
                    return f"{name} ({exe})"
            except Exception as exc:  # noqa: BLE001 - fall back to the default browser
                log.warning("cannot start %s: %s", exe, exc)
    webbrowser.open(url)
    return "default browser (Chrome or Edge is needed for WebUSB)"


# ----------------------------------------------------------------------------------------------------
# serve
# ----------------------------------------------------------------------------------------------------


def page_url(host: str, port: int) -> str:
    """URL for the browser: wildcard / loopback hosts map to 127.0.0.1."""
    h = host.strip("[]")
    if h in ("0.0.0.0", "::", "", "localhost", "127.0.0.1", "::1"):
        h = "127.0.0.1"
    if ":" in h:
        h = f"[{h}]"
    return f"http://{h}:{port}/"


def _port_in_use(host: str, port: int) -> bool:
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as s:
        excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if sys.platform == "win32" and excl is not None:
            # Without it Windows lets a 127.0.0.1 bind succeed next to a 0.0.0.0 listener.
            s.setsockopt(socket.SOL_SOCKET, excl, 1)
        try:
            s.bind((host.strip("[]"), port))
        except OSError:
            return True
    return False


def _existing_server(url: str) -> str | None:
    """Version of an OTP_Provisioner already answering at ``url``, else None."""
    try:
        with urllib.request.urlopen(url + "api/status", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        v = data.get("version")
        return str(v) if v is not None else None
    except (OSError, ValueError, urllib.error.URLError):
        return None


class _QuietPolls(logging.Filter):
    """Drop successful access-log lines of the page's periodic polling (GET status/modules/builds/jobs)."""

    POLLED = ("/api/status", "/api/modules", "/api/builds", "/api/jobs")

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 5:
            method, path, status = str(args[1]), str(args[2]).split("?", 1)[0], args[4]
            if method == "GET" and status in (200, 304) and path in self.POLLED:
                return False
        return True


def cmd_serve(ns: argparse.Namespace, cfg) -> int:
    import uvicorn

    from .app import create_app

    host, port = cfg.server.host, cfg.server.port
    url = page_url(host, port)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: listening on {host}: the API hands out per-board signing files and LUKS recovery "
              "passphrases to anyone who can reach this port. Use 127.0.0.1 unless you know why not.",
              file=sys.stderr)
    if _port_in_use(host, port):
        other = _existing_server(url)
        if other is not None:
            print(f"OTP_Provisioner {other} is already running at {url}")
            if cfg.server.open_browser:
                print(f"Opening {url} in {open_browser(url)}")
            return 0
        print(f"ERROR: port {port} on {host} is in use by another program; pick another with --port", file=sys.stderr)
        return 2

    app = create_app(cfg)
    svc = app.state.services
    print(f"OTP_Provisioner {__version__}")
    print(f"  config : {cfg.config_path or '(defaults, no config file)'}")
    print(f"  work   : {cfg.work_dir}")
    st = svc.storage_status()
    print(f"  storage: {st.get('backend')} {'ok' if st.get('ok') else 'NOT USABLE'} - {st.get('location') or st.get('detail')}")
    if not st.get("ok") and st.get("detail"):
        print(f"           {st.get('detail')}")
    print(f"  builds : auto={'on' if cfg.builds.auto else 'off'}")

    logging.getLogger("uvicorn.access").addFilter(_QuietPolls())
    server = uvicorn.Server(uvicorn.Config(app, host=host.strip("[]"), port=port, log_level="info"))

    def announce() -> None:
        deadline = time.monotonic() + 60
        while not getattr(server, "started", False):
            if server.should_exit or time.monotonic() > deadline:
                return
            time.sleep(0.1)
        print(f"\n  Open {url}  (Chrome or Edge: WebUSB)\n", flush=True)
        if cfg.server.open_browser:
            try:
                print(f"  Opening the page in {open_browser(url)}", flush=True)
            except Exception as exc:  # noqa: BLE001 - never kill the server over a browser
                print(f"  Could not open a browser: {exc}", flush=True)

    threading.Thread(target=announce, name="announce", daemon=True).start()
    server.run()
    return 0


# ----------------------------------------------------------------------------------------------------
# build / modules / status
# ----------------------------------------------------------------------------------------------------


def _services(cfg):
    from .app import create_services

    return create_services(cfg)


def cmd_build(ns: argparse.Namespace, cfg) -> int:
    svc = _services(cfg)
    if svc.artifacts is None:
        print(f"ERROR: artifacts not available: {svc.artifacts_error}", file=sys.stderr)
        return 1
    job = svc.artifacts.start_build(ns.target, force=bool(ns.force))
    index = 0
    try:
        while True:
            done = job.done
            lines, index = job.lines_since(index)
            for ln in lines:
                print(ln, flush=True)
            if done:
                lines, index = job.lines_since(index)
                for ln in lines:
                    print(ln, flush=True)
                break
            job.wait(0.25)
    except KeyboardInterrupt:
        print("interrupted; the build process may still be running in Docker", file=sys.stderr)
        return 130
    if job.status == "succeeded":
        print(f"==> {job.title}: succeeded")
        return 0
    rc = job.rc if isinstance(job.rc, int) and job.rc != 0 else 1
    print(f"==> {job.title}: {job.status} (rc {rc}){': ' + job.error if job.error else ''}", file=sys.stderr)
    return rc


def cmd_modules(ns: argparse.Namespace, cfg) -> int:
    svc = _services(cfg)
    if svc.modules is None:
        print(f"ERROR: module store is not usable: {svc.store_error}", file=sys.stderr)
        return 1
    from .storage.base import StoreError

    action = getattr(ns, "modules_action", None)
    if action in ("mark-locked", "mark-unlocked"):
        # A running server caches registry records (Google backends): send the override through it so
        # its next write cannot silently undo the change. Without a server, write the store directly.
        url = page_url(cfg.server.host, cfg.server.port)
        server_url = url if _existing_server(url) else None
        return _mark_otp(svc.modules, ns.serial, locked=action == "mark-locked", yes=bool(ns.yes),
                         server_url=server_url)

    try:
        views = [svc.modules.public_view(r) for r in svc.modules.list()]
    except StoreError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if ns.json:
        print(json.dumps(views, indent=2))
        return 0
    if not views:
        print(f"no modules ({svc.storage_status().get('location', '')})")
        return 0
    print(f"{'SERIAL':<10} {'STAGE':<8} {'UPDATED':<21} {'OTP':<8} {'DUID':<17} MAC")
    for v in views:
        otp = v["otp"]
        lock = "ours" if otp["locked_to_our_key"] else ("foreign" if otp["locked"] else "-")
        print(f"{v['serial']:<10} {v['stage']:<8} {v['updated']:<21} {lock:<8} {v['duid'] or '-':<17} {v['mac'] or '-'}")
    return 0


def _post_otp_override(server_url: str, key: str, locked: bool) -> dict:
    """POST the override to a running server (``/api/modules/<serial>/otp``); returns its Module view.

    :raises RuntimeError: the server refused or could not be reached (message for the operator)."""
    body = json.dumps({"action": "mark-locked" if locked else "mark-unlocked", "note": "CLI"}).encode("utf-8")
    req = urllib.request.Request(f"{server_url}api/modules/{key}/otp", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))["module"]
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get("detail")
        except (OSError, ValueError):
            detail = None
        raise RuntimeError(f"the running server refused the change (HTTP {exc.code}): {detail or exc.reason}") from None
    except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        raise RuntimeError(f"could not reach the running server at {server_url}: {exc}") from None


def _mark_otp(modules, serial: str, *, locked: bool, yes: bool, server_url: str | None = None) -> int:
    """``modules mark-locked|mark-unlocked``: operator override of the recorded OTP lock state.

    With ``server_url`` (a running OTP_Provisioner) the change is sent through that server; otherwise
    the store is written directly."""
    from .modules import normalize_serial
    from .storage.base import StoreError

    try:
        key = normalize_serial(serial)
        rec = modules.get(key)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except StoreError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if rec is None:
        print(f"ERROR: unknown module {key!r}", file=sys.stderr)
        return 1
    v = modules.public_view(rec)
    otp = v["otp"]
    print(f"module {key}: stage {v['stage']}, OTP key hash {otp['customer_key_hash'] or '(none recorded)'}, "
          f"secure boot provisioned {'yes' if otp['secure_boot_provisioned'] else 'no'}")
    if locked:
        print(f"This records that the board OTP holds THIS module's key hash {v['secrets']['customer_key_hash']}.\n"
              "From now on every stage is served signed for that key; an unlocked board will reject them.\n"
              "Do this only when the OTP was programmed but the stage-1 report never reached the server.")
    else:
        print("This clears the recorded OTP lock: stages will be served unsigned again, which a board whose\n"
              "OTP really holds a key hash will reject. Do this only to undo a wrong mark-locked.")
    if not yes:
        try:
            typed = input(f"Type the serial {key} to confirm: ")
        except (EOFError, KeyboardInterrupt):
            typed = ""
            print()
        if typed.strip().lower() != key:
            print("aborted: nothing changed", file=sys.stderr)
            return 1
    if server_url:
        print(f"(sending the change through the running server at {server_url})")
        try:
            otp = _post_otp_override(server_url, key, locked)["otp"]
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(f"module {key}: OTP {'locked to our key' if otp['locked_to_our_key'] else 'not locked'} "
              f"(key hash {otp['customer_key_hash'] or 'none'})")
        return 0
    try:
        saved = modules.mark_locked(key, "CLI") if locked else modules.mark_unlocked(key, "CLI")
    except (KeyError, ValueError) as exc:
        msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1
    except StoreError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    otp = modules.public_view(saved)["otp"]
    print(f"module {key}: OTP {'locked to our key' if otp['locked_to_our_key'] else 'not locked'} "
          f"(key hash {otp['customer_key_hash'] or 'none'})")
    return 0


def _make_store(cfg):
    from .storage import make_store

    return make_store(cfg)


def cmd_login(ns: argparse.Namespace, cfg) -> int:
    """``login``: interactive OAuth (or a service-account connectivity check) for the Google backends."""
    backend = cfg.storage.backend
    if backend not in ("gsheets", "gdrive"):
        print(f"backend {backend} needs no login")
        return 0
    from .storage.base import StoreError

    try:
        store = _make_store(cfg)
        if not hasattr(store, "login"):
            print(f"backend {backend} needs no login")
            return 0
        msg = store.login()
    except StoreError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("login interrupted", file=sys.stderr)
        return 130
    print(msg or f"backend {backend}: login done")
    return 0


def cmd_status(ns: argparse.Namespace, cfg) -> int:
    svc = _services(cfg)
    print(json.dumps(svc.status(), indent=2, default=str))
    return 0


def main(argv: Sequence[str] | None = None, *, prog: str = "python -m otp_server") -> int:
    """CLI entry point; returns the process exit code."""
    ns = parse_args(argv, prog=prog)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        cfg = _load(ns)
    except (FileNotFoundError, ValueError) as exc:
        # Config problems (missing --config file, invalid value) are user errors: no traceback.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    handlers = {"build": cmd_build, "modules": cmd_modules, "status": cmd_status, "login": cmd_login}
    return handlers.get(ns.command, cmd_serve)(ns, cfg)


if __name__ == "__main__":
    sys.exit(main())
