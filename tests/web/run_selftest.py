#!/usr/bin/env python3
"""Headless-Chrome runner for the WebUSB page self-test (tests/web/selftest.js), plus page screenshots.

    python tests/web/run_selftest.py                       # run the self-test, print PASS/FAIL lines, exit 0/1
    python tests/web/run_selftest.py --screenshot out.png --width 1600 --height 1200 [--state idle|demo|demo-fastboot|offline]
    python tests/web/run_selftest.py --serve               # serve the page + fake API until Ctrl-C

A stdlib HTTP server serves the repository read-only (GET/HEAD only, no directory listings, nothing outside the
repo), the self-test page (/__selftest.html = index.html + tests/web/mocks.js + selftest.js), a canned API under
/api/ (tests/web/fake_api.py) and accepts the result on POST /__result. Chrome: --chrome, env OTP_CHROME, the
default Windows install path, or google-chrome / chromium / chrome / msedge on PATH.
"""
from __future__ import annotations

import argparse
import http.server
import json
import mimetypes
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parents[1]
sys.path.insert(0, str(TESTS))
sys.dont_write_bytecode = True  # no __pycache__ in the tree (the repo has no .gitignore on purpose)
import fake_api  # noqa: E402

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]
CHROME_NAMES = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "msedge"]

# Real rpiboot fixtures inside the repo (first existing regular file wins; git symlinks on Windows are text stubs).
BOOTFILES = ["external/usbboot/firmware/bootfiles.bin", "stage-dirs/mass-storage-gadget/bootfiles.bin",
             "stage-dirs/fastboot-gadget/bootfiles.bin"]
CONFIGS = ["stage-dirs/mass-storage-gadget/config.txt", "external/usbboot/mass-storage-gadget64/config.txt",
           "stage-dirs/fastboot-gadget/config.txt"]


def find_chrome(explicit: str | None) -> str:
    for c in [explicit, os.environ.get("OTP_CHROME"), *CHROME_CANDIDATES]:
        if c and pathlib.Path(c).is_file():
            return c
    for name in CHROME_NAMES:
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit("Chrome not found: pass --chrome PATH or set OTP_CHROME")


def pick_fixture(candidates: list[str], min_size: int) -> str:
    for rel in candidates:
        p = REPO / rel
        if p.is_file() and not p.is_symlink() and p.stat().st_size >= min_size:
            return "/" + rel
    raise SystemExit(f"no fixture found among {candidates}")


class State:
    offline = False
    inject = ""
    result: str | None = None
    done = threading.Event()


def page_html(extra: str) -> bytes:
    html = (REPO / "index.html").read_text(encoding="utf-8")
    if "</body>" not in html:
        raise SystemExit("index.html has no </body>")
    return html.replace("</body>", extra + "\n</body>").encode("utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "otp-selftest/1"

    def log_message(self, fmt: str, *args: object) -> None:  # quiet
        pass

    def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, obj: object) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json")

    def _api(self, method: str, path: str, body: bytes) -> None:
        if State.offline:
            self.close_connection = True
            self._json(404, {"detail": "Not Found"})
            return
        status, payload = fake_api.handle(method, path, body)
        if status == 0:
            self._sse(payload)
        else:
            self._json(status, payload)

    def _sse(self, job: dict) -> None:
        frames, finished = fake_api.sse_events(job)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            for f in frames:
                self.wfile.write(f)
                self.wfile.flush()
            if not finished:
                for _ in range(20):  # a running job: keep the stream open for a while
                    time.sleep(1.0)
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except OSError:
            pass
        self.close_connection = True

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, (REPO / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/__selftest.html" or path == "/__page.html":
            self._send(200, page_html(State.inject), "text/html; charset=utf-8")
            return
        if path.startswith("/api/"):
            self._api("GET", self.path, b"")
            return
        rel = urllib.parse.unquote(path).lstrip("/")
        target = (REPO / rel).resolve()
        try:
            target.relative_to(REPO)
        except ValueError:
            self._json(403, {"detail": "outside the repository"})
            return
        if ".." in pathlib.PurePosixPath(rel).parts or not target.is_file():
            self._json(404, {"detail": "Not Found"})
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype)

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n) if n else b""
        path = urllib.parse.urlsplit(self.path).path
        if path == "/__result":
            State.result = body.decode("utf-8", "replace")
            self._send(200, b"ok", "text/plain")
            State.done.set()
            return
        if path.startswith("/api/"):
            self._api("POST", self.path, body)
            return
        self._json(405, {"detail": "read-only"})

    def do_PUT(self) -> None:
        self._json(405, {"detail": "read-only"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT


def demo_inject(state: str) -> str:
    """Scripts appended to the page for --state demo / demo-fastboot (screenshots only)."""
    if not state.startswith("demo"):
        return ""
    variant = state.split("-", 1)[1] if "-" in state else ""
    return (f"<script>window.__DEMO = {json.dumps(variant)};</script>\n"
            '<script src="/tests/web/demo.js"></script>')


def start_server(port: int) -> http.server.ThreadingHTTPServer:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def chrome_cmd(chrome: str, profile: str, url: str, extra: list[str]) -> list[str]:
    return [chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--disable-background-networking", "--hide-scrollbars",
            f"--user-data-dir={profile}", *extra, url]


def run_selftest(args: argparse.Namespace) -> int:
    fix = {"bootfiles": pick_fixture(BOOTFILES, 100_000), "config": pick_fixture(CONFIGS, 10)}
    State.inject = ('<pre id="test-out" class="hidden">running</pre>\n'
                    f"<script>window.__FIX = {json.dumps(fix)};</script>\n"
                    '<script src="/tests/web/mocks.js"></script>\n<script src="/tests/web/selftest.js"></script>')
    srv = start_server(args.port)
    port = srv.server_address[1]
    chrome = find_chrome(args.chrome)
    profile = tempfile.mkdtemp(prefix="otp-selftest-")
    errlog = pathlib.Path(profile) / "chrome-stderr.txt"
    t0 = time.time()
    with open(errlog, "w", encoding="utf-8", errors="replace") as err:
        proc = subprocess.Popen(chrome_cmd(chrome, profile, f"http://127.0.0.1:{port}/__selftest.html",
                                           ["--enable-logging=stderr", "--v=0", "--window-size=1400,1000"]),
                                stdout=subprocess.DEVNULL, stderr=err)
        ok = State.done.wait(timeout=args.timeout)
        proc.kill()
        proc.wait(timeout=20)
    srv.shutdown()
    rc = 1
    if ok and State.result is not None:
        text = State.result
        report, _, applog = text.partition("\n--- app log ---\n")
        lines = report.splitlines()
        shown = lines if args.verbose else [ln for ln in lines if not ln.startswith("PASS")]
        print("\n".join(shown))
        passed = sum(1 for ln in lines if ln.startswith("PASS"))
        failed = sum(1 for ln in lines if ln.startswith("FAIL"))
        print(f"-- {passed} passed, {failed} failed, {time.time() - t0:.1f} s (chrome: {chrome})")
        if args.verbose and applog.strip():
            print("--- app log ---\n" + applog)
        rc = 0 if ("SUMMARY ALL PASS" in report and failed == 0) else 1
    else:
        print(f"TIMEOUT after {args.timeout:.0f} s: no result posted")
        text = errlog.read_text(encoding="utf-8", errors="replace")
        hits = [ln for ln in text.splitlines() if "CONSOLE" in ln or "Uncaught" in ln or "rror" in ln]
        print("\n".join(hits[:60]))
    shutil.rmtree(profile, ignore_errors=True)
    return rc


def screenshot(args: argparse.Namespace) -> int:
    State.offline = args.state == "offline"
    State.inject = demo_inject(args.state)
    srv = start_server(args.port)
    port = srv.server_address[1]
    chrome = find_chrome(args.chrome)
    profile = tempfile.mkdtemp(prefix="otp-shot-")
    out = pathlib.Path(args.screenshot).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = chrome_cmd(chrome, profile, f"http://127.0.0.1:{port}/__page.html",
                     [f"--screenshot={out}", f"--window-size={args.width},{args.height}",
                      f"--virtual-time-budget={args.budget}"])
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    srv.shutdown()
    shutil.rmtree(profile, ignore_errors=True)
    if not out.is_file():
        print(res.stdout.decode(errors="replace")[-2000:])
        return 1
    print(f"screenshot: {out} ({out.stat().st_size} bytes, {args.width}x{args.height}, state {args.state})")
    return 0


def serve(args: argparse.Namespace) -> int:
    State.offline = args.state == "offline"
    State.inject = demo_inject(args.state)
    srv = start_server(args.port)
    print(f"serving http://127.0.0.1:{srv.server_address[1]}/__page.html (fake API{' off' if State.offline else ''}); Ctrl-C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    srv.shutdown()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chrome", help="path to Chrome/Chromium")
    ap.add_argument("--port", type=int, default=0, help="HTTP port (default: any free port)")
    ap.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for the self-test result")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every PASS line and the page log")
    ap.add_argument("--screenshot", metavar="PNG", help="take a screenshot of the page instead of running the tests")
    ap.add_argument("--width", type=int, default=1600)
    ap.add_argument("--height", type=int, default=1200)
    ap.add_argument("--state", choices=["idle", "demo", "demo-fastboot", "offline"], default="idle",
                    help="page state for --screenshot/--serve: idle (fake API), demo (mid-run), demo-fastboot (waiting for the gadget), offline (no API)")
    ap.add_argument("--budget", type=int, default=4000, help="virtual time budget (ms) before the screenshot")
    ap.add_argument("--serve", action="store_true", help="serve the page with the fake API until Ctrl-C")
    args = ap.parse_args(argv)
    if args.serve:
        return serve(args)
    if args.screenshot:
        return screenshot(args)
    return run_selftest(args)


if __name__ == "__main__":
    sys.exit(main())
