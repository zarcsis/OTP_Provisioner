#!/usr/bin/env python3
"""End-to-end test of the whole station without hardware: real server + real page + mock Raspberry Pi 5.

    python -B tests/web/run_e2e.py [--scenario A|B|both] [--recovery-passphrase] [--scratch DIR] [--keep] [--chrome PATH]

For every scenario the runner
  1. starts ITS OWN server: python -B tests/web/e2e_server.py --port <free> --registry <temp dir> -- the real app
     without Google (nothing gated) and with an in-memory registry that is also dumped to <temp dir>/<serial>.json.
     The work dir stays the default one, so the real tools image, gadget and both OS images (clear + crypt)
     are reused. Before the first run it waits (GET /api/builds every 20 s, up to 40 min) until tools, gadget and
     image (both variants) are ready (and the builds of a live server on :8765, if any, are finished); it never
     starts a build itself;
  2. runs a stdlib reverse proxy that serves the server's page with /__e2e__/mocks.js + /__e2e__/e2e.js injected
     before the page's own scripts, forwards everything else to the server (streaming, incl. SSE and 256 MiB
     pieces), records the requests and the stage manifests the page fetched, and takes the verdict on
     POST /__e2e_result;
  3. loads the page in headless Chrome; tests/web/e2e.js plugs a mock Pi 5 into navigator.usb and clicks through the
     real UI (scenario radio → Connect board → Provision → typed serial → Select device / Connect fastboot gadget);
  4. checks the report against the server files, the API and the dumped registry, and prints PASS/FAIL lines.

Scenario A (radio "open"): unsigned stages 1-3, the clear image, nothing written to OTP, no key export, no
oem fwcrypto init. Scenario B (radio "secure"): signed stage 1 with program_pubkey=1; the board then reports our
key hash, so stages 2 and 3 are signed (boot.sig, counter-signed bootfiles.bin, per-board re-signed boot slot); the
crypt image; before anything is erased the page has the gadget's otp-keyexport helper generate the OTP device key
(the mock's slot is blank) and hands it to the server, which keeps it; the board then writes the container the
station built and checks its key against it (oem cryptcheck). The mock gadget answers only what the station's
rpi-fastbootd does (docker/fastbootd/otp-station.patch). provisioning.recovery_passphrase is off by default;
--recovery-passphrase turns it on for B (the station adds keyslot 1) and checks the passphrase.
Exit code 0 when every assertion passed.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import http.server
import io
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parents[1]
sys.path.insert(0, str(REPO))

from otp_server import imagejson  # noqa: E402
from otp_server.secrets_gen import public_key_fingerprint, same_public_key  # noqa: E402

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium",
]
LIVE_SERVER = "http://127.0.0.1:8765"
SCENARIOS = {
    "A": {"serial": "e2e5a7c1", "mode": "open"},
    "B": {"serial": "e2e5b7c2", "mode": "secure"},
}
#: otp_server/artifacts/image.py KEY_EXPORT (where the gadget's otp-keyexport helper works)
KEY_EXPORT = {"dir": "/run/otp-keyexport", "key": "/run/otp-keyexport/key.der",
              "status": "/run/otp-keyexport/status", "request": "/run/otp-keyexport/request"}
MAC = "2c:cf:67:e2:e5:01"
INJECT_BEFORE = '<script src="js/duid.js"></script>'
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length"}


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get_json(url: str, timeout: float = 30.0) -> tuple[int, object]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body.decode("utf-8", "replace")


def sha256_url(url: str) -> tuple[int, str]:
    h = hashlib.sha256()
    n = 0
    with urllib.request.urlopen(url, timeout=600) as r:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            h.update(b)
            n += len(b)
    return n, h.hexdigest()


def get_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=600) as r:
        return r.read()


def work_dir() -> pathlib.Path:
    return pathlib.Path(os.environ.get("OTP_WORK_DIR") or pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "OTP_Provisioner")


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def current_set(variant: str) -> tuple[pathlib.Path, dict]:
    """(set dir, manifest.json) of the image set current-<variant>.json names in the work dir."""
    root = work_dir() / "artifacts" / "image"
    name = json.loads((root / f"current-{variant}.json").read_text(encoding="utf-8"))["set"]
    return root / name, json.loads((root / name / "manifest.json").read_text(encoding="utf-8"))


def image_blocks(variant: str) -> list[str]:
    """What rpi-fastbootd's "oem idpgetblk" names for the image.json a board gets: "<dev>:<simage>" in image.json
    order. The crypt set goes to a board as the station-built containers (imagejson.station_luks): plain partitions
    <disk>p1, p2, ... whose root simage is root.luks.sparse; a clear set's partitions are the same shape."""
    set_dir, man = current_set(variant)
    ij = imagejson.load(set_dir / "image.json")
    if variant == "crypt":
        ij, containers = imagejson.station_luks(ij, 16 << 20)
        man = dict(man, simages={**(man.get("simages") or {}), **{c["simage"]: [] for c in containers}})
    disk = imagejson.storage_device(ij)
    order = [s for s in imagejson.simages(ij) if s in (man.get("simages") or {})]
    crypt = imagejson.crypt_containers(ij)
    out = []
    for i, s in enumerate(order):
        if i == 0:
            out.append(f"{imagejson.partition_name(disk, 1)}:{s}")
        elif crypt:
            out.append(f"mapper/{crypt[0]['mname']}:{s}")
        else:
            out.append(f"{imagejson.partition_name(disk, i + 1)}:{s}")
    return out


def files_snapshot(d: pathlib.Path) -> list[tuple[str, int]]:
    return sorted((p.name, p.stat().st_mtime_ns) for p in d.glob("*") if p.is_file()) if d.is_dir() else []


# ---------------------------------------------------------------------------------------------- checks

class Checks:
    def __init__(self, title: str):
        self.title = title
        self.lines: list[str] = []
        self.failed = 0
        self.passed = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        ok = bool(ok)
        line = f"{'PASS' if ok else 'FAIL'} [{self.title}] {name}" + (f" -- {detail}" if detail else "")
        self.lines.append(line)
        print(line, flush=True)
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        return ok

    def eq(self, name: str, got: object, want: object, show: bool = True) -> bool:
        ok = got == want
        return self.check(name, ok, (f"got {got!r}, want {want!r}" if not ok else (f"{got!r}" if show else "")) if show or not ok else "")


# ---------------------------------------------------------------------------------------------- proxy

class ProxyState:
    def __init__(self, backend_port: int, inject: str, registry: pathlib.Path):
        self.backend_port = backend_port
        self.inject = inject
        self.registry = registry
        self.manifests: list[dict] = []     # every stage-manifest response: {stage, status, body, harness, t}
        self.downloads: list[dict] = []     # every stage file download: {path, size, sha256, status}
        self.requests: list[str] = []       # "METHOD path" of everything forwarded to the server, in order
        self.times: list[float] = []        # when each of them arrived (time.time())
        self.bodies: list[dict] = []        # small JSON request bodies the page POSTed: {path, body}
        self.errors: list[str] = []
        self.result: dict | None = None
        self.done = threading.Event()
        self.lock = threading.Lock()


def make_handler(st: ProxyState):
    manifest_re = re.compile(r"^/api/modules/([^/]+)/stage/(\d)$")
    file_re = re.compile(r"^/api/modules/([^/]+)/stage/(\d)/files/(.+)$")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"   # one request per connection; bodies without a length end at close
        server_version = "otp-e2e-proxy/1"

        def log_message(self, fmt: str, *args: object) -> None:
            pass

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self) -> None:
            path = urllib.parse.urlsplit(self.path).path
            if path in ("/", "/index.html"):
                return self._page()
            if path in ("/__e2e__/mocks.js", "/__e2e__/e2e.js"):
                return self._send(200, (TESTS / path.rsplit("/", 1)[1]).read_bytes(), "text/javascript; charset=utf-8")
            if path == "/__e2e__/keyhash":
                serial = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("serial", [""])[0]
                if not re.fullmatch(r"[0-9a-f]{8}", serial):
                    return self._send(400, b'{"detail":"bad serial"}', "application/json")
                p = st.registry / f"{serial}.json"
                if not p.is_file():
                    return self._send(404, b'{"detail":"no record"}', "application/json")
                rec = json.loads(p.read_text(encoding="utf-8"))
                return self._send(200, json.dumps({"customer_key_hash": rec.get("customer_key_hash", "")}).encode(),
                                  "application/json")
            self._forward()

        def do_HEAD(self) -> None:
            self._forward()

        def do_POST(self) -> None:
            if urllib.parse.urlsplit(self.path).path == "/__e2e_result":
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                try:
                    st.result = json.loads(body)
                except ValueError as exc:
                    st.result = {"errors": [f"unparsable result: {exc}"]}
                self._send(200, b"ok", "text/plain")
                st.done.set()
                return
            self._forward()

        def _page(self) -> None:
            conn = http.client.HTTPConnection("127.0.0.1", st.backend_port, timeout=60)
            conn.request("GET", "/")
            r = conn.getresponse()
            html = r.read().decode("utf-8")
            conn.close()
            if r.status != 200 or INJECT_BEFORE not in html:
                st.errors.append(f"page: HTTP {r.status}, injection point present: {INJECT_BEFORE in html}")
                return self._send(502, html.encode(), "text/html; charset=utf-8")
            html = html.replace(INJECT_BEFORE, st.inject + "\n" + INJECT_BEFORE, 1)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

        def _forward(self) -> None:
            path = urllib.parse.urlsplit(self.path).path
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            with st.lock:
                st.requests.append(f"{self.command} {path}")
                st.times.append(time.time())
                if self.command == "POST" and body is not None and len(body) <= 65536:
                    try:
                        st.bodies.append({"path": path, "body": json.loads(body)})
                    except ValueError:
                        pass
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            conn = http.client.HTTPConnection("127.0.0.1", st.backend_port, timeout=900)
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                r = conn.getresponse()
            except OSError as exc:
                conn.close()
                st.errors.append(f"backend {self.command} {self.path}: {exc}")
                return self._send(502, json.dumps({"detail": f"proxy: {exc}"}).encode(), "application/json")
            mm = manifest_re.match(path) if self.command == "GET" else None
            fm = file_re.match(path) if self.command == "GET" else None
            try:
                if mm:   # small JSON: buffer and record
                    data = r.read()
                    try:
                        parsed = json.loads(data)
                    except ValueError:
                        parsed = None
                    with st.lock:
                        st.manifests.append({"serial": mm.group(1), "stage": int(mm.group(2)), "status": r.status,
                                             "body": parsed, "harness": self.headers.get("X-E2E-Harness") == "1",
                                             "t": time.time()})
                    self.send_response(r.status)
                    for k, v in r.getheaders():
                        if k.lower() not in HOP:
                            self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(r.status)
                length = r.getheader("Content-Length")
                for k, v in r.getheaders():
                    if k.lower() not in HOP:
                        self.send_header(k, v)
                if length is not None:
                    self.send_header("Content-Length", length)
                self.end_headers()
                if self.command == "HEAD":
                    return
                h = hashlib.sha256() if fm else None
                keep = [] if fm and length is not None and int(length) <= (4 << 20) else None
                total = 0
                while True:
                    chunk = r.read1(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if h:
                        h.update(chunk)
                    if keep is not None:
                        keep.append(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                if fm:
                    with st.lock:
                        st.downloads.append({"stage": int(fm.group(2)), "name": urllib.parse.unquote(fm.group(3)),
                                             "status": r.status, "size": total, "sha256": h.hexdigest(),
                                             "body": b"".join(keep) if keep is not None else None})
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            finally:
                conn.close()
                self.close_connection = True

    return Handler


# ---------------------------------------------------------------------------------------------- server

class OwnServer:
    """tests/web/e2e_server.py on a free port: the real app, no Google, registry in memory (dumped to ``registry``)."""

    def __init__(self, scratch: pathlib.Path, name: str, settings: list[str]):
        self.dir = scratch / name
        if self.dir.exists():
            shutil.rmtree(self.dir)
        self.registry = self.dir / "registry"
        self.registry.mkdir(parents=True)
        self.settings = list(settings)
        self.recovery_passphrase = "provisioning.recovery_passphrase=true" in self.settings
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.logfile = self.dir / "server.log"
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
        for k in ("OTP_CONFIG", "OTP_STORAGE", "OTP_PORT"):
            env.pop(k, None)
        self._log = open(self.logfile, "wb")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        cmd = [sys.executable, "-B", "-u", str(TESTS / "e2e_server.py"), "--port", str(self.port),
               "--registry", str(self.registry)]
        for s in self.settings:
            cmd += ["--set", s]
        self.proc = subprocess.Popen(cmd, cwd=str(REPO), env=env, stdout=self._log, stderr=subprocess.STDOUT,
                                     creationflags=flags)
        t0 = time.time()
        while time.time() - t0 < 90:
            if self.proc.poll() is not None:
                raise SystemExit(f"server exited with {self.proc.returncode}:\n{self.logfile.read_text(errors='replace')}")
            try:
                code, s = get_json(self.base + "/api/status", timeout=5)
                if code == 200:
                    return
            except OSError:
                pass
            time.sleep(0.5)
        raise SystemExit("server did not answer /api/status in 90 s")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            else:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if getattr(self, "_log", None):
            self._log.close()


def wait_for_builds(base: str, max_minutes: float) -> dict:
    """Poll GET /api/builds every 20 s until tools, gadget and image (both variants) are ready and no live build runs."""
    t0 = time.time()
    while True:
        code, b = get_json(base + "/api/builds")
        ready = code == 200 and all(b.get(t, {}).get("ready") for t in ("tools", "gadget", "image"))
        live_running: list[str] = []
        try:
            lc, jobs = get_json(LIVE_SERVER + "/api/jobs", timeout=5)
            if lc == 200:
                live_running = [f"{j['target']}:{j['status']}" for j in jobs
                                if j.get("status") in ("queued", "running") and j.get("target") in ("gadget", "image", "tools")]
        except OSError:
            pass
        state = ", ".join(f"{t}={'ready' if b.get(t, {}).get('ready') else 'missing'}" for t in ("tools", "gadget", "image")) if code == 200 else f"HTTP {code}"
        if ready and not live_running:
            v = b["image"].get("variants") or {}
            log(f"builds ready ({state}); gadget {b['gadget'].get('version')}, image "
                + ", ".join(f"{k} {x.get('set')}" for k, x in v.items()))
            return b
        if time.time() - t0 > max_minutes * 60:
            raise SystemExit(f"builds not ready after {max_minutes} min: {state}; live jobs {live_running}")
        detail = "; ".join(f"{t}: {b.get(t, {}).get('detail', '')[:160]}" for t in ("gadget", "image")) if code == 200 else ""
        log(f"waiting for builds: {state}; live server jobs running: {live_running or 'none'}; {detail}")
        time.sleep(20)


def find_chrome(explicit: str | None) -> str:
    for c in [explicit, os.environ.get("OTP_CHROME"), *CHROME_CANDIDATES]:
        if c and pathlib.Path(c).is_file():
            return c
    for n in ("google-chrome", "chromium", "chrome", "msedge"):
        if shutil.which(n):
            return shutil.which(n)
    raise SystemExit("Chrome not found (--chrome)")


# ---------------------------------------------------------------------------------------------- one scenario

def run_scenario(name: str, args: argparse.Namespace, scratch: pathlib.Path, chrome: str, shared: dict) -> Checks:
    sc = SCENARIOS[name]
    serial = sc["serial"]
    secure = sc["mode"] == "secure"
    C = Checks(name)
    settings = ["provisioning.recovery_passphrase=true"] if (secure and args.recovery_passphrase) else []
    if args.image_name:
        settings.append(f"image.name={args.image_name}")
    srv = OwnServer(scratch, f"scenario-{name}", settings)
    google_dir = work_dir() / "google"
    google_before = files_snapshot(google_dir)
    t_start = time.time()
    proxy = None
    chrome_proc = None
    profile = pathlib.Path(tempfile.mkdtemp(prefix=f"otp-e2e-{name}-", dir=str(scratch)))
    try:
        srv.start()
        log(f"scenario {name}: server {srv.base} (registry dump {srv.registry}{', ' + ' '.join(settings) if settings else ''})")
        if not shared.get("builds"):
            shared["builds"] = wait_for_builds(srv.base, args.wait_builds)
        code, status = get_json(srv.base + "/api/status")
        prov = status["config"]["provisioning"]
        C.eq("server: no Google wiring (google null, google_ready true)", (status.get("google"), status.get("google_ready")), (None, True))
        C.eq("server: registry is the in-memory test store", status["storage"]["backend"], "memory")
        C.eq("server: provisioning.default_mode", prov.get("default_mode"), "open")
        C.eq("server: provisioning.modes", prov.get("modes"), ["open", "secure"])
        C.check("server: provisioning.secure_boot is gone", "secure_boot" not in prov, json.dumps(sorted(prov)))
        C.eq("server: provisioning.recovery_passphrase", prov.get("recovery_passphrase"), srv.recovery_passphrase)
        variants = (status["artifacts"]["image"].get("variants") or {})
        C.check("server: both image variants (clear, crypt) ready", sorted(variants) == ["clear", "crypt"] and all(v.get("ready") for v in variants.values()),
                json.dumps({k: v.get("detail") for k, v in variants.items()}))
        blocks = image_blocks("crypt" if secure else "clear")
        cfg = {"scenario": name, "serial": serial, "mode": sc["mode"], "blocks": blocks, "timeoutMs": int(args.timeout * 1000)}
        inject = (f"<script>window.__E2E = {json.dumps(cfg)};</script>\n"
                  '<script src="/__e2e__/mocks.js"></script>\n<script src="/__e2e__/e2e.js"></script>')
        st = ProxyState(srv.port, inject, srv.registry)
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(st))
        proxy.daemon_threads = True
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        purl = f"http://127.0.0.1:{proxy.server_address[1]}/"
        log(f"scenario {name}: proxy {purl} → {srv.base}; Chrome headless; scenario radio {sc['mode']}, blocks {blocks}")
        errlog = open(profile / "chrome-stderr.txt", "wb")
        chrome_proc = subprocess.Popen([chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                                        "--disable-extensions", "--disable-background-networking",
                                        "--disable-background-timer-throttling", "--disable-renderer-backgrounding",
                                        "--disable-backgrounding-occluded-windows", "--window-size=1600,1200",
                                        "--enable-logging=stderr", "--v=0", f"--user-data-dir={profile}", purl],
                                       stdout=subprocess.DEVNULL, stderr=errlog)
        got = st.done.wait(timeout=args.timeout + 120)
        chrome_proc.kill()
        chrome_proc.wait(timeout=30)
        errlog.close()
        if not got or st.result is None:
            text = (profile / "chrome-stderr.txt").read_text(errors="replace")
            hits = [ln for ln in text.splitlines() if "CONSOLE" in ln or "Uncaught" in ln][:40]
            C.check("page posted a result", False, "timeout; " + " | ".join(hits))
            return C
        rep = st.result
        (srv.dir / "report.json").write_text(json.dumps(_redact(rep), indent=1), encoding="utf-8")
        log(f"scenario {name}: page finished in {rep.get('elapsedMs', 0) / 1000:.1f} s")
        for line in rep.get("timeline", []):
            print("    " + line)
        verify(C, name, sc, serial, srv, st, rep, t_start, shared)
        C.eq("the station's Google login files are untouched (the test server has no Google wiring)",
             files_snapshot(google_dir), google_before, show=False)
        return C
    finally:
        if chrome_proc and chrome_proc.poll() is None:
            chrome_proc.kill()
        if proxy:
            proxy.shutdown()
        srv.stop()
        shutil.rmtree(profile, ignore_errors=True)


def _redact(rep: dict) -> dict:
    r = json.loads(json.dumps(rep))
    fb = ((r.get("board") or {}).get("fastboot") or {})
    if fb.get("deviceKeyDerB64"):
        fb["deviceKeyDerB64"] = "<redacted>"
    return r


def served(st: ProxyState, stage: int, name: str) -> dict | None:
    """What the server streamed to the page for a stage file during the run (the proxy's capture)."""
    d = [x for x in st.downloads if x["stage"] == stage and x["name"] == name and x["status"] == 200]
    return d[-1] if d else None


def last_page_manifest(st: ProxyState, stage: int) -> dict | None:
    ms = [m for m in st.manifests if m["stage"] == stage and not m["harness"] and m["status"] == 200]
    return ms[-1]["body"] if ms else None


def _is_export_cmd(c: str) -> bool:
    return c == "upload" or c.startswith("oem upload-file ") or c.startswith("oem download-file ")


def verify(C: Checks, name: str, sc: dict, serial: str, srv: OwnServer, st: ProxyState, rep: dict,
           t_start: float, shared: dict) -> None:
    base = srv.base
    mode = sc["mode"]
    secure = mode == "secure"
    variant = "crypt" if secure else "clear"
    with_pass = secure and srv.recovery_passphrase
    C.check("page ran without errors", not rep.get("errors") and not st.errors,
            "; ".join((rep.get("errors") or []) + st.errors)[:2000])
    C.eq("page not gated (no Google wiring on this server)", (rep.get("gated"), rep.get("googleGateHidden")), (False, True))
    board = rep.get("board") or {}
    C.eq("board went ROM → recovery → ROM → bootloader → fastboot", board.get("history"), ["rom", "fs", "rom", "fs", "fastboot"])
    C.eq("the page's board card shows the serial", (rep.get("boardCardSerial") or "").strip(), serial)

    # ---------------- scenario
    C.eq("scenario radio preselected from provisioning.default_mode", rep.get("scenarioDefault"), "open")
    if "scenarioDetour" in rep:   # the wanted radio was preselected: the operator switched away and back
        C.eq("scenario radio: switching to the other scenario works", rep["scenarioDetour"], "secure" if mode == "open" else "open")
    C.eq(f"scenario radio picked: {mode}", (rep.get("scenarioRadio"), rep.get("scenarioAfter")), (mode, mode))
    C.eq("the choice is remembered (localStorage otp.scenario)", rep.get("scenarioRemembered"), mode)
    C.check("provisioning mode text describes the scenario", (rep.get("provisionMode") or "").startswith("Secure:" if secure else "Open:"),
            rep.get("provisionMode"))
    C.check("provision hint names the scenario", f"· {mode} scenario" in (rep.get("provisionHint") or ""), rep.get("provisionHint"))
    hello = rep.get("moduleAfterHello") or {}
    C.eq("new record after hello: the server default, nothing chosen", (hello.get("mode"), hello.get("mode_chosen"), hello.get("stage")), ("open", "", "new"))
    mode_path = f"/api/modules/{serial}/mode"
    reqs = st.requests
    i_mode = [i for i, r in enumerate(reqs) if r == f"POST {mode_path}"]
    i_stage = next((i for i, r in enumerate(reqs) if r.startswith(f"GET /api/modules/{serial}/stage/")), -1)
    C.check("the page sent the scenario once (POST /api/modules/<serial>/mode), before the first stage manifest",
            len(i_mode) == 1 and 0 <= i_mode[0] < i_stage, f"mode POSTs at {i_mode}, first stage request at {i_stage}")
    C.eq("scenario POST body", [b["body"] for b in st.bodies if b["path"] == mode_path], [{"mode": mode}])
    start = rep.get("moduleAtStart") or {}
    C.eq("the module at the start of the run carries the choice", (start.get("mode"), start.get("mode_chosen")), (mode, mode))

    page_ms = [m for m in st.manifests if not m["harness"]]
    if secure:
        # Artifacts._stage: stages 2 and 3 of a secure board wait until its OTP holds our key hash (stage 1)
        first = {n: next((m for m in page_ms if m["stage"] == n), None) for n in (2, 3)}
        C.check("secure: the early stage 2 and 3 manifests are refused (409 'run stage 1 first')",
                all(m and m["status"] == 409 and "run stage 1 first" in str((m["body"] or {}).get("reason", "")) for m in first.values()),
                json.dumps({n: (m["status"], (m["body"] or {}).get("reason")) if m else None for n, m in first.items()}))
        t_res1 = next((st.times[i] for i, r in enumerate(reqs) if r == f"POST /api/modules/{serial}/stage/1/result"), None)
        before = [m for m in page_ms if m["stage"] in (2, 3) and t_res1 is not None and m["t"] < t_res1]
        after = [m for m in page_ms if m["stage"] in (2, 3) and t_res1 is not None and m["t"] > t_res1]
        gate_after = [m for m in after if "run stage 1 first" in str((m["body"] or {}).get("reason", ""))]
        C.check("secure: … every time before stage 1 reported our key hash, and never after it (both are served then)",
                t_res1 is not None and before and all(m["status"] == 409 for m in before) and not gate_after
                and {2, 3} <= {m["stage"] for m in after if m["status"] == 200},
                f"before: {[(m['stage'], m['status']) for m in before]}, after: {[(m['stage'], m['status']) for m in after]}")
    else:
        C.eq("open: every stage manifest was served at once (no 409)", sorted({m["status"] for m in page_ms}), [200])
    m1, m2, m3 = (last_page_manifest(st, n) for n in (1, 2, 3))
    C.check("page fetched manifests for stages 1, 2, 3", all((m1, m2, m3)),
            f"stages: {[m['stage'] for m in st.manifests if not m['harness']]}")
    if not all((m1, m2, m3)):
        return
    roms = board.get("roms") or []
    fss = board.get("fileServers") or []

    # ---------------- stage 1
    s1 = {f["name"]: f for f in m1["files"]}
    C.eq("stage 1: manifest files", sorted(s1), ["bootcode5.bin", "config.txt", "pieeprom.bin", "pieeprom.sig"])
    cap1 = {n: served(st, 1, n) for n in s1}
    server1 = {n: ((c["size"], c["sha256"]) if c else None) for n, c in cap1.items()}
    for n, f in s1.items():
        C.check(f"stage 1: server streamed {n} = manifest (size+sha256)", server1[n] == (f["size"], f["sha256"]),
                f"server {server1[n]}, manifest {(f['size'], f['sha256'])}")
    rom1 = roms[0] if roms else {}
    C.check("stage 1: ROM received bootcode5.bin == server file",
            rom1.get("sent") and server1["bootcode5.bin"] and (rom1.get("size"), rom1.get("sha256")) == server1["bootcode5.bin"],
            f"sent {rom1.get('size')} {str(rom1.get('sha256'))[:16]}, server {server1['bootcode5.bin']}")
    C.check("stage 1: boot message length field = file size", rom1.get("header_len") == 24 and rom1.get("header_size_field") == rom1.get("size"),
            f"{rom1.get('header_len')} / {rom1.get('header_size_field')}")
    fs1 = fss[0]["files"] if fss else {}
    for n in ("config.txt", "pieeprom.sig", "pieeprom.bin"):
        got = fs1.get(n) or {}
        C.check(f"stage 1: recovery received {n} == server file", (got.get("size"), got.get("sha256")) == server1[n],
                f"got {got}, server {server1[n]}")
    cfg1 = ((cap1.get("config.txt") or {}).get("body") or b"").decode()
    C.eq("stage 1: config.txt on the server == manifest config_txt", cfg1, m1["config_txt"], show=False)
    flags = [f for d in rep.get("dialogs", []) for f in d["flags"]]
    if secure:
        C.eq("stage 1: mode", m1["mode"], "signed")
        C.check("stage 1: config.txt carries program_pubkey=1", "program_pubkey=1" in cfg1.splitlines(), repr(cfg1))
        C.check("stage 1: manifest lists program_pubkey as irreversible",
                any(i["key"] == "program_pubkey" and i["value"] == "1" for i in m1["irreversible"]), json.dumps(m1["irreversible"]))
        C.check("stage 1: expect = secure_boot_provision + our key hash",
                m1["expect"].get("secure_boot_provision") is True and m1["expect"].get("customer_key_hash") == rep.get("registryKeyHash"),
                json.dumps(m1["expect"]))
        C.check("confirmation dialog lists program_pubkey=1", any(f.startswith("stage 1: program_pubkey=1") for f in flags), json.dumps(flags))
        unsigned_pie = shared.get("A_pieeprom_sha")
        if unsigned_pie:
            C.check("stage 1: signed pieeprom.bin differs from the unsigned one", server1["pieeprom.bin"][1] != unsigned_pie)
    else:
        C.eq("stage 1: mode", m1["mode"], "unsigned")
        C.check("stage 1: config.txt has no program_pubkey", "program_pubkey" not in cfg1, repr(cfg1))
        C.eq("stage 1: nothing irreversible", m1["irreversible"], [])
        C.eq("stage 1: expect no OTP programming", m1["expect"].get("secure_boot_provision"), False)
        C.check("confirmation dialog lists nothing for stage 1", not any(f.startswith("stage 1:") for f in flags), json.dumps(flags))
        shared["A_pieeprom_sha"] = server1["pieeprom.bin"][1]

    # ---------------- stage 2
    s2 = {f["name"]: f for f in m2["files"]}
    want2 = ["boot.img", "boot.sig", "bootfiles.bin", "config.txt"] if secure else ["boot.img", "bootfiles.bin", "config.txt"]
    C.eq("stage 2: manifest files", sorted(s2), want2)
    cap2 = {n: served(st, 2, n) for n in s2}
    server2 = {n: ((c["size"], c["sha256"]) if c else sha256_url(base + s2[n]["url"])) for n, c in cap2.items()}
    for n, f in s2.items():
        C.check(f"stage 2: server {'streamed' if cap2[n] else 'file'} {n} = manifest (size+sha256)", server2[n] == (f["size"], f["sha256"]),
                f"server {server2[n]}, manifest {(f['size'], f['sha256'])}")
    bf = (cap2.get("bootfiles.bin") or {}).get("body") or get_bytes(base + s2["bootfiles.bin"]["url"])
    with tarfile.open(fileobj=io.BytesIO(bf)) as tf:
        member = next((m for m in tf.getmembers() if m.name.lower().lstrip("./") == "2712/bootcode5.bin"), None)
        bc5 = tf.extractfile(member).read() if member else b""
    rom2 = roms[1] if len(roms) > 1 else {}
    C.check("stage 2: ROM received 2712/bootcode5.bin from bootfiles.bin",
            member is not None and rom2.get("sent") and (rom2.get("size"), rom2.get("sha256")) == (len(bc5), hashlib.sha256(bc5).hexdigest()),
            f"sent {rom2.get('size')} {str(rom2.get('sha256'))[:16]}, tar member {len(bc5)} {hashlib.sha256(bc5).hexdigest()[:16]}")
    fs2 = fss[1]["files"] if len(fss) > 1 else {}
    for n in ("config.txt", "boot.img"):
        got = fs2.get(n) or {}
        C.check(f"stage 2: bootloader received {n} == server file", (got.get("size"), got.get("sha256")) == server2[n],
                f"got {got}, server {server2[n]}")
    repo_bf = sha256_file(REPO / "external" / "usbboot" / "firmware" / "bootfiles.bin")
    if secure:
        C.eq("stage 2: mode", m2["mode"], "signed")
        got = fs2.get("boot.sig") or {}
        C.check("stage 2: bootloader received boot.sig == server file", (got.get("size"), got.get("sha256")) == server2["boot.sig"],
                f"got {got}, server {server2['boot.sig']}")
        sig = ((cap2.get("boot.sig") or {}).get("body") or get_bytes(base + s2["boot.sig"]["url"])).decode("ascii", "replace")
        C.check("stage 2: boot.sig has an rsa2048 signature line", re.search(r"^rsa2048: ?[0-9a-f]{512}$", sig, re.M) is not None)
        C.check("stage 2: bootfiles.bin differs from the unsigned one", server2["bootfiles.bin"][1] != repo_bf and
                server2["bootfiles.bin"][1] != shared.get("A_bootfiles_sha", repo_bf))
    else:
        C.eq("stage 2: mode", m2["mode"], "unsigned")
        C.eq("stage 2: bootfiles.bin is the repo file", server2["bootfiles.bin"][1], repo_bf, show=False)
        C.check("stage 2: boot.sig not served", not (fs2.get("boot.sig") or {}).get("size"), json.dumps(fs2.get("boot.sig")))
        shared["A_bootfiles_sha"] = server2["bootfiles.bin"][1]

    # ---------------- stage 3: manifest
    fb = board.get("fastboot") or {}
    parts = m3["parts"]
    blocks = rep.get("blocks") or []
    set_dir, setman = current_set(variant)
    C.check("stage 3: manifest kind/device/erase", m3["kind"] == "fastboot-idp" and m3["storage_device"] == "mmcblk0" and m3["erase"] is True,
            f"{m3['kind']} {m3['storage_device']} erase {m3['erase']}")
    C.eq("stage 3: scenario", m3.get("scenario"), mode)
    C.eq(f"stage 3: the {variant} image (variant, encrypted)", (m3["image"].get("variant"), m3["image"].get("encrypted")), (variant, secure))
    C.eq(f"stage 3: the current {variant} image set", m3["image"].get("set"), setman.get("set", set_dir.name))
    C.check("stage 3: the final manifest has nothing pending", not m3.get("pending"), str(m3.get("pending")))
    C.eq("stage 3: fwcrypto_init", m3["fwcrypto_init"], secure)
    first3 = next((m["body"] for m in st.manifests if m["stage"] == 3 and not m["harness"] and m["status"] == 200), {})
    C.eq("stage 3: key_export (first manifest)", first3.get("key_export"), KEY_EXPORT if secure else None)
    C.eq("stage 3: no key_export once the station holds the key (final manifest)", m3.get("key_export"), None)
    C.eq("stage 3: irreversible", [i["key"] for i in m3["irreversible"]], (["oem fwcrypto init"] if secure else []) + ["erase"])
    C.check("stage 3: mock block list = real simages", len(blocks) == len(parts) and blocks[0].startswith("mmcblk0p1:")
            and all(b.split(":", 1)[1] == s for b, s in zip(blocks, parts)), json.dumps(blocks))
    C.check("stage 3: no passphrase field for the page (the station adds the recovery keyslot itself)", "crypt" not in m3)
    if secure:
        er = m3.get("encrypted_root") or {}
        C.check("stage 3: encrypted root built by the station, keyslots", er.get("built_by") == "station"
                and [c["keyslots"] for c in er.get("containers") or []] == [[0, 1] if with_pass else [0]], json.dumps(er))
        C.eq("stage 3: verify_key", m3.get("verify_key"), [{"dev": "mmcblk0p2", "label": "OSROOT_CRYPT"}])
    else:
        C.check("stage 3: open: no encrypted root, nothing to verify", not m3.get("encrypted_root") and not m3.get("verify_key"))

    # ---------------- stage 3: what the gadget saw
    cmds = fb.get("commands") or []
    req_dl = [i - 1 for i, c in enumerate(cmds) if c.startswith("oem download-file ") and i > 0 and cmds[i - 1].startswith("download:")]
    export_idx = sorted({i for i, c in enumerate(cmds) if _is_export_cmd(c)} | set(req_dl))
    core = [c for i, c in enumerate(cmds) if i not in export_idx]
    sig = [c for c in core if not c.startswith("getvar:") or c == "getvar:public-key"]
    ij = m3["image_json"]
    expect = (["getvar:public-key", "oem fwcrypto init", "getvar:public-key"] if secure else ["getvar:public-key"])
    expect += ["erase:mmcblk0", f"download:{ij['size']:08x}", "oem idpinit", "oem idpwrite"]
    order: list[tuple[str, str, dict]] = []
    for b in blocks:
        dev, simage = b.split(":", 1)
        expect.append("oem idpgetblk")
        for p in parts[simage]:
            expect += [f"download:{p['size']:08x}", f"flash:{dev}"]
            order.append((dev, simage, p))
    expect += ["oem idpgetblk"] + (["oem cryptcheck mmcblk0p2"] if secure else []) + ["oem idpdone", "shutdown"]
    C.check("stage 3: command order (key export aside)", sig == expect, "\n      got:  " + " | ".join(sig) + "\n      want: " + " | ".join(expect))
    first_state = next((i for i, c in enumerate(cmds) if not c.startswith("getvar:")), -1)
    C.check("stage 3: identify (getvar serialno/product/...) before any state-changing command",
            first_state > 0 and "getvar:serialno" in cmds[:first_state] and "getvar:product" in cmds[:first_state],
            " | ".join(cmds[:max(first_state, 0) + 1]))
    i_fw = cmds.index("oem fwcrypto init") if "oem fwcrypto init" in cmds else -1
    i_erase = cmds.index("erase:mmcblk0") if "erase:mmcblk0" in cmds else -1
    if secure:
        kx = KEY_EXPORT
        C.eq("stage 3: the first state-touching command fetches key.der", cmds[first_state] if first_state >= 0 else None, f"oem upload-file {kx['key']}")
        C.check("stage 3: blank OTP slot → the page asked the gadget to generate the key (oem download-file request)",
                f"oem download-file {kx['request']}" in cmds and fb.get("keyRequests") == 1 and fb.get("keyGenerated") is True,
                f"requests {fb.get('keyRequests')}, generated {fb.get('keyGenerated')}")
        C.eq("stage 3: the request file was 'export\\n' (7 bytes), written once", fb.get("fileWrites"), [{"path": kx["request"], "size": 7}])
        last_export = export_idx[-1] if export_idx else -1
        C.check("stage 3: the key export finished BEFORE oem fwcrypto init and BEFORE erase", 0 <= last_export < i_fw < i_erase,
                f"last export command {last_export}, fwcrypto {i_fw}, erase {i_erase}")
        C.eq("stage 3: the export ends with the upload of key.der", cmds[last_export - 1:last_export + 1] if last_export > 0 else [],
             [f"oem upload-file {kx['key']}", "upload"])
        ups = [u for u in fb.get("uploads") or [] if u["path"] == kx["key"]]
        C.check("stage 3: key.der uploaded once, every read asking for exactly the bytes still due",
                len(ups) == 1 and ups[0]["asked"] == [ups[0]["size"] - sum(ups[0]["sent"][:k]) for k in range(len(ups[0]["sent"]))],
                json.dumps(ups))
        C.eq("stage 3: the helper's status after the export", fb.get("keyStatus"), "exported key.der")
    else:
        C.eq("stage 3: no key export and no oem fwcrypto init", [c for c in cmds if _is_export_cmd(c) or c == "oem fwcrypto init"], [])
        C.eq("stage 3: the OTP key slot stays empty", (fb.get("keyProvisioned"), fb.get("keyRequests"), fb.get("devicePem")), (False, 0, None))
    dls = fb.get("downloads") or []
    n_req = len(req_dl)
    C.check("stage 3: the only downloads before image.json are key-export requests (7 bytes)", all(d["size"] == 7 for d in dls[:n_req]),
            json.dumps([d["size"] for d in dls[:n_req]]))
    img_dls = dls[n_req:]
    C.check("stage 3: first image download is image.json (size+sha256)", bool(img_dls) and (img_dls[0]["size"], img_dls[0]["sha256"]) == (ij["size"], ij["sha256"]),
            f"{img_dls[0] if img_dls else None} vs {(ij['size'], ij['sha256'])}")
    pieces_got = [(d["size"], d["sha256"]) for d in img_dls[1:]]
    pieces_want = [(p["size"], p["sha256"]) for _, _, p in order]
    C.check(f"stage 3: {len(pieces_want)} pieces downloaded in order, size+sha256 = manifest", pieces_got == pieces_want,
            f"got {[(s, h[:12]) for s, h in pieces_got]}, want {[(s, h[:12]) for s, h in pieces_want]}")
    C.eq("stage 3: flash targets in order", [f["dev"] for f in fb.get("flashes") or []], [d for d, _, _ in order])
    bad = [(i, d["chunks"]) for i, d in enumerate(dls) if any(c % 65536 for c in d["chunks"][:-1])]
    C.check("stage 3: every data-phase transfer except the last is a multiple of 65536", not bad and bool(dls),
            f"{len(dls)} downloads, chunk sizes {sorted({c for d in dls for c in d['chunks'][:-1]})}; bad {bad[:3]}")
    C.check("stage 3: max-download-size respected", all(d["size"] <= 0x10000000 for d in dls), str(max((d["size"] for d in dls), default=0)))
    for dev, simage, p in order:
        c = served(st, 3, p["name"]) or {}
        n, h = sha256_url(base + p["url"])
        C.check(f"stage 3: server piece {p['name']} = manifest (size+sha256), streamed to the page and re-downloaded",
                (c.get("size"), c.get("sha256")) == (n, h) == (p["size"], p["sha256"]))
    n, h = sha256_url(base + ij["url"])
    C.check("stage 3: server image.json = manifest", (n, h) == (ij["size"], ij["sha256"]))
    if secure:
        bij = imagejson.load(work_dir() / "modules" / serial / "luks" / next(
            d.name for d in (work_dir() / "modules" / serial / "luks").iterdir() if (d / "image.json").is_file()) / "image.json")
        C.check("stage 3: image.json is the board's: no encrypted block, the root as root.luks.sparse",
                not imagejson.is_encrypted(bij) and imagejson.simages(bij) == list(parts), json.dumps(imagejson.simages(bij)))
        C.eq("stage 3: the board's own key opens keyslot 0 of its encrypted root (oem cryptcheck)", fb.get("cryptChecks"),
             [{"dev": "mmcblk0p2", "keyslot": 0}])
        plain = {p["sha256"] for ps in (setman.get("simages") or {}).values() for p in ps}
        C.check("stage 3: no piece of the plain crypt set went to the page", not plain & {p["sha256"] for _, _, p in order})
    else:
        C.check(f"stage 3: image.json is the {variant} set's", (ij["size"], ij["sha256"]) == (setman["image_json"]["size"], setman["image_json"]["sha256"]))
    C.eq("stage 3: erased", fb.get("erased"), ["mmcblk0"])
    C.eq("stage 3: the board was powered off at the end (shutdown), not rebooted", fb.get("poweredOff"), True)

    # ---------------- secrets: what the server stored, what must never leak
    rec = json.loads((srv.registry / f"{serial}.json").read_text(encoding="utf-8"))
    passphrase = ""
    C.check("stage 3: nothing reached the gadget that sets a passphrase or opens/mounts a container",
            not any(c.startswith(("oem cryptsetpassword", "oem cryptopen", "oem mount")) for c in cmds))
    if with_pass:
        passphrase = hmac.new(bytes.fromhex(rec["device_secret"]), f"osroot_crypt:{serial}".encode(), hashlib.sha256).hexdigest()
    secrets = {"device_secret": rec.get("device_secret") or ""}
    if passphrase:
        secrets["recovery passphrase"] = passphrase
    if fb.get("deviceKeyDerB64"):
        secrets["exported device key (DER, base64)"] = fb["deviceKeyDerB64"]
    priv_lines = [ln for ln in (rec.get("device_private_pem") or "").splitlines() if ln and not ln.startswith("-----")]
    if priv_lines:
        secrets["stored device key (PEM line)"] = max(priv_lines, key=len)
    texts = {"page log": rep.get("pageLog") or "", "page text": (rep.get("jobLog") or "") + (rep.get("bodyText") or ""),
             "server log": srv.logfile.read_text(encoding="utf-8", errors="replace")}
    for jl in (work_dir() / "jobs").glob("*.log"):
        if jl.stat().st_mtime >= t_start - 5:
            texts[f"job log {jl.name}"] = jl.read_text(encoding="utf-8", errors="replace")
    leaks = [f"{what} in {where}" for what, s in secrets.items() if s for where, t in texts.items() if s in t]
    C.check(f"secrets ({', '.join(secrets)}) never appear in the page log, page text, server log or job logs",
            all(secrets.values()) and not leaks, ", ".join(leaks))
    C.check("verbose page log was checked (debug lines present)", "DEBUG" in (rep.get("pageLog") or ""))

    # every board gets its own boot partition (its first-boot files; re-signed on a secure board)
    C.eq("stage 3: mode", m3["mode"], "signed" if secure else "unsigned")
    boot = blocks[0].split(":", 1)[1] if blocks else next(iter(parts))
    set_boot = [p["sha256"] for p in setman["simages"][boot]]
    C.check(f"stage 3: boot slot {boot} is the board's own (sha256 differs from the image set)",
            [p["sha256"] for p in parts[boot]] != set_boot and all(p["sha256"] not in set_boot for p in parts[boot]),
            f"served {[p['sha256'][:12] for p in parts[boot]]}, set {[h[:12] for h in set_boot]}")
    others = [s for s in parts if s != boot]
    if secure:
        luks_files = {sha256_file(f) for f in (work_dir() / "modules" / serial / "luks").glob("*/root.luks.sparse*")
                      if not f.name.endswith(".sha256")}
        C.check("stage 3: root pieces are the board's container in <work>/modules/<serial>/luks/<fp>/",
                others == ["root.luks.sparse"] and all(p["sha256"] in luks_files for s in others for p in parts[s]))
    else:
        C.check("stage 3: root pieces are the image set's",
                all([p["sha256"] for p in parts[s]] == [p["sha256"] for p in setman["simages"][s]] for s in others))
    per_board = []
    for p in parts[boot]:
        hits = list((work_dir() / "modules" / serial / "stage3").glob(f"*/{p['name']}"))
        per_board.append(any(sha256_file(h) == p["sha256"] for h in hits))
    C.check("stage 3: the boot pieces are the files in <work>/modules/<serial>/stage3/<fp>/", per_board and all(per_board), str(per_board))
    first_boot = m3.get("firstboot") or {}
    C.check("stage 3: the manifest names the board's first boot (host name with the serial, cloud-init files)",
            serial in first_boot.get("hostname", "") and first_boot.get("files") == ["meta-data", "user-data"],
            json.dumps(first_boot))

    # ---------------- final record + page
    code, mod = get_json(f"{base}/api/modules/{serial}")
    C.eq("GET /api/modules/<serial>: HTTP", code, 200)
    if code != 200:
        return
    C.eq("final module: stage", mod["stage"], "flashed")
    C.eq("final module: scenario (mode, mode_chosen, mode_locked)", (mod.get("mode"), mod.get("mode_chosen"), mod.get("mode_locked")), (mode, mode, secure))
    C.eq("registry: mode", rec.get("mode"), mode)
    C.eq("final module: mac", mod.get("mac"), MAC)
    C.eq("final module: duid (16-hex fastboot serial)", mod.get("duid"), "10000000" + serial)
    otp = mod.get("otp") or {}
    kinds = [(e["kind"], e["note"]) for e in mod.get("events") or []]
    if secure:
        dev_pem = fb.get("devicePem") or ""
        fp = public_key_fingerprint(dev_pem) if dev_pem else ""
        C.check("final module: device key stored, fingerprint = SPKI sha256 of the mock gadget's key",
                bool(fp) and otp.get("device_key") is True and otp.get("device_key_fingerprint") == fp,
                f"{otp.get('device_key')} {otp.get('device_key_fingerprint')} vs {fp}")
        C.eq("final module: otp.device_key_exported", otp.get("device_key_exported"), True)
        C.check("registry: device_private_pem is the key the gadget generated (same public key)",
                bool(dev_pem) and "PRIVATE KEY" in (rec.get("device_private_pem") or "") and same_public_key(rec["device_private_pem"], dev_pem))
        C.check("registry: device_key_pem = getvar:public-key", bool(dev_pem) and same_public_key(rec.get("device_key_pem") or "", dev_pem))
        C.check("final module: device_key_export event", any(k == "device_key_export" and fp[:16] in note for k, note in kinds), json.dumps(kinds))
        C.check("final module: OTP locked to our key, secure boot provisioned",
                otp.get("locked") and otp.get("locked_to_our_key") and otp.get("secure_boot_provisioned"), json.dumps(otp))
        C.eq("registry: otp_key_hash == customer_key_hash", rec.get("otp_key_hash"), rec.get("customer_key_hash"), show=False)
    else:
        C.check("final module: no device key (open: the OTP key slot is never touched)",
                otp.get("device_key") is False and otp.get("device_key_exported") is False and not rec.get("device_private_pem")
                and not rec.get("device_key_pem"), json.dumps(otp))
        C.check("final module: OTP not locked", not otp.get("locked") and not otp.get("secure_boot_provisioned"), json.dumps(otp))
    for k in ("stage1", "stage2", "stage3"):
        C.check(f"final module: event {k} ok", (k, "ok") in kinds, json.dumps(kinds))
    C.check(f"final module: mode event 'scenario {mode}'", any(k == "mode" and note.startswith(f"scenario {mode}") for k, note in kinds), json.dumps(kinds))
    C.check("final module: no secrets in the public view", "PRIVATE" not in json.dumps(mod) and rec["device_secret"] not in json.dumps(mod))
    stages = rep.get("stages") or {}
    C.check("page shows all three steps done", all("state-done" in (stages.get(str(n)) or {}).get("uiClass", "") for n in (1, 2, 3)),
            json.dumps({n: (stages.get(str(n)) or {}).get("uiClass") for n in (1, 2, 3)}))
    for n in (1, 2, 3):
        s = stages.get(str(n)) or {}
        print(f"      step {n}: {s.get('uiIcon')} {s.get('uiState')} · {s.get('uiDetail')}")
    C.check("confirmation dialog: Proceed disabled until the serial is typed",
            bool(rep.get("dialogs")) and all(d["okDisabledBeforeTyping"] and not d["okDisabledAfterTyping"] and d["token"] == serial for d in rep["dialogs"]),
            json.dumps(rep.get("dialogs")))
    keys = sorted(f.split(" — ")[0] for f in flags)
    want_flags = sorted((["stage 1: program_pubkey=1", "stage 3: oem fwcrypto init"] if secure else []) + ["stage 3: erase=mmcblk0"])
    C.eq("confirmation dialogs list exactly the irreversible steps of the scenario", keys, want_flags)
    per_dialog = [sorted(f.split(" — ")[0] for f in d["flags"]) for d in rep.get("dialogs") or []]
    if secure:
        # stages 2 and 3 of a secure board are refused until stage 1 burnt the key hash, so the stage-3 steps
        # are confirmed once its manifest is available (after stage 1), not up front
        C.eq("two confirmations: program_pubkey up front, fwcrypto init + erase after stage 1", per_dialog,
             [["stage 1: program_pubkey=1"], ["stage 3: erase=mmcblk0", "stage 3: oem fwcrypto init"]])
    else:
        C.eq("one confirmation per run (the erase)", per_dialog, [["stage 3: erase=mmcblk0"]])
    if secure:
        log_text = rep.get("pageLog") or ""
        C.check("page log: the OTP key generation was announced and the key stored on the server",
                "OTP key slot is empty: the gadget generates the device key" in log_text and "OTP device key stored on the server" in log_text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=["A", "B", "both"], default="both")
    ap.add_argument("--recovery-passphrase", action="store_true",
                    help="scenario B with provisioning.recovery_passphrase on (keyslot 1 + passphrase checks)")
    ap.add_argument("--scratch", help="directory for temp registries and logs (default: a new temp dir)")
    ap.add_argument("--keep", action="store_true", help="keep the scratch dir and the per-board artifact dirs")
    ap.add_argument("--chrome")
    ap.add_argument("--timeout", type=float, default=1800.0, help="seconds per scenario run in the page")
    ap.add_argument("--wait-builds", type=float, default=40.0, help="minutes to wait for tools/gadget/image")
    ap.add_argument("--image-name", help="image.name of the test server (default: the name of the station's current "
                                         "image sets, so the e2e uses them instead of asking for a rebuild)")
    args = ap.parse_args(argv)
    if args.image_name is None:
        try:
            args.image_name = (current_set("crypt")[1].get("image_settings") or {}).get("name") or ""
        except (OSError, ValueError, KeyError):
            args.image_name = ""
    chrome = find_chrome(args.chrome)
    made = not args.scratch
    scratch = pathlib.Path(args.scratch or tempfile.mkdtemp(prefix="otp-e2e-")).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    work = work_dir()
    shared: dict = {}
    results = []
    names = ["A", "B"] if args.scenario == "both" else [args.scenario]
    try:
        for n in names:
            log(f"=== scenario {n} ({SCENARIOS[n]['serial']}, {SCENARIOS[n]['mode']}) ===")
            results.append(run_scenario(n, args, scratch, chrome, shared))
    finally:
        if not args.keep:
            for n in names:
                d = work / "modules" / SCENARIOS[n]["serial"]
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
            for n in names:
                shutil.rmtree(scratch / f"scenario-{n}", ignore_errors=True)
            if made:
                shutil.rmtree(scratch, ignore_errors=True)
    total_f = sum(c.failed for c in results)
    total_p = sum(c.passed for c in results)
    print(f"-- {total_p} passed, {total_f} failed ({', '.join(f'{c.title}: {c.passed}/{c.passed + c.failed}' for c in results)})")
    return 0 if total_f == 0 and len(results) == len(names) else 1


if __name__ == "__main__":
    sys.exit(main())
