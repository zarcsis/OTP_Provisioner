#!/usr/bin/env python3
"""End-to-end test of the whole station without hardware: real server + real page + mock Raspberry Pi 5.

    python tests/web/run_e2e.py [--scenario A|B|both] [--scratch DIR] [--keep] [--chrome PATH]

For every scenario the runner
  1. starts ITS OWN server (python server.py --no-browser --no-auto-build --port <free> --config <temp yaml>);
     the temp yaml only moves the registry (storage.local.dir) into a temp dir and, for scenario B, sets
     provisioning.secure_boot: true. The work dir stays the default one, so the real tools image, gadget and
     droneos image are reused. Before the first run it waits (GET /api/builds every 20 s, up to 40 min) until
     tools, gadget and image are ready (and the builds of a live server on :8765, if any, are finished);
  2. runs a stdlib reverse proxy that serves the server's page with /__e2e__/mocks.js + /__e2e__/e2e.js injected
     before the page's own scripts, forwards everything else to the server (streaming, incl. SSE and 256 MiB
     pieces), records the stage manifests the page fetched, and takes the verdict on POST /__e2e_result;
  3. loads the page in headless Chrome; tests/web/e2e.js plugs a mock Pi 5 into navigator.usb and clicks
     through the real UI (Connect board → Provision → typed serial → Select device / Connect fastboot gadget);
  4. checks the report against the server files, the API and the temp registry, and prints PASS/FAIL lines.

Scenario A: unprovisioned board (CUSTOMER_KEY_HASH all zeros), secure_boot false → unsigned stages 1-3.
Scenario B: secure_boot true → signed stage 1 with program_pubkey=1; the board then reports our key hash, so
stages 2 and 3 are signed (boot.sig, counter-signed bootfiles.bin, per-board re-signed boot slot).
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

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from otp_server.secrets_gen import public_key_fingerprint  # noqa: E402

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium",
]
LIVE_SERVER = "http://127.0.0.1:8765"
SCENARIOS = {
    "A": {"serial": "e2e5a7c1", "secure_boot": False},
    "B": {"serial": "e2e5b7c2", "secure_boot": True},
}
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
        self.requests: list[str] = []
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
            with st.lock:
                st.requests.append(f"{self.command} {self.path}")
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
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
    def __init__(self, scratch: pathlib.Path, name: str, secure_boot: bool):
        self.dir = scratch / name
        if self.dir.exists():
            shutil.rmtree(self.dir)
        self.registry = self.dir / "registry"
        self.registry.mkdir(parents=True)
        self.cfg = self.dir / "config.yaml"
        lines = ["storage:", "  local:", f"    dir: '{self.registry.as_posix()}'"]
        if secure_boot:
            lines += ["provisioning:", "  secure_boot: true"]
        self.cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.logfile = self.dir / "server.log"
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
        env.pop("OTP_CONFIG", None)
        env.pop("OTP_STORAGE", None)
        env.pop("OTP_PORT", None)
        self._log = open(self.logfile, "wb")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.proc = subprocess.Popen([sys.executable, "-u", str(REPO / "server.py"), "--no-browser", "--no-auto-build",
                                      "--port", str(self.port), "--config", str(self.cfg)],
                                     cwd=str(REPO), env=env, stdout=self._log, stderr=subprocess.STDOUT,
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
    """Poll GET /api/builds every 20 s until tools, gadget and image are ready and no live build is running."""
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
            log(f"builds ready ({state}); gadget {b['gadget'].get('source')} {b['gadget'].get('version')}, image {b['image'].get('version')}")
            return b
        if time.time() - t0 > max_minutes * 60:
            raise SystemExit(f"builds not ready after {max_minutes} min: {state}; live jobs {live_running}")
        log(f"waiting for builds: {state}; live server jobs running: {live_running or 'none'}")
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
    C = Checks(name)
    srv = OwnServer(scratch, f"scenario-{name}", sc["secure_boot"])
    live_reg = work_dir() / "registry"
    live_before = sorted((p.name, p.stat().st_mtime_ns) for p in live_reg.glob("*.json")) if live_reg.is_dir() else []
    t_start = time.time()
    key = ec.generate_private_key(ec.SECP256R1())
    device_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    cfg = {"scenario": name, "serial": serial, "secureBoot": sc["secure_boot"], "devicePem": device_pem,
           "timeoutMs": int(args.timeout * 1000)}
    inject = (f"<script>window.__E2E = {json.dumps(cfg)};</script>\n"
              '<script src="/__e2e__/mocks.js"></script>\n<script src="/__e2e__/e2e.js"></script>')
    proxy = None
    chrome_proc = None
    profile = pathlib.Path(tempfile.mkdtemp(prefix=f"otp-e2e-{name}-", dir=str(scratch)))
    try:
        srv.start()
        log(f"scenario {name}: server {srv.base} (config {srv.cfg}, registry {srv.registry})")
        if not shared.get("builds"):
            shared["builds"] = wait_for_builds(srv.base, args.wait_builds)
        code, status = get_json(srv.base + "/api/status")
        prov = status["config"]["provisioning"]
        C.eq("server config: provisioning.secure_boot", prov["secure_boot"], sc["secure_boot"])
        C.eq("server config: registry is the temp dir", pathlib.Path(status["storage"]["location"]).resolve(), srv.registry.resolve())
        st = ProxyState(srv.port, inject, srv.registry)
        proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(st))
        proxy.daemon_threads = True
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        purl = f"http://127.0.0.1:{proxy.server_address[1]}/"
        log(f"scenario {name}: proxy {purl} → {srv.base}; Chrome headless")
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
        verify(C, name, sc, serial, srv, st, rep, device_pem, t_start, shared)
        live_after = sorted((p.name, p.stat().st_mtime_ns) for p in live_reg.glob("*.json")) if live_reg.is_dir() else []
        C.eq("live server registry untouched", live_after, live_before, show=False)
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
    for p in fb.get("passwords") or []:
        p["pass"] = "<redacted>"
    return r


def served(st: ProxyState, stage: int, name: str) -> dict | None:
    """What the server streamed to the page for a stage file during the run (the proxy's capture)."""
    d = [x for x in st.downloads if x["stage"] == stage and x["name"] == name and x["status"] == 200]
    return d[-1] if d else None


def last_page_manifest(st: ProxyState, stage: int) -> dict | None:
    ms = [m for m in st.manifests if m["stage"] == stage and not m["harness"] and m["status"] == 200]
    return ms[-1]["body"] if ms else None


def verify(C: Checks, name: str, sc: dict, serial: str, srv: OwnServer, st: ProxyState, rep: dict, device_pem: str,
           t_start: float, shared: dict) -> None:
    base = srv.base
    C.check("page ran without errors", not rep.get("errors") and not st.errors,
            "; ".join((rep.get("errors") or []) + st.errors)[:2000])
    board = rep.get("board") or {}
    C.eq("board went ROM → recovery → ROM → bootloader → fastboot", board.get("history"), ["rom", "fs", "rom", "fs", "fastboot"])
    C.eq("the page's board card shows the serial", (rep.get("boardCardSerial") or "").strip(), serial)
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
            rom1.get("sent") and (rom1.get("size"), rom1.get("sha256")) == server1["bootcode5.bin"],
            f"sent {rom1.get('size')} {str(rom1.get('sha256'))[:16]}, server {server1['bootcode5.bin'][0]} {server1['bootcode5.bin'][1][:16]}")
    C.check("stage 1: boot message length field = file size", rom1.get("header_len") == 24 and rom1.get("header_size_field") == rom1.get("size"),
            f"{rom1.get('header_len')} / {rom1.get('header_size_field')}")
    fs1 = fss[0]["files"] if fss else {}
    for n in ("config.txt", "pieeprom.sig", "pieeprom.bin"):
        got = fs1.get(n) or {}
        C.check(f"stage 1: recovery received {n} == server file", (got.get("size"), got.get("sha256")) == server1[n],
                f"got {got}, server {server1[n]}")
    cfg1 = ((cap1.get("config.txt") or {}).get("body") or b"").decode()
    C.eq("stage 1: config.txt on the server == manifest config_txt", cfg1, m1["config_txt"], show=False)
    if sc["secure_boot"]:
        C.eq("stage 1: mode", m1["mode"], "signed")
        C.check("stage 1: config.txt carries program_pubkey=1", "program_pubkey=1" in cfg1.splitlines(), repr(cfg1))
        C.check("stage 1: manifest lists program_pubkey as irreversible",
                any(i["key"] == "program_pubkey" and i["value"] == "1" for i in m1["irreversible"]), json.dumps(m1["irreversible"]))
        C.check("stage 1: expect = secure_boot_provision + our key hash",
                m1["expect"].get("secure_boot_provision") is True and m1["expect"].get("customer_key_hash") == rep.get("registryKeyHash"),
                json.dumps(m1["expect"]))
        flags = [f for d in rep.get("dialogs", []) for f in d["flags"]]
        C.check("confirmation dialog lists program_pubkey=1", any(f.startswith("stage 1: program_pubkey=1") for f in flags), json.dumps(flags))
        unsigned_pie = shared.get("A_pieeprom_sha")
        if unsigned_pie:
            C.check("stage 1: signed pieeprom.bin differs from the unsigned one", server1["pieeprom.bin"][1] != unsigned_pie)
    else:
        C.eq("stage 1: mode", m1["mode"], "unsigned")
        C.check("stage 1: config.txt has no program_pubkey", "program_pubkey" not in cfg1, repr(cfg1))
        C.eq("stage 1: nothing irreversible", m1["irreversible"], [])
        shared["A_pieeprom_sha"] = server1["pieeprom.bin"][1]

    # ---------------- stage 2
    s2 = {f["name"]: f for f in m2["files"]}
    want2 = ["boot.img", "boot.sig", "bootfiles.bin", "config.txt"] if sc["secure_boot"] else ["boot.img", "bootfiles.bin", "config.txt"]
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
    if sc["secure_boot"]:
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

    # ---------------- stage 3
    fb = board.get("fastboot") or {}
    parts = m3["parts"]
    blocks = rep.get("blocks") or []
    C.check("stage 3: manifest kind/device", m3["kind"] == "fastboot-idp" and m3["storage_device"] == "mmcblk0" and m3["fwcrypto_init"] and m3["erase"],
            f"{m3['kind']} {m3['storage_device']} fwcrypto {m3['fwcrypto_init']} erase {m3['erase']}")
    C.check("stage 3: mock block list = real simages", len(blocks) == len(parts) and blocks[0].startswith("mmcblk0p1:")
            and all(b.split(":", 1)[1] == s for b, s in zip(blocks, parts)), json.dumps(blocks))
    crypt = m3.get("crypt") or []
    C.check("stage 3: one LUKS container mmcblk0p2 / osroot_crypt", len(crypt) == 1 and crypt[0]["dev"] == "mmcblk0p2" and crypt[0]["mname"] == "osroot_crypt",
            json.dumps([{k: v for k, v in c.items() if k != "passphrase"} for c in crypt]))
    cmds = fb.get("commands") or []
    sig = [c for c in cmds if not c.startswith("getvar:") or c == "getvar:public-key"]
    expect = ["oem fwcrypto init", "getvar:public-key", "erase:mmcblk0", f"download:{m3['image_json']['size']:08x}", "oem idpinit", "oem idpwrite"]
    order: list[tuple[str, str, dict]] = []
    for b in blocks:
        dev, simage = b.split(":", 1)
        expect.append("oem idpgetblk")
        for p in parts[simage]:
            expect += [f"download:{p['size']:08x}", f"flash:{dev}"]
            order.append((dev, simage, p))
    expect += ["oem idpgetblk", f"oem cryptsetpassword {crypt[0]['dev'] if crypt else '?'} <pass>", "oem idpdone", "reboot"]
    C.check("stage 3: command order", sig == expect, "\n      got:  " + " | ".join(sig) + "\n      want: " + " | ".join(expect))
    idx_fw = cmds.index("oem fwcrypto init") if "oem fwcrypto init" in cmds else -1
    C.check("stage 3: identify (getvar serialno/product/...) before any state-changing command",
            idx_fw > 0 and "getvar:serialno" in cmds[:idx_fw] and "getvar:product" in cmds[:idx_fw]
            and all(c.startswith("getvar:") for c in cmds[:idx_fw]), " | ".join(cmds[:max(idx_fw, 0) + 1]))
    dls = fb.get("downloads") or []
    ij = m3["image_json"]
    C.check("stage 3: first download is image.json (size+sha256)", bool(dls) and (dls[0]["size"], dls[0]["sha256"]) == (ij["size"], ij["sha256"]),
            f"{dls[0] if dls else None} vs {(ij['size'], ij['sha256'])}")
    pieces_got = [(d["size"], d["sha256"]) for d in dls[1:]]
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
    C.eq("stage 3: erased", fb.get("erased"), ["mmcblk0"])

    rec = json.loads((srv.registry / f"{serial}.json").read_text(encoding="utf-8"))
    pw = fb.get("passwords") or []
    passphrase = pw[0]["pass"] if pw else ""
    expected = hmac.new(bytes.fromhex(rec["device_secret"]), f"osroot_crypt:{serial}".encode(), hashlib.sha256).hexdigest()
    C.check("stage 3: cryptsetpassword mmcblk0p2 <64 hex>", len(pw) == 1 and pw[0]["dev"] == "mmcblk0p2" and re.fullmatch(r"[0-9a-f]{64}", passphrase or "") is not None,
            f"{len(pw)} password command(s)")
    C.check("stage 3: passphrase == HMAC-SHA256(device_secret, 'osroot_crypt:<serial>') from the registry", passphrase == expected)
    C.check("stage 3: manifest passphrase == what the board received", bool(crypt) and crypt[0].get("passphrase") == passphrase)
    leaks = []
    if passphrase:
        if passphrase in (rep.get("pageLog") or ""):
            leaks.append("page log")
        if passphrase in (rep.get("jobLog") or "") or passphrase in (rep.get("bodyText") or ""):
            leaks.append("page text")
        if passphrase in srv.logfile.read_text(encoding="utf-8", errors="replace"):
            leaks.append("server log")
        work = work_dir() / "jobs"
        for jl in work.glob("*.log"):
            if jl.stat().st_mtime >= t_start - 5 and passphrase in jl.read_text(encoding="utf-8", errors="replace"):
                leaks.append(f"job log {jl.name}")
    C.check("passphrase never appears in the page log, page text, server log or job logs", bool(passphrase) and not leaks, ", ".join(leaks))
    C.check("verbose page log was checked (debug lines present)", "DEBUG" in (rep.get("pageLog") or ""))

    if sc["secure_boot"]:
        C.eq("stage 3: mode", m3["mode"], "signed")
        img_root = work_dir() / "artifacts" / "image"
        cur = json.loads((img_root / "current.json").read_text(encoding="utf-8"))["set"]
        setman = json.loads((img_root / cur / "manifest.json").read_text(encoding="utf-8"))
        boot = blocks[0].split(":", 1)[1] if blocks else next(iter(parts))
        unsigned_boot = [p["sha256"] for p in setman["simages"][boot]]
        C.check(f"stage 3: boot slot {boot} re-signed per board (sha256 differs from the image set)",
                [p["sha256"] for p in parts[boot]] != unsigned_boot and all(p["sha256"] not in unsigned_boot for p in parts[boot]),
                f"served {[p['sha256'][:12] for p in parts[boot]]}, set {[h[:12] for h in unsigned_boot]}")
        others = [s for s in parts if s != boot]
        C.check("stage 3: root pieces are the image set's (not re-signed)",
                all([p["sha256"] for p in parts[s]] == [p["sha256"] for p in setman["simages"][s]] for s in others))
        per_board = []
        for p in parts[boot]:
            hits = list((work_dir() / "modules" / serial / "stage3").glob(f"*/{p['name']}"))
            per_board.append(any(sha256_file(h) == p["sha256"] for h in hits))
        C.check("stage 3: re-signed boot pieces are the files in <work>/modules/<serial>/stage3/<fp>/", per_board and all(per_board), str(per_board))
    else:
        C.eq("stage 3: mode", m3["mode"], "unsigned")
        shared["A_stage3_boot"] = [p["sha256"] for p in next(iter(parts.values()))]

    # ---------------- final record + page
    code, mod = get_json(f"{base}/api/modules/{serial}")
    C.eq("GET /api/modules/<serial>: HTTP", code, 200)
    if code != 200:
        return
    C.eq("final module: stage", mod["stage"], "flashed")
    C.eq("final module: mac", mod.get("mac"), MAC)
    C.eq("final module: duid (16-hex fastboot serial)", mod.get("duid"), "10000000" + serial)
    fp = public_key_fingerprint(device_pem)
    otp = mod.get("otp") or {}
    C.check("final module: device key stored, fingerprint = SPKI sha256 of the board's key",
            otp.get("device_key") is True and otp.get("device_key_fingerprint") == fp,
            f"{otp.get('device_key')} {otp.get('device_key_fingerprint')} vs {fp}")
    kinds = [(e["kind"], e["note"]) for e in mod.get("events") or []]
    for k in ("stage1", "stage2", "stage3"):
        C.check(f"final module: event {k} ok", (k, "ok") in kinds, json.dumps(kinds))
    C.check("final module: no secrets in the public view", "PRIVATE" not in json.dumps(mod) and rec["device_secret"] not in json.dumps(mod))
    if sc["secure_boot"]:
        C.check("final module: OTP locked to our key, secure boot provisioned",
                otp.get("locked") and otp.get("locked_to_our_key") and otp.get("secure_boot_provisioned"), json.dumps(otp))
        C.eq("registry: otp_key_hash == customer_key_hash", rec.get("otp_key_hash"), rec.get("customer_key_hash"), show=False)
    else:
        C.check("final module: OTP not locked", not otp.get("locked") and not otp.get("secure_boot_provisioned"), json.dumps(otp))
    stages = rep.get("stages") or {}
    C.check("page shows all three steps done", all("state-done" in (stages.get(str(n)) or {}).get("uiClass", "") for n in (1, 2, 3)),
            json.dumps({n: (stages.get(str(n)) or {}).get("uiClass") for n in (1, 2, 3)}))
    for n in (1, 2, 3):
        s = stages.get(str(n)) or {}
        print(f"      step {n}: {s.get('uiIcon')} {s.get('uiState')} · {s.get('uiDetail')}")
    C.check("confirmation dialog: Proceed disabled until the serial is typed",
            bool(rep.get("dialogs")) and all(d["okDisabledBeforeTyping"] and not d["okDisabledAfterTyping"] and d["token"] == serial for d in rep["dialogs"]),
            json.dumps(rep.get("dialogs")))
    want_flags = {"stage 3: oem fwcrypto init", "stage 3: erase=mmcblk0"}
    flags = [f.split(" — ")[0] for d in rep.get("dialogs", []) for f in d["flags"]]
    C.check("confirmation dialog lists fwcrypto init and erase", want_flags <= set(flags), json.dumps(flags))
    C.check("one confirmation per run", len(rep.get("dialogs") or []) == 1, f"{len(rep.get('dialogs') or [])} dialogs")
    C.check("provisioning mode text", ("secure boot" in (rep.get("provisionMode") or "")) == sc["secure_boot"], rep.get("provisionMode"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=["A", "B", "both"], default="both")
    ap.add_argument("--scratch", help="directory for temp registries, configs and logs (default: a new temp dir)")
    ap.add_argument("--keep", action="store_true", help="keep the scratch dir and the per-board artifact dirs")
    ap.add_argument("--chrome")
    ap.add_argument("--timeout", type=float, default=1800.0, help="seconds per scenario run in the page")
    ap.add_argument("--wait-builds", type=float, default=40.0, help="minutes to wait for tools/gadget/image")
    args = ap.parse_args(argv)
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
            log(f"=== scenario {n} ({SCENARIOS[n]['serial']}, secure_boot {SCENARIOS[n]['secure_boot']}) ===")
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
