"""HTTP API tests (SPEC section 8) with fastapi's TestClient and httpx.ASGITransport.

The module registry is real (ModuleService on the in-memory store of ``tests/memstore.py``); Docker,
the artifacts facade and the Google account are fakes, except in the integration tests, which use the
real ``Artifacts`` with a fake Docker runner, or the real ``GoogleAccount`` without network access.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from memstore import MemoryStore

from otp_server import __version__
from otp_server.app import create_app
from otp_server.artifacts.common import NotReady
from otp_server.artifacts.image import KEY_EXPORT
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.secrets_gen import public_key_fingerprint
from otp_server.storage.base import StoreError

SERIAL = "a7eb274c"
#: The page is served on loopback; any other Host is refused (DNS rebinding guard).
BASE = "http://127.0.0.1:8765"
MODULE_KEYS = {"serial", "stage", "stage_label", "mode", "mode_chosen", "mode_locked", "created", "updated", "chip",
               "board", "duid", "mac", "factory_uuid", "boardrev", "secrets", "otp", "metadata", "facts", "events"}
OTP_KEYS = {"customer_key_hash", "locked", "locked_to_our_key", "secure_boot_provisioned", "lock_suspected",
            "lock_note", "device_key", "device_key_fingerprint", "device_key_exported"}
JOB_KEYS = {"id", "target", "title", "status", "started", "finished", "rc", "error", "lines"}
STATUS_KEYS = {"version", "google", "google_ready", "settings", "config", "storage", "docker", "usb_driver",
               "artifacts", "jobs"}
SIGN_IN_FIRST = "sign in to Google first"


def _p256(fmt: str = "sec1"):
    """A throw-away P-256 key standing in for the board's OTP device key: ``(exported bytes, public PEM,
    private PEM)``. ``fmt``: ``sec1`` / ``pkcs8`` DER (what rpi-fw-crypto writes) or ``raw`` (32-byte d)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    if fmt == "raw":
        exported = key.private_numbers().private_value.to_bytes(32, "big")
    else:
        pf = serialization.PrivateFormat.TraditionalOpenSSL if fmt == "sec1" else serialization.PrivateFormat.PKCS8
        exported = key.private_bytes(serialization.Encoding.DER, pf, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()
    return exported, pub, priv


PUBLIC_PEM = _p256()[1]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _wait_for(cond, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return bool(cond())


def _google_error(location: str) -> str:
    """The ``google_error`` text of a ``/?google_error=...`` redirect."""
    parts = urlsplit(location)
    assert parts.path == "/", location
    return parse_qs(parts.query)["google_error"][0]


# ----------------------------------------------------------------------------------------------------
# fakes
# ----------------------------------------------------------------------------------------------------


class FakeDocker:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.release = threading.Event()
        self.release.set()
        self.labels: dict[str, dict] = {}
        self.calls: list[str] = []

    def status(self, max_age: float = 5.0) -> dict:
        if not self.ok:
            return {"ok": False, "version": "", "detail": "Cannot connect to the Docker daemon", "arm64": None}
        return {"ok": True, "version": "29.6.0", "detail": "", "arm64": True}

    def ensure_daemon(self, log=None, timeout: float = 180.0) -> None:
        self.calls.append("ensure_daemon")

    def ensure_arm64(self, log=None) -> None:
        self.calls.append("ensure_arm64")

    def image_exists(self, tag: str) -> bool:
        return tag in self.labels

    def image_label(self, tag: str, label: str):
        return self.labels[tag].get(label, "") if tag in self.labels else None

    def image_info(self, tag: str):
        return {"id": "sha256:1", "created": "2026-09-30T10:00:00Z", "size": 1} if tag in self.labels else None

    def build_image(self, tag, dockerfile, context, *, platform=None, pull=False, labels=None, build_args=None,
                    log=None) -> None:
        self.calls.append(f"build_image {tag}")
        if log:
            log(f"building {tag}")
        self.release.wait(10)
        self.labels[tag] = dict(labels or {})

    def volume_exists(self, name: str) -> bool:
        return True

    def run(self, *a, **kw) -> int:
        raise AssertionError("no container runs expected in API tests")


class FakeArtifacts:
    """Minimal Artifacts facade: stages 1 and 3 with real files on disk, configurable NotReady. Like the
    real facade it plans stage 3 in the board's scenario (``ModuleService.mode_of``)."""

    TITLES = {"tools": "Build otp-tools image", "gadget": "Build fastboot gadget",
              "image": "Build OS images (clear + crypt)"}

    def __init__(self, root: Path, jobs: JobManager, modules: ModuleService):
        self.jobs = jobs
        self.modules = modules
        self.root = root
        self.not_ready: dict[int, NotReady] = {}
        self.fail: dict[int, Exception] = {}
        self.auto_calls = 0
        self.job_fn = lambda job: job.log("hello from the build")
        self.files = {}
        for stage, names in ((1, ["bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "config.txt"]),
                             (3, ["image.json", "root.ext4.sparse.0"])):
            d = root / f"stage{stage}"
            d.mkdir(parents=True, exist_ok=True)
            for name in names:
                p = d / name
                p.write_bytes(f"{stage}:{name}".encode() * 10)
                self.files[(stage, name)] = p
        # A file that exists next to the stage files but is NOT in any manifest.
        (root / "stage1" / "secret.pem").write_text("not for download")

    def _status(self, t: str) -> dict:
        job = self.jobs.current(t)
        st = {"target": t, "ready": t == "tools", "source": "built" if t == "tools" else None, "version": "v",
              "path": "", "size": None, "built": None, "detail": "", "job": job.to_dict() if job else None}
        if t == "image":
            st["variants"] = {v: {"ready": False, "set": "", "version": "", "path": "", "size": None, "built": None,
                                  "detail": f"the {v} image is not built yet"} for v in ("clear", "crypt")}
        return st

    def status(self) -> dict:
        return {t: self._status(t) for t in ("tools", "gadget", "image")}

    def start_build(self, target: str, force: bool = False):
        if target not in self.TITLES:
            raise ValueError(f"unknown build target {target!r}")
        fn = self.job_fn
        return self.jobs.submit(target, self.TITLES[target] + (" (forced)" if force else ""), fn)

    def auto_build(self) -> list:
        self.auto_calls += 1
        return []

    def _names(self, stage: int) -> list[str]:
        return [n for (s, n) in self.files if s == stage]

    def stage_manifest(self, serial: str, stage: int, base_url: str = "") -> dict:
        rec = self.modules.require(serial)
        if stage in self.fail:
            raise self.fail[stage]
        if stage in self.not_ready:
            raise self.not_ready[stage]
        if stage == 2:
            raise NotReady("no fastboot gadget yet", None)
        s = rec["serial"]
        files = []
        for n in self._names(stage):
            data = self.files[(stage, n)].read_bytes()
            files.append({"name": n, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                          "url": f"{base_url}/api/modules/{s}/stage/{stage}/files/{n}"})
        man = {"stage": stage, "kind": "rpiboot" if stage < 3 else "fastboot-idp", "ready": True, "mode": "unsigned",
               "files": files}
        if stage == 3:
            secure = self.modules.mode_of(rec) == "secure"
            man.update(scenario="secure" if secure else "open", fwcrypto_init=secure,
                       image={"variant": "crypt" if secure else "clear"},
                       key_export=dict(KEY_EXPORT) if secure else None)
        return man

    def stage_file(self, serial: str, stage: int, name: str) -> Path:
        self.stage_manifest(serial, stage)
        p = self.files.get((stage, name))
        if p is None:
            raise FileNotFoundError(f"{name} is not part of stage {stage}")
        return p


class BrokenStore:
    backend = "gsheets"

    def get(self, serial):
        raise StoreError("spreadsheet is not shared with the service account")

    def put(self, record):
        raise StoreError("spreadsheet is not shared with the service account")

    def list(self):
        raise StoreError("spreadsheet is not shared with the service account")

    def describe(self):
        return {"backend": "gsheets", "ok": False, "location": "sheet", "detail": "not shared"}


class FakeAccount:
    """Stands in for :class:`otp_server.google_account.GoogleAccount` (no OAuth, no network)."""

    LOGIN_URL = "https://accounts.google.com/o/oauth2/auth?client_id=station&state=s1"

    def __init__(self, *, signed_in: bool = False, client: bool = True,
                 sheet_error: str = "not signed in to Google: open the page and sign in"):
        self.signed_in = signed_in
        self.client = client
        self.sheet_error = sheet_error
        self.client_file = Path("repo") / "google-oauth-client.json"
        self.last_error = ""
        self.begin_calls: list[str] = []
        self.begin_error: Exception | None = None
        self.finish_calls: list[tuple[str, str]] = []
        self.finish_error: str | None = None
        self.logout_calls = 0

    def client_configured(self) -> bool:
        return self.client

    def has_token(self) -> bool:
        return self.signed_in

    def status(self) -> dict:
        return {"client": self.client, "client_file": str(self.client_file), "signed_in": self.signed_in,
                "spreadsheet_id": "", "spreadsheet_url": "", "error": self.last_error}

    def spreadsheet(self):
        raise StoreError(self.sheet_error)

    def spreadsheet_url(self) -> str:
        return ""

    def explain(self, exc: BaseException) -> str:
        self.last_error = str(exc)
        return self.last_error

    def begin_login(self, redirect_uri: str) -> str:
        self.begin_calls.append(redirect_uri)
        if self.begin_error is not None:
            raise self.begin_error
        return self.LOGIN_URL

    def finish_login(self, state: str, code: str) -> None:
        self.finish_calls.append((state, code))
        if self.finish_error:
            raise StoreError(self.finish_error)
        self.signed_in = True

    def logout(self) -> None:
        self.logout_calls += 1
        self.signed_in = False


class FakeSettings:
    """The ``settings`` worksheet: ``read()`` returns ``{key: cell text}`` or raises ``StoreError``."""

    def __init__(self, rows: dict | None = None, error: str | None = None):
        self.rows = dict(rows or {})
        self.error = error
        self.error_type = StoreError
        self.reads = 0
        self.writes: list[dict] = []
        self.write_error: str | None = None

    def read(self) -> dict:
        self.reads += 1
        if self.error:
            raise self.error_type(self.error)
        return dict(self.rows)

    def write(self, updates: dict) -> dict:
        from otp_server.settings import encode_value

        if self.write_error:
            raise StoreError(self.write_error)
        written = {k: encode_value(v) for k, v in updates.items()}
        self.writes.append(written)
        self.rows.update(written)
        return written


# ----------------------------------------------------------------------------------------------------
# fixtures
# ----------------------------------------------------------------------------------------------------


class Env:
    pass


@pytest.fixture
def env(make_cfg, tmp_path):
    """No Google account wired (an injected store): nothing is gated."""
    cfg = make_cfg(tmp_path)
    store = MemoryStore()
    modules = ModuleService(cfg, store)
    jobs = JobManager(cfg.work_dir)
    arts = FakeArtifacts(tmp_path / "fake-artifacts", jobs, modules)
    docker = FakeDocker()
    app = create_app(cfg, store=store, docker=docker, jobs=jobs, modules=modules, artifacts=arts, auto_build=False)
    e = Env()
    e.cfg, e.store, e.modules, e.jobs, e.artifacts, e.docker, e.app = cfg, store, modules, jobs, arts, docker, app
    e.svc = app.state.services
    e.client = TestClient(app, base_url=BASE)
    return e


@pytest.fixture
def genv(make_cfg, tmp_path):
    """A Google account (fake, not signed in) and a fake settings sheet that is re-read on every request."""
    cfg = make_cfg(tmp_path)
    store = MemoryStore()
    modules = ModuleService(cfg, store)
    jobs = JobManager(cfg.work_dir)
    arts = FakeArtifacts(tmp_path / "fake-artifacts", jobs, modules)
    account = FakeAccount()
    app = create_app(cfg, store=store, docker=FakeDocker(), jobs=jobs, modules=modules, artifacts=arts,
                     account=account, auto_build=False)
    e = Env()
    e.cfg, e.store, e.modules, e.jobs, e.artifacts, e.account, e.app = cfg, store, modules, jobs, arts, account, app
    e.svc = app.state.services
    e.sheet = e.svc.settings = FakeSettings()
    e.svc.SETTINGS_TTL = 0
    e.client = TestClient(app, base_url=BASE)
    return e


def hello(client, serial=SERIAL, **extra):
    body = {"serial": serial, "chip": "BCM2712", "board": "Pi 5 / CM5 / Pi 500",
            "usb": {"vendor_id": 0x0A5C, "product_id": 0x2712, "product_name": "BCM2712 Boot",
                    "manufacturer": "Broadcom", "serial_number": serial}, "rom_stage": "rom"}
    body.update(extra)
    return client.post("/api/modules/hello", json=body)


def wait_job(job, timeout=10.0):
    assert job.wait(timeout), f"job {job.id} did not finish"


# ----------------------------------------------------------------------------------------------------
# status
# ----------------------------------------------------------------------------------------------------


def test_status_shape(env, monkeypatch):
    import otp_server.winusb as winusb

    monkeypatch.setattr(winusb, "check_usb_driver", lambda *a, **k: {"platform": "windows", "rpiboot": True,
                                                                      "fastboot": False, "detail": "x"})
    r = env.client.get("/api/status")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    s = r.json()
    assert set(s) == STATUS_KEYS
    assert s["version"] == __version__
    # no Google account wired (injected store): nothing to sign in to, nothing gated
    assert s["google"] is None and s["google_ready"] is True
    assert s["settings"] == {"ok": True, "error": "", "unknown": [], "worksheet": "settings"}
    conf = s["config"]
    assert "storage" not in conf and "config_path" not in conf
    assert isinstance(conf["settings"], str) and "settings" in conf["settings"]
    assert conf["server"]["browser"] is None
    prov = conf["provisioning"]
    assert prov["confirm_irreversible"] is True and prov["recovery_passphrase"] is False
    assert prov["default_mode"] == "open" and prov["modes"] == ["open", "secure"]
    assert "secure_boot" not in prov and "mode" not in prov
    assert "source" not in conf["builds"]["gadget"] and conf["builds"]["image"]["overrides"] == []
    assert s["storage"] == {"backend": "memory", "ok": True, "location": "memory", "detail": "0 module record(s)"}
    assert s["docker"] == {"ok": True, "version": "29.6.0", "detail": "", "arm64": True}
    assert s["usb_driver"] == {"platform": "windows", "rpiboot": True, "fastboot": False, "detail": "x"}
    assert set(s["artifacts"]) == {"tools", "gadget", "image"}
    assert set(s["artifacts"]["image"]["variants"]) == {"clear", "crypt"}
    assert s["jobs"] == []
    assert "PRIVATE KEY" not in r.text


def test_status_never_contains_secrets(env):
    hello(env.client)
    der, pub, priv = _p256()
    assert env.client.post(f"/api/modules/{SERIAL}/device-key",
                           json={"key_der_b64": _b64(der), "device_key_pem": pub}).status_code == 200
    text = env.client.get("/api/status").text
    assert "PRIVATE KEY" not in text and _b64(der) not in text
    assert env.store.get(SERIAL)["rsa_private_pem"].split("\n")[1] not in text


def test_status_usb_driver_null_off_windows(env, monkeypatch):
    import otp_server.winusb as winusb

    monkeypatch.setattr(winusb.sys, "platform", "linux")
    assert env.client.get("/api/status").json()["usb_driver"] is None


def test_status_jobs_running_or_last_per_target(env):
    gate = threading.Event()
    env.artifacts.job_fn = lambda job: gate.wait(10)
    first = env.client.post("/api/builds/gadget", json={}).json()["job"]
    gate.set()
    wait_job(env.jobs.get(first["id"]))
    gate2 = threading.Event()
    env.artifacts.job_fn = lambda job: gate2.wait(10)
    second = env.client.post("/api/builds/gadget", json={"force": True}).json()["job"]
    env.artifacts.job_fn = lambda job: None
    img = env.client.post("/api/builds/image").json()["job"]
    wait_job(env.jobs.get(img["id"]))
    jobs = env.client.get("/api/status").json()["jobs"]
    by_target = {j["target"]: j for j in jobs}
    assert set(by_target) == {"gadget", "image"}
    assert by_target["gadget"]["id"] == second["id"] and by_target["gadget"]["status"] in ("queued", "running")
    assert by_target["image"]["status"] == "succeeded"
    gate2.set()
    wait_job(env.jobs.get(second["id"]))


def test_status_docker_down_and_google_unreachable(make_cfg, tmp_path):
    """The real Google wiring (GoogleSheetsStore + settings sheet) over an account whose spreadsheet cannot
    be opened: /api/status still answers; the gate stays closed while the settings cannot be read, and
    once they can, an unreachable registry worksheet is a 503."""
    cfg = make_cfg(tmp_path)
    account = FakeAccount(signed_in=True,
                          sheet_error="Google unreachable (ConnectionError: refused); check the network -- retrying")
    app = create_app(cfg, docker=FakeDocker(ok=False), jobs=JobManager(cfg.work_dir), account=account,
                     auto_build=False)
    svc = app.state.services
    assert svc.account is account and svc.store.backend == "gsheets" and svc.settings is not None
    c = TestClient(app, base_url=BASE)
    r = c.get("/api/status")
    assert r.status_code == 200
    s = r.json()
    assert s["docker"]["ok"] is False and "Docker daemon" in s["docker"]["detail"]
    assert s["storage"]["ok"] is False and s["storage"]["backend"] == "gsheets"
    assert "Google unreachable" in s["storage"]["detail"]
    assert s["google_ready"] is False and s["google"]["signed_in"] is True
    assert s["settings"]["ok"] is False and "Google unreachable" in s["settings"]["error"]
    endpoints = (("GET", "/api/modules", None), ("POST", "/api/modules/hello", {"serial": SERIAL}),
                 ("GET", f"/api/modules/{SERIAL}", None),
                 ("POST", "/api/fastboot/identify", {"serialno": "100000005e21c09a"}))
    for method, url, body in endpoints:
        r = c.request(method, url, json=body)
        assert r.status_code == 401, (url, r.text)
        assert "Google unreachable" in r.json()["detail"]
    # the settings sheet becomes readable, the registry worksheet still is not: the store problem is a 503
    svc.settings = FakeSettings({})
    assert svc.refresh_settings(force=True) is True
    for method, url, body in endpoints:
        r = c.request(method, url, json=body)
        assert r.status_code == 503, (url, r.text)
        assert "store" in r.json()["detail"] and "Google unreachable" in r.json()["detail"]


def test_store_error_at_runtime_is_503(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = BrokenStore()
    app = create_app(cfg, store=store, modules=ModuleService(cfg, store), docker=FakeDocker(),
                     jobs=JobManager(cfg.work_dir), artifacts=None, auto_build=False)
    c = TestClient(app, base_url=BASE)
    assert c.get("/api/modules").status_code == 503
    r = hello(c)
    assert r.status_code == 503 and "not shared" in r.json()["detail"]
    assert c.get("/api/status").json()["storage"]["ok"] is False


# ----------------------------------------------------------------------------------------------------
# modules
# ----------------------------------------------------------------------------------------------------


def test_hello_new_then_existing(env):
    r = hello(env.client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"module", "created"} and body["created"] is True
    m = body["module"]
    assert set(m) == MODULE_KEYS
    assert m["serial"] == SERIAL and m["stage"] == "new" and m["stage_label"] == "New"
    assert m["mode"] == "open" and m["mode_chosen"] == "" and m["mode_locked"] is False
    assert m["chip"] == "BCM2712" and m["board"] == "Pi 5 / CM5 / Pi 500"
    assert m["secrets"]["rsa_key"] is True and m["secrets"]["device_secret"] is True
    assert len(m["secrets"]["customer_key_hash"]) == 64
    assert set(m["otp"]) == OTP_KEYS
    assert m["otp"]["device_key_exported"] is False
    assert "PRIVATE" not in r.text and "device_secret\":\"" not in r.text
    hash1 = m["secrets"]["customer_key_hash"]

    r2 = hello(env.client, serial=SERIAL.upper())
    assert r2.status_code == 200 and r2.json()["created"] is False
    assert r2.json()["module"]["secrets"]["customer_key_hash"] == hash1
    # the secrets are really stored (server side only)
    assert "BEGIN PRIVATE KEY" in env.store.get(SERIAL)["rsa_private_pem"]


def test_hello_default_mode_comes_from_config(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, provisioning={"default_mode": "secure"})
    store = MemoryStore()
    c = TestClient(create_app(cfg, store=store, docker=FakeDocker(), jobs=JobManager(cfg.work_dir),
                              artifacts=None, auto_build=False), base_url=BASE)
    m = hello(c).json()["module"]
    assert m["mode"] == "secure" and m["mode_chosen"] == "" and m["mode_locked"] is False


@pytest.mark.parametrize("serial", ["Broadcom", "", "xyz12345", "a7eb27", 12345678, None])
def test_hello_bad_serial_400(env, serial):
    r = env.client.post("/api/modules/hello", json={"serial": serial})
    assert r.status_code == 400, r.text
    assert "usable USB serial" in r.json()["detail"]


def test_hello_bad_body_400(env):
    assert env.client.post("/api/modules/hello", json=[1, 2]).status_code == 400
    r = env.client.post("/api/modules/hello", content=b"{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)


def test_module_get_list_and_404(env):
    hello(env.client, serial="0c4f88d1")
    time.sleep(1.1)  # 'updated' has one-second resolution
    hello(env.client, serial=SERIAL)
    r = env.client.get("/api/modules")
    assert r.status_code == 200
    serials = [m["serial"] for m in r.json()]
    assert serials == [SERIAL, "0c4f88d1"]  # newest updated first
    assert all(set(m) == MODULE_KEYS for m in r.json())
    assert env.client.get(f"/api/modules/{SERIAL}").json()["serial"] == SERIAL
    assert env.client.get("/api/modules/10000000A7EB274C").json()["serial"] == SERIAL  # 16-hex form
    assert env.client.get("/api/modules/deadbeef").status_code == 404
    assert env.client.get("/api/modules/not-a-serial").status_code == 404


def test_facts(env):
    hello(env.client)
    r = env.client.post(f"/api/modules/{SERIAL}/facts",
                        json={"device_key_pem": PUBLIC_PEM, "duid": "10000000A7EB274C",
                              "fastboot_vars": {"product": "rpi5", "evil": "x"}, "event": {"kind": "note", "note": "hi"},
                              "unknown": 1})
    assert r.status_code == 200, r.text
    m = r.json()["module"]
    assert set(r.json()) == {"module"}
    assert m["duid"] == "10000000a7eb274c"
    assert m["otp"]["device_key"] is True and m["otp"]["device_key_exported"] is False
    assert m["facts"]["fastboot"] == {"product": "rpi5"}
    assert any(e["kind"] == "note" and e["note"] == "hi" for e in m["events"])
    assert env.client.post(f"/api/modules/{SERIAL}/facts", json={"device_key_pem": "nope"}).status_code == 400
    assert env.client.post(f"/api/modules/{SERIAL}/facts", json={"duid": "zz"}).status_code == 400
    assert env.client.post("/api/modules/deadbeef/facts", json={}).status_code == 404


def test_fastboot_identify(env):
    r = env.client.post("/api/fastboot/identify",
                        json={"serialno": "10000000a7eb274c\x00", "vars": {"product": "rpi5", "secure": "no",
                                                                            "bogus": "1"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] is True
    m = body["module"]
    assert m["serial"] == SERIAL and m["duid"] == "10000000a7eb274c" and m["stage"] == "gadget"
    assert m["facts"]["fastboot"] == {"product": "rpi5", "secure": "no"}
    r2 = env.client.post("/api/fastboot/identify", json={"serialno": "10000000a7eb274c"})
    assert r2.status_code == 200 and r2.json()["created"] is False
    assert env.client.post("/api/fastboot/identify", json={"serialno": "Broadcom"}).status_code == 400
    assert env.client.post("/api/fastboot/identify", json={}).status_code == 400
    assert env.client.post("/api/fastboot/identify", json={"serialno": "10000000a7eb274c", "vars": [1]}).status_code == 400


def test_stage_results(env):
    hello(env.client)
    md = {"EEPROM_UPDATE": "success", "MAC_ADDR": "2C:CF:67:70:76:F3", "USER_BOARDREV": "B04170",
          "CUSTOMER_KEY_HASH": "0" * 64, "SECURE_BOOT_PROVISION": "skipped"}
    body = {"ok": True, "metadata": md, "files_served": [{"name": "bootcode5.bin", "size": 10}], "interrupted": False,
            "error": None, "expect": {"secure_boot_provision": False, "customer_key_hash": None}}
    r = env.client.post(f"/api/modules/{SERIAL}/stage/1/result", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert set(out) == {"module", "verdict"}
    assert out["verdict"]["ok"] is True and isinstance(out["verdict"]["notes"], list)
    assert out["module"]["stage"] == "eeprom" and out["module"]["mac"] == "2c:cf:67:70:76:f3"

    r = env.client.post(f"/api/modules/{SERIAL}/stage/2/result",
                        json={"ok": True, "files_served": [{"name": "bootfiles.bin", "size": 1}]})
    assert r.json()["verdict"]["ok"] is False and r.json()["module"]["stage"] == "eeprom"
    r = env.client.post(f"/api/modules/{SERIAL}/stage/2/result",
                        json={"ok": True, "files_served": [{"name": "boot.img", "size": 1}]})
    assert r.json()["verdict"]["ok"] is True and r.json()["module"]["stage"] == "gadget"
    r = env.client.post(f"/api/modules/{SERIAL}/stage/3/result",
                        json={"ok": True, "error": None,
                              "details": {"flashed": ["root.ext4.sparse"], "crypt": [{"dev": "mmcblk0p2", "passphrase": "x" * 64}],
                                          "device_key_pem": PUBLIC_PEM}})
    assert r.status_code == 200
    m = r.json()["module"]
    # open scenario (the default): no exported device key needed
    assert m["mode"] == "open" and m["stage"] == "flashed" and m["otp"]["device_key"] is True
    assert "x" * 64 not in r.text  # passphrases are never echoed back or stored
    assert [e["kind"] for e in m["events"]][-3:] == ["stage2", "stage2", "stage3"]

    assert env.client.post(f"/api/modules/{SERIAL}/stage/4/result", json={"ok": True}).status_code == 404
    assert env.client.post("/api/modules/deadbeef/stage/1/result", json={"ok": True}).status_code == 404
    assert env.client.post(f"/api/modules/{SERIAL}/stage/1/result", json="x").status_code == 400


# ----------------------------------------------------------------------------------------------------
# per-board scenario (POST /api/modules/{serial}/mode)
# ----------------------------------------------------------------------------------------------------


def test_mode_choose_and_switch(env):
    hello(env.client)
    r = env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "secure"})
    assert r.status_code == 200, r.text
    assert set(r.json()) == {"module"}
    m = r.json()["module"]
    assert set(m) == MODULE_KEYS
    assert m["mode"] == "secure" and m["mode_chosen"] == "secure" and m["mode_locked"] is False
    assert m["events"][-1]["kind"] == "mode" and "secure" in m["events"][-1]["note"]
    assert env.store.get(SERIAL)["mode"] == "secure"
    n_events = len(m["events"])
    # choosing the same scenario again changes nothing
    m = env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "SECURE"}).json()["module"]
    assert m["mode"] == "secure" and len(m["events"]) == n_events
    # a board that went through a stage in one scenario starts over when switched to the other
    env.client.post(f"/api/modules/{SERIAL}/stage/2/result", json={"ok": True, "files_served": [{"name": "boot.img"}]})
    assert env.client.get(f"/api/modules/{SERIAL}").json()["stage"] == "gadget"
    r = env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "open"})
    assert r.status_code == 200, r.text
    m = r.json()["module"]
    assert m["mode"] == "open" and m["mode_chosen"] == "open" and m["stage"] == "new"
    assert m["events"][-1]["kind"] == "mode" and "reset to new" in m["events"][-1]["note"]


def test_mode_errors(env):
    hello(env.client)
    for body in ({"mode": "bogus"}, {"mode": ""}, {}, {"mode": 1}):
        r = env.client.post(f"/api/modules/{SERIAL}/mode", json=body)
        assert r.status_code == 400, (body, r.text)
        assert "mode must be one of open, secure" in r.json()["detail"]
    assert env.client.post(f"/api/modules/{SERIAL}/mode", json=["secure"]).status_code == 400
    r = env.client.post("/api/modules/deadbeef/mode", json={"mode": "secure"})
    assert r.status_code == 404 and "unknown module" in r.json()["detail"]
    assert env.client.post("/api/modules/Broadcom/mode", json={"mode": "secure"}).status_code == 404
    assert env.client.get(f"/api/modules/{SERIAL}").json()["mode_chosen"] == ""


def test_mode_open_refused_on_a_locked_board(env):
    hello(env.client)
    r = env.client.post(f"/api/modules/{SERIAL}/otp", json={"action": "mark-locked"})
    assert r.status_code == 200
    m = r.json()["module"]
    # the OTP holds a key hash: secure is the only scenario, whatever was chosen
    assert m["mode"] == "secure" and m["mode_locked"] is True and m["mode_chosen"] == ""
    r = env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "open"})
    assert r.status_code == 400 and "only the secure scenario is possible" in r.json()["detail"]
    assert env.store.get(SERIAL)["mode"] == ""
    r = env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "secure"})
    assert r.status_code == 200 and r.json()["module"]["mode_chosen"] == "secure"


def test_stage3_manifest_follows_the_board_scenario(env):
    hello(env.client)
    m = env.client.get(f"/api/modules/{SERIAL}/stage/3").json()
    assert m["scenario"] == "open" and m["key_export"] is None and m["fwcrypto_init"] is False
    assert m["image"]["variant"] == "clear"
    env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "secure"})
    m = env.client.get(f"/api/modules/{SERIAL}/stage/3").json()
    assert m["scenario"] == "secure" and m["fwcrypto_init"] is True and m["image"]["variant"] == "crypt"
    assert m["key_export"] == KEY_EXPORT and set(m["key_export"]) == {"dir", "key", "status", "request"}


# ----------------------------------------------------------------------------------------------------
# OTP device key export (POST /api/modules/{serial}/device-key)
# ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["sec1", "pkcs8", "raw"])
def test_device_key_export_ok(env, fmt):
    hello(env.client)
    der, pub, priv = _p256(fmt)
    r = env.client.post(f"/api/modules/{SERIAL}/device-key", json={"key_der_b64": _b64(der), "device_key_pem": pub})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"module", "device_key"}
    fp = public_key_fingerprint(pub)
    assert body["device_key"] == {"fingerprint": fp, "already": False, "zero_words": 0}
    m = body["module"]
    assert set(m) == MODULE_KEYS
    assert m["otp"]["device_key_exported"] is True and m["otp"]["device_key"] is True
    assert m["otp"]["device_key_fingerprint"] == fp
    assert m["events"][-1]["kind"] == "device_key_export" and fp[:16] in m["events"][-1]["note"]
    # the private key never comes back out, in any representation
    for text in (r.text, env.client.get(f"/api/modules/{SERIAL}").text, env.client.get("/api/modules").text):
        assert "PRIVATE" not in text and "device_private_pem" not in text
        assert _b64(der) not in text and priv.split("\n")[1] not in text
    # ... but it is kept server side (PKCS#8), next to the public key
    rec = env.store.get(SERIAL)
    assert rec["device_private_pem"] == priv and rec["device_key_pem"] == pub
    # a second export of the same key changes nothing
    puts = env.store.puts
    r = env.client.post(f"/api/modules/{SERIAL}/device-key", json={"key_der_b64": _b64(der), "device_key_pem": pub})
    assert r.status_code == 200 and r.json()["device_key"]["already"] is True
    assert env.store.puts == puts


def test_device_key_export_errors(env):
    hello(env.client)
    der, pub, _ = _p256()
    _der2, pub2, _ = _p256()
    url = f"/api/modules/{SERIAL}/device-key"
    cases = [
        ({"key_der_b64": "not base64!", "device_key_pem": pub}, "not valid base64"),
        ({"key_der_b64": "QQ", "device_key_pem": pub}, "not valid base64"),                    # padding missing
        ({"key_der_b64": "", "device_key_pem": pub}, "non-empty base64"),
        ({"device_key_pem": pub}, "non-empty base64"),
        ({"key_der_b64": 1234, "device_key_pem": pub}, "non-empty base64"),
        ({"key_der_b64": _b64(der)}, "device_key_pem"),                                      # pem missing
        ({"key_der_b64": _b64(der), "device_key_pem": "nope"}, "device_key_pem"),
        ({"key_der_b64": _b64(der), "device_key_pem": pub2}, "does not match"),               # someone else's key
        ({"key_der_b64": _b64(b"\x30\x03\x02\x01\x01"), "device_key_pem": pub}, "not a DER private key"),
        ({"key_der_b64": _b64(b"\x00" * 32), "device_key_pem": pub}, "not a valid P-256"),
        ({"key_der_b64": _b64(b"\x01" * 2048), "device_key_pem": pub}, "1..1024 bytes"),
    ]
    for body, why in cases:
        r = env.client.post(url, json=body)
        assert r.status_code == 400, (body, r.text)
        assert why in r.json()["detail"], (body, r.json())
        assert "PRIVATE" not in r.text
    assert env.client.post(url, json=[1]).status_code == 400
    rec = env.store.get(SERIAL)
    assert rec["device_private_pem"] == "" and rec["device_key_pem"] == ""
    r = env.client.post("/api/modules/deadbeef/device-key", json={"key_der_b64": _b64(der), "device_key_pem": pub})
    assert r.status_code == 404 and "unknown module" in r.json()["detail"]


def test_device_key_export_must_match_the_recorded_key(env):
    """An OTP key cannot change: a key that differs from the one the board reported or exported is refused."""
    hello(env.client)
    der, pub, _ = _p256()
    der2, pub2, _ = _p256()
    # the board reported its public key earlier (facts): another key does not match it
    assert env.client.post(f"/api/modules/{SERIAL}/facts", json={"device_key_pem": pub}).status_code == 200
    r = env.client.post(f"/api/modules/{SERIAL}/device-key", json={"key_der_b64": _b64(der2), "device_key_pem": pub2})
    assert r.status_code == 400 and "differs from the one recorded" in r.json()["detail"]
    assert env.client.post(f"/api/modules/{SERIAL}/device-key",
                           json={"key_der_b64": _b64(der), "device_key_pem": pub}).status_code == 200
    # once exported, the board cannot report another public key
    r = env.client.post(f"/api/modules/{SERIAL}/facts", json={"device_key_pem": pub2})
    assert r.status_code == 400 and "differs from the exported one" in r.json()["detail"]
    assert env.store.get(SERIAL)["device_key_pem"] == pub


def test_secure_stage3_needs_the_exported_device_key(env):
    hello(env.client)
    env.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "secure"})
    der, pub, _ = _p256()
    _der2, pub2, _ = _p256()
    url = f"/api/modules/{SERIAL}/stage/3/result"
    r = env.client.post(url, json={"ok": True, "details": {"flashed": ["root"], "device_key_pem": pub}})
    out = r.json()
    assert out["verdict"]["ok"] is False and out["module"]["stage"] == "new"
    assert any("device key was not exported" in n for n in out["verdict"]["notes"])
    assert env.client.post(f"/api/modules/{SERIAL}/device-key",
                           json={"key_der_b64": _b64(der), "device_key_pem": pub}).status_code == 200
    # a board reporting another device key than the exported one is not flashed
    out = env.client.post(url, json={"ok": True, "details": {"flashed": ["root"], "device_key_pem": pub2}}).json()
    assert out["verdict"]["ok"] is False and out["module"]["stage"] == "new"
    assert any("differs from the exported one" in n for n in out["verdict"]["notes"])
    out = env.client.post(url, json={"ok": True, "details": {"flashed": ["root"], "device_key_pem": pub,
                                                               "verified": [{"dev": "mmcblk0p2", "keyslot": 0}]}}).json()
    assert out["verdict"]["ok"] is True and out["module"]["stage"] == "flashed"
    assert out["module"]["otp"]["device_key_exported"] is True


# ----------------------------------------------------------------------------------------------------
# stage manifests and files
# ----------------------------------------------------------------------------------------------------


def test_stage_manifest_ok(env):
    hello(env.client)
    r = env.client.get(f"/api/modules/{SERIAL}/stage/1")
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    m = r.json()
    assert m["stage"] == 1 and m["ready"] is True
    names = [f["name"] for f in m["files"]]
    assert names == ["bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "config.txt"]
    assert m["files"][0]["url"] == f"/api/modules/{SERIAL}/stage/1/files/bootcode5.bin"


def test_stage_manifest_not_ready_409(env):
    hello(env.client)
    job = env.jobs.submit("image", "Build OS images (clear + crypt)", lambda j: j.log("x"))
    wait_job(job)
    env.artifacts.not_ready[3] = NotReady("the OS image for the open scenario (clear) is not built yet", job)
    r = env.client.get(f"/api/modules/{SERIAL}/stage/3")
    assert r.status_code == 409
    body = r.json()
    assert body["ready"] is False and body["reason"] == "the OS image for the open scenario (clear) is not built yet"
    assert set(body["job"]) == JOB_KEYS and body["job"]["id"] == job.id
    r2 = env.client.get(f"/api/modules/{SERIAL}/stage/2")  # NotReady without a job
    assert r2.status_code == 409 and r2.json() == {"ready": False, "reason": "no fastboot gadget yet", "job": None}
    # files of a stage that is not ready are not served either
    assert env.client.get(f"/api/modules/{SERIAL}/stage/3/files/image.json").status_code == 409


def test_stage_manifest_errors(env):
    assert env.client.get("/api/modules/deadbeef/stage/1").status_code == 404
    hello(env.client)
    assert env.client.get(f"/api/modules/{SERIAL}/stage/0").status_code == 404
    assert env.client.get(f"/api/modules/{SERIAL}/stage/4").status_code == 404
    assert env.client.get(f"/api/modules/{SERIAL}/stage/x").status_code == 400
    env.artifacts.fail[1] = RuntimeError("docker exploded")
    r = env.client.get(f"/api/modules/{SERIAL}/stage/1")
    assert r.status_code == 500 and "docker exploded" in r.json()["detail"]
    env.artifacts.fail[1] = StoreError("quota")
    assert env.client.get(f"/api/modules/{SERIAL}/stage/1").status_code == 503


def test_stage_file_download(env):
    hello(env.client)
    r = env.client.get(f"/api/modules/{SERIAL}/stage/1/files/pieeprom.bin")
    assert r.status_code == 200
    assert r.content == env.artifacts.files[(1, "pieeprom.bin")].read_bytes()
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["cache-control"] == "no-store"
    assert int(r.headers["content-length"]) == len(r.content)
    r = env.client.get(f"/api/modules/{SERIAL}/stage/3/files/root.ext4.sparse.0")
    assert r.status_code == 200


@pytest.mark.parametrize("name", [
    "secret.pem",                                  # exists on disk but not in the manifest
    "nope.bin",
    "..%2fstage1%2fsecret.pem",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/config.py",
    "%2e%2e%2f%2e%2e%2fsecret.pem",
    "..%5c..%5csecret.pem",
    "sub/pieeprom.bin",
    ".hidden",
    "C:%5cWindows%5cwin.ini",
    "pieeprom.bin::$DATA",
])
def test_stage_file_rejects_unknown_and_traversal(env, name):
    hello(env.client)
    r = env.client.get(f"/api/modules/{SERIAL}/stage/1/files/{name}")
    assert r.status_code == 404, (name, r.status_code)
    assert b"not for download" not in r.content


def test_stage_file_raw_dot_dot_paths(env):
    """Raw ../ segments (client-normalised or not) never reach a file outside the manifest."""
    hello(env.client)

    async def go():
        transport = httpx.ASGITransport(app=env.app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
            out = []
            for url in (f"/api/modules/{SERIAL}/stage/1/files/../../../../../index.html",
                        f"/api/modules/{SERIAL}/stage/1/files/../files/secret.pem",
                        f"/api/modules/{SERIAL}/stage/1/files/%2e%2e/secret.pem",
                        f"/api/modules/{SERIAL}/stage/1/files/%2E%2E%2Fsecret.pem"):
                r = await c.get(url)
                out.append((url, r.status_code, r.content))
            return out

    for url, code, content in asyncio.run(go()):
        assert code == 404 or (code == 200 and b"<html" in content.lower()), (url, code)
        assert b"not for download" not in content


def test_stage_file_unknown_module(env):
    assert env.client.get("/api/modules/deadbeef/stage/1/files/pieeprom.bin").status_code == 404


# ----------------------------------------------------------------------------------------------------
# builds and jobs
# ----------------------------------------------------------------------------------------------------


def test_builds_and_jobs(env):
    r = env.client.get("/api/builds")
    assert r.status_code == 200 and set(r.json()) == {"tools", "gadget", "image"}
    assert env.client.post("/api/builds/nope", json={}).status_code == 400
    assert env.client.post("/api/builds/gadget", json={"force": "yes"}).status_code == 400
    r = env.client.post("/api/builds/gadget", json={"force": True})
    assert r.status_code == 200, r.text
    job = r.json()["job"]
    assert set(job) == JOB_KEYS and job["target"] == "gadget" and job["title"].endswith("(forced)")
    wait_job(env.jobs.get(job["id"]))
    r = env.client.post("/api/builds/tools")  # no body at all
    assert r.status_code == 200
    wait_job(env.jobs.get(r.json()["job"]["id"]))

    jobs = env.client.get("/api/jobs").json()
    assert [j["target"] for j in jobs] == ["tools", "gadget"]  # newest first
    j = env.client.get(f"/api/jobs/{job['id']}").json()
    assert j["status"] == "succeeded" and j["rc"] == 0 and j["lines"] >= 2
    assert env.client.get("/api/jobs/ffffffff").status_code == 404
    assert env.client.get("/api/jobs/ffffffff/log").status_code == 404


def test_build_dedupe_returns_running_job(env):
    gate = threading.Event()
    env.artifacts.job_fn = lambda job: gate.wait(10)
    a = env.client.post("/api/builds/image").json()["job"]
    b = env.client.post("/api/builds/image").json()["job"]
    assert a["id"] == b["id"]
    gate.set()
    wait_job(env.jobs.get(a["id"]))


def _parse_sse(text: str) -> list[tuple[str, str]]:
    events = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        if block.startswith(":"):
            events.append(("comment", block[1:].strip()))
            continue
        ev, data = "message", []
        for line in block.split("\n"):
            if line.startswith("event:"):
                ev = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
        events.append((ev, "\n".join(data)))
    return events


def test_job_log_sse_replay_and_done(env):
    def fn(job):
        for i in range(3):
            job.log(f"line {i}")
        job.log("secret-free line with \"quotes\"")

    env.artifacts.job_fn = fn
    job = env.client.post("/api/builds/gadget").json()["job"]
    wait_job(env.jobs.get(job["id"]))
    with env.client.stream("GET", f"/api/jobs/{job['id']}/log") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        text = "".join(r.iter_text())
    events = _parse_sse(text)
    lines = [json.loads(d)["line"] for ev, d in events if ev == "message"]
    assert lines[0].startswith("==> Build fastboot gadget")
    assert lines[1:5] == ["line 0", "line 1", "line 2", 'secret-free line with "quotes"']
    assert events[-1][0] == "done"
    assert json.loads(events[-1][1]) == {"status": "succeeded", "rc": 0}


def test_job_log_sse_follows_live_job(env):
    gate = threading.Event()

    def fn(job):
        job.log("before")
        gate.wait(10)
        job.log("after")
        raise RuntimeError("boom")

    env.artifacts.job_fn = fn
    job = env.client.post("/api/builds/image").json()["job"]

    async def go():
        transport = httpx.ASGITransport(app=env.app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE, timeout=20) as c:
            chunks = []
            async with c.stream("GET", f"/api/jobs/{job['id']}/log") as r:
                assert r.status_code == 200
                async for chunk in r.aiter_text():
                    chunks.append(chunk)
                    if "before" in "".join(chunks) and not gate.is_set():
                        gate.set()
            return "".join(chunks)

    text = asyncio.run(go())
    events = _parse_sse(text)
    lines = [json.loads(d)["line"] for ev, d in events if ev == "message"]
    assert "before" in lines and "after" in lines
    assert lines.index("before") < lines.index("after")
    assert any(ln.startswith("ERROR: boom") for ln in lines)
    assert events[-1][0] == "done" and json.loads(events[-1][1]) == {"status": "failed", "rc": 1}


# ----------------------------------------------------------------------------------------------------
# static page
# ----------------------------------------------------------------------------------------------------


def test_static_routes(env):
    root = env.cfg.web_dir
    r = env.client.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert r.headers["cache-control"] == "no-store"
    assert r.content == (root / "index.html").read_bytes()
    r = env.client.get("/js/app.js")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/javascript")
    assert r.content == (root / "js" / "app.js").read_bytes()
    r = env.client.get("/css/app.css")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css")
    # without a Google account there is no OAuth callback: the query is ignored
    r = env.client.get("/?state=s1&code=c1", follow_redirects=False)
    assert r.status_code == 200 and r.content == (root / "index.html").read_bytes()


@pytest.mark.parametrize("url", [
    "/README.md", "/server.py", "/otp_server/config.py", "/external/usbboot/README.md", "/js/", "/css",
    "/js/nope.js", "/js/%2e%2e/server.py", "/js/..%2fserver.py", "/js/..%5cserver.py", "/css/%2e%2e/README.md",
    "/js/C:%5cWindows%5cwin.ini", "/js/app.js::$DATA", "/tests/web/selftest.js", "/index.html/%2e%2e/server.py",
])
def test_static_nothing_else(env, url):
    r = env.client.get(url)
    assert r.status_code == 404, (url, r.status_code)


# ----------------------------------------------------------------------------------------------------
# auto build
# ----------------------------------------------------------------------------------------------------


def test_auto_build_runs_in_background(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = MemoryStore()
    modules = ModuleService(cfg, store)
    jobs = JobManager(cfg.work_dir)
    arts = FakeArtifacts(tmp_path / "fa", jobs, modules)
    app = create_app(cfg, store=store, modules=modules, docker=FakeDocker(), jobs=jobs, artifacts=arts,
                     auto_build=True)
    with TestClient(app, base_url=BASE) as c:
        assert c.get("/api/status").status_code == 200
        app.state.startup_thread.join(5)
        assert _wait_for(lambda: arts.auto_calls == 1)
        app.state.services.start_auto_build()  # once per process
    time.sleep(0.1)
    assert arts.auto_calls == 1
    # auto_build=None and cfg.builds.auto False (test default): nothing happens
    arts2 = FakeArtifacts(tmp_path / "fb", jobs, modules)
    app2 = create_app(cfg, store=store, modules=modules, docker=FakeDocker(), jobs=jobs, artifacts=arts2)
    with TestClient(app2, base_url=BASE):
        app2.state.startup_thread.join(5)
    assert arts2.auto_calls == 0 and app2.state.services.auto_build_done is False


def test_auto_build_failure_does_not_crash(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = MemoryStore()
    modules = ModuleService(cfg, store)

    class Exploding(FakeArtifacts):
        def auto_build(self):
            raise RuntimeError("docker not found")

    arts = Exploding(tmp_path / "fa", JobManager(cfg.work_dir), modules)
    app = create_app(cfg, store=store, modules=modules, docker=FakeDocker(ok=False), jobs=arts.jobs,
                     artifacts=arts, auto_build=True)
    with TestClient(app, base_url=BASE) as c:
        app.state.startup_thread.join(5)
        assert _wait_for(lambda: app.state.services.auto_build_error == "docker not found")
        assert c.get("/api/status").status_code == 200
    assert app.state.services.auto_build_error == "docker not found"


def test_auto_build_waits_for_the_google_login(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = MemoryStore()
    modules = ModuleService(cfg, store)
    jobs = JobManager(cfg.work_dir)
    arts = FakeArtifacts(tmp_path / "fa", jobs, modules)
    account = FakeAccount()
    app = create_app(cfg, store=store, modules=modules, docker=FakeDocker(), jobs=jobs, artifacts=arts,
                     account=account, auto_build=True)
    app.state.services.settings = FakeSettings({"builds.auto": "false"})  # auto_build=True wins over the sheet
    with TestClient(app, base_url=BASE) as c:
        app.state.startup_thread.join(5)
        assert arts.auto_calls == 0  # not signed in: nothing is built
        r = c.get("/?state=s1&code=c1", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/"
        assert _wait_for(lambda: arts.auto_calls == 1)
        assert c.get("/?state=s2&code=c2", follow_redirects=False).status_code == 303  # a second login
    time.sleep(0.1)
    assert arts.auto_calls == 1


# ----------------------------------------------------------------------------------------------------
# Google sign-in and the settings sheet
# ----------------------------------------------------------------------------------------------------


def _gated_requests():
    der, pub, _ = _p256()
    return [
        ("GET", "/api/modules", None),
        ("POST", "/api/modules/hello", {"serial": SERIAL}),
        ("GET", f"/api/modules/{SERIAL}", None),
        ("GET", f"/api/modules/{SERIAL}/stage/1", None),
        ("GET", f"/api/modules/{SERIAL}/stage/3", None),
        ("GET", f"/api/modules/{SERIAL}/stage/1/files/pieeprom.bin", None),
        ("POST", f"/api/modules/{SERIAL}/stage/1/result", {"ok": True}),
        ("POST", f"/api/modules/{SERIAL}/facts", {"duid": "10000000a7eb274c"}),
        ("POST", f"/api/modules/{SERIAL}/mode", {"mode": "secure"}),
        ("POST", f"/api/modules/{SERIAL}/device-key", {"key_der_b64": _b64(der), "device_key_pem": pub}),
        ("POST", f"/api/modules/{SERIAL}/otp", {"action": "mark-locked"}),
        ("POST", "/api/fastboot/identify", {"serialno": "10000000a7eb274c"}),
        ("POST", "/api/builds/tools", {}),
        ("POST", "/api/builds/image", {"force": True}),
    ]


def test_google_gate_closed_until_signed_in(genv):
    problem = genv.svc.google_problem()
    assert problem.startswith(SIGN_IN_FIRST)
    for method, url, body in _gated_requests():
        r = genv.client.request(method, url, json=body)
        assert r.status_code == 401, (url, r.status_code, r.text)
        assert r.json()["detail"] == problem
    assert genv.store.puts == 0 and genv.jobs.list() == []  # nothing was written or started
    # the status document still answers (the page needs it to offer the sign-in)
    r = genv.client.get("/api/status")
    assert r.status_code == 200
    s = r.json()
    assert set(s) == STATUS_KEYS
    assert s["google_ready"] is False and s["google"] == genv.account.status()
    assert s["google"]["signed_in"] is False and s["google"]["client"] is True
    assert s["settings"]["ok"] is False
    assert genv.sheet.reads == 0  # not signed in: the sheet is not even tried


def test_google_gate_without_oauth_client(genv):
    genv.account.client = False
    r = genv.client.get("/api/modules")
    assert r.status_code == 401
    assert r.json()["detail"].startswith("no Google OAuth client") and "google-oauth-client.json" in r.json()["detail"]
    assert genv.client.get("/api/status").json()["google"]["client"] is False


def test_google_gate_opens_and_applies_the_sheet_settings(genv):
    genv.account.signed_in = True
    genv.sheet.rows = {"provisioning.erase_storage": "false", "provisioning.default_mode": "secure",
                       "provisioning.bogus_switch": "1", "builds.image.overrides": "A=1\nB=2"}
    s = genv.client.get("/api/status").json()
    assert s["google_ready"] is True and s["google"]["signed_in"] is True
    assert s["settings"] == {"ok": True, "error": "", "unknown": ["provisioning.bogus_switch"], "worksheet": "settings"}
    assert s["config"]["provisioning"]["erase_storage"] is False
    assert s["config"]["provisioning"]["default_mode"] == "secure"
    assert s["config"]["builds"]["image"]["overrides"] == ["A=1", "B=2"]
    assert genv.cfg.provisioning.erase_storage is False  # applied in place: every service sees it
    assert genv.client.get("/api/modules").status_code == 200
    m = hello(genv.client).json()["module"]
    assert m["mode"] == "secure" and m["mode_chosen"] == ""  # the sheet's default scenario
    assert genv.client.post(f"/api/modules/{SERIAL}/mode", json={"mode": "open"}).status_code == 200
    r = genv.client.post("/api/builds/tools", json={})
    assert r.status_code == 200
    wait_job(genv.jobs.get(r.json()["job"]["id"]))
    assert genv.client.get(f"/api/modules/{SERIAL}/stage/1").status_code == 200


def test_settings_sheet_broken_value_keeps_the_previous_settings(genv):
    genv.account.signed_in = True
    genv.sheet.rows = {"provisioning.erase_storage": "false"}
    assert genv.client.get("/api/status").json()["config"]["provisioning"]["erase_storage"] is False
    genv.sheet.rows = {"provisioning.erase_storage": "true", "provisioning.default_mode": "maybe"}
    s = genv.client.get("/api/status").json()
    assert "invalid value in the settings sheet" in s["settings"]["error"]
    assert "provisioning.default_mode" in s["settings"]["error"]
    assert s["settings"]["ok"] is True and s["google_ready"] is True  # the last good settings stay in force
    assert s["config"]["provisioning"]["erase_storage"] is False
    assert s["config"]["provisioning"]["default_mode"] == "open"
    assert genv.client.get("/api/modules").status_code == 200
    # Google unreachable: the same
    genv.sheet.error = "Google unreachable (ConnectionError: x); check the network -- retrying"
    s = genv.client.get("/api/status").json()
    assert s["settings"]["error"].startswith("Google unreachable") and s["google_ready"] is True
    assert s["config"]["provisioning"]["erase_storage"] is False
    # fixed in the sheet: taken over, the error is gone
    genv.sheet.error = None
    genv.sheet.rows = {"provisioning.erase_storage": "true"}
    s = genv.client.get("/api/status").json()
    assert s["settings"]["error"] == "" and s["config"]["provisioning"]["erase_storage"] is True


def test_revoked_login_closes_the_gate(genv):
    from otp_server.google_account import NotSignedIn

    genv.account.signed_in = True   # the token file is still there ...
    assert genv.client.get("/api/modules").status_code == 200
    genv.sheet.error_type = NotSignedIn  # ... but Google rejects it (revoked / 7-day testing token expired)
    genv.sheet.error = "Google rejected the saved login (invalid_grant); sign in again"
    s = genv.client.get("/api/status").json()
    assert s["google_ready"] is False
    r = genv.client.get("/api/modules")
    assert r.status_code == 401 and "sign in again" in r.json()["detail"]


def test_settings_sheet_unreadable_at_first_keeps_the_gate_closed(genv):
    genv.account.signed_in = True
    genv.sheet.rows = {"provisioning.max_piece_size": "lots"}
    r = genv.client.get("/api/modules")
    assert r.status_code == 401
    assert "invalid value in the settings sheet" in r.json()["detail"]
    assert "provisioning.max_piece_size" in r.json()["detail"]
    s = genv.client.get("/api/status").json()
    assert s["google_ready"] is False and s["settings"]["ok"] is False
    genv.sheet.rows = {}
    genv.sheet.error = "worksheet 'settings': row 1 must be: key | value | description"
    r = genv.client.post("/api/builds/tools", json={})
    assert r.status_code == 401 and "row 1 must be" in r.json()["detail"]
    genv.sheet.error = None
    assert genv.client.post("/api/builds/tools", json={}).status_code == 200


@pytest.mark.parametrize("base, host, want", [
    (BASE, None, "http://127.0.0.1:8765/"),
    ("http://localhost:8765", None, "http://localhost:8765/"),
    ("http://LOCALHOST:8765", None, "http://localhost:8765/"),
    (BASE, "[::1]:8765", "http://127.0.0.1:8765/"),
    (BASE, "127.0.0.1:43117", "http://127.0.0.1:43117/"),   # the port the page was opened on
    (BASE, "127.0.0.1", "http://127.0.0.1:8799/"),          # no port in Host: the configured one
])
def test_google_login_redirects_to_google(genv, base, host, want):
    genv.cfg.server.port = 8799
    c = TestClient(genv.app, base_url=base)
    r = c.get("/api/google/login", headers={"host": host} if host else None, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert r.headers["location"] == FakeAccount.LOGIN_URL
    assert genv.account.begin_calls == [want]


def test_google_login_error_redirects_to_the_page(genv):
    genv.account.begin_error = StoreError("no OAuth client: save the client JSON as x.json")
    r = genv.client.get("/api/google/login", follow_redirects=False)
    assert r.status_code == 303
    assert _google_error(r.headers["location"]) == "no OAuth client: save the client JSON as x.json"
    genv.account.begin_error = RuntimeError("flow & broken?")
    r = genv.client.get("/api/google/login", follow_redirects=False)
    assert r.status_code == 303 and _google_error(r.headers["location"]) == "flow & broken?"


def test_google_login_without_account_is_404(env):
    assert env.client.get("/api/google/login", follow_redirects=False).status_code == 404


def test_oauth_callback(genv):
    genv.sheet.rows = {"provisioning.erase_storage": "false"}
    assert genv.client.get("/api/modules").status_code == 401
    r = genv.client.get("/?state=s1&code=4/abc", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert genv.account.finish_calls == [("s1", "4/abc")]
    # signed in: the settings were read right away and the gate is open
    assert genv.cfg.provisioning.erase_storage is False
    assert genv.client.get("/api/modules").status_code == 200
    assert genv.client.get("/api/status").json()["google_ready"] is True


def test_oauth_callback_errors(genv):
    genv.account.finish_error = "this Google login is unknown or has expired; start it again from the page"
    r = genv.client.get("/?state=old&code=c", follow_redirects=False)
    assert r.status_code == 303
    assert _google_error(r.headers["location"]) == genv.account.finish_error
    assert genv.client.get("/api/modules").status_code == 401
    # the operator declined on Google's consent screen: nothing is exchanged
    r = genv.client.get("/?state=s1&error=access_denied", follow_redirects=False)
    assert r.status_code == 303
    assert _google_error(r.headers["location"]) == "Google sign-in was not completed: access_denied"
    assert genv.account.finish_calls == [("old", "c")]


def test_index_without_oauth_query_is_the_page(genv):
    page = (genv.cfg.web_dir / "index.html").read_bytes()
    for url in ("/", "/?state=s1", "/?code=c1", "/?google_error=x"):
        r = genv.client.get(url, follow_redirects=False)
        assert r.status_code == 200 and r.content == page, url
    assert genv.account.finish_calls == []


def test_google_logout_closes_the_gate(genv):
    genv.account.signed_in = True
    assert genv.client.get("/api/modules").status_code == 200
    # a foreign page cannot sign the station out
    assert genv.client.post("/api/google/logout", headers={"origin": "http://attacker.example"}).status_code == 403
    assert genv.account.logout_calls == 0
    r = genv.client.post("/api/google/logout")
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert genv.account.logout_calls == 1
    r = genv.client.get("/api/modules")
    assert r.status_code == 401 and r.json()["detail"].startswith(SIGN_IN_FIRST)
    s = genv.client.get("/api/status").json()
    assert s["google_ready"] is False and s["google"]["signed_in"] is False
    assert s["settings"]["ok"] is False and s["settings"]["error"] == "not signed in to Google"


def test_real_google_account_wiring(make_cfg, tmp_path):
    """Without an injected store the server wires the real GoogleAccount; nothing here touches the network."""
    from otp_server.google_account import GoogleAccount

    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = make_cfg(tmp_path, repo_root=repo)
    app = create_app(cfg, docker=FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False)
    svc = app.state.services
    assert isinstance(svc.account, GoogleAccount) and svc.store.backend == "gsheets"
    c = TestClient(app, base_url=BASE)
    s = c.get("/api/status").json()
    assert s["google"]["client"] is False and s["google"]["signed_in"] is False and s["google_ready"] is False
    assert s["google"]["client_file"] == str(repo / "google-oauth-client.json")
    assert s["storage"]["ok"] is False and s["storage"]["backend"] == "gsheets"
    r = c.get("/api/modules")
    assert r.status_code == 401 and r.json()["detail"].startswith("no Google OAuth client")
    r = c.get("/api/google/login", follow_redirects=False)
    assert r.status_code == 303 and _google_error(r.headers["location"]).startswith("no OAuth client")

    pytest.importorskip("google_auth_oauthlib")
    (repo / "google-oauth-client.json").write_text(json.dumps({"installed": {
        "client_id": "station.apps.googleusercontent.com", "client_secret": "not-secret",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"]}}), encoding="utf-8")
    assert c.get("/api/modules").json()["detail"].startswith(SIGN_IN_FIRST)
    r = c.get("/api/google/login", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    q = parse_qs(urlsplit(loc).query)
    assert loc.startswith("https://accounts.google.com/o/oauth2/auth?")
    assert q["redirect_uri"] == ["http://127.0.0.1:8765/"] and q["client_id"] == ["station.apps.googleusercontent.com"]
    assert "code_challenge" in q and svc.account.pending_login(q["state"][0])


# ----------------------------------------------------------------------------------------------------
# integration with the real Artifacts facade (fake Docker)
# ----------------------------------------------------------------------------------------------------


def test_real_artifacts_stage1_waits_for_tools_image(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    docker = FakeDocker()
    docker.release.clear()  # the tools image build blocks until released
    jobs = JobManager(cfg.work_dir)
    app = create_app(cfg, store=MemoryStore(), docker=docker, jobs=jobs, auto_build=False)
    c = TestClient(app, base_url=BASE)
    assert hello(c).status_code == 200
    r = c.get(f"/api/modules/{SERIAL}/stage/1")
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["ready"] is False and "otp-tools" in body["reason"]
    assert body["job"]["target"] == "tools" and body["job"]["status"] in ("queued", "running")
    st = c.get("/api/builds").json()
    assert set(st) == {"tools", "gadget", "image"}
    for t, a in st.items():
        assert a["target"] == t
        assert set(a) >= {"target", "ready", "source", "version", "path", "size", "built", "detail", "job"}
    assert st["tools"]["ready"] is False
    # the gadget is always built here (no prebuilt source); the image has a clear and a crypt variant
    assert st["gadget"]["ready"] is False and st["gadget"]["source"] is None
    assert st["image"]["ready"] is False and set(st["image"]["variants"]) == {"clear", "crypt"}
    assert all(v["ready"] is False for v in st["image"]["variants"].values())
    docker.release.set()
    wait_job(jobs.get(body["job"]["id"]))
    assert jobs.get(body["job"]["id"]).status == "succeeded"
    assert c.get("/api/builds").json()["tools"]["ready"] is True


def test_real_artifacts_unknown_module_and_bad_target(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    app = create_app(cfg, store=MemoryStore(), docker=FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False)
    c = TestClient(app, base_url=BASE)
    assert c.get("/api/modules/deadbeef/stage/1").status_code == 404
    assert c.get("/api/modules/deadbeef/stage/1/files/pieeprom.bin").status_code == 404
    assert c.post("/api/builds/firmware", json={"force": False}).status_code == 400


# ----------------------------------------------------------------------------------------------------
# DNS rebinding / cross-site request guard
# ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["attacker.example", "attacker.example:8765", "127.0.0.1.attacker.example:8765",
                                  "evil.com:80@127.0.0.1", "192.168.1.5:8765", ""])
def test_foreign_host_is_rejected(env, host):
    hello(env.client)
    for url in ("/api/status", f"/api/modules/{SERIAL}", f"/api/modules/{SERIAL}/stage/3", "/",
                "/?state=s1&code=c1", "/api/google/login"):
        r = env.client.get(url, headers={"host": host}, follow_redirects=False)
        assert r.status_code == 403, (host, url, r.text)
        assert "not allowed" in r.json()["detail"] or "no Host" in r.json()["detail"]


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "127.0.0.1", "localhost:8765", "LOCALHOST", "localhost.:8765",
                                  "[::1]:8765", "127.0.0.1:43117"])  # another port: the e2e proxy on loopback
def test_loopback_hosts_pass(env, host):
    r = env.client.get("/api/status", headers={"host": host})
    assert r.status_code == 200, (host, r.text)


def test_cross_site_post_is_rejected(env):
    der, pub, _ = _p256()
    hello(env.client, serial="0c4f88d1")
    for headers in ({"origin": "http://attacker.example"}, {"origin": "null"},
                    {"origin": "http://127.0.0.1.attacker.example:8765"},
                    {"referer": "http://attacker.example/page.html"}):
        r = env.client.post("/api/builds/tools", headers=headers)  # no body: a "simple" cross-site request
        assert r.status_code == 403, (headers, r.text)
        assert "cross-site POST" in r.json()["detail"]
        r = env.client.post("/api/modules/hello", json={"serial": SERIAL}, headers=headers)
        assert r.status_code == 403
        r = env.client.post("/api/modules/0c4f88d1/mode", json={"mode": "secure"}, headers=headers)
        assert r.status_code == 403
        r = env.client.post("/api/modules/0c4f88d1/device-key", json={"key_der_b64": _b64(der), "device_key_pem": pub},
                            headers=headers)
        assert r.status_code == 403
    assert env.jobs.list() == []  # no build was started
    assert env.modules.get(SERIAL) is None  # nothing written to the registry
    rec = env.modules.get("0c4f88d1")
    assert rec["mode"] == "" and rec["device_private_pem"] == ""


def test_same_origin_and_originless_posts_pass(env):
    for headers in ({"origin": BASE}, {"origin": "http://localhost:8765"}, {"origin": "http://127.0.0.1:43117"},
                    {"origin": "http://[::1]:8765"}, {"referer": BASE + "/"}, {}):
        r = env.client.post("/api/modules/hello", json={"serial": SERIAL}, headers=headers)
        assert r.status_code == 200, (headers, r.text)
    # A GET is never subject to the Origin check (the page's <script> and fetch loads).
    assert env.client.get("/api/status", headers={"origin": "http://attacker.example"}).status_code == 200


def test_configured_host_is_allowed(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, server={"host": "192.168.1.5"})
    c = TestClient(create_app(cfg, store=MemoryStore(), docker=FakeDocker(), jobs=JobManager(cfg.work_dir),
                              auto_build=False), base_url=BASE)
    assert c.get("/api/status", headers={"host": "192.168.1.5:8765"}).status_code == 200
    assert c.get("/api/status", headers={"host": "10.0.0.7:8765"}).status_code == 403
    assert c.post("/api/modules/hello", json={"serial": SERIAL},
                  headers={"host": "192.168.1.5:8765", "origin": "http://192.168.1.5:8765"}).status_code == 200


def test_wildcard_listen_accepts_ip_literals_only(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, server={"host": "0.0.0.0"})
    c = TestClient(create_app(cfg, store=MemoryStore(), docker=FakeDocker(), jobs=JobManager(cfg.work_dir),
                              auto_build=False), base_url=BASE)
    assert c.get("/api/status", headers={"host": "10.0.0.7:8765"}).status_code == 200
    assert c.get("/api/status", headers={"host": "[fe80::1]:8765"}).status_code == 200
    assert c.get("/api/status", headers={"host": "rebind.attacker.example:8765"}).status_code == 403
    assert c.post("/api/builds/tools", headers={"host": "10.0.0.7:8765",
                                                "origin": "http://rebind.attacker.example"}).status_code == 403


def test_wildcard_listen_origin_must_be_same_origin(make_cfg, tmp_path):
    """With a wildcard listen an IP-literal Origin passes only when it is this server (host AND port)."""
    cfg = make_cfg(tmp_path, server={"host": "0.0.0.0"})
    c = TestClient(create_app(cfg, store=MemoryStore(), docker=FakeDocker(), jobs=JobManager(cfg.work_dir),
                              auto_build=False), base_url=BASE)
    host = {"host": "10.0.0.7:8765"}
    # a foreign site reached by IP address must not be able to POST (no-cors fetch, empty body)
    assert c.post("/api/builds/tools", headers={**host, "origin": "http://203.0.113.7"}).status_code == 403
    assert c.post("/api/builds/tools", headers={**host, "origin": "http://10.0.0.7"}).status_code == 403     # port 80
    assert c.post("/api/builds/tools", headers={**host, "origin": "http://10.0.0.7:9999"}).status_code == 403
    assert c.post("/api/builds/tools", headers={**host, "referer": "http://203.0.113.7/x"}).status_code == 403
    # the page served by this server itself, and loopback pages, still work
    assert c.post("/api/modules/hello", json={"serial": SERIAL},
                  headers={**host, "origin": "http://10.0.0.7:8765"}).status_code == 200
    assert c.post("/api/modules/hello", json={"serial": SERIAL},
                  headers={"host": "127.0.0.1:8765", "origin": "http://127.0.0.1:8799"}).status_code == 200


@pytest.mark.parametrize("value, want", [("127.0.0.1:8765", 8765), ("[::1]:8765", 8765), ("[::1]", None),
                                         ("localhost", None), ("10.0.0.7:80", 80), ("fe80::1", None)])
def test_host_header_port(value, want):
    from otp_server.app import host_header_port

    assert host_header_port(value) == want


@pytest.mark.parametrize("value, want", [("127.0.0.1:8765", "127.0.0.1"), ("[::1]:8765", "::1"), ("[::1]", "::1"),
                                         ("LocalHost.", "localhost"), ("example.com", "example.com"),
                                         ("fe80::1", "fe80::1")])
def test_host_header_hostname(value, want):
    from otp_server.app import host_header_hostname

    assert host_header_hostname(value) == want


# ----------------------------------------------------------------------------------------------------
# OS image settings (/api/image)
# ----------------------------------------------------------------------------------------------------

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD op@station"


def test_image_settings_get_and_save_without_a_sheet(env):
    r = env.client.get("/api/image")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    view = r.json()
    assert view["settings"]["hostname"] == "pi5-{serial}" and view["settings"]["password_set"] is False
    assert view["settings"]["ssh_authorized_keys"] == [] and view["settings"]["wifi_password_set"] is False
    assert view["settings"]["sudo"] == "wizard"
    assert view["warnings"] == ["no password and no SSH key: the board's first boot stops at the Raspberry Pi OS "
                                "wizard on its console (screen and keyboard), which asks for a user name and password"]
    assert "Europe/Kyiv" in view["choices"]["timezones"] and ["UA", "Ukraine"] in view["choices"]["countries"]

    r = env.client.post("/api/image", json={
        "hostname": "Drone-7", "password": "s3cret $x", "ssh": True, "ssh_password_login": False,
        "ssh_authorized_keys": [KEY], "wifi_ssid": "Field Net", "wifi_password": " pass phrase ",
        "wifi_country": "pl", "wifi_hidden": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["saved"] == ["image.hostname", "image.password_hash", "image.ssh", "image.ssh_authorized_keys",
                             "image.ssh_password_login", "image.wifi_country", "image.wifi_hidden",
                             "image.wifi_password", "image.wifi_ssid"]
    st = body["settings"]
    assert st["hostname"] == "drone-7" and st["wifi_country"] == "PL" and st["password_set"] is True
    assert st["sudo"] == "passwd" and st["ssh_authorized_keys"] == [KEY]
    assert body["warnings"] == ["every board gets the host name 'drone-7'; put {serial} in it (e.g. pi5-{serial}) "
                                "to tell them apart on the network"]
    img = env.cfg.image
    assert img.password_hash.startswith("$6$") and img.wifi_password == " pass phrase "
    from otp_server.passhash import verify
    assert verify("s3cret $x", img.password_hash)
    for text in (r.text, env.client.get("/api/image").text, env.client.get("/api/status").text):
        assert "s3cret" not in text and "pass phrase" not in text and img.password_hash not in text

    # null = unchanged, "" = remove
    r = env.client.post("/api/image", json={"password": None, "wifi_password": None, "hostname": "drone-7"})
    assert r.json()["saved"] == ["image.hostname"] and env.cfg.image.password_hash == img.password_hash
    r = env.client.post("/api/image", json={"password": "", "wifi_password": ""})
    assert r.json()["settings"]["password_set"] is False and r.json()["settings"]["wifi_password_set"] is False
    assert env.cfg.image.password_hash == "" and env.cfg.image.wifi_password == ""
    assert env.client.post("/api/image", json={}).json()["saved"] == []


@pytest.mark.parametrize("body, needle", [
    ({"hostname": "bad_host"}, "image.hostname"),
    ({"wifi_password": "short"}, "image.wifi_password"),
    ({"ssh_authorized_keys": ["not a key"]}, "image.ssh_authorized_keys"),
    ({"user": "root"}, "image.user"),
    ({"timezone": "Europe/Kiev"}, "image.timezone"),
    ({"wifi_country": "XX"}, "image.wifi_country"),
    ({"password": 5}, "password must be a string"),
    ({"wifi_password": ["x"]}, "wifi_password must be a string"),
    ({"password_hash": "$6$a$b"}, "unknown image setting(s): password_hash"),
    ({"nope": 1, "zzz": 2}, "unknown image setting(s): nope, zzz"),
])
def test_image_settings_validation(env, body, needle):
    before = env.cfg.image
    r = env.client.post("/api/image", json=body)
    assert r.status_code == 400 and needle in r.json()["detail"], r.text
    assert env.cfg.image == before                        # nothing applied


def test_image_settings_body_must_be_an_object(env):
    assert env.client.post("/api/image", json=[1, 2]).status_code == 400


def test_image_settings_go_to_the_sheet_and_only_a_new_name_rebuilds(genv):
    genv.account.signed_in = True
    genv.svc.auto_build = True
    assert genv.client.get("/api/image").status_code == 200
    calls = genv.artifacts.auto_calls
    r = genv.client.post("/api/image", json={"hostname": "drone8", "password": "pw", "wifi_ssid": "N",
                                             "wifi_password": "password1"})
    assert r.status_code == 200, r.text
    assert len(genv.sheet.writes) == 1
    written = genv.sheet.writes[0]
    assert set(written) == {"image.hostname", "image.password_hash", "image.wifi_ssid", "image.wifi_password"}
    assert written["image.password_hash"].startswith("$6$") and "pw" != written["image.password_hash"]
    assert written["image.wifi_password"] == "password1"           # stored as typed (it must reach the board)
    assert genv.cfg.image.hostname == "drone8"                      # read back from the sheet
    assert r.json()["settings"]["hostname"] == "drone8"
    __import__("time").sleep(0.05)
    assert genv.artifacts.auto_calls == calls                      # board settings: written at stage 3, no build
    assert genv.client.post("/api/image", json={"name": "rpios-fleet"}).status_code == 200
    deadline = __import__("time").monotonic() + 5
    while genv.artifacts.auto_calls == calls and __import__("time").monotonic() < deadline:
        __import__("time").sleep(0.01)
    assert genv.artifacts.auto_calls == calls + 1                  # a new image name: the images are rebuilt


def test_image_settings_without_auto_build_do_not_build(genv):
    genv.account.signed_in = True
    genv.svc.auto_build = False
    calls = genv.artifacts.auto_calls
    assert genv.client.post("/api/image", json={"name": "rpios-fleet"}).status_code == 200
    __import__("time").sleep(0.05)
    assert genv.artifacts.auto_calls == calls


def test_image_settings_sheet_failure_is_503(genv):
    genv.account.signed_in = True
    genv.sheet.write_error = "Google unreachable (ConnectionError)"
    r = genv.client.post("/api/image", json={"hostname": "drone9"})
    assert r.status_code == 503 and "Google unreachable" in r.json()["detail"]
    assert genv.cfg.image.hostname == "pi5-{serial}"


def test_image_settings_need_the_google_login(genv):
    for method, body in (("GET", None), ("POST", {"hostname": "x1"})):
        r = genv.client.request(method, "/api/image", json=body)
        assert r.status_code == 401
    assert genv.sheet.writes == []
