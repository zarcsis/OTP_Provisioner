"""HTTP API tests (SPEC section 8) with fastapi's TestClient and httpx.ASGITransport.

The module registry is real (ModuleService + LocalJsonStore in tmp_path); Docker and the artifacts
facade are fakes, except in the integration tests at the end, which use the real ``Artifacts`` with a
fake Docker runner.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from otp_server import __version__
from otp_server.app import create_app
from otp_server.artifacts.common import NotReady
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.storage.base import StoreError
from otp_server.storage.local import LocalJsonStore

SERIAL = "a7eb274c"
#: The page is served on loopback; any other Host is refused (DNS rebinding guard).
BASE = "http://127.0.0.1:8765"
MODULE_KEYS = {"serial", "stage", "stage_label", "created", "updated", "chip", "board", "duid", "mac", "factory_uuid",
               "boardrev", "secrets", "otp", "metadata", "facts", "events"}
JOB_KEYS = {"id", "target", "title", "status", "started", "finished", "rc", "error", "lines"}


def _device_key_pem() -> str:
    """A throw-away P-256 public key standing in for the board's OTP device key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


PUBLIC_PEM = _device_key_pem()


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
    """Minimal Artifacts facade: two stages with real files on disk, configurable NotReady."""

    TITLES = {"tools": "Build otp-tools image", "gadget": "Build fastboot gadget", "image": "Build droneos image"}

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

    def status(self) -> dict:
        return {t: {"target": t, "ready": t == "tools", "source": "built" if t == "tools" else None, "version": "v",
                    "path": "", "size": None, "built": None, "detail": "",
                    "job": (self.jobs.current(t).to_dict() if self.jobs.current(t) else None)}
                for t in ("tools", "gadget", "image")}

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
        return {"stage": stage, "kind": "rpiboot" if stage < 3 else "fastboot-idp", "ready": True, "mode": "unsigned",
                "files": files}

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


# ----------------------------------------------------------------------------------------------------
# fixtures
# ----------------------------------------------------------------------------------------------------


@pytest.fixture
def env(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = LocalJsonStore(cfg.storage.local_dir)
    modules = ModuleService(cfg, store)
    jobs = JobManager(cfg.work_dir)
    arts = FakeArtifacts(tmp_path / "fake-artifacts", jobs, modules)
    docker = FakeDocker()
    app = create_app(cfg, store=store, docker=docker, jobs=jobs, modules=modules, artifacts=arts, auto_build=False)

    class Env:
        pass

    e = Env()
    e.cfg, e.store, e.modules, e.jobs, e.artifacts, e.docker, e.app = cfg, store, modules, jobs, arts, docker, app
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
    assert set(s) == {"version", "config", "storage", "docker", "usb_driver", "artifacts", "jobs"}
    assert s["version"] == __version__
    assert s["config"]["provisioning"]["confirm_irreversible"] is True
    assert s["storage"]["backend"] == "local" and s["storage"]["ok"] is True
    assert set(s["storage"]) >= {"backend", "ok", "location", "detail"}
    assert s["docker"] == {"ok": True, "version": "29.6.0", "detail": "", "arm64": True}
    assert s["usb_driver"] == {"platform": "windows", "rpiboot": True, "fastboot": False, "detail": "x"}
    assert set(s["artifacts"]) == {"tools", "gadget", "image"}
    assert s["jobs"] == []
    text = r.text
    assert "PRIVATE KEY" not in text


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


def test_status_docker_down_and_store_error(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, storage={"backend": "gsheets"})  # no spreadsheet configured
    jobs = JobManager(cfg.work_dir)
    app = create_app(cfg, docker=FakeDocker(ok=False), jobs=jobs, auto_build=False)
    c = TestClient(app, base_url=BASE)
    s = c.get("/api/status").json()
    assert s["docker"]["ok"] is False and "Docker daemon" in s["docker"]["detail"]
    assert s["storage"]["ok"] is False and s["storage"]["backend"] == "gsheets"
    assert s["storage"]["detail"]
    # module endpoints report the store problem as 503
    for method, url, body in (("GET", "/api/modules", None), ("POST", "/api/modules/hello", {"serial": SERIAL}),
                              ("GET", f"/api/modules/{SERIAL}", None),
                              ("POST", "/api/fastboot/identify", {"serialno": "100000005e21c09a"})):
        r = c.request(method, url, json=body)
        assert r.status_code == 503, (url, r.text)
        assert "store" in r.json()["detail"]


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
    assert m["chip"] == "BCM2712" and m["board"] == "Pi 5 / CM5 / Pi 500"
    assert m["secrets"]["rsa_key"] is True and m["secrets"]["device_secret"] is True
    assert len(m["secrets"]["customer_key_hash"]) == 64
    assert set(m["otp"]) == {"customer_key_hash", "locked", "locked_to_our_key", "secure_boot_provisioned",
                             "device_key", "device_key_fingerprint"}
    assert "PRIVATE" not in r.text and "device_secret\":\"" not in r.text
    hash1 = m["secrets"]["customer_key_hash"]

    r2 = hello(env.client, serial=SERIAL.upper())
    assert r2.status_code == 200 and r2.json()["created"] is False
    assert r2.json()["module"]["secrets"]["customer_key_hash"] == hash1
    # the secrets are really stored (server side only)
    assert "BEGIN PRIVATE KEY" in env.store.get(SERIAL)["rsa_private_pem"]


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
    assert m["otp"]["device_key"] is True
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
    assert m["stage"] == "flashed" and m["otp"]["device_key"] is True
    assert "x" * 64 not in r.text  # passphrases are never echoed back or stored
    assert [e["kind"] for e in m["events"]][-3:] == ["stage2", "stage2", "stage3"]

    assert env.client.post(f"/api/modules/{SERIAL}/stage/4/result", json={"ok": True}).status_code == 404
    assert env.client.post("/api/modules/deadbeef/stage/1/result", json={"ok": True}).status_code == 404
    assert env.client.post(f"/api/modules/{SERIAL}/stage/1/result", json="x").status_code == 400


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
    job = env.jobs.submit("image", "Build droneos image", lambda j: j.log("x"))
    wait_job(job)
    env.artifacts.not_ready[3] = NotReady("the droneos image is being built", job)
    r = env.client.get(f"/api/modules/{SERIAL}/stage/3")
    assert r.status_code == 409
    body = r.json()
    assert body["ready"] is False and body["reason"] == "the droneos image is being built"
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


@pytest.mark.parametrize("url", [
    "/README.md", "/server.py", "/otp_server/config.py", "/external/usbboot/README.md", "/js/", "/css",
    "/js/nope.js", "/js/%2e%2e/server.py", "/js/..%2fserver.py", "/js/..%5cserver.py", "/css/%2e%2e/README.md",
    "/js/C:%5cWindows%5cwin.ini", "/js/app.js::$DATA", "/tests/web/selftest.js", "/index.html/%2e%2e/server.py",
])
def test_static_nothing_else(env, url):
    r = env.client.get(url)
    assert r.status_code == 404, (url, r.status_code)


def test_auto_build_runs_in_background(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = LocalJsonStore(cfg.storage.local_dir)
    modules = ModuleService(cfg, store)
    jobs = JobManager(cfg.work_dir)
    arts = FakeArtifacts(tmp_path / "fa", jobs, modules)
    app = create_app(cfg, store=store, modules=modules, docker=FakeDocker(), jobs=jobs, artifacts=arts,
                     auto_build=True)
    with TestClient(app, base_url=BASE) as c:
        assert c.get("/api/status").status_code == 200
        app.state.auto_build_thread.join(5)
    assert arts.auto_calls == 1
    # auto_build=False and cfg.builds.auto False (test default): nothing happens
    arts2 = FakeArtifacts(tmp_path / "fb", jobs, modules)
    with TestClient(create_app(cfg, store=store, modules=modules, docker=FakeDocker(), jobs=jobs, artifacts=arts2), base_url=BASE):
        pass
    assert arts2.auto_calls == 0


def test_auto_build_failure_does_not_crash(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    store = LocalJsonStore(cfg.storage.local_dir)
    modules = ModuleService(cfg, store)

    class Exploding(FakeArtifacts):
        def auto_build(self):
            raise RuntimeError("docker not found")

    arts = Exploding(tmp_path / "fa", JobManager(cfg.work_dir), modules)
    app = create_app(cfg, store=store, modules=modules, docker=FakeDocker(ok=False), jobs=arts.jobs,
                     artifacts=arts, auto_build=True)
    with TestClient(app, base_url=BASE) as c:
        app.state.auto_build_thread.join(5)
        assert c.get("/api/status").status_code == 200
    assert app.state.services.auto_build_error == "docker not found"


# ----------------------------------------------------------------------------------------------------
# integration with the real Artifacts facade (fake Docker)
# ----------------------------------------------------------------------------------------------------


def test_real_artifacts_stage1_waits_for_tools_image(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    docker = FakeDocker()
    docker.release.clear()  # the tools image build blocks until released
    jobs = JobManager(cfg.work_dir)
    app = create_app(cfg, docker=docker, jobs=jobs, auto_build=False)
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
    docker.release.set()
    wait_job(jobs.get(body["job"]["id"]))
    assert jobs.get(body["job"]["id"]).status == "succeeded"
    assert c.get("/api/builds").json()["tools"]["ready"] is True


def test_real_artifacts_unknown_module_and_bad_target(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    app = create_app(cfg, docker=FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False)
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
    for url in ("/api/status", f"/api/modules/{SERIAL}", f"/api/modules/{SERIAL}/stage/3", "/"):
        r = env.client.get(url, headers={"host": host})
        assert r.status_code == 403, (host, url, r.text)
        assert "not allowed" in r.json()["detail"] or "no Host" in r.json()["detail"]


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "127.0.0.1", "localhost:8765", "LOCALHOST", "localhost.:8765",
                                  "[::1]:8765", "127.0.0.1:43117"])  # another port: the e2e proxy on loopback
def test_loopback_hosts_pass(env, host):
    r = env.client.get("/api/status", headers={"host": host})
    assert r.status_code == 200, (host, r.text)


def test_cross_site_post_is_rejected(env):
    for headers in ({"origin": "http://attacker.example"}, {"origin": "null"},
                    {"origin": "http://127.0.0.1.attacker.example:8765"},
                    {"referer": "http://attacker.example/page.html"}):
        r = env.client.post("/api/builds/tools", headers=headers)  # no body: a "simple" cross-site request
        assert r.status_code == 403, (headers, r.text)
        assert "cross-site POST" in r.json()["detail"]
        r = env.client.post("/api/modules/hello", json={"serial": SERIAL}, headers=headers)
        assert r.status_code == 403
    assert env.jobs.list() == []  # no build was started
    assert env.modules.get(SERIAL) is None  # nothing written to the registry


def test_same_origin_and_originless_posts_pass(env):
    for headers in ({"origin": BASE}, {"origin": "http://localhost:8765"}, {"origin": "http://127.0.0.1:43117"},
                    {"origin": "http://[::1]:8765"}, {"referer": BASE + "/"}, {}):
        r = env.client.post("/api/modules/hello", json={"serial": SERIAL}, headers=headers)
        assert r.status_code == 200, (headers, r.text)
    # A GET is never subject to the Origin check (the page's <script> and fetch loads).
    assert env.client.get("/api/status", headers={"origin": "http://attacker.example"}).status_code == 200


def test_configured_host_is_allowed(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, server={"host": "192.168.1.5"})
    c = TestClient(create_app(cfg, docker=FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False), base_url=BASE)
    assert c.get("/api/status", headers={"host": "192.168.1.5:8765"}).status_code == 200
    assert c.get("/api/status", headers={"host": "10.0.0.7:8765"}).status_code == 403
    assert c.post("/api/modules/hello", json={"serial": SERIAL},
                  headers={"host": "192.168.1.5:8765", "origin": "http://192.168.1.5:8765"}).status_code == 200


def test_wildcard_listen_accepts_ip_literals_only(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path, server={"host": "0.0.0.0"})
    c = TestClient(create_app(cfg, docker=FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False), base_url=BASE)
    assert c.get("/api/status", headers={"host": "10.0.0.7:8765"}).status_code == 200
    assert c.get("/api/status", headers={"host": "[fe80::1]:8765"}).status_code == 200
    assert c.get("/api/status", headers={"host": "rebind.attacker.example:8765"}).status_code == 403
    assert c.post("/api/builds/tools", headers={"host": "10.0.0.7:8765",
                                                "origin": "http://rebind.attacker.example"}).status_code == 403


def test_wildcard_listen_origin_must_be_same_origin(make_cfg, tmp_path):
    """With a wildcard listen an IP-literal Origin passes only when it is this server (host AND port)."""
    cfg = make_cfg(tmp_path, server={"host": "0.0.0.0"})
    c = TestClient(create_app(cfg, docker=FakeDocker(), jobs=JobManager(cfg.work_dir), auto_build=False), base_url=BASE)
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
