"""Canned OTP_Provisioner API (SPEC §8 shapes) for the web self-test runner and page screenshots.

Only what the page reads without a board attached: status, modules, builds, jobs and a job log (SSE).
Stage manifests and results are exercised in JS with an in-page fake (tests/web/mocks.js).
"""
from __future__ import annotations

import json
import time
from typing import Any

VERSION = "0.2.0-fake"

_JOBS: dict[str, dict[str, Any]] = {
    "b7c1d2e3": {"id": "b7c1d2e3", "target": "image", "title": "Build droneos image", "status": "running",
                 "started": "2026-09-30T12:40:02Z", "finished": None, "rc": None, "error": "", "lines": 1834},
    "a1b2c3d4": {"id": "a1b2c3d4", "target": "gadget", "title": "Build fastboot gadget", "status": "succeeded",
                 "started": "2026-09-30T11:02:10Z", "finished": "2026-09-30T11:19:45Z", "rc": 0, "error": "", "lines": 5120},
}

_ARTIFACTS: dict[str, dict[str, Any]] = {
    "tools": {"target": "tools", "ready": True, "source": "built", "version": "otp-tools:latest · 3f9a1c2e", "path": "",
              "size": 412_000_000, "built": "2026-09-30T10:55:31Z", "detail": "debian:trixie-slim + rpi-eeprom tools", "job": None},
    "gadget": {"target": "gadget", "ready": True, "source": "built", "version": "5d0c1e7a9b3f-pi5-family",
               "path": "", "size": 27_632_640, "built": "2026-09-30T11:19:45Z",
               "detail": "pi-gen-micro fastboot pi5-family, rpi-fastbootd 14.0.0~git20260902", "job": _JOBS["a1b2c3d4"]},
    "image": {"target": "image", "ready": False, "source": None, "version": "", "path": "", "size": None, "built": None,
              "detail": "droneos.yaml + IGconf_image_pmap=crypt", "job": _JOBS["b7c1d2e3"]},
}


def _module(serial: str, stage: str, label: str, updated: str, *, locked: bool = False, device_key: bool = False,
            duid: str = "", mac: str = "", events: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "serial": serial, "stage": stage, "stage_label": label, "created": "2026-09-30T09:12:44Z", "updated": updated,
        "chip": "BCM2712", "board": "Pi 5 / CM5 / Pi 500", "duid": duid, "mac": mac, "factory_uuid": "", "boardrev": "d04170",
        "secrets": {"rsa_key": True, "customer_key_hash": "8251a63a2edee9d8f710d63e9da5d639064929ce15a2238986a189ac6fcd3cee",
                    "device_secret": True, "rsa_key_fingerprint": "4be1c3f0a9d2e87b61c05f3a2d9e4b7c8a1f0e3d2c5b6a79"},
        "otp": {"customer_key_hash": "", "locked": locked, "locked_to_our_key": locked, "secure_boot_provisioned": locked,
                "device_key": device_key, "device_key_fingerprint": "9c0d7e21f4a3b58c6d2e1f0a9b8c7d6e" if device_key else ""},
        "metadata": {}, "facts": {},
        "events": events or [{"t": "2026-09-30T09:12:44Z", "kind": "hello", "note": "created"}],
    }


MODULES: list[dict[str, Any]] = [
    _module("a7eb274c", "eeprom", "EEPROM flashed", "2026-09-30T12:41:10Z", mac="2c:cf:67:70:76:f3", events=[
        {"t": "2026-09-30T12:38:02Z", "kind": "hello", "note": "created"},
        {"t": "2026-09-30T12:40:51Z", "kind": "stage1", "note": "ok"},
    ]),
    _module("5e21c09a", "flashed", "Image written", "2026-09-30T11:58:03Z", device_key=True, duid="100000005e21c09a",
            mac="2c:cf:67:11:02:9b", events=[
                {"t": "2026-09-30T11:40:00Z", "kind": "stage1", "note": "ok"},
                {"t": "2026-09-30T11:41:30Z", "kind": "stage2", "note": "ok"},
                {"t": "2026-09-30T11:58:03Z", "kind": "stage3", "note": "ok"},
            ]),
    _module("0c4f88d1", "gadget", "Fastboot gadget booted", "2026-09-30T10:20:17Z", duid="100000000c4f88d1",
            events=[{"t": "2026-09-30T10:20:17Z", "kind": "stage3", "note": "failed: the board was disconnected"}]),
]


def status() -> dict[str, Any]:
    return {
        "version": VERSION,
        "config": {"provisioning": {"secure_boot": False, "jtag_lock": False, "recovery_passphrase": True,
                                    "confirm_irreversible": True, "erase_storage": True}},
        "storage": {"backend": "local", "ok": True, "location": "%LOCALAPPDATA%/OTP_Provisioner/registry",
                    "detail": f"{len(MODULES)} records"},
        "docker": {"ok": True, "version": "29.6.0", "detail": "Docker Desktop, linux engine", "arm64": True},
        "usb_driver": {"platform": "windows", "rpiboot": True, "fastboot": False,
                       "detail": "WinUSB is not bound to 18d1:4e40 yet (wdi-simple -v 0x18d1 -p 0x4e40)"},
        "artifacts": _ARTIFACTS,
        "jobs": list(_JOBS.values()),
    }


def handle(method: str, path: str, body: bytes) -> tuple[int, Any]:
    """Return (HTTP status, JSON body) for a request, or (0, job) for the SSE log endpoint."""
    parts = [p for p in path.split("?")[0].split("/") if p]
    if parts[:1] != ["api"]:
        return 404, {"detail": "Not Found"}
    rest = parts[1:]
    if method == "GET" and rest == ["status"]:
        return 200, status()
    if method == "GET" and rest == ["modules"]:
        return 200, sorted(MODULES, key=lambda m: m["updated"], reverse=True)
    if method == "GET" and len(rest) == 2 and rest[0] == "modules":
        for m in MODULES:
            if m["serial"] == rest[1]:
                return 200, m
        return 404, {"detail": f"unknown module {rest[1]}"}
    if method == "GET" and rest == ["builds"]:
        return 200, _ARTIFACTS
    if method == "POST" and len(rest) == 2 and rest[0] == "builds":
        if rest[1] not in _ARTIFACTS:
            return 400, {"detail": f"unknown build target {rest[1]}"}
        job = {"id": "f00d%04d" % (int(time.time()) % 10000), "target": rest[1], "title": f"Build {rest[1]}",
               "status": "queued", "started": None, "finished": None, "rc": None, "error": "", "lines": 0}
        _JOBS[job["id"]] = job
        return 200, {"job": job}
    if method == "GET" and rest == ["jobs"]:
        return 200, list(_JOBS.values())
    if method == "GET" and len(rest) == 2 and rest[0] == "jobs":
        job = _JOBS.get(rest[1])
        return (200, job) if job else (404, {"detail": "unknown job"})
    if method == "GET" and len(rest) == 3 and rest[0] == "jobs" and rest[2] == "log":
        job = _JOBS.get(rest[1])
        return (0, job) if job else (404, {"detail": "unknown job"})
    return 404, {"detail": "Not Found"}


def job_log_lines(job: dict[str, Any]) -> list[str]:
    """A plausible log for the SSE endpoint."""
    if job["target"] == "image":
        return [
            "==> ensure docker daemon: ok (29.6.0)",
            "==> ensure arm64 emulation: aarch64",
            "==> docker build -t droneos-builder:trixie external/droneos/docker",
            "#8 [5/7] RUN apt-get install -y --no-install-recommends mmdebstrap genimage ...",
            "#8 DONE 41.2s",
            "==> docker run droneos-builder:trixie --in-container -B /work -o /out -c /src/droneos.yaml -- IGconf_image_pmap=crypt",
            "I: rpi-image-gen v2.8.0, config droneos.yaml, layer image-rpios (pmap crypt)",
            "I: bdebstrap: resolving 412 packages",
            "I: Retrieved 412 packages (138 MB)",
            "I: Unpacking base system ...",
            "I: customize10-pmap: LUKS2 aes-xts-plain64 / 512 / sha256 -> provisionmap.json",
            "I: Configuring cryptsetup-initramfs ...",
            "I: Configuring rpifwcrypto ...",
        ]
    return ["==> pi-gen-micro fastboot pi5-family", "I: building ramdisk", "==> boot.img 27632640 bytes", "done"]


def sse_events(job: dict[str, Any]) -> tuple[list[bytes], bool]:
    """Encoded SSE frames and whether the stream should end with 'done'."""
    frames = [f"data: {json.dumps({'line': line})}\n\n".encode() for line in job_log_lines(job)]
    finished = job["status"] in ("succeeded", "failed")
    if finished:
        frames.append(f"event: done\ndata: {json.dumps({'status': job['status'], 'rc': job['rc']})}\n\n".encode())
    return frames, finished
