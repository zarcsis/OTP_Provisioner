"""Canned OTP_Provisioner API (SPEC §8 shapes) for the web self-test runner and page screenshots.

What the page reads without a board attached: status (with the Google sign-in state and the settings
sheet), modules (with their scenario), builds, jobs and a job log (SSE); plus the per-board calls the
page makes around a run: the scenario choice (POST /api/modules/{serial}/mode), the OTP device key
hand-over (POST /api/modules/{serial}/device-key) and stage manifests (stage 3 names the gadget's key
export paths for a secure board; stages 2 and 3 of a secure board answer 409 until its OTP holds its key
hash, like otp_server/artifacts). Whole provisioning runs are exercised in JS with an in-page fake
(tests/web/mocks.js).

Test hooks (run_selftest.py): :func:`set_status_overrides` merges into /api/status (e.g. a signed-out
Google state), :func:`counts` tells how often each endpoint was hit, :func:`reset` restores everything.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import pathlib
import re
import time
from collections import Counter
from typing import Any

VERSION = "0.2.0-fake"
SPREADSHEET_ID = "1Fak3SpreadsheetIdForTheSelfTest0123456789"
SPREADSHEET_URL = f"https://docs.google.com/spreadsheets/d/{SPREADSHEET_ID}/edit"
KEY_EXPORT = {"dir": "/run/otp-keyexport", "key": "/run/otp-keyexport/key.der",
              "status": "/run/otp-keyexport/status", "request": "/run/otp-keyexport/request"}
MODES = ("open", "secure")
DEFAULT_MODE = "open"

_JOBS: dict[str, dict[str, Any]] = {
    "b7c1d2e3": {"id": "b7c1d2e3", "target": "image", "title": "Build OS images (clear + crypt)", "status": "running",
                 "started": "2026-09-30T12:40:02Z", "finished": None, "rc": None, "error": "", "lines": 1834},
    "a1b2c3d4": {"id": "a1b2c3d4", "target": "gadget", "title": "Build fastboot gadget", "status": "succeeded",
                 "started": "2026-09-30T11:02:10Z", "finished": "2026-09-30T11:19:45Z", "rc": 0, "error": "", "lines": 5120},
}

_ARTIFACTS: dict[str, dict[str, Any]] = {
    "tools": {"target": "tools", "ready": True, "source": "built", "version": "otp-tools:latest · 3f9a1c2e", "path": "",
              "size": 412_000_000, "built": "2026-09-30T10:55:31Z", "detail": "debian:trixie-slim + rpi-eeprom tools", "job": None},
    "gadget": {"target": "gadget", "ready": True, "source": "built", "version": "5d0c1e7a9b3f-c3833052-pi5-family",
               "path": "", "size": 27_632_640, "built": "2026-09-30T11:19:45Z",
               "detail": "pi-gen-micro fastboot pi5-family, rpi-fastbootd 14.0.0~git20260902, helpers: otp-keyexport",
               "job": _JOBS["a1b2c3d4"]},
    "image": {"target": "image", "ready": False, "source": "built", "version": "368e8f0", "path": "", "size": 2_934_000_000,
              "built": "2026-09-30T09:01:12Z",
              "detail": "clear: the clear image is not built yet; crypt: deb13-arm64-min (pi5, sd, encrypted)",
              "job": _JOBS["b7c1d2e3"],
              "variants": {
                  "clear": {"ready": False, "set": "", "version": "", "path": "", "size": None, "built": None,
                            "detail": "the clear image is not built yet"},
                  "crypt": {"ready": True, "set": "deb13-arm64-min-crypt-368e8f0-e2798183", "version": "368e8f0", "path": "",
                            "size": 2_934_000_000, "built": "2026-09-30T09:01:12Z",
                            "detail": "deb13-arm64-min (pi5, sd, encrypted)"},
              }},
}


def _module(serial: str, stage: str, label: str, updated: str, *, locked: bool = False, mode_chosen: str = "",
            device_key: bool = False, exported: bool = False, duid: str = "", mac: str = "",
            events: list[dict[str, str]] | None = None) -> dict[str, Any]:
    khash = "8251a63a2edee9d8f710d63e9da5d639064929ce15a2238986a189ac6fcd3cee"
    return {
        "serial": serial, "stage": stage, "stage_label": label,
        "mode": "secure" if locked else (mode_chosen or DEFAULT_MODE), "mode_chosen": mode_chosen, "mode_locked": locked,
        "created": "2026-09-30T09:12:44Z", "updated": updated,
        "chip": "BCM2712", "board": "Pi 5 / CM5 / Pi 500", "duid": duid, "mac": mac, "factory_uuid": "", "boardrev": "d04170",
        "secrets": {"rsa_key": True, "customer_key_hash": khash,
                    "device_secret": True, "rsa_key_fingerprint": "4be1c3f0a9d2e87b61c05f3a2d9e4b7c8a1f0e3d2c5b6a79"},
        "otp": {"customer_key_hash": khash if locked else "", "locked": locked, "locked_to_our_key": locked,
                "secure_boot_provisioned": locked, "device_key": device_key,
                "device_key_fingerprint": "9c0d7e21f4a3b58c6d2e1f0a9b8c7d6e" if device_key else "",
                "device_key_exported": exported},
        "metadata": {}, "facts": {},
        "events": events or [{"t": "2026-09-30T09:12:44Z", "kind": "hello", "note": "created"}],
    }


_INITIAL_MODULES: list[dict[str, Any]] = [
    _module("a7eb274c", "eeprom", "EEPROM flashed", "2026-09-30T12:41:10Z", mode_chosen="open", mac="2c:cf:67:70:76:f3", events=[
        {"t": "2026-09-30T12:38:02Z", "kind": "hello", "note": "created"},
        {"t": "2026-09-30T12:38:05Z", "kind": "mode", "note": "scenario open"},
        {"t": "2026-09-30T12:40:51Z", "kind": "stage1", "note": "ok"},
    ]),
    _module("5e21c09a", "flashed", "Image written", "2026-09-30T11:58:03Z", locked=True, mode_chosen="secure", device_key=True,
            exported=True, duid="100000005e21c09a", mac="2c:cf:67:11:02:9b", events=[
                {"t": "2026-09-30T11:39:40Z", "kind": "mode", "note": "scenario secure"},
                {"t": "2026-09-30T11:40:00Z", "kind": "stage1", "note": "ok"},
                {"t": "2026-09-30T11:41:30Z", "kind": "stage2", "note": "ok"},
                {"t": "2026-09-30T11:52:10Z", "kind": "device_key_export", "note": "device key 9c0d7e21f4a3b58c exported"},
                {"t": "2026-09-30T11:58:03Z", "kind": "stage3", "note": "ok"},
            ]),
    _module("0c4f88d1", "gadget", "Fastboot gadget booted", "2026-09-30T10:20:17Z", duid="100000000c4f88d1",
            events=[{"t": "2026-09-30T10:20:17Z", "kind": "stage3", "note": "failed: the board was disconnected"}]),
]

MODULES: list[dict[str, Any]] = copy.deepcopy(_INITIAL_MODULES)
_STATUS_OVERRIDES: dict[str, Any] = {}
_COUNTS: Counter = Counter()

#: The image.* settings (otp_server.config.ImageCfg) behind GET/POST /api/image; secrets as the server keeps them.
_INITIAL_IMAGE: dict[str, Any] = {
    "name": "deb13-arm64-min", "hostname": "pi5", "timezone": "Europe/Kyiv", "keyboard": "us", "user": "pi", "password_hash": "",
    "ssh": False, "ssh_password_login": True, "ssh_authorized_keys": [], "wifi_ssid": "", "wifi_password": "",
    "wifi_country": "UA", "wifi_hidden": False,
}
IMAGE: dict[str, Any] = copy.deepcopy(_INITIAL_IMAGE)
IMAGE_FIELDS = ("name", "hostname", "timezone", "keyboard", "user", "ssh", "ssh_password_login", "ssh_authorized_keys",
                "wifi_ssid", "wifi_country", "wifi_hidden")


def reset() -> None:
    """Back to the canned state (modules, status overrides, request counts, image settings)."""
    MODULES[:] = copy.deepcopy(_INITIAL_MODULES)
    _STATUS_OVERRIDES.clear()
    _COUNTS.clear()
    IMAGE.clear()
    IMAGE.update(copy.deepcopy(_INITIAL_IMAGE))


_CHOICES_FILE = pathlib.Path(__file__).resolve().parents[2] / "otp_server" / "image_choices.json"


def _choices() -> dict[str, Any]:
    """The real lists (otp_server/image_choices.json): what the page renders is what the server offers."""
    d = json.loads(_CHOICES_FILE.read_text(encoding="utf-8"))
    return {"timezones": d["timezones"], "countries": d["countries"], "keyboards": d["keyboards"],
            "_valid": set(d["timezones"]) | set(d["timezones_valid"])}


def image_view() -> dict[str, Any]:
    """otp_server.app.Services.image_settings: no password or hash, only whether they are set."""
    i = IMAGE
    sudo = "passwd" if i["password_hash"] else ("nopasswd" if i["ssh"] and i["ssh_authorized_keys"] else "wizard")
    view = {k: copy.deepcopy(i[k]) for k in ("name", "hostname", "timezone", "keyboard", "user", "ssh", "ssh_password_login",
                                             "ssh_authorized_keys", "wifi_ssid", "wifi_country", "wifi_hidden")}
    view.update(password_set=bool(i["password_hash"]), wifi_password_set=bool(i["wifi_password"]), sudo=sudo)
    warnings = []
    if not i["password_hash"] and not (i["ssh"] and i["ssh_authorized_keys"]):
        warnings.append("no password and no SSH key: the board's first boot stops at the Raspberry Pi OS wizard on "
                        "its console (screen and keyboard), which asks for a user name and password")
    if i["wifi_ssid"] and not i["wifi_password"]:
        warnings.append(f"Wi-Fi {i['wifi_ssid']!r} has no password: the board joins it as an open network")
    ch = _choices()
    return {"settings": view, "warnings": warnings,
            "choices": {"timezones": ch["timezones"], "countries": ch["countries"], "keyboards": ch["keyboards"]}}


def _save_image(data: Any) -> tuple[int, Any]:
    """otp_server.app.Services.save_image_settings (a few of its checks; the real ones live in config.py)."""
    if not isinstance(data, dict):
        return 400, {"detail": "body must be a JSON object"}
    unknown = sorted(set(data) - set(IMAGE_FIELDS) - {"password", "wifi_password"})
    if unknown:
        return 400, {"detail": "unknown image setting(s): " + ", ".join(unknown)}
    changed = {k: data[k] for k in IMAGE_FIELDS if data.get(k) is not None}
    host = changed.get("hostname")
    if host is not None and not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
                                             str(host).strip().lower().replace("{serial}", "0123abcd")):
        return 400, {"detail": f"config image.hostname: hostname {host!r}: lower-case letters, digits and '-'"}
    ch = _choices()
    if changed.get("timezone") is not None and str(changed["timezone"]).strip() not in ch["_valid"]:
        return 400, {"detail": f"config image.timezone: time zone {changed['timezone']!r} is not in the image's tzdata"}
    if changed.get("wifi_country") is not None and str(changed["wifi_country"]).strip().upper() not in {c for c, _ in ch["countries"]}:
        return 400, {"detail": f"config image.wifi_country: Wi-Fi country {changed['wifi_country']!r} is not in wireless-regdb"}
    if data.get("password") is not None:
        changed["password_hash"] = ("$6$fakesalt$" + "x" * 86) if data["password"] else ""
    if data.get("wifi_password") is not None:
        pw = data["wifi_password"]
        if pw and not 8 <= len(pw) <= 63:
            return 400, {"detail": "config image.wifi_password: Wi-Fi password: 8 to 63 characters"}
        changed["wifi_password"] = pw
    if "hostname" in changed:
        changed["hostname"] = str(changed["hostname"]).strip().lower()
    if "wifi_country" in changed:
        changed["wifi_country"] = str(changed["wifi_country"]).strip().upper()
    IMAGE.update(changed)
    return 200, {**image_view(), "saved": sorted(f"image.{k}" for k in changed)}


def _merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)
    return dst


def set_status_overrides(obj: dict) -> None:
    """Merge ``obj`` into every later /api/status (``{}`` keeps what is set; use :func:`reset` to clear)."""
    if isinstance(obj, dict):
        _merge(_STATUS_OVERRIDES, obj)


def counts() -> dict[str, int]:
    return dict(_COUNTS)


def status() -> dict[str, Any]:
    s = {
        "version": VERSION,
        "google": {"client": True, "client_file": "C:/station/OTP_Provisioner/google-oauth-client.json", "signed_in": True,
                   "email": "operator@example.com", "spreadsheet_id": SPREADSHEET_ID, "spreadsheet_url": SPREADSHEET_URL,
                   "error": ""},
        "google_ready": True,
        "settings": {"ok": True, "error": "", "unknown": [], "worksheet": "settings"},
        "config": {"settings": "Google Sheets (worksheet settings)",
                   "provisioning": {"default_mode": DEFAULT_MODE, "modes": list(MODES), "jtag_lock": False,
                                    "recovery_passphrase": False, "confirm_irreversible": True, "erase_storage": True,
                                    "firmware_channel": "default", "max_piece_size": 268435456}},
        "storage": {"backend": "gsheets", "ok": True, "location": SPREADSHEET_URL,
                    "detail": f"{len(MODULES)} module record(s) in worksheet modules"},
        "docker": {"ok": True, "version": "29.6.0", "detail": "Docker Desktop, linux engine", "arm64": True},
        "usb_driver": {"platform": "windows", "rpiboot": True, "fastboot": False,
                       "detail": "WinUSB is not bound to 18d1:4e40 yet (wdi-simple -v 0x18d1 -p 0x4e40)"},
        "artifacts": _ARTIFACTS,
        "jobs": list(_JOBS.values()),
    }
    return _merge(s, _STATUS_OVERRIDES)


def _google_problem(s: dict) -> str:
    g = s.get("google") or {}
    if not g.get("client"):
        return f"no Google OAuth client: save the 'Desktop app' client JSON as {g.get('client_file')}, then sign in on the page"
    if not g.get("signed_in"):
        return "sign in to Google first (button on the page, or python -m otp_server login)"
    return (s.get("settings") or {}).get("error") or "the settings sheet has not been read yet"


def _find(serial: str) -> dict | None:
    return next((m for m in MODULES if m["serial"] == serial), None)


def _set_mode(m: dict, mode: Any) -> tuple[int, Any]:
    """otp_server.modules.ModuleService.set_mode, on the public view."""
    want = str(mode or "").strip().lower()
    if want not in MODES:
        return 400, {"detail": f"mode must be one of open, secure, got {mode!r}"}
    if want == "open" and m["mode_locked"]:
        return 400, {"detail": f"board {m['serial']}: its OTP holds a key hash (secure boot is provisioned), so it only "
                               "runs signed code; only the secure scenario is possible"}
    if m["mode_chosen"] != want:
        effective = m["mode"]
        note = f"scenario {want}" + (f" (was {m['mode_chosen']})" if m["mode_chosen"] else "")
        m["mode_chosen"] = want
        m["mode"] = want
        if effective != want and m["stage"] != "new":
            note += f"; stage {m['stage']} reset to new: every stage is redone in the new scenario"
            m["stage"], m["stage_label"] = "new", "New"
        m["events"].append({"t": _now(), "kind": "mode", "note": note})
        m["updated"] = _now()
    return 200, {"module": m}


def _device_key(m: dict, body: dict) -> tuple[int, Any]:
    raw = body.get("key_der_b64")
    pem = body.get("device_key_pem")
    if not isinstance(raw, str) or not raw.strip():
        return 400, {"detail": "key_der_b64 must be a non-empty base64 string"}
    try:
        der = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        return 400, {"detail": "key_der_b64 is not valid base64"}
    mm = re.search(r"-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----", pem or "")
    if not der or not mm:
        return 400, {"detail": "device_key_pem must be the PEM public key the board reports (getvar:public-key)"}
    fp = hashlib.sha256(base64.b64decode("".join(mm.group(1).split()))).hexdigest()
    otp = m["otp"]
    already = bool(otp.get("device_key_exported")) and otp.get("device_key_fingerprint") == fp
    if otp.get("device_key_exported") and not already:
        return 400, {"detail": f"module {m['serial']}: a different device private key is already stored"}
    otp.update(device_key=True, device_key_exported=True, device_key_fingerprint=fp)
    if not already:
        m["events"].append({"t": _now(), "kind": "device_key_export", "note": f"device key {fp[:16]} exported"})
    return 200, {"module": m, "device_key": {"fingerprint": fp, "already": already, "zero_words": 0}}


def _manifest(m: dict, n: int) -> dict:
    """A small stage manifest of the right shape (no real files: runs are exercised in mocks.js)."""
    secure = m["mode"] == "secure"
    locked = m["mode_locked"]
    if n == 1:
        program = secure and not locked
        return {"stage": 1, "kind": "rpiboot", "title": "EEPROM & OTP", "ready": True,
                "mode": "signed" if secure or locked else "unsigned", "files": [],
                "config_txt": "uart_2ndstage=1\nrecovery_reboot=1\n" + ("program_pubkey=1\n" if program else ""),
                "irreversible": [{"key": "program_pubkey", "value": "1", "why": "burns the key hash into OTP"}] if program else [],
                "expect": {"secure_boot_provision": program,
                           "customer_key_hash": m["secrets"]["customer_key_hash"] if program else None},
                "notes": []}
    if n == 2:
        return {"stage": 2, "kind": "rpiboot", "title": "Fastboot gadget", "ready": True,
                "mode": "signed" if locked else "unsigned", "files": [], "config_txt": "boot_ramdisk=1\nuart_2ndstage=1\n",
                "irreversible": [], "expect": {"secure_boot_provision": False, "customer_key_hash": None}, "notes": []}
    variant = "crypt" if secure else "clear"
    irreversible = ([{"key": "oem fwcrypto init", "value": "", "why": "device key in OTP"}] if secure else []) + \
        [{"key": "erase", "value": "mmcblk0", "why": "wipes the whole storage device"}]
    return {"stage": 3, "kind": "fastboot-idp", "title": "Image", "ready": True,
            "mode": "signed" if locked else "unsigned", "scenario": "secure" if secure else "open",
            "image": {"name": "deb13-arm64-min", "version": "368e8f0", "set": f"deb13-arm64-min-{variant}-368e8f0-e2798183",
                      "built": "2026-09-30T09:01:12Z", "variant": variant, "device_class": "pi5", "storage_type": "sd",
                      "encrypted": secure},
            "storage_device": "mmcblk0", "image_json": None, "parts": {}, "total_bytes": 0, "max_piece_size": 268435456,
            "fwcrypto_init": secure, "key_export": dict(KEY_EXPORT) if secure else None, "erase": True, "crypt": [],
            "irreversible": irreversible, "notes": []}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def handle(method: str, path: str, body: bytes) -> tuple[int, Any]:
    """Return (HTTP status, JSON body) for a request, or (0, job) for the SSE log endpoint."""
    parts = [p for p in path.split("?")[0].split("/") if p]
    if parts[:1] != ["api"]:
        return 404, {"detail": "Not Found"}
    rest = parts[1:]
    _COUNTS[f"{method} {'/'.join(rest[:1] + (['*'] if len(rest) > 1 else []))}"] += 1
    try:
        data = json.loads(body) if body else {}
    except ValueError:
        return 400, {"detail": "body is not JSON"}
    if method == "GET" and rest == ["status"]:
        return 200, status()
    if method == "POST" and rest == ["google", "logout"]:
        set_status_overrides({"google": {"signed_in": False, "spreadsheet_id": "", "spreadsheet_url": ""},
                              "google_ready": False,
                              "settings": {"ok": False, "error": "not signed in to Google"}})
        return 200, {"ok": True}
    st = status()
    if rest[:1] in (["modules"], ["builds"], ["fastboot"], ["image"]) and st.get("google_ready") is False:
        return 401, {"detail": _google_problem(st)}
    if method == "GET" and rest == ["image"]:
        return 200, image_view()
    if method == "POST" and rest == ["image"]:
        return _save_image(data)
    if method == "GET" and rest == ["modules"]:
        return 200, sorted(MODULES, key=lambda m: m["updated"], reverse=True)
    if len(rest) >= 2 and rest[0] == "modules" and rest[1] != "hello":
        m = _find(rest[1])
        if m is None:
            return 404, {"detail": f"unknown module {rest[1]!r}"}
        if method == "GET" and len(rest) == 2:
            return 200, m
        if method == "POST" and rest[2:] == ["mode"]:
            return _set_mode(m, data.get("mode"))
        if method == "POST" and rest[2:] == ["device-key"]:
            return _device_key(m, data if isinstance(data, dict) else {})
        if method == "GET" and len(rest) == 4 and rest[2] == "stage" and rest[3] in ("1", "2", "3"):
            n = int(rest[3])
            if n in (2, 3) and m["mode"] == "secure" and not (m["otp"]["locked"] and m["otp"]["locked_to_our_key"]):
                # otp_server/artifacts Artifacts._stage: the secure scenario is a signed boot chain
                return 409, {"ready": False, "job": None,
                             "reason": f"board {m['serial']} is in the secure scenario but its OTP does not hold this board's "
                                       "key hash yet: run stage 1 first (signed EEPROM + program_pubkey)"}
            return 200, _manifest(m, n)
        return 404, {"detail": "Not Found"}
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
            "==> OS image (crypt) already built: deb13-arm64-min-crypt-v2.8.0-e2798183",
            "==> ensure docker daemon: ok (29.6.0)",
            "==> ensure arm64 emulation: aarch64",
            "==> docker build -t otp-image-builder:trixie image/docker",
            "#8 [5/7] RUN apt-get install -y --no-install-recommends mmdebstrap genimage ...",
            "#8 DONE 41.2s",
            "==> rpi-image-gen v2.8.0 (clear): IGconf_image_pmap=clear",
            "==> otp-image.yaml (from the image.* settings):",
            "I: rpi-image-gen v2.8.0, config otp-image.yaml, layer image-rpios (pmap clear)",
            "I: bdebstrap: resolving 412 packages",
            "I: Retrieved 412 packages (138 MB)",
            "I: Unpacking base system ...",
            "I: customize10-pmap: plain ext4 root -> provisionmap.json",
        ]
    return ["==> pi-gen-micro fastboot pi5-family", "    helper packages: otp-keyexport", "I: building ramdisk",
            "==> boot.img 27632640 bytes", "done"]


def sse_events(job: dict[str, Any]) -> tuple[list[bytes], bool]:
    """Encoded SSE frames and whether the stream should end with 'done'."""
    frames = [f"data: {json.dumps({'line': line})}\n\n".encode() for line in job_log_lines(job)]
    finished = job["status"] in ("succeeded", "failed")
    if finished:
        frames.append(f"event: done\ndata: {json.dumps({'status': job['status'], 'rc': job['rc']})}\n\n".encode())
    return frames, finished
