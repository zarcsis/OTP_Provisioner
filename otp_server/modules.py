"""Board ("module") lifecycle on top of a :class:`~otp_server.storage.base.ModuleStore` (SPEC section 7).

A module is keyed by the 8-hex USB serial the BCM2712 boot ROM reports. Stages only move forward:
``new`` -> ``eeprom`` -> ``gadget`` -> ``flashed``. Every read-modify-write goes through one lock so
concurrent API requests cannot lose updates. Records hold secrets; :meth:`ModuleService.public_view`
is the only representation that may leave the server.
"""

from __future__ import annotations

import copy
import functools
import logging
import re
import threading
from typing import Any

from .secrets_gen import (customer_key_hash, new_module_secrets, otp_zero_words, parse_device_private_key,
                          public_key_fingerprint, public_pem_from_private, same_public_key)
from .storage.base import MAX_EVENTS, StoreError, normalize_record, utc_now_iso

log = logging.getLogger(__name__)

STAGES = ("new", "eeprom", "gadget", "flashed")
#: Provisioning scenarios a board can be run in (chosen per board on the page).
MODES = ("open", "secure")
STAGE_LABELS = {
    "new": "New",
    "eeprom": "EEPROM flashed",
    "gadget": "Fastboot gadget booted",
    "flashed": "Image written",
}
ZERO_HASH = "0" * 64

#: ``getvar`` names kept from rpi-fastbootd (``facts["fastboot"]``).
FASTBOOT_VARS = (
    "product",
    "version-bootloader",
    "version-fastbootd",
    "secure",
    "secure-otp",
    "secure-devkey",
    "mmc-cid",
    "mac-ethernet",
    "rpi-duid",
    "otp-lock-status",
    "block-devices",
    "max-download-size",
)
#: USB descriptor fields kept from ``hello`` (``facts["usb"]``).
USB_KEYS = ("vendor_id", "product_id", "product_name", "manufacturer", "serial_number")

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_SECRET_KEYS = ("rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret", "device_private_pem")
#: Largest exported device key accepted (DER of a P-256 key is ~121-138 bytes).
MAX_DEVICE_KEY_BYTES = 1024


def normalize_serial(s: str) -> str:
    """Canonical 8-hex board serial.

    Strips whitespace and NULs and lowercases; accepts 8 hex chars, or 16 (the 64-bit serial of the
    fastboot gadget / DUID form) of which the last 8 are the boot-ROM serial.

    :raises ValueError: ``"board reported no usable USB serial: ..."`` for anything else (empty,
        ``"Broadcom"``, non-hex, other lengths).
    """
    raw = s.decode("latin-1") if isinstance(s, (bytes, bytearray)) else str(s if s is not None else "")
    v = raw.replace("\x00", "").strip().lower()
    if _HEX_RE.match(v) and len(v) in (8, 16):
        return v[-8:]
    raise ValueError(f"board reported no usable USB serial: {raw!r}")


def _clean_text(v: Any, limit: int = 4096) -> str:
    s = v if isinstance(v, str) else ("" if v is None else str(v))
    return s.replace("\x00", "").strip()[:limit]


def _stage_max(a: str, b: str) -> str:
    ia = STAGES.index(a) if a in STAGES else 0
    ib = STAGES.index(b) if b in STAGES else 0
    return STAGES[max(ia, ib)]


def _add_event(rec: dict, kind: str, note: str) -> None:
    rec["events"].append({"t": utc_now_iso(), "kind": _clean_text(kind, 64), "note": _clean_text(note, 500)})
    del rec["events"][:-MAX_EVENTS]


@functools.lru_cache(maxsize=512)
def _fingerprint(pem: str) -> str:
    try:
        return public_key_fingerprint(pem)
    except ValueError:
        return ""


def _is_public_pem(v: Any) -> bool:
    return isinstance(v, str) and "BEGIN PUBLIC KEY" in v and "PRIVATE" not in v


class ModuleService:
    """Board registry operations used by the HTTP API.

    :param cfg: server :class:`~otp_server.config.Config` (kept for callers; not needed for the rules).
    :param store: any :class:`~otp_server.storage.base.ModuleStore`.
    """

    def __init__(self, cfg: Any, store: Any):
        self.cfg = cfg
        self.store = store
        self._lock = threading.RLock()

    # -- internals ----------------------------------------------------------------------------------

    def _load_or_new(self, serial: str) -> tuple[dict, bool]:
        rec = self.store.get(serial)
        if rec is not None:
            return normalize_record(rec), False
        now = utc_now_iso()
        return normalize_record({"serial": serial, "stage": "new", "created": now, "updated": now}), True

    @staticmethod
    def _ensure_secrets(rec: dict) -> bool:
        """Fill missing secrets without ever replacing an existing key. Returns True if changed."""
        changed = False
        if not rec["rsa_private_pem"]:
            fresh = new_module_secrets()
            rec["rsa_private_pem"] = fresh["rsa_private_pem"]
            rec["rsa_public_pem"] = fresh["rsa_public_pem"]
            rec["customer_key_hash"] = fresh["customer_key_hash"]
            if not rec["device_secret"]:
                rec["device_secret"] = fresh["device_secret"]
            return True
        if not rec["rsa_public_pem"]:
            rec["rsa_public_pem"] = public_pem_from_private(rec["rsa_private_pem"])
            changed = True
        if not rec["customer_key_hash"]:
            rec["customer_key_hash"] = customer_key_hash(rec["rsa_public_pem"])
            changed = True
        if not rec["device_secret"]:
            rec["device_secret"] = new_module_secrets()["device_secret"]
            changed = True
        return changed

    def _save(self, rec: dict) -> dict:
        rec["updated"] = utc_now_iso()
        if not rec["created"]:
            rec["created"] = rec["updated"]
        self.store.put(rec)
        return copy.deepcopy(rec)

    @staticmethod
    def _filter_vars(vars: Any) -> dict:
        if not isinstance(vars, dict):
            return {}
        return {k: _clean_text(vars[k]) for k in FASTBOOT_VARS if k in vars and vars[k] is not None}

    # -- public API ---------------------------------------------------------------------------------

    def hello(self, serial: str, info: dict | None = None) -> tuple[dict, bool]:
        """Get-or-create the module for a board seen in RPIBOOT mode.

        Creates the board secrets when missing, updates ``chip``/``board`` from ``info``
        (``{"chip", "board", "usb": {...}, "rom_stage"}``), stores the USB descriptor under
        ``facts["usb"]`` and appends a ``hello`` event.

        :returns: ``(record, created)``
        :raises ValueError: unusable serial. :raises StoreError: store unavailable.
        """
        key = normalize_serial(serial)
        info = info if isinstance(info, dict) else {}
        with self._lock:
            rec, created = self._load_or_new(key)
            self._ensure_secrets(rec)
            if _clean_text(info.get("chip")):
                rec["chip"] = _clean_text(info.get("chip"), 64)
            if _clean_text(info.get("board")):
                rec["board"] = _clean_text(info.get("board"), 128)
            usb = info.get("usb")
            if isinstance(usb, dict):
                rec["facts"]["usb"] = {k: usb[k] for k in USB_KEYS if k in usb and isinstance(usb[k], (str, int))}
            if _clean_text(info.get("rom_stage")):
                rec["facts"]["rom_stage"] = _clean_text(info.get("rom_stage"), 64)
            note = "created" if created else "seen"
            if rec["chip"]:
                note += f" ({rec['chip']})"
            _add_event(rec, "hello", note)
            return self._save(rec), created

    def identify_fastboot(self, serialno: str, vars: dict | None = None) -> tuple[dict, bool]:
        """Record a board that booted the fastboot gadget.

        ``serialno`` is ``getvar:serialno`` (16 hex; NULs/whitespace stripped); the module is its last
        8 hex chars (hello semantics: created with secrets if unknown). Stores ``duid`` (the full 16
        hex), the whitelisted fastboot vars under ``facts["fastboot"]``, raises the stage to at least
        ``gadget`` and appends a ``fastboot`` event.

        :returns: ``(record, created)``
        """
        sn = _clean_text(serialno).lower()
        key = normalize_serial(sn)
        with self._lock:
            rec, created = self._load_or_new(key)
            self._ensure_secrets(rec)
            if len(sn) == 16:
                rec["duid"] = sn
            fv = self._filter_vars(vars)
            if fv:
                rec["facts"]["fastboot"] = {**rec["facts"].get("fastboot", {}), **fv}
            rec["stage"] = _stage_max(rec["stage"], "gadget")
            _add_event(rec, "fastboot", f"serialno {sn}")
            return self._save(rec), created

    def get(self, serial: str) -> dict | None:
        """The record, or ``None`` when unknown or when ``serial`` is not a usable serial."""
        try:
            key = normalize_serial(serial)
        except ValueError:
            return None
        return self.store.get(key)

    def require(self, serial: str) -> dict:
        """The record; ``KeyError`` when unknown (or not a usable serial)."""
        rec = self.get(serial)
        if rec is None:
            raise KeyError(f"unknown module {serial!r}")
        return rec

    def list(self) -> list[dict]:
        """All records, most recently updated first."""
        recs = [normalize_record(r) for r in self.store.list()]
        recs.sort(key=lambda r: (r["updated"], r["serial"]), reverse=True)
        return recs

    def add_facts(self, serial: str, facts: dict) -> dict:
        """Merge facts learnt by the page.

        Accepted keys: ``device_key_pem`` (str containing ``BEGIN PUBLIC KEY``), ``duid`` (hex),
        ``fastboot_vars`` (dict, whitelisted), ``event`` (``{"kind", "note"}``). Unknown keys are
        ignored. :raises KeyError: unknown module. :raises ValueError: malformed accepted value.
        """
        facts = facts if isinstance(facts, dict) else {}
        pem = facts.get("device_key_pem")
        if pem is not None and not _is_public_pem(pem):
            raise ValueError("device_key_pem must be a PEM public key (-----BEGIN PUBLIC KEY-----)")
        duid = facts.get("duid")
        if duid is not None:
            duid = _clean_text(duid).lower()
            if not duid or len(duid) > 64 or not _HEX_RE.match(duid):
                raise ValueError("duid must be a hex string")
        fv = facts.get("fastboot_vars")
        if fv is not None and not isinstance(fv, dict):
            raise ValueError("fastboot_vars must be an object")
        ev = facts.get("event")
        if ev is not None and not (isinstance(ev, dict) and _clean_text(ev.get("kind"))):
            raise ValueError("event must be an object with a non-empty 'kind'")
        with self._lock:
            rec = normalize_record(self.require(serial))
            if pem is not None:
                pem = pem.replace("\r\n", "\n").strip() + "\n"
                if rec["device_private_pem"] and not same_public_key(pem, rec["device_private_pem"]):
                    raise ValueError(f"module {rec['serial']}: the reported device key differs from the exported one "
                                     "kept for this board (an OTP key cannot change)")
                if pem != rec["device_key_pem"]:
                    rec["device_key_pem"] = pem
                    fp = _fingerprint(pem)
                    _add_event(rec, "device_key", f"device key {fp[:16]}" if fp else "device key stored")
            if duid is not None:
                rec["duid"] = duid
            if fv is not None:
                filtered = self._filter_vars(fv)
                if filtered:
                    rec["facts"]["fastboot"] = {**rec["facts"].get("fastboot", {}), **filtered}
            if ev is not None:
                _add_event(rec, _clean_text(ev.get("kind"), 64), _clean_text(ev.get("note"), 500))
            return self._save(rec)

    def mode_of(self, record: dict) -> str:
        """The scenario the board's stages are planned for.

        ``secure`` whenever the board OTP holds a key hash (it only runs signed code any more), else the
        scenario chosen for it, else ``provisioning.default_mode``.
        """
        r = record or {}
        if self.is_locked(r) or bool(r.get("secure_boot_provisioned")):
            return "secure"
        m = str(r.get("mode") or "").strip().lower()
        if m in MODES:
            return m
        prov = getattr(self.cfg, "provisioning", None)
        default = str(getattr(prov, "default_mode", "") or "open")
        return default if default in MODES else "open"

    def set_mode(self, serial: str, mode: str) -> dict:
        """Choose the scenario for a board (``open`` or ``secure``).

        Refused for ``open`` once the board OTP holds a key hash. Switching a board that already went
        through stages in the other scenario -- the one :meth:`mode_of` gave before, which for a record
        without a choice is ``provisioning.default_mode`` -- resets its stage to ``new`` (every stage has to
        be redone: the EEPROM, the gadget signing and the image all differ). Appends a ``mode`` event.

        :raises KeyError: unknown module. :raises ValueError: unknown scenario or ``open`` on a locked board.
        """
        m = str(mode or "").strip().lower()
        if m not in MODES:
            raise ValueError(f"mode must be one of {', '.join(MODES)}, got {mode!r}")
        with self._lock:
            rec = normalize_record(self.require(serial))
            if m == "open" and (self.is_locked(rec) or rec["secure_boot_provisioned"]):
                raise ValueError(f"board {rec['serial']}: its OTP holds a key hash (secure boot is provisioned), so it "
                                 "only runs signed code; only the secure scenario is possible")
            prev = rec["mode"]
            if prev == m:
                return copy.deepcopy(rec)
            effective = self.mode_of(rec)      # the scenario the stages done so far ran in
            rec["mode"] = m
            note = f"scenario {m}" + (f" (was {prev})" if prev else "")
            if effective != m and rec["stage"] != "new":
                if not prev:
                    note += f" (the stages so far ran as {effective})"
                note += f"; stage {rec['stage']} reset to new: every stage is redone in the new scenario"
                rec["stage"] = "new"
            _add_event(rec, "mode", note)
            return self._save(rec)

    def store_device_key(self, serial: str, key_der: bytes, reported_pem: str) -> tuple[dict, dict]:
        """Keep the board's OTP device private key exported by the fastboot gadget (``secure`` mode).

        ``key_der`` is the gadget's ``rpi-fw-crypto privkey --key-id 1`` output (DER, or the raw
        32-byte scalar); ``reported_pem`` is ``getvar:public-key`` read from the same gadget. The key
        is accepted only when its public half equals ``reported_pem`` and, when the record already
        knows the board's device key, that one too (an OTP key can never change). A second export of
        the same key changes nothing.

        :returns: ``(record, info)`` with ``info = {"fingerprint", "already", "zero_words"}``;
            ``zero_words`` > 0 means OTP rows of the key are zero (a key write that was cut short).
        :raises KeyError: unknown module. :raises ValueError: unusable key or a public-key mismatch.
        """
        raw = bytes(key_der or b"")
        if not raw or len(raw) > MAX_DEVICE_KEY_BYTES:
            raise ValueError(f"the exported device key must be 1..{MAX_DEVICE_KEY_BYTES} bytes, got {len(raw)}")
        if not _is_public_pem(reported_pem):
            raise ValueError("device_key_pem must be the PEM public key the board reports (getvar:public-key)")
        d, priv, pub = parse_device_private_key(raw)
        if not same_public_key(pub, reported_pem):
            raise ValueError("the exported device key does not match the public key the board reports")
        fp = _fingerprint(pub)
        zero = otp_zero_words(d)
        with self._lock:
            rec = normalize_record(self.require(serial))
            if rec["device_key_pem"] and not same_public_key(pub, rec["device_key_pem"]):
                raise ValueError(f"module {rec['serial']}: the exported device key differs from the one recorded "
                                 f"for this board ({_fingerprint(rec['device_key_pem'])[:16]}); an OTP key cannot change")
            if rec["device_private_pem"]:
                if not same_public_key(rec["device_private_pem"], pub):
                    raise ValueError(f"module {rec['serial']}: a different device private key is already stored")
                return copy.deepcopy(rec), {"fingerprint": fp, "already": True, "zero_words": zero}
            rec["device_private_pem"] = priv
            rec["device_key_pem"] = pub
            note = f"device key {fp[:16]} exported"
            if zero:
                note += f"; WARNING: {zero} of its 8 OTP words are zero (key generation was probably interrupted)"
            _add_event(rec, "device_key_export", note)
            return self._save(rec), {"fingerprint": fp, "already": False, "zero_words": zero}

    def record_result(self, serial: str, stage: int, result: dict) -> tuple[dict, dict]:
        """Apply the page's report of a stage run (rules in SPEC section 7).

        :returns: ``(record, verdict)`` with ``verdict = {"ok": bool, "notes": [str]}``.
        :raises KeyError: unknown module. :raises ValueError: stage not 1, 2 or 3.
        """
        try:
            n = int(stage)
        except (TypeError, ValueError):
            raise ValueError(f"stage must be 1, 2 or 3, got {stage!r}") from None
        if n not in (1, 2, 3):
            raise ValueError(f"stage must be 1, 2 or 3, got {stage!r}")
        result = result if isinstance(result, dict) else {}
        with self._lock:
            rec = normalize_record(self.require(serial))
            notes: list[str] = []
            ok = bool(result.get("ok"))
            err = _clean_text(result.get("error"), 500) if result.get("error") else ""
            if not ok:
                notes.append(f"page reported failure: {err}" if err else "page reported failure")
            if result.get("interrupted") and not (n == 2 and "boot.img" in self._served_names(result)):
                # A stage 2 board leaves the file server once boot.img is out: that is the expected
                # hand-off to the gadget ramdisk, not an interruption worth telling the operator.
                notes.append("run was interrupted")
            if n == 1:
                ok = self._apply_stage1(rec, result, ok, notes)
            elif n == 2:
                ok = self._apply_stage2(rec, result, ok, notes)
            else:
                ok = self._apply_stage3(rec, result, ok, notes)
            rec["facts"][f"stage{n}"] = {
                "ok": ok,
                "at": utc_now_iso(),
                "error": err,
                "notes": notes[:20],
                **self._stage_facts(n, result),
            }
            if ok:
                note = "ok"
            else:
                reasons = [x for x in notes if not x.startswith("warning:")]
                note = "failed: " + ("; ".join(reasons) if reasons else (err or "unknown error"))
            _add_event(rec, f"stage{n}", note)
            saved = self._save(rec)
            return saved, {"ok": ok, "notes": notes}

    # stage rules ---------------------------------------------------------------------------------

    def _apply_stage1(self, rec: dict, result: dict, ok: bool, notes: list[str]) -> bool:
        md_in = result.get("metadata")
        md = {str(k): _clean_text(v, 1024) for k, v in md_in.items()} if isinstance(md_in, dict) else {}
        rec["metadata"].update(md)
        if md.get("MAC_ADDR"):
            rec["mac"] = md["MAC_ADDR"].lower()
        if md.get("FACTORY_UUID"):
            rec["factory_uuid"] = md["FACTORY_UUID"]
        if md.get("USER_BOARDREV"):
            rec["boardrev"] = md["USER_BOARDREV"].lower()
        reported_hash = md.get("CUSTOMER_KEY_HASH", "").lower()
        if reported_hash:
            rec["otp_key_hash"] = reported_hash
        if md.get("SECURE_BOOT_PROVISION") == "success":
            # OTP writes are permanent: once provisioned, never downgraded by a later report.
            rec["secure_boot_provisioned"] = True

        eeprom = md.get("EEPROM_UPDATE")
        if eeprom is None:
            notes.append("no EEPROM_UPDATE in metadata")
            ok = False
        elif eeprom != "success":
            notes.append(f"EEPROM_UPDATE={eeprom}")
            ok = False

        expect = result.get("expect") if isinstance(result.get("expect"), dict) else {}
        if expect.get("secure_boot_provision"):
            sbp = md.get("SECURE_BOOT_PROVISION")
            if sbp != "success":
                notes.append(f"SECURE_BOOT_PROVISION={sbp or 'missing'} (expected success)")
                ok = False
            want = (expect.get("customer_key_hash") or rec["customer_key_hash"] or "").lower()
            if reported_hash != rec["customer_key_hash"] or (want and reported_hash != want):
                notes.append(
                    f"CUSTOMER_KEY_HASH {reported_hash or 'missing'} does not match this board's key "
                    f"{rec['customer_key_hash']}"
                )
                ok = False
        elif self.is_locked(rec) and not self.locked_to_our_key(rec):
            notes.append("warning: board OTP is locked to a different key (CUSTOMER_KEY_HASH " f"{rec['otp_key_hash']})")

        usn = md.get("USER_SERIAL_NUM")
        if usn:
            u = usn.strip().lower()
            if u.startswith("0x"):
                u = u[2:]
            if u[-8:] != rec["serial"]:
                notes.append(f"warning: USER_SERIAL_NUM {usn} differs from the USB serial {rec['serial']}")
        if ok:
            rec["stage"] = _stage_max(rec["stage"], "eeprom")
        return ok

    @staticmethod
    def _served_names(result: dict) -> list[str]:
        files = result.get("files_served")
        if not isinstance(files, list):
            return []
        return [str(f.get("name")) for f in files if isinstance(f, dict) and f.get("name")]

    def _apply_stage2(self, rec: dict, result: dict, ok: bool, notes: list[str]) -> bool:
        if "boot.img" not in self._served_names(result):
            notes.append("boot.img was not served to the board")
            ok = False
        if ok:
            rec["stage"] = _stage_max(rec["stage"], "gadget")
        return ok

    def _apply_stage3(self, rec: dict, result: dict, ok: bool, notes: list[str]) -> bool:
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        pem = details.get("device_key_pem")
        if pem:
            if not _is_public_pem(pem):
                notes.append("warning: device_key_pem ignored (not a PEM public key)")
            elif rec["device_private_pem"] and not same_public_key(pem, rec["device_private_pem"]):
                notes.append("the board reports a device key that differs from the exported one")
                ok = False
            else:
                pem = pem.replace("\r\n", "\n").strip() + "\n"
                if pem != rec["device_key_pem"]:
                    rec["device_key_pem"] = pem
        if ok and self.mode_of(rec) == "secure" and not rec["device_private_pem"]:
            notes.append("the OTP device key was not exported to the server (secure mode needs it)")
            ok = False
        verified = details.get("verified") if isinstance(details.get("verified"), list) else []
        if ok and self.mode_of(rec) == "secure":
            # oem cryptcheck: the board's key must open keyslot 0, the slot the station gave it (1 = recovery)
            good = [v for v in verified if isinstance(v, dict) and isinstance(v.get("dev"), str)
                    and v.get("keyslot") == 0 and not isinstance(v.get("keyslot"), bool)]
            if not good or len(good) != len(verified):
                notes.append("the page did not confirm that the board's OTP key opens keyslot 0 of its station-built "
                             "encrypted root (oem cryptcheck); the board may not boot")
                ok = False
        if ok:
            rec["stage"] = "flashed"
        return ok

    def _stage_facts(self, n: int, result: dict) -> dict:
        if n in (1, 2):
            files = result.get("files_served")
            served = []
            if isinstance(files, list):
                for f in files[:50]:
                    if isinstance(f, dict) and f.get("name"):
                        size = f.get("size")
                        served.append({"name": _clean_text(f["name"], 200), "size": size if isinstance(size, int) else None})
            return {"files_served": served}
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        flashed = details.get("flashed") if isinstance(details.get("flashed"), list) else []
        # Only what the station asked for is kept: whatever else the page sends (a passphrase, say) is not.
        verified_in = details.get("verified") if isinstance(details.get("verified"), list) else []
        verified = []
        for c in verified_in[:16]:
            if isinstance(c, dict) and isinstance(c.get("dev"), str):
                v = {"dev": _clean_text(c["dev"], 64)}
                if isinstance(c.get("keyslot"), int) and not isinstance(c.get("keyslot"), bool):
                    v["keyslot"] = c["keyslot"]
                verified.append(v)
        return {"flashed": [x if isinstance(x, (str, int)) else _clean_text(x, 200) for x in flashed[:100]],
                "verified": verified}

    # operator overrides --------------------------------------------------------------------------

    def mark_locked(self, serial: str, note: str = "") -> dict:
        """Record that the board OTP holds this module's key hash (``otp_key_hash = customer_key_hash``,
        ``secure_boot_provisioned = true``) without a stage-1 report.

        Escape hatch for a board whose OTP was programmed while the stage-1 result never reached the
        server (page closed, POST lost): without it the server keeps planning unsigned stages the ROM
        rejects. Appends an ``otp_override`` event.

        :raises KeyError: unknown module. :raises ValueError: the module has no private signing key (a key
            generated now cannot be the one burnt into the OTP, and without the private key nothing can
            be signed for this board anyway).
        """
        with self._lock:
            rec = normalize_record(self.require(serial))
            if not rec["rsa_private_pem"]:
                raise ValueError(f"module {rec['serial']} has no private signing key; marking it locked would be "
                                 "useless (nothing could be signed for it). Restore the key in storage first")
            # Never generate keys here: only fill in what follows from the existing private key.
            if not rec["rsa_public_pem"]:
                rec["rsa_public_pem"] = public_pem_from_private(rec["rsa_private_pem"])
            derived = customer_key_hash(rec["rsa_public_pem"])
            if rec["customer_key_hash"] and rec["customer_key_hash"] != derived:
                raise ValueError(f"module {rec['serial']}: stored customer_key_hash {rec['customer_key_hash']} does not "
                                 f"match its RSA key ({derived}); fix the record in storage first")
            rec["customer_key_hash"] = derived
            prev = rec["otp_key_hash"] or "none"
            rec["otp_key_hash"] = rec["customer_key_hash"]
            rec["secure_boot_provisioned"] = True
            text = f"operator marked OTP locked to our key {rec['customer_key_hash']} (was {prev})"
            _add_event(rec, "otp_override", f"{text}; {note}" if note else text)
            return self._save(rec)

    def mark_unlocked(self, serial: str, note: str = "") -> dict:
        """Clear ``otp_key_hash`` and ``secure_boot_provisioned`` (undo a wrong :meth:`mark_locked`).
        Appends an ``otp_override`` event. :raises KeyError: unknown module."""
        with self._lock:
            rec = normalize_record(self.require(serial))
            prev = rec["otp_key_hash"] or "none"
            rec["otp_key_hash"] = ""
            rec["secure_boot_provisioned"] = False
            text = f"operator marked OTP unlocked (was {prev})"
            _add_event(rec, "otp_override", f"{text}; {note}" if note else text)
            return self._save(rec)

    # views ---------------------------------------------------------------------------------------

    @staticmethod
    def is_locked(record: dict) -> bool:
        """The board OTP holds a customer key hash (secure boot provisioned to *some* key)."""
        h = str(record.get("otp_key_hash") or "").strip().lower()
        return h not in ("", ZERO_HASH)

    def locked_to_our_key(self, record: dict) -> bool:
        """The board OTP holds exactly this module's ``customer_key_hash``."""
        h = str(record.get("otp_key_hash") or "").strip().lower()
        ours = str(record.get("customer_key_hash") or "").strip().lower()
        return self.is_locked(record) and bool(ours) and h == ours

    def public_view(self, record: dict) -> dict:
        """The Module JSON of SPEC section 8. Never contains ``rsa_private_pem`` or ``device_secret``."""
        r = normalize_record(record)
        stage = r["stage"]
        return {
            "serial": r["serial"],
            "stage": stage,
            "stage_label": STAGE_LABELS.get(stage, stage),
            "mode": self.mode_of(r),
            "mode_chosen": r["mode"],
            "mode_locked": self.is_locked(r) or r["secure_boot_provisioned"],
            "created": r["created"],
            "updated": r["updated"],
            "chip": r["chip"],
            "board": r["board"],
            "duid": r["duid"],
            "mac": r["mac"],
            "factory_uuid": r["factory_uuid"],
            "boardrev": r["boardrev"],
            "secrets": {
                "rsa_key": bool(r["rsa_private_pem"]),
                "customer_key_hash": r["customer_key_hash"],
                "device_secret": bool(r["device_secret"]),
                "rsa_key_fingerprint": _fingerprint(r["rsa_public_pem"]) if r["rsa_public_pem"] else "",
            },
            "otp": {
                "customer_key_hash": r["otp_key_hash"],
                "locked": self.is_locked(r),
                "locked_to_our_key": self.locked_to_our_key(r),
                "secure_boot_provisioned": r["secure_boot_provisioned"],
                "device_key": bool(r["device_key_pem"]),
                "device_key_fingerprint": _fingerprint(r["device_key_pem"]) if r["device_key_pem"] else "",
                "device_key_exported": bool(r["device_private_pem"]),
            },
            "metadata": r["metadata"],
            "facts": r["facts"],
            "events": r["events"],
        }

    def secrets_for(self, serial: str) -> dict:
        """``{"rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret", "device_private_pem"}``
        for the module (missing secrets are generated and stored first; ``device_private_pem`` is ``""``
        until the gadget exported the OTP device key). :raises KeyError: unknown module."""
        with self._lock:
            rec = normalize_record(self.require(serial))
            if self._ensure_secrets(rec):
                rec = self._save(rec)
            return {k: rec[k] for k in _SECRET_KEYS}


__all__ = [
    "STAGES",
    "STAGE_LABELS",
    "ZERO_HASH",
    "FASTBOOT_VARS",
    "normalize_serial",
    "ModuleService",
    "StoreError",
]
