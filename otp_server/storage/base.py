"""Record schema and store protocol shared by every storage backend (SPEC section 6).

A *record* is a plain dict with exactly the keys in :data:`FIELDS` (in that order; the Google Sheets
header row uses exactly these names):

* scalar fields are ``str`` (``''`` when unknown),
* ``secure_boot_provisioned`` is ``bool``,
* ``metadata`` and ``facts`` are ``dict``,
* ``events`` is a list of ``{"t": iso, "kind": str, "note": str}`` (last :data:`MAX_EVENTS` kept),
* ``stage`` is one of :data:`STAGES`,
* timestamps are UTC ISO-8601 with seconds: ``2026-09-30T12:34:56Z``.

Records contain secrets (``rsa_private_pem``, ``device_secret``): never log a record.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger(__name__)

FIELDS: tuple[str, ...] = (
    "serial",
    "stage",
    "created",
    "updated",
    "chip",
    "board",
    "duid",
    "mac",
    "factory_uuid",
    "boardrev",
    "customer_key_hash",
    "otp_key_hash",
    "secure_boot_provisioned",
    "device_key_pem",
    "rsa_public_pem",
    "rsa_private_pem",
    "device_secret",
    "metadata",
    "facts",
    "events",
)

STAGES: tuple[str, ...] = ("new", "eeprom", "gadget", "flashed")
BOOL_FIELDS = frozenset({"secure_boot_provisioned"})
DICT_FIELDS = frozenset({"metadata", "facts"})
LIST_FIELDS = frozenset({"events"})
#: Fields stored lowercase (hex values and the serial).
LOWER_FIELDS = frozenset({"serial", "duid", "customer_key_hash", "otp_key_hash", "device_secret", "boardrev"})
MAX_EVENTS = 100

# Store keys are file names / sheet keys: keep them boring.
_SERIAL_KEY_RE = re.compile(r"^[0-9a-z][0-9a-z_-]{0,63}$")


class StoreError(Exception):
    """The store is misconfigured or unreachable. The message is meant for the operator."""


@runtime_checkable
class ModuleStore(Protocol):
    """Upsert-by-serial record store."""

    backend: str

    def get(self, serial: str) -> dict | None:
        """The record for ``serial`` or ``None``."""

    def put(self, record: dict) -> None:
        """Insert or replace the record keyed by ``record["serial"]``."""

    def list(self) -> list[dict]:
        """All records (order is backend-specific)."""

    def describe(self) -> dict:
        """``{"backend", "ok": bool, "location": str, "detail": str}`` -- cheap, safe to poll."""


def utc_now_iso() -> str:
    """Current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_serial_key(serial: Any) -> str:
    """Validate a record key before it becomes a file name or sheet key; returns it lowercased."""
    s = str(serial or "").strip().lower()
    if not _SERIAL_KEY_RE.match(s):
        raise StoreError(f"invalid module serial for storage: {serial!r}")
    return s


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _as_json(v: Any, kind: type) -> Any:
    if isinstance(v, kind):
        return copy.deepcopy(v)
    if isinstance(v, str) and v.strip():
        try:
            parsed = json.loads(v)
        except ValueError:
            log.warning("record field holds non-JSON text; replaced with an empty %s", kind.__name__)
            return kind()
        if isinstance(parsed, kind):
            return parsed
    return kind()


def _norm_event(e: Any) -> dict | None:
    if not isinstance(e, dict):
        return None
    return {
        "t": str(e.get("t") or ""),
        "kind": str(e.get("kind") or ""),
        "note": str(e.get("note") if e.get("note") is not None else ""),
    }


def normalize_record(d: dict) -> dict:
    """Return a new record with every field of :data:`FIELDS` present and of the right type.

    Unknown keys are dropped, ``None`` becomes the empty value, JSON text in ``metadata`` /
    ``facts`` / ``events`` (as read back from a sheet cell) is decoded, booleans are parsed from
    ``"TRUE"``/``"true"``/``"1"``, hex fields and the serial are lowercased, ``stage`` falls back to
    ``"new"`` when empty or unknown, and ``events`` keeps the last :data:`MAX_EVENTS` entries.
    """
    src = d or {}
    out: dict[str, Any] = {}
    for f in FIELDS:
        v = src.get(f)
        if f in BOOL_FIELDS:
            out[f] = _as_bool(v)
        elif f in DICT_FIELDS:
            out[f] = _as_json(v, dict)
        elif f in LIST_FIELDS:
            evs = [_norm_event(e) for e in _as_json(v, list)]
            out[f] = [e for e in evs if e is not None][-MAX_EVENTS:]
        else:
            s = "" if v is None else (v if isinstance(v, str) else str(v))
            if f in LOWER_FIELDS:
                s = s.strip().lower()
            out[f] = s
    if out["stage"] not in STAGES:
        if out["stage"]:
            log.warning("record %s: unknown stage %r reset to 'new'", out["serial"], out["stage"])
        out["stage"] = "new"
    return out


def encode_cell(field: str, value: Any) -> str:
    """Encode one record field as a sheet cell string (JSON for dict/list, ``true``/``false``)."""
    if field in BOOL_FIELDS:
        return "true" if value else "false"
    if field in DICT_FIELDS or field in LIST_FIELDS:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "" if value is None else str(value)


def record_to_json(record: dict) -> str:
    """Serialize a (normalized) record for file-based backends."""
    return json.dumps(normalize_record(record), ensure_ascii=False, indent=2) + "\n"
