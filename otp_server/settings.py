"""Server settings kept in the ``settings`` worksheet of the station spreadsheet (there is no config file).

Layout: row 1 is ``key | value | description``, then one row per setting, ``key`` being the dotted name
from :data:`otp_server.config.DEFAULTS` (``provisioning.default_mode``, ``builds.image.overrides``, ...).
Values are plain text: ``true``/``false`` for switches, numbers as digits, lists (``builds.image.overrides``)
one item per line (never split at commas: a ``KEY=a,b`` override keeps its comma), multi-line text
(``provisioning.boot_conf``) as it is. An empty value means "the
default". The server appends a row (with the default and a description) for every setting the sheet
lacks and never changes a value an operator wrote.

``server.*`` and ``paths.work`` are not settings: they are needed before anyone has signed in, so they
come from the command line / environment (:mod:`otp_server.config`).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from .config import DEFAULTS
from .google_account import NotSignedIn, exc_named, is_auth_failure
from .storage.base import StoreError

log = logging.getLogger(__name__)

WORKSHEET = "settings"
HEADER = ["key", "value", "description"]
#: Not settings: needed before the Google login (command line / environment).
BOOTSTRAP = ("server", "paths.work")

DESCRIPTIONS: dict[str, str] = {
    "paths.droneos": "droneos checkout the image is built from (relative to the repository root)",
    "provisioning.default_mode": "scenario the page preselects for a new board: open or secure",
    "provisioning.jtag_lock": "secure scenario: also burn program_jtag_lock=1 (IRREVERSIBLE)",
    "provisioning.recovery_passphrase": "secure scenario: add a server-derived LUKS passphrase as keyslot 1",
    "provisioning.confirm_irreversible": "the page asks the operator to type the serial before OTP writes / erase",
    "provisioning.erase_storage": "stage 3: erase the storage device before the image is written",
    "provisioning.firmware_channel": "rpi-eeprom firmware channel for stage 1: default or latest",
    "provisioning.max_piece_size": "largest sparse piece sent to the board (bytes, rpi-fastbootd max-download-size)",
    "provisioning.boot_conf": "EEPROM boot.conf written in stage 1 (multi-line)",
    "builds.auto": "build what is missing (tools, gadget, both images) once the station is signed in",
    "builds.tools.image_tag": "Docker tag of the tools image",
    "builds.gadget.targets": "pi-gen-micro device list of the fastboot gadget",
    "builds.gadget.image_tag": "Docker tag of the gadget builder image",
    "builds.gadget.volume": "Docker volume with the gadget build tree",
    "builds.image.config": "rpi-image-gen config inside the droneos checkout",
    "builds.image.overrides": "extra KEY=VALUE overrides for the droneos build, one per line "
                              "(IGconf_image_pmap is set per scenario)",
    "builds.image.builder_tag": "Docker tag of the droneos builder image",
    "builds.image.volume": "Docker volume with the droneos build tree",
    "builds.image.keep_raw_image": "keep the raw .img next to the sparse pieces",
    "docker.binary": "docker CLI to run",
    "docker.start_desktop": "Windows: start Docker Desktop when the engine is down",
    "docker.desktop_path": "Docker Desktop executable (empty = the standard location)",
    "docker.idle_timeout": "seconds without output before a docker build/run is stopped (0 = never)",
}


def setting_defaults() -> list[tuple[str, Any]]:
    """``[(dotted key, default value)]`` of every sheet-backed setting, in :data:`DEFAULTS` order."""
    out: list[tuple[str, Any]] = []

    def walk(prefix: str, node: dict) -> None:
        for k, v in node.items():
            key = f"{prefix}{k}"
            if key in BOOTSTRAP:
                continue
            if isinstance(v, dict):
                walk(key + ".", v)
            else:
                out.append((key, v))

    walk("", DEFAULTS)
    return out


def encode_value(value: Any) -> str:
    """Cell text for a setting value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value)
    return str(value)


def decode_rows(rows: dict[str, str]) -> tuple[dict, list[str]]:
    """``(nested settings tree, unknown keys)`` from ``{key: cell text}``.

    Empty cells are left out (the default applies); lists are split by lines only (an item may contain
    commas); everything else stays text and is validated by :func:`otp_server.config.load_config`.
    """
    defaults = dict(setting_defaults())
    tree: dict[str, Any] = {}
    unknown: list[str] = []
    for key, text in rows.items():
        if key not in defaults:
            unknown.append(key)
            continue
        raw = str(text if text is not None else "")
        if not raw.strip():
            continue
        if isinstance(defaults[key], list):
            parts = raw.replace("\r\n", "\n").split("\n")
            value: Any = [p.strip() for p in parts if p.strip()]
        elif isinstance(defaults[key], str) and "\n" in defaults[key]:
            value = raw.replace("\r\n", "\n")
        else:
            value = raw.strip()
        node = tree
        parts = key.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    return tree, unknown


class SettingsSheet:
    """The ``settings`` worksheet: read (and complete with defaults) the station settings.

    :param account: :class:`~otp_server.google_account.GoogleAccount` (or a fake with ``spreadsheet()``).
    """

    def __init__(self, account: Any, *, worksheet: str = WORKSHEET, clock: Callable[[], float] = time.monotonic):
        self.account = account
        self.worksheet = worksheet
        self._clock = clock
        self._lock = threading.RLock()

    def _open(self) -> Any:
        sh = self.account.spreadsheet()
        try:
            return sh.worksheet(self.worksheet)
        except Exception as exc:
            if not exc_named(exc, "WorksheetNotFound"):
                raise
        log.info("creating worksheet %r in the station spreadsheet", self.worksheet)
        ws = sh.add_worksheet(title=self.worksheet, rows=max(40, len(setting_defaults()) + 10), cols=len(HEADER))
        ws.update([HEADER], "A1:C1", value_input_option="RAW")
        return ws

    def read(self) -> dict[str, str]:
        """``{key: cell text}``; missing settings are appended with their defaults first.

        :raises StoreError: Google is not reachable / not signed in (the operator text says why).
        """
        with self._lock:
            try:
                ws = self._open()
                values = ws.get_all_values()
                header = [str(c).strip().lower() for c in (values[0] if values else [])]
                if header[:2] != HEADER[:2]:
                    if any(any(str(c).strip() for c in row) for row in values):
                        raise StoreError(f"worksheet {self.worksheet!r}: row 1 must be: " + " | ".join(HEADER))
                    ws.update([HEADER], "A1:C1", value_input_option="RAW")
                    values = [HEADER]
                rows: dict[str, str] = {}
                for row in values[1:]:
                    key = str(row[0]).strip() if row else ""
                    if not key or key.startswith("#"):
                        continue
                    if key in rows:
                        log.warning("settings sheet: duplicate key %s ignored", key)
                        continue
                    rows[key] = str(row[1]) if len(row) > 1 else ""
                missing = [(k, v) for k, v in setting_defaults() if k not in rows]
                if missing:
                    ws.append_rows([[k, encode_value(v), DESCRIPTIONS.get(k, "")] for k, v in missing],
                                   value_input_option="RAW", insert_data_option="INSERT_ROWS", table_range="A1")
                    log.info("settings sheet: added %d default setting(s)", len(missing))
                    for k, v in missing:
                        rows[k] = encode_value(v)
                return rows
            except StoreError:
                raise
            except Exception as exc:
                text = self.account.explain(exc)
                if is_auth_failure(exc):        # Google rejected the login mid-call: the station is signed out
                    raise NotSignedIn(text) from None
                raise StoreError(text) from None
