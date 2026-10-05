"""Server settings kept in the ``settings`` worksheet of the station spreadsheet (there is no config file).

Layout: row 1 is ``key | value | description``, then one row per setting, ``key`` being the dotted name
from :data:`otp_server.config.DEFAULTS` (``provisioning.default_mode``, ``builds.image.overrides``, ...).
Values are plain text: ``true``/``false`` for switches, numbers as digits, lists (``builds.image.overrides``)
one item per line (never split at commas: a ``KEY=a,b`` override keeps its comma), multi-line text
(``provisioning.boot_conf``) as it is, ``image.wifi_password`` exactly as typed (spaces belong to a
passphrase). An empty value means "the default". The server appends a row (with the default and a
description) for every setting the sheet lacks, removes the rows of retired settings (:data:`RETIRED`)
and otherwise changes a value only when the page saves one (:meth:`SettingsSheet.write`: the image
settings form).

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

#: Retired settings: their rows are removed from the sheet (the value no longer means anything).
RETIRED: dict[str, str] = {
    "paths.droneos": "the image is built from the station's image/ directory",
    "builds.image.config": "the rpi-image-gen config is written from the image.* settings",
}
#: Defaults of earlier versions that an older server wrote into the sheet; read as the current default (the
#: cell is rewritten). Any other value is the operator's and stays.
REPLACED_DEFAULTS: dict[str, frozenset[str]] = {
    "builds.image.builder_tag": frozenset({"droneos-builder:trixie"}),
    "builds.image.volume": frozenset({"otp-droneos-work"}),
    "image.name": frozenset({"deb13-arm64-min"}),
}
#: Descriptions earlier versions wrote; such a cell is rewritten with the current text (any other text in the
#: description column is the operator's note and stays).
OLD_DESCRIPTIONS: dict[str, frozenset[str]] = {
    "builds.image.overrides": frozenset({"extra KEY=VALUE overrides for the droneos build, one per line "
                                         "(IGconf_image_pmap is set per scenario)"}),
    "builds.image.builder_tag": frozenset({"Docker tag of the droneos builder image"}),
    "builds.image.volume": frozenset({"Docker volume with the droneos build tree"}),
    "image.timezone": frozenset({"time zone (IANA name, e.g. Europe/Kyiv)"}),
    "image.wifi_country": frozenset({"Wi-Fi regulatory country, two letters (UA; 00 = world)"}),
    "image.name": frozenset({"image name (part of the image set names)"}),
    "image.hostname": frozenset({"hostname of the boards"}),
    "image.user": frozenset({"login account created on the boards"}),
}
#: Values kept exactly as typed (never trimmed).
RAW_VALUES = frozenset({"image.wifi_password"})

DESCRIPTIONS: dict[str, str] = {
    "provisioning.default_mode": "scenario the page preselects for a new board: open or secure",
    "provisioning.jtag_lock": "secure scenario: also burn program_jtag_lock=1 (IRREVERSIBLE)",
    "provisioning.recovery_passphrase": "secure scenario: add a server-derived LUKS passphrase as keyslot 1",
    "provisioning.confirm_irreversible": "the page asks the operator to type the serial before OTP writes / erase",
    "provisioning.erase_storage": "stage 3: erase the storage device before the image is written",
    "provisioning.firmware_channel": "rpi-eeprom firmware channel for stage 1: default or latest",
    "provisioning.max_piece_size": "largest sparse piece sent to the board (bytes, rpi-fastbootd max-download-size)",
    "provisioning.boot_conf": "EEPROM boot.conf written in stage 1 (multi-line)",
    "image.name": "name of the OS image (Raspberry Pi OS Lite; part of the image set names; a new name rebuilds it). "
                  "The other image.* settings are written to each board at stage 3 and rebuild nothing",
    "image.hostname": "host name of the boards; {serial} = the board's 8-hex serial (pi5-{serial})",
    "image.timezone": "time zone of the image's tzdata (Europe/Kyiv, UTC, ...; the page offers the list)",
    "image.keyboard": "keyboard layout of the boards' console (xkb: us, gb, ua, ...; the page offers the list). "
                      "Raspberry Pi OS itself defaults to gb, where Shift+2 is \" and Shift+' is @",
    "image.user": "the boards' login account (Raspberry Pi OS renames its first user pi to it at first boot)",
    "image.password_hash": "crypt hash of the account password (set it on the page; empty = no password)",
    "image.ssh": "SSH server on the boards",
    "image.ssh_password_login": "SSH accepts the account password (false = keys only)",
    "image.ssh_authorized_keys": "SSH public keys of the account, one per line",
    "image.wifi_ssid": "Wi-Fi network the boards join (empty = no Wi-Fi profile)",
    "image.wifi_password": "Wi-Fi passphrase (8-63 characters or a 64-digit hex key; empty = open network)",
    "image.wifi_country": "Wi-Fi country known to wireless-regdb, two letters (UA; 00 = world; the page offers the list)",
    "image.wifi_hidden": "the Wi-Fi network does not broadcast its name",
    "builds.auto": "build what is missing (tools, gadget, both images) once the station is signed in",
    "builds.tools.image_tag": "Docker tag of the tools image",
    "builds.gadget.targets": "pi-gen-micro device list of the fastboot gadget",
    "builds.gadget.image_tag": "Docker tag of the gadget builder image",
    "builds.gadget.volume": "Docker volume with the gadget build tree",
    "builds.image.overrides": "extra IGconf_KEY=VALUE overrides for rpi-image-gen, one per line "
                              "(IGconf_image_pmap is set per scenario)",
    "builds.image.builder_tag": "Docker tag of the image builder (rpi-image-gen)",
    "builds.image.volume": "Docker volume with the image build tree",
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
        if key in RETIRED:
            continue
        if key not in defaults:
            unknown.append(key)
            continue
        raw = str(text if text is not None else "")
        if not raw.strip():
            continue
        if key in RAW_VALUES:
            value: Any = raw
        elif isinstance(defaults[key], list):
            parts = raw.replace("\r\n", "\n").split("\n")
            value = [p.strip() for p in parts if p.strip()]
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
    """The ``settings`` worksheet: read (and complete with defaults) and write the station settings.

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

    def _values(self, ws: Any) -> list[list[str]]:
        """All rows of the worksheet, row 1 checked (and written into an empty sheet)."""
        values = ws.get_all_values()
        header = [str(c).strip().lower() for c in (values[0] if values else [])]
        if header[:2] != HEADER[:2]:
            if any(any(str(c).strip() for c in row) for row in values):
                raise StoreError(f"worksheet {self.worksheet!r}: row 1 must be: " + " | ".join(HEADER))
            ws.update([HEADER], "A1:C1", value_input_option="RAW")
            values = [HEADER]
        return values

    def _failed(self, exc: Exception) -> Exception:
        text = self.account.explain(exc)
        if is_auth_failure(exc):        # Google rejected the login mid-call: the station is signed out
            return NotSignedIn(text)
        return StoreError(text)

    def read(self) -> dict[str, str]:
        """``{key: cell text}``; missing settings are appended with their defaults first, rows of retired
        settings are deleted, defaults and descriptions written by earlier versions (:data:`REPLACED_DEFAULTS`,
        :data:`OLD_DESCRIPTIONS`) are replaced; everything else the operator wrote stays.

        :raises StoreError: Google is not reachable / not signed in (the operator text says why).
        """
        with self._lock:
            try:
                ws = self._open()
                values = self._values(ws)
                rows: dict[str, str] = {}
                where: dict[str, int] = {}
                descs: dict[str, str] = {}
                retired: list[tuple[int, str]] = []
                for n, row in enumerate(values[1:], start=2):
                    key = str(row[0]).strip() if row else ""
                    if not key or key.startswith("#"):
                        continue
                    if key in RETIRED:
                        retired.append((n, key))
                        continue
                    if key in rows:
                        log.warning("settings sheet: duplicate key %s ignored", key)
                        continue
                    rows[key] = str(row[1]) if len(row) > 1 else ""
                    where[key] = n
                    descs[key] = str(row[2]) if len(row) > 2 else ""
                defaults = dict(setting_defaults())
                for key, n in where.items():      # before any row is deleted: the row numbers are still valid
                    if rows[key].strip() in REPLACED_DEFAULTS.get(key, ()):
                        new = encode_value(defaults[key])
                        ws.update([[new]], f"B{n}", value_input_option="RAW")
                        log.info("settings sheet: %s %r was the default of an earlier version, now %r",
                                 key, rows[key], new)
                        rows[key] = new
                    if descs[key].strip() in OLD_DESCRIPTIONS.get(key, ()):
                        ws.update([[DESCRIPTIONS[key]]], f"C{n}", value_input_option="RAW")
                for n, key in sorted(retired, reverse=True):      # bottom up: the row numbers stay valid
                    ws.delete_rows(n)
                    log.info("settings sheet: removed the retired setting %s (%s)", key, RETIRED[key])
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
                raise self._failed(exc) from None

    def write(self, updates: dict[str, Any]) -> dict[str, str]:
        """Write settings (dotted key -> value) into the sheet: the value cell of an existing row, else a new
        row with the description. Values go in as RAW text (``00`` stays text, ``=x`` is no formula).

        :returns: ``{key: cell text written}``
        :raises ValueError: a key that is not a setting.
        :raises StoreError: Google is not reachable / not signed in.
        """
        defaults = dict(setting_defaults())
        bad = [k for k in updates if k not in defaults]
        if bad:
            raise ValueError("not a setting: " + ", ".join(sorted(bad)))
        written = {k: encode_value(v) for k, v in updates.items()}
        if not written:
            return written
        with self._lock:
            try:
                ws = self._open()
                values = self._values(ws)
                where: dict[str, int] = {}
                for n, row in enumerate(values[1:], start=2):
                    key = str(row[0]).strip() if row else ""
                    if key and key not in where:
                        where[key] = n
                new_rows = []
                for key, text in written.items():
                    if key in where:
                        ws.update([[text]], f"B{where[key]}", value_input_option="RAW")
                    else:
                        new_rows.append([key, text, DESCRIPTIONS.get(key, "")])
                if new_rows:
                    ws.append_rows(new_rows, value_input_option="RAW", insert_data_option="INSERT_ROWS",
                                   table_range="A1")
                log.info("settings sheet: wrote %s", ", ".join(sorted(written)))
                return written
            except StoreError:
                raise
            except Exception as exc:
                raise self._failed(exc) from None
