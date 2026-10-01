"""Google Sheets module registry (gspread 6.x): worksheet ``modules`` of the station spreadsheet.

The spreadsheet and the login come from :class:`otp_server.google_account.GoogleAccount` (the operator
signs in to Google on the page; the server creates the spreadsheet on first use). This is the only
place board records are kept.

Row layout: row 1 is the header (:data:`~otp_server.storage.base.FIELDS`, in order; extra columns to
the right are tolerated, and a header written by an older version -- a prefix of the current one -- is
extended in place), every other row is one module. dict/list/bool fields are JSON-encoded
(``true``/``false`` for booleans). All writes use ``value_input_option="RAW"`` so PEMs, hex strings
and serials are stored verbatim and never parsed as numbers or formulas.

Quota (60 requests/min/user): records are cached in memory. ``get``/``put`` refresh the cache when it
is older than 30 s (or, rate-limited to once per 2 s, on a cache miss); ``list`` refreshes at most
every 10 s; ``describe`` never refreshes. Before overwriting a cached row in place, ``put`` reads that
row's serial cell (one small request) and re-reads the sheet when the rows have moved, so a row
deleted, inserted or sorted by hand never gets another module's record written over it. Every
request has an HTTP timeout. The spreadsheet holds board secrets: anyone who can open it can read
the private keys and device secrets (a demo station: protecting them is out of scope).
"""

from __future__ import annotations

import copy
import logging
import re
import threading
import time
from typing import Any, Callable

from .base import FIELDS, StoreError, check_serial_key, encode_cell, normalize_record

log = logging.getLogger(__name__)


def exc_named(exc: BaseException, *names: str) -> bool:
    """True when ``exc`` is (a subclass of) a class with one of ``names`` -- recognises gspread /
    google-auth exceptions without importing those libraries (a copy of the one in google_account,
    which imports this package)."""
    return any(c.__name__ in names for c in type(exc).__mro__)

CELL_LIMIT = 45_000  # Google Sheets hard limit is 50,000 characters per cell
WORKSHEET = "modules"


def column_letter(n: int) -> str:
    """1-based column number -> A1 letters (1 -> A, 20 -> T, 27 -> AA)."""
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


LAST_COL = column_letter(len(FIELDS))
_ROW_RE = re.compile(r"![A-Z]+(\d+)")


class GoogleSheetsStore:
    """Module registry in the ``modules`` worksheet of the station spreadsheet.

    :param account: the :class:`~otp_server.google_account.GoogleAccount` (or a test fake with
        ``spreadsheet()``, ``explain(exc)`` and ``spreadsheet_url()``).
    :param clock: monotonic clock (tests).
    """

    backend = "gsheets"
    INDEX_MAX_AGE = 30.0
    LIST_MAX_AGE = 10.0
    MISS_MIN_INTERVAL = 2.0
    RETRY_CONNECT_AFTER = 10.0

    def __init__(self, account: Any, *, worksheet: str = WORKSHEET, clock: Callable[[], float] = time.monotonic):
        self.account = account
        self.worksheet = worksheet
        self._clock = clock
        self._lock = threading.RLock()
        self._ws: Any = None
        self._records: dict[str, dict] = {}
        self._rows: dict[str, int] = {}
        self._loaded_at = float("-inf")
        self._last_attempt = float("-inf")
        self._last_error: str | None = None

    # -- connection ---------------------------------------------------------------------------------

    @property
    def location(self) -> str:
        url = ""
        try:
            url = self.account.spreadsheet_url()
        except Exception:  # noqa: BLE001 - only for display
            pass
        return f"Google Sheets {url or '(not created yet)'} / {self.worksheet}"

    def _explain(self, exc: BaseException) -> str:
        if isinstance(exc, StoreError):
            return str(exc)
        self._ws = None if self._ws is not None and _auth_like(exc) else self._ws
        return self.account.explain(exc)

    def reset(self) -> None:
        """Forget the connection and the cache (after a new login)."""
        with self._lock:
            self._ws = None
            self._records, self._rows = {}, {}
            self._loaded_at = float("-inf")
            self._last_attempt = float("-inf")
            self._last_error = None

    def _connect(self) -> Any:
        if self._ws is not None:
            return self._ws
        now = self._clock()
        if self._last_error is not None and now - self._last_attempt < self.RETRY_CONNECT_AFTER:
            raise StoreError(self._last_error)
        self._last_attempt = now
        try:
            sh = self.account.spreadsheet()
            name = self.worksheet
            try:
                ws = sh.worksheet(name)
            except Exception as exc:
                if not exc_named(exc, "WorksheetNotFound"):
                    raise
                log.info("creating worksheet %r in the station spreadsheet", name)
                ws = sh.add_worksheet(title=name, rows=100, cols=len(FIELDS))
                ws.update([list(FIELDS)], f"A1:{LAST_COL}1", value_input_option="RAW")
            values = ws.get_all_values()
            values = self._check_header(ws, values)
            self._ws = ws
            self._load(values)
        except StoreError as exc:
            self._last_error = str(exc)
            raise
        except Exception as exc:
            self._last_error = self._explain(exc)
            raise StoreError(self._last_error) from None
        self._last_error = None
        return self._ws

    def _check_header(self, ws: Any, values: list[list[Any]]) -> list[list[Any]]:
        header = [str(c).strip() for c in (values[0] if values else [])]
        while header and not header[-1]:
            header.pop()
        if header[: len(FIELDS)] == list(FIELDS):
            return values
        if header and len(header) < len(FIELDS) and header == list(FIELDS[: len(header)]):
            # Written by an older version: fields are only ever appended, so extend the header in place
            # (rows simply lack the new trailing cells, which read back as empty values).
            log.info("registry sheet: adding column(s) %s to the header", ", ".join(FIELDS[len(header):]))
            cols = getattr(ws, "col_count", None)
            if isinstance(cols, int) and cols < len(FIELDS):
                ws.resize(cols=len(FIELDS))
            ws.update([list(FIELDS)], f"A1:{LAST_COL}1", value_input_option="RAW")
            return [list(FIELDS)] + values[1:]
        has_data = any(any(str(c).strip() for c in row) for row in values[1:])
        if has_data:
            raise StoreError(
                f"worksheet {self.worksheet!r} already holds data under a different header "
                f"(row 1 starts with {header[:4]!r}); use an empty worksheet or make row 1 exactly: "
                + ", ".join(FIELDS)
            )
        cols = getattr(ws, "col_count", None)
        if isinstance(cols, int) and cols < len(FIELDS):
            ws.resize(cols=len(FIELDS))
        ws.update([list(FIELDS)], f"A1:{LAST_COL}1", value_input_option="RAW")
        return [list(FIELDS)]

    # -- cache --------------------------------------------------------------------------------------

    def _load(self, values: list[list[Any]]) -> None:
        records: dict[str, dict] = {}
        rows: dict[str, int] = {}
        n = len(FIELDS)
        for i, row in enumerate(values[1:], start=2):
            cells = [str(c) for c in row[:n]] + [""] * max(0, n - len(row))
            key = cells[0].strip().lower()
            if not key:
                continue
            if key in rows:
                log.warning("registry sheet: duplicate serial %s in row %d ignored (first is row %d)", key, i, rows[key])
                continue
            rec = normalize_record(dict(zip(FIELDS, cells)))
            rows[key] = i
            records[key] = rec
        self._records, self._rows = records, rows
        self._loaded_at = self._clock()

    def _refresh(self) -> None:
        try:
            values = self._ws.get_all_values()
        except Exception as exc:
            raise StoreError(self._explain(exc)) from None
        header = [str(c).strip() for c in (values[0] if values else [])]
        if header[: len(FIELDS)] != list(FIELDS):
            self._ws = None
            raise StoreError(f"worksheet {self.worksheet!r}: header row changed; expected " + ", ".join(FIELDS))
        self._load(values)

    def _age(self) -> float:
        return self._clock() - self._loaded_at

    def _encode(self, rec: dict) -> list[str]:
        cells = [encode_cell(f, rec[f]) for f in FIELDS]
        ev = FIELDS.index("events")
        while len(cells[ev]) > CELL_LIMIT and rec["events"]:
            drop = max(1, len(rec["events"]) // 4)
            rec["events"] = rec["events"][drop:]
            cells[ev] = encode_cell("events", rec["events"])
        for f, c in zip(FIELDS, cells):
            if len(c) > CELL_LIMIT:
                raise StoreError(
                    f"module {rec['serial']}: field {f!r} is {len(c)} characters, over the "
                    f"{CELL_LIMIT}-character Google Sheets cell budget"
                )
        return cells

    # -- ModuleStore --------------------------------------------------------------------------------

    def get(self, serial: str) -> dict | None:
        key = check_serial_key(serial)
        with self._lock:
            self._connect()
            age = self._age()
            if age > self.INDEX_MAX_AGE or (key not in self._records and age > self.MISS_MIN_INTERVAL):
                self._refresh()
            rec = self._records.get(key)
            return copy.deepcopy(rec) if rec is not None else None

    def put(self, record: dict) -> None:
        rec = normalize_record(record)
        key = check_serial_key(rec["serial"])
        rec["serial"] = key
        cells = self._encode(rec)
        with self._lock:
            ws = self._connect()
            age = self._age()
            if age > self.INDEX_MAX_AGE or (key not in self._rows and age > self.MISS_MIN_INTERVAL):
                self._refresh()
            row = self._rows.get(key)
            try:
                if row is not None and not self._row_holds(ws, row, key):
                    # rows were deleted / inserted / sorted in the sheet since the last read: never
                    # overwrite whatever module sits in that row now
                    log.warning("registry sheet: row %d no longer holds %s; re-reading the sheet", row, key)
                    self._refresh()
                    row = self._rows.get(key)
                if row is not None:
                    ws.update([cells], f"A{row}:{LAST_COL}{row}", value_input_option="RAW")
                else:
                    # INSERT_ROWS: never write over rows an operator keeps below a blank row
                    resp = ws.append_row(cells, value_input_option="RAW", insert_data_option="INSERT_ROWS",
                                         table_range="A1")
                    new_row = self._appended_row(resp)
                    if new_row is not None:
                        self._rows[key] = new_row
                    else:
                        self._loaded_at = float("-inf")  # unknown row: re-read before the next write
            except StoreError:
                raise
            except Exception as exc:
                self._loaded_at = float("-inf")
                raise StoreError(self._explain(exc)) from None
            self._records[key] = copy.deepcopy(rec)

    @staticmethod
    def _row_holds(ws: Any, row: int, key: str) -> bool:
        """One cheap read: does column A of ``row`` still hold ``key``?"""
        cell = ws.acell(f"A{row}")
        return str(getattr(cell, "value", "") or "").strip().lower() == key

    @staticmethod
    def _appended_row(resp: Any) -> int | None:
        try:
            rng = resp["updates"]["updatedRange"]
        except (KeyError, TypeError):
            return None
        m = _ROW_RE.search(str(rng))
        return int(m.group(1)) if m else None

    def list(self) -> list[dict]:
        with self._lock:
            self._connect()
            if self._age() > self.LIST_MAX_AGE:
                self._refresh()
            return [copy.deepcopy(r) for r in self._records.values()]

    def describe(self) -> dict:
        with self._lock:
            try:
                self._connect()
            except StoreError as exc:
                return {"backend": self.backend, "ok": False, "location": self.location, "detail": str(exc)}
            return {
                "backend": self.backend,
                "ok": True,
                "location": self.location,
                "detail": f"{len(self._records)} module record(s) cached",
            }


def _auth_like(exc: BaseException) -> bool:
    from ..google_account import is_auth_failure

    return is_auth_failure(exc)

