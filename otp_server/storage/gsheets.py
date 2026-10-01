"""Google Sheets store (gspread 6.x): one worksheet, one row per module.

Setup (once, by the operator):

1. In a Google Cloud project enable **both** the Google Sheets API and the Google Drive API.
2. Either create a service account and download its JSON key (``auth: service_account``), or create
   an OAuth "Desktop app" client and download its JSON (``auth: oauth``). With OAuth run
   ``python -m otp_server login`` once on the station: it opens the browser and caches the token in
   ``storage.gsheets.token``. The server itself never opens a browser; when the token is missing or
   rejected (while the OAuth app is in "Testing" the refresh token expires after 7 days) the store
   reports it and the operator runs ``login`` again. ``login`` with a service account only checks
   that the spreadsheet can be opened.
3. Create the spreadsheet **in your own Google account** and, for a service account, share it with
   the key's ``client_email`` as Editor. Service accounts created after 2025-04-15 cannot own Drive
   items, so letting the service account create the spreadsheet does not work.
4. Set ``storage.gsheets.spreadsheet`` to the spreadsheet key or its full URL. The worksheet
   (``storage.gsheets.worksheet``, default ``modules``) is created with the header row when missing.

Row layout: row 1 is the header (:data:`~otp_server.storage.base.FIELDS`, in order; extra columns to
the right are tolerated), every other row is one module. dict/list/bool fields are JSON-encoded
(``true``/``false`` for booleans). All writes use ``value_input_option="RAW"`` so PEMs, hex strings
and serials are stored verbatim and never parsed as numbers or formulas.

Quota (60 requests/min/user): records are cached in memory. ``get``/``put`` refresh the cache when it
is older than 30 s (or, rate-limited to once per 2 s, on a cache miss); ``list`` refreshes at most
every 10 s; ``describe`` never refreshes. Before overwriting a cached row in place, ``put`` reads that
row's serial cell (one small request) and re-reads the sheet when the rows have moved, so a row
deleted, inserted or sorted by hand never gets another module's record written over it. Every
request has an HTTP timeout (:data:`HTTP_TIMEOUT`). The spreadsheet holds board secrets: anyone who can open
it can read the private keys and device secrets.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .base import FIELDS, StoreError, check_serial_key, encode_cell, normalize_record

log = logging.getLogger(__name__)

CELL_LIMIT = 45_000  # Google Sheets hard limit is 50,000 characters per cell


def column_letter(n: int) -> str:
    """1-based column number -> A1 letters (1 -> A, 20 -> T, 27 -> AA)."""
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


LAST_COL = column_letter(len(FIELDS))
_ROW_RE = re.compile(r"![A-Z]+(\d+)")


def exc_named(exc: BaseException, *names: str) -> bool:
    """True when ``exc`` is (a subclass of) a class with one of ``names`` -- lets us recognise
    gspread / google-auth exceptions without importing those libraries."""
    return any(c.__name__ in names for c in type(exc).__mro__)


def check_google_credentials(g: Any, key: str) -> None:
    """Fail early with an actionable message when the credential files cannot work."""
    if g.auth == "service_account":
        if g.credentials is None:
            raise StoreError(
                f"{key}.credentials is not set: download a service-account JSON key "
                "(Google Cloud console > IAM > Service accounts > Keys > Add key > JSON) and point "
                f"{key}.credentials at it"
            )
        if not g.credentials.is_file():
            raise StoreError(f"{key}.credentials: service-account key file not found: {g.credentials}")
    else:  # oauth
        have_token = g.token is not None and g.token.is_file()
        have_client = g.credentials is not None and g.credentials.is_file()
        if not have_token and not have_client:
            raise StoreError(
                f"{key}: auth is oauth but neither the OAuth client JSON ({key}.credentials = "
                f"{g.credentials}) nor a cached token ({key}.token = {g.token}) exists; create an OAuth "
                "'Desktop app' client in the Google Cloud console and download its JSON"
            )


# -- shared Google auth helpers (also used by gdrive.py) ------------------------------------------

#: The CLI command that runs the interactive OAuth login -- the only place a browser is ever opened.
LOGIN_CMD = "python -m otp_server login"
#: How long ``login`` waits for the browser to come back before giving up (seconds).
LOGIN_TIMEOUT = 300
SHEETS_SCOPES = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
#: (connect, read) seconds for every Sheets HTTP request; gspread's own default is no timeout at all.
HTTP_TIMEOUT = (10, 60)


def is_network_error(exc: BaseException) -> bool:
    """A transport-level failure (DNS, refused/reset connection, timeout): worth retrying."""
    return exc_named(
        exc, "TransportError", "Timeout", "TimeoutError", "timeout", "ConnectionError", "ServerNotFoundError"
    )


def http_status(exc: BaseException) -> int | None:
    """HTTP status of a gspread ``APIError`` (``.response.status_code`` / ``.code``) or a googleapiclient
    ``HttpError`` (``.resp.status``); ``None`` when the exception carries none."""
    for holder, attr in ((getattr(exc, "response", None), "status_code"), (getattr(exc, "resp", None), "status"),
                         (exc, "code")):
        value = getattr(holder, attr, None) if holder is not None else None
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            continue
    return None


def is_auth_failure(exc: BaseException) -> bool:
    """Google rejected the credentials themselves (not a network hiccup): a non-retryable
    ``RefreshError`` or an HTTP 401."""
    if exc_named(exc, "RefreshError"):
        return not getattr(exc, "retryable", False)
    return http_status(exc) == 401


def credentials_rejected(g: Any, key: str, what: str, exc: BaseException) -> str:
    """Operator advice when Google refuses the configured credentials, per auth mode."""
    if g.auth == "service_account":
        return (
            f"{what}: the service-account key {g.credentials} was rejected ({exc}): it was deleted, "
            "disabled or rotated; create a new JSON key (Google Cloud console > IAM > Service accounts > "
            f"Keys > Add key > JSON) and point {key}.credentials at it"
        )
    return (
        f"{what}: the OAuth token {g.token} was rejected ({exc}): it was revoked or has expired (an OAuth "
        f"app in 'Testing' issues 7-day tokens); run '{LOGIN_CMD}' on this machine to log in again"
    )


def explain_refresh_error(g: Any, key: str, what: str, exc: BaseException) -> str:
    """A failed credential refresh: rejected credentials, or just no network (retried later)."""
    if exc_named(exc, "RefreshError") and not getattr(exc, "retryable", False):
        return credentials_rejected(g, key, what, exc)
    return (
        f"{what}: cannot reach Google to refresh the credentials ({type(exc).__name__}: {exc}); "
        "check the network -- retrying"
    )


def save_token(path: Path, creds: Any) -> None:
    """Write an OAuth token atomically (0600 on POSIX)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".token.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(creds.to_json())
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_oauth_token(g: Any, key: str, scopes: list[str], what: str) -> Any:
    """The cached OAuth token, refreshed when needed. Never interactive: this runs on request threads,
    so a missing or rejected token is a :class:`StoreError` that tells the operator to run ``login``."""
    if g.token is None or not g.token.is_file():
        raise StoreError(
            f"{what}: not logged in (no OAuth token at {key}.token = {g.token}); run '{LOGIN_CMD}' on this "
            "machine once"
        )
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError:
        raise StoreError("google-auth is not installed (pip install -r requirements.txt)") from None
    try:
        creds = Credentials.from_authorized_user_file(str(g.token), scopes)
    except (OSError, ValueError) as exc:
        raise StoreError(
            f"{what}: the OAuth token file {g.token} is unreadable ({type(exc).__name__}); run '{LOGIN_CMD}' "
            "to log in again"
        ) from None
    if creds.valid:
        return creds
    if not creds.refresh_token:
        raise StoreError(
            f"{what}: the OAuth token {g.token} has expired and holds no refresh token; run '{LOGIN_CMD}' "
            "to log in again"
        )
    try:
        creds.refresh(Request())
    except Exception as exc:
        raise StoreError(explain_refresh_error(g, key, what, exc)) from None
    try:
        save_token(g.token, creds)
    except OSError as exc:
        log.warning("%s: could not save the refreshed OAuth token to %s (%s); using it from memory", what, g.token, exc)
    return creds


def run_oauth_flow(client_file: Path, scopes: list[str], *, timeout: float, open_browser: bool = True) -> Any:
    """The interactive browser login (``InstalledAppFlow`` on a loopback port). CLI only."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_file), scopes)
    return flow.run_local_server(port=0, timeout_seconds=max(1, int(timeout)), open_browser=open_browser)


def oauth_login(g: Any, key: str, scopes: list[str], what: str, *, timeout: float, open_browser: bool = True) -> Any:
    """Run the interactive OAuth login and cache the token (``python -m otp_server login`` only)."""
    if g.credentials is None or not g.credentials.is_file():
        raise StoreError(
            f"{what}: auth is oauth but the OAuth client JSON ({key}.credentials = {g.credentials}) does not "
            "exist; create an OAuth 'Desktop app' client in the Google Cloud console and download its JSON"
        )
    if g.token is None:
        raise StoreError(f"{key}.token is not set")
    try:
        creds = run_oauth_flow(g.credentials, scopes, timeout=timeout, open_browser=open_browser)
    except ImportError:
        raise StoreError("google-auth-oauthlib is not installed (pip install -r requirements.txt)") from None
    except Exception as exc:
        if exc_named(exc, "WSGITimeoutError"):
            raise StoreError(f"{what}: no answer from the browser within {int(timeout)} s; run '{LOGIN_CMD}' again") from None
        raise StoreError(f"{what}: OAuth login failed ({type(exc).__name__}: {exc})") from None
    try:
        save_token(g.token, creds)
    except OSError as exc:
        raise StoreError(f"{what}: could not save the OAuth token to {g.token}: {exc}") from None
    return creds


def service_account_email(g: Any) -> str:
    """``client_email`` of the configured service-account key (for messages)."""
    try:
        return str(json.loads(Path(g.credentials).read_text(encoding="utf-8")).get("client_email") or "?")
    except (OSError, ValueError, TypeError, AttributeError):
        return "?"


def fs_permission_error(exc: BaseException) -> bool:
    """A PermissionError from the local file system (it has an errno / file name), as opposed to the
    bare ``PermissionError`` gspread raises for an HTTP 403."""
    return isinstance(exc, PermissionError) and (exc.errno is not None or exc.filename is not None)


class GoogleSheetsStore:
    """Module registry in a Google Sheets worksheet.

    :param cfg: the server :class:`~otp_server.config.Config` (``cfg.storage.gsheets`` is used).
    :param client: an already authorized gspread ``Client`` (or a test fake with ``open_by_key`` /
        ``open_by_url``). When ``None`` the client is created lazily from the configured credentials.
    :param clock: monotonic clock (tests).
    """

    backend = "gsheets"
    INDEX_MAX_AGE = 30.0
    LIST_MAX_AGE = 10.0
    MISS_MIN_INTERVAL = 2.0
    RETRY_CONNECT_AFTER = 10.0

    def __init__(self, cfg: Any, *, client: Any = None, clock: Callable[[], float] = time.monotonic):
        g = cfg.storage.gsheets
        self.gcfg = g
        if not g.spreadsheet:
            raise StoreError(
                "storage.gsheets.spreadsheet is not set: create a spreadsheet in your Google account, "
                "share it with the service account's client_email (Editor) and put its key or URL here"
            )
        if client is None:
            check_google_credentials(g, "storage.gsheets")
        self._gc = client
        self._own_client = client is None   # only a client built here may be dropped and rebuilt
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
        return f"Google Sheets {self.gcfg.spreadsheet} / {self.gcfg.worksheet}"

    def _make_client(self) -> Any:
        try:
            import gspread
        except ImportError:
            raise StoreError("the gspread package is not installed (pip install -r requirements.txt)") from None
        g = self.gcfg
        if g.auth == "service_account":
            gc = gspread.service_account(filename=str(g.credentials))
        else:
            # Never gspread.oauth(): with no token it starts a browser login on this (request) thread.
            gc = gspread.authorize(load_oauth_token(g, "storage.gsheets", SHEETS_SCOPES, "Google Sheets"))
        return self._with_timeout(gc)

    @staticmethod
    def _with_timeout(gc: Any) -> Any:
        """Bound every Sheets request: a stalled one would otherwise hold the store lock forever."""
        hc = getattr(gc, "http_client", None)
        if hc is not None and hasattr(hc, "set_timeout"):
            hc.set_timeout(HTTP_TIMEOUT)
        return gc

    def _drop_client_on_auth_failure(self, exc: BaseException) -> None:
        """A rejected token/key: forget the connection so the next connect (after the retry throttle)
        rebuilds the client and re-reads the token file -- a ``python -m otp_server login`` done while
        the server runs then takes effect without a restart."""
        if not is_auth_failure(exc):
            return
        self._ws = None
        if self._own_client:
            self._gc = None

    def _explain(self, exc: BaseException) -> str:
        self._drop_client_on_auth_failure(exc)
        g = self.gcfg
        who = (
            "the service account's client_email"
            if g.auth == "service_account"
            else "the Google account you logged in with (python -m otp_server login)"
        )
        if exc_named(exc, "SpreadsheetNotFound"):
            return (
                f"spreadsheet {g.spreadsheet!r} not found or not shared: share it with {who} as Editor "
                "(and enable the Sheets + Drive APIs)"
            )
        if exc_named(exc, "NoValidUrlKeyFound"):
            return f"storage.gsheets.spreadsheet {g.spreadsheet!r} is not a spreadsheet URL"
        if exc_named(exc, "RefreshError"):
            return explain_refresh_error(g, "storage.gsheets", "Google Sheets", exc)
        if is_network_error(exc):
            return f"Google Sheets unreachable ({type(exc).__name__}: {exc}); check the network -- retrying"
        if exc_named(exc, "APIError"):
            return f"Google Sheets API error: {exc}"
        if fs_permission_error(exc):
            return f"local file-system permission error (not a spreadsheet sharing problem): {exc}"
        if isinstance(exc, PermissionError):  # gspread: HTTP 403 on open
            return f"no permission to open spreadsheet {g.spreadsheet!r}: share it with {who} as Editor"
        if isinstance(exc, FileNotFoundError):
            return f"Google credentials file not found: {exc}"
        return f"Google Sheets error: {type(exc).__name__}: {exc}"

    def login(self, *, timeout: float = LOGIN_TIMEOUT, open_browser: bool = True) -> str:
        """``python -m otp_server login``: with ``auth: oauth`` run the browser login (bounded by
        ``timeout``) and cache the token; with a service account only check that the spreadsheet opens.
        Then connect once and return a one-line result for the operator.

        :raises StoreError: the login or the connectivity check failed.
        """
        g = self.gcfg
        gc = None
        if g.auth == "oauth":
            creds = oauth_login(g, "storage.gsheets", SHEETS_SCOPES, "Google Sheets", timeout=timeout,
                                open_browser=open_browser)
            try:
                import gspread
            except ImportError:
                raise StoreError("the gspread package is not installed (pip install -r requirements.txt)") from None
            gc = self._with_timeout(gspread.authorize(creds))
            head = f"OAuth login done, token saved to {g.token}"
        else:
            head = f"service account {service_account_email(g)}"
        with self._lock:
            if gc is not None:
                self._gc = gc
            self._ws = None
            self._last_error = None
            self._last_attempt = float("-inf")
            self._connect()
            return f"{head}: {self.location} is reachable, {len(self._records)} module record(s)"

    def _connect(self) -> Any:
        if self._ws is not None:
            return self._ws
        now = self._clock()
        if self._last_error is not None and now - self._last_attempt < self.RETRY_CONNECT_AFTER:
            raise StoreError(self._last_error)
        self._last_attempt = now
        try:
            if self._gc is None:
                self._gc = self._make_client()
            s = self.gcfg.spreadsheet.strip()
            sh = self._gc.open_by_url(s) if s.startswith(("http://", "https://")) else self._gc.open_by_key(s)
            name = self.gcfg.worksheet
            try:
                ws = sh.worksheet(name)
            except Exception as exc:
                if not exc_named(exc, "WorksheetNotFound"):
                    raise
                log.info("creating worksheet %r in the registry spreadsheet", name)
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
        has_data = any(any(str(c).strip() for c in row) for row in values[1:])
        if has_data:
            raise StoreError(
                f"worksheet {self.gcfg.worksheet!r} already holds data under a different header "
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
            raise StoreError(f"worksheet {self.gcfg.worksheet!r}: header row changed; expected " + ", ".join(FIELDS))
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
                    resp = ws.append_row(cells, value_input_option="RAW", table_range="A1")
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
