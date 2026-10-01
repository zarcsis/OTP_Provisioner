"""The station's Google account: OAuth login from the page and the spreadsheet the server keeps everything in.

There is no configuration file: the server's settings (``settings`` worksheet) and the module registry
(``modules`` worksheet) both live in one Google spreadsheet, so signing in to Google is required before
anything else works.

* **OAuth client.** An OAuth client of type "Desktop app" (Google Cloud console > APIs & Services >
  Credentials), downloaded as JSON to ``<repo>/google-oauth-client.json``. For desktop clients Google
  does not treat the client secret as confidential, so it ships with the repository. The project needs
  the Google Sheets API and the Google Drive API enabled. The only scope is ``drive.file`` (non-sensitive),
  so the app can be published without Google's verification: no test-user list, no 7-day token expiry.
* **Login.** The page sends the operator to ``/api/google/login``; the server answers with a redirect to
  Google's consent screen, Google redirects back to ``http://127.0.0.1:<port>/?state=..&code=..`` (a
  loopback redirect, allowed for desktop clients) and the server exchanges the code (PKCE) for a token.
  ``python -m otp_server login`` does the same from a terminal.
* **What stays on this machine** (``<work>/google/``): ``token.json`` (the OAuth token) and
  ``spreadsheet.json`` (which spreadsheet belongs to which signed-in account). Nothing else.
* **One spreadsheet per Google account.** Every operator signs in with their own account and works in
  their own spreadsheet "OTP_Provisioner", in their own Drive; spreadsheets of different accounts never
  meet (scope ``drive.file``: under a user's login the server only sees the files it created for that
  user). On a sign-in the server opens the account's remembered spreadsheet, else finds the one it created
  in that account's Drive earlier (another station), else creates it with the ``modules`` and ``settings``
  worksheets.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .storage.base import StoreError

log = logging.getLogger(__name__)

#: Only ``drive.file``: per-file access to the files this app created. The Sheets API accepts it for such
#: spreadsheets, and it is a non-sensitive scope, so the OAuth app can be published ("In production") without
#: Google's verification: any Google account can sign in, there is no test-user list and no 7-day token expiry
#: (the ``spreadsheets`` scope is sensitive and would force all of that).
SCOPES = ["https://www.googleapis.com/auth/drive.file"]
SPREADSHEET_TITLE = "OTP_Provisioner"
CLIENT_FILE_NAME = "google-oauth-client.json"
SHEET_MIME = "application/vnd.google-apps.spreadsheet"
DRIVE_ABOUT_URL = "https://www.googleapis.com/drive/v3/about"
DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files"
LOGIN_PATH = "/api/google/login"
LOGIN_CMD = "python -m otp_server login"
#: (connect, read) seconds for every Sheets HTTP request; gspread's own default is no timeout at all.
HTTP_TIMEOUT = (10, 60)
#: Pending browser logins are forgotten after this many seconds.
FLOW_TTL = 900


class NotSignedIn(StoreError):
    """No usable Google login (no token, or Google rejected it): the operator has to sign in."""


def exc_named(exc: BaseException, *names: str) -> bool:
    """True when ``exc`` is (a subclass of) a class with one of ``names`` -- lets us recognise
    gspread / google-auth exceptions without importing those libraries."""
    return any(c.__name__ in names for c in type(exc).__mro__)


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


def is_network_error(exc: BaseException) -> bool:
    """A transport-level failure (DNS, refused/reset connection, timeout): worth retrying."""
    return exc_named(
        exc, "TransportError", "Timeout", "TimeoutError", "timeout", "ConnectionError", "ServerNotFoundError"
    )


def is_auth_failure(exc: BaseException) -> bool:
    """Google rejected the credentials themselves (not a network hiccup): a non-retryable
    ``RefreshError`` or an HTTP 401."""
    if isinstance(exc, NotSignedIn):
        return True
    if exc_named(exc, "RefreshError"):
        return not getattr(exc, "retryable", False)
    return http_status(exc) == 401


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` atomically (0600 on POSIX)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class GoogleAccount:
    """OAuth credentials of the station and the spreadsheet opened with them.

    :param repo_root: repository root (holds ``google-oauth-client.json``).
    :param work_dir: work directory (``google/token.json``, ``google/spreadsheet.json``).
    :param client_factory: tests: ``() -> gspread-like client`` used instead of a real login.
    """

    def __init__(self, repo_root: Path, work_dir: Path, *, client_factory: Callable[[], Any] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.client_file = Path(repo_root) / CLIENT_FILE_NAME
        self.token_file = Path(work_dir) / "google" / "token.json"
        self.sheet_file = Path(work_dir) / "google" / "spreadsheet.json"
        self._client_factory = client_factory
        self._clock = clock
        self._lock = threading.RLock()
        self._flows: dict[str, tuple[float, Any]] = {}
        self._gc: Any = None
        self._sh: Any = None
        #: (account e-mail, spreadsheet id) once connected; None after a new login until the next connection
        self._current: tuple[str, str] | None = None
        self._fresh_login = False
        self.last_error = ""

    # ------------------------------------------------------------------ state
    def client_configured(self) -> bool:
        """``google-oauth-client.json`` exists and looks like an OAuth client (or a test client is injected)."""
        if self._client_factory is not None:
            return True
        try:
            data = json.loads(self.client_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(data, dict) and any(isinstance(data.get(k), dict) for k in ("installed", "web"))

    def has_token(self) -> bool:
        return self._client_factory is not None or self.token_file.is_file()

    def _sheet_data(self) -> dict:
        """``spreadsheet.json``: ``{"id", "title", "email", "accounts": {email: id}}`` (``{}`` when unreadable)."""
        try:
            data = json.loads(self.sheet_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _remember(self, email: str, sid: str) -> None:
        data = self._sheet_data()
        accounts = data.get("accounts") if isinstance(data.get("accounts"), dict) else {}
        if email:
            accounts[email] = sid
        _atomic_write(self.sheet_file, json.dumps(
            {"id": sid, "title": SPREADSHEET_TITLE, "email": email, "accounts": accounts}, indent=2) + "\n")
        self._current = (email, sid)
        self._fresh_login = False

    def account_email(self) -> str:
        """E-mail of the signed-in account, once the server has connected (``""`` before that)."""
        return self._current[0] if self._current else ""

    def spreadsheet_id(self) -> str:
        """The spreadsheet of the signed-in account: the connected one, else the last one used on this station
        (``""`` right after a new sign-in, until the server has connected with it)."""
        if self._current:
            return self._current[1]
        if self._fresh_login:
            return ""
        return str(self._sheet_data().get("id") or "")

    def spreadsheet_url(self) -> str:
        sid = self.spreadsheet_id()
        return f"https://docs.google.com/spreadsheets/d/{sid}/edit" if sid else ""

    def status(self) -> dict:
        """``{"client", "client_file", "signed_in", "email", "spreadsheet_id", "spreadsheet_url", "error"}``
        (cheap; no network)."""
        return {
            "client": self.client_configured(),
            "client_file": str(self.client_file),
            "signed_in": self.has_token(),
            "email": self.account_email(),
            "spreadsheet_id": self.spreadsheet_id(),
            "spreadsheet_url": self.spreadsheet_url(),
            "error": self.last_error,
        }

    # ------------------------------------------------------------------ login
    def _require_client_file(self) -> None:
        if not self.client_configured():
            raise StoreError(
                f"no OAuth client: create an OAuth client of type 'Desktop app' in the Google Cloud console "
                f"(APIs & Services > Credentials; enable the Google Sheets and Google Drive APIs), download its "
                f"JSON and save it as {self.client_file}"
            )

    def begin_login(self, redirect_uri: str) -> str:
        """Start a browser login; returns the Google consent URL to send the operator to."""
        self._require_client_file()
        try:
            from google_auth_oauthlib.flow import Flow
        except ImportError:
            raise StoreError("google-auth-oauthlib is not installed (pip install -r requirements.txt)") from None
        flow = Flow.from_client_secrets_file(str(self.client_file), scopes=SCOPES, redirect_uri=redirect_uri,
                                             autogenerate_code_verifier=True)
        url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopes="true")
        now = self._clock()
        with self._lock:
            self._flows = {s: v for s, v in self._flows.items() if now - v[0] < FLOW_TTL}
            self._flows[state] = (now, flow)
        return url

    def pending_login(self, state: str) -> bool:
        with self._lock:
            entry = self._flows.get(state)
            return entry is not None and self._clock() - entry[0] < FLOW_TTL

    def finish_login(self, state: str, code: str) -> None:
        """Exchange the code Google redirected back with for a token and save it."""
        with self._lock:
            entry = self._flows.pop(state, None)
        if entry is None or self._clock() - entry[0] >= FLOW_TTL:
            raise StoreError("this Google login is unknown or has expired; start it again from the page")
        flow = entry[1]
        os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")   # Google may echo the scopes in another order
        try:
            flow.fetch_token(code=code)
        except Exception as exc:
            raise StoreError(f"Google did not accept the login ({type(exc).__name__}: {exc}); try again") from None
        self.save_credentials(flow.credentials)

    def login_interactive(self, *, timeout: float = 300, open_browser: bool = True) -> None:
        """Terminal login (``python -m otp_server login``): a loopback browser flow, token saved."""
        self._require_client_file()
        try:
            from google_auth_oauthlib.flow import InstalledAppFlow
        except ImportError:
            raise StoreError("google-auth-oauthlib is not installed (pip install -r requirements.txt)") from None
        flow = InstalledAppFlow.from_client_secrets_file(str(self.client_file), SCOPES)
        try:
            creds = flow.run_local_server(port=0, timeout_seconds=max(1, int(timeout)), open_browser=open_browser)
        except Exception as exc:
            if exc_named(exc, "WSGITimeoutError"):
                raise StoreError(f"no answer from the browser within {int(timeout)} s; run '{LOGIN_CMD}' again") from None
            raise StoreError(f"Google login failed ({type(exc).__name__}: {exc})") from None
        self.save_credentials(creds)

    def save_credentials(self, creds: Any) -> None:
        _atomic_write(self.token_file, creds.to_json())
        with self._lock:
            self._gc = None
            self._sh = None
            self._current = None        # possibly another account: its spreadsheet is looked up on connect
            self._fresh_login = True
            self.last_error = ""
        log.info("Google login saved to %s", self.token_file)

    def logout(self) -> None:
        """Forget the token (the spreadsheet id is kept: signing in again reopens the same spreadsheet)."""
        try:
            self.token_file.unlink()
        except FileNotFoundError:
            pass
        with self._lock:
            self._gc = None
            self._sh = None
            self._current = None
            self.last_error = ""

    # ------------------------------------------------------------------ connection
    def credentials(self) -> Any:
        """The saved token, refreshed when needed. :raises NotSignedIn: no token or Google rejected it."""
        if not self.token_file.is_file():
            raise NotSignedIn("not signed in to Google: open the page and sign in")
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
        except ImportError:
            raise StoreError("google-auth is not installed (pip install -r requirements.txt)") from None
        try:
            creds = Credentials.from_authorized_user_file(str(self.token_file), SCOPES)
        except (OSError, ValueError) as exc:
            raise NotSignedIn(f"the saved Google login is unreadable ({type(exc).__name__}); sign in again") from None
        if creds.valid:
            return creds
        if not creds.refresh_token:
            raise NotSignedIn("the Google login has expired; sign in again")
        try:
            creds.refresh(Request())
        except Exception as exc:
            if exc_named(exc, "RefreshError") and not getattr(exc, "retryable", False):
                raise NotSignedIn(f"Google rejected the saved login ({exc}): it was revoked or has expired "
                                  "(an OAuth app in 'Testing' issues 7-day logins); sign in again") from None
            raise StoreError(f"cannot reach Google to refresh the login ({type(exc).__name__}: {exc}); "
                             "check the network -- retrying") from None
        try:
            _atomic_write(self.token_file, creds.to_json())
        except OSError as exc:
            log.warning("could not save the refreshed Google token to %s (%s); using it from memory",
                        self.token_file, exc)
        return creds

    def client(self) -> Any:
        """An authorized gspread client (cached)."""
        with self._lock:
            if self._gc is not None:
                return self._gc
            if self._client_factory is not None:
                self._gc = self._client_factory()
                return self._gc
            try:
                import gspread
            except ImportError:
                raise StoreError("the gspread package is not installed (pip install -r requirements.txt)") from None
            gc = gspread.authorize(self.credentials())
            hc = getattr(gc, "http_client", None)
            if hc is not None and hasattr(hc, "set_timeout"):
                hc.set_timeout(HTTP_TIMEOUT)
            self._gc = gc
            return gc

    @staticmethod
    def _drive(gc: Any) -> Any:
        """gspread's authorized HTTP client (``None`` for clients without one: test fakes)."""
        hc = getattr(gc, "http_client", None)
        return hc if hc is not None and hasattr(hc, "request") else None

    def _signed_in_email(self, gc: Any) -> str:
        """Drive ``about.user.emailAddress`` of the signed-in account (``""`` when it cannot be told)."""
        hc = self._drive(gc)
        if hc is None:
            return ""
        r = hc.request("get", DRIVE_ABOUT_URL, params={"fields": "user(emailAddress)"})
        return str(((r.json() or {}).get("user") or {}).get("emailAddress") or "").strip().lower()

    def _find_own_spreadsheet(self, gc: Any) -> str:
        """Id of the newest "OTP_Provisioner" spreadsheet this app created in the account's Drive (not trashed)."""
        hc = self._drive(gc)
        if hc is None:
            return ""
        q = f"name = '{SPREADSHEET_TITLE}' and mimeType = '{SHEET_MIME}' and trashed = false"
        r = hc.request("get", DRIVE_FILES_URL, params={"q": q, "orderBy": "modifiedTime desc", "pageSize": 10,
                                                      "fields": "files(id,name,modifiedTime)"})
        files = (r.json() or {}).get("files") or []
        return str(files[0].get("id") or "") if files else ""

    @staticmethod
    def _gone(exc: BaseException) -> bool:
        return exc_named(exc, "SpreadsheetNotFound") or http_status(exc) in (403, 404) or (
            isinstance(exc, PermissionError) and exc.errno is None and exc.filename is None)

    def spreadsheet(self) -> Any:
        """The signed-in account's spreadsheet.

        Remembered for the account in ``spreadsheet.json`` -> opened; else the newest "OTP_Provisioner"
        this app created in the account's Drive (e.g. on another station) -> adopted; else created. A
        remembered spreadsheet of this account that is gone is an error (never replaced silently: that
        would start an empty registry). Accounts never see each other's spreadsheets.
        """
        with self._lock:
            if self._sh is not None:
                return self._sh
            gc = self.client()
            email = self._signed_in_email(gc)
            data = self._sheet_data()
            accounts = data.get("accounts") if isinstance(data.get("accounts"), dict) else {}
            mine = str(accounts.get(email) or "") if email else ""
            last = str(data.get("id") or "")
            last_owner = str(data.get("email") or "")
            if not mine and last and (not email or not last_owner or last_owner == email):
                mine = last          # the station's last spreadsheet, recorded before accounts were known
                adopted = bool(email)
            else:
                adopted = False
            if mine:
                try:
                    sh = gc.open_by_key(mine)
                except Exception as exc:
                    if adopted and self._gone(exc):
                        sh = None    # the station's old spreadsheet is another account's: look in this one's Drive
                    elif exc_named(exc, "SpreadsheetNotFound") or http_status(exc) == 404:
                        raise StoreError(
                            f"the station spreadsheet {mine}{' of ' + email if email else ''} is gone (deleted, or "
                            f"not created by this OAuth client); restore it from the Drive trash, or delete "
                            f"{self.sheet_file} to let the server find or create another one") from None
                    else:
                        raise        # e.g. HTTP 403: explained by explain()
                if sh is not None:
                    self._remember(email, mine)
                    self._sh = sh
                    return sh
            found = self._find_own_spreadsheet(gc)
            if found:
                sh = gc.open_by_key(found)
                self._remember(email, found)
                log.info("using the station spreadsheet %s found in the Drive of %s", found, email or "this account")
                self._sh = sh
                return sh
            sh = gc.create(SPREADSHEET_TITLE)
            self._remember(email, sh.id)
            try:
                sh.sheet1.update_title("modules")     # the registry; "settings" is added next to it
            except Exception as exc:  # cosmetic only: the stores add the worksheets they miss
                log.info("could not rename the first worksheet of the new spreadsheet: %s", exc)
            log.info("created the station spreadsheet %s (%s) for %s", SPREADSHEET_TITLE, sh.id, email or "this account")
            self._sh = sh
            return sh

    def drop_connection(self) -> None:
        """Forget the cached client/spreadsheet (after an auth failure the next call re-reads the token)."""
        with self._lock:
            self._gc = None
            self._sh = None

    def explain(self, exc: BaseException) -> str:
        """Operator text for a failure talking to Google (and drop the connection on auth failures)."""
        if is_auth_failure(exc):
            self.drop_connection()
        if isinstance(exc, StoreError):
            text = str(exc)
        elif exc_named(exc, "RefreshError") and not getattr(exc, "retryable", False):
            text = f"Google rejected the saved login ({exc}); sign in again"
        elif exc_named(exc, "RefreshError") or is_network_error(exc):
            text = f"Google unreachable ({type(exc).__name__}: {exc}); check the network -- retrying"
        elif exc_named(exc, "APIError"):
            text = f"Google Sheets API error: {exc}"
        elif isinstance(exc, PermissionError) and exc.errno is None and exc.filename is None:
            text = "Google refused access to the station spreadsheet (HTTP 403); sign in again with the account that created it"
        else:
            text = f"Google Sheets error: {type(exc).__name__}: {exc}"
        self.last_error = text
        return text
