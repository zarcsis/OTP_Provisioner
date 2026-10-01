"""The station's Google account (otp_server/google_account.py): OAuth client file, token, login flows,
the station spreadsheet and the operator texts for Google failures.

Everything runs against temporary directories with the real google-auth / google-auth-oauthlib / gspread
code where that code stays offline; the token endpoint, the loopback login server and the Sheets API are
replaced. An autouse fixture makes any real HTTP request, browser launch or loopback login fail the test."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import inspect
import json
import os
import time
from urllib.parse import parse_qs, urlsplit

import pytest

from otp_server import google_account as ga
from otp_server.google_account import (
    CLIENT_FILE_NAME,
    FLOW_TTL,
    HTTP_TIMEOUT,
    SCOPES,
    SPREADSHEET_TITLE,
    GoogleAccount,
    NotSignedIn,
    exc_named,
    http_status,
    is_auth_failure,
    is_network_error,
)
from otp_server.storage.base import StoreError

gspread = pytest.importorskip("gspread")
requests = pytest.importorskip("requests")
pytest.importorskip("google.oauth2.credentials")
pytest.importorskip("google_auth_oauthlib.flow")

from google.auth.exceptions import RefreshError, TransportError  # noqa: E402
from google.oauth2.credentials import Credentials  # noqa: E402
from google_auth_oauthlib.flow import InstalledAppFlow, WSGITimeoutError  # noqa: E402
from gspread.client import Client as RealClient  # noqa: E402
from gspread.exceptions import APIError, SpreadsheetNotFound  # noqa: E402
from gspread.worksheet import Worksheet as RealWorksheet  # noqa: E402
from requests_oauthlib import OAuth2Session  # noqa: E402

CLIENT = {
    "client_id": "cid.apps.googleusercontent.com",
    "client_secret": "csecret",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "redirect_uris": ["http://localhost"],
}
REDIRECT = "http://127.0.0.1:8080/"


class Clock:
    def __init__(self):
        self.t = 5000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test may reach Google, open a browser or start the loopback login server."""

    def refuse(*a, **k):
        raise AssertionError("a test tried to open a browser or reach the network")

    import webbrowser

    for name in ("open", "open_new", "open_new_tab"):
        monkeypatch.setattr(webbrowser, name, refuse)
    monkeypatch.setattr(requests.Session, "send", refuse)
    monkeypatch.setattr(InstalledAppFlow, "run_local_server", refuse)
    return refuse


def account(tmp_path, **kw) -> GoogleAccount:
    return GoogleAccount(tmp_path / "repo", tmp_path / "work", **kw)


def write_client(acct: GoogleAccount, data=None, *, kind="installed") -> None:
    acct.client_file.parent.mkdir(parents=True, exist_ok=True)
    payload = data if data is not None else {kind: dict(CLIENT)}
    text = payload if isinstance(payload, str) else json.dumps(payload)
    acct.client_file.write_text(text, encoding="utf-8")


def write_token(acct: GoogleAccount, *, expired=True, refresh_token="r-token", token="old-access") -> None:
    acct.token_file.parent.mkdir(parents=True, exist_ok=True)
    acct.token_file.write_text(json.dumps({
        "token": token, "refresh_token": refresh_token, "client_id": CLIENT["client_id"],
        "client_secret": CLIENT["client_secret"], "token_uri": CLIENT["token_uri"],
        "expiry": "2020-01-01T00:00:00Z" if expired else "2999-01-01T00:00:00Z",
    }), encoding="utf-8")


def write_sheet_id(acct: GoogleAccount, sid: str) -> None:
    acct.sheet_file.parent.mkdir(parents=True, exist_ok=True)
    acct.sheet_file.write_text(json.dumps({"id": sid, "title": SPREADSHEET_TITLE}), encoding="utf-8")


def leftovers(directory):
    """Temporary files an atomic write would leave behind on failure."""
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(".tmp"))


def bind(real, *args, **kwargs):
    """Fail the test when a call does not match the real gspread signature."""
    return inspect.signature(real).bind(None, *args, **kwargs).arguments


class FakeWorksheet:
    def __init__(self, title):
        self.title = title

    def update_title(self, *a, **k):
        self.title = bind(RealWorksheet.update_title, *a, **k)["title"]
        return {}


class FakeSpreadsheet:
    def __init__(self, sid):
        self.id = sid
        self.first = FakeWorksheet("Sheet1")

    @property
    def sheet1(self):
        return self.first


class FakeClient:
    """gspread-shaped client: ``open_by_key`` for known ids, ``create`` mints ``new_id``."""

    def __init__(self, *existing, new_id="NEWID"):
        self.sheets = {sid: FakeSpreadsheet(sid) for sid in existing}
        self.new_id = new_id
        self.opened, self.created = [], []

    def open_by_key(self, *a, **k):
        key = bind(RealClient.open_by_key, *a, **k)["key"]
        self.opened.append(key)
        if key not in self.sheets:
            raise SpreadsheetNotFound(key)
        return self.sheets[key]

    def create(self, *a, **k):
        args = bind(RealClient.create, *a, **k)
        assert args.get("folder_id") is None
        self.created.append(args["title"])
        sh = FakeSpreadsheet(self.new_id)
        self.sheets[sh.id] = sh
        return sh


class Factory:
    """``client_factory`` that counts how often the account (re)builds its client."""

    def __init__(self, client=None):
        self.client = client if client is not None else FakeClient("SHEETKEY")
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.client


def api_error(status, message="boom"):
    resp = requests.Response()
    resp.status_code = status
    resp._content = json.dumps({"error": {"code": status, "message": message, "status": "X"}}).encode()
    return APIError(resp)


# ==================================================================================================
# state: client file, token, spreadsheet id, status
# ==================================================================================================


def test_paths(tmp_path):
    acct = account(tmp_path)
    assert acct.client_file == tmp_path / "repo" / CLIENT_FILE_NAME == tmp_path / "repo" / "google-oauth-client.json"
    assert acct.token_file == tmp_path / "work" / "google" / "token.json"
    assert acct.sheet_file == tmp_path / "work" / "google" / "spreadsheet.json"


@pytest.mark.parametrize("content, ok", [
    (None, False),                                    # missing file
    ("{not json", False),                             # invalid JSON
    ("[1, 2]", False),                                # JSON, but not an object
    (json.dumps({"other": dict(CLIENT)}), False),     # neither "installed" nor "web"
    (json.dumps({"installed": "x"}), False),          # not an object inside
    (json.dumps({"installed": dict(CLIENT)}), True),  # a "Desktop app" client
    (json.dumps({"web": dict(CLIENT)}), True),        # a "Web application" client
], ids=["missing", "invalid-json", "list", "other-key", "installed-not-dict", "installed", "web"])
def test_client_configured(tmp_path, content, ok):
    acct = account(tmp_path)
    if content is not None:
        write_client(acct, content)
    assert acct.client_configured() is ok
    assert acct.status()["client"] is ok


def test_client_configured_with_a_test_client(tmp_path):
    acct = account(tmp_path, client_factory=Factory())
    assert acct.client_configured() is True and acct.has_token() is True
    assert not acct.client_file.exists() and not acct.token_file.exists()


def test_status_spreadsheet_id_and_token(tmp_path):
    acct = account(tmp_path)
    assert acct.status() == {"client": False, "client_file": str(acct.client_file), "signed_in": False, "email": "",
                             "spreadsheet_id": "", "spreadsheet_url": "", "error": ""}
    assert acct.has_token() is False and acct.spreadsheet_id() == "" and acct.spreadsheet_url() == ""
    write_sheet_id(acct, "1AbC-xyz_09")
    assert acct.spreadsheet_id() == "1AbC-xyz_09"
    assert acct.spreadsheet_url() == "https://docs.google.com/spreadsheets/d/1AbC-xyz_09/edit"
    write_token(acct)
    write_client(acct)
    assert acct.has_token() is True
    assert acct.status() == {"client": True, "client_file": str(acct.client_file), "signed_in": True, "email": "",
                             "spreadsheet_id": "1AbC-xyz_09",
                             "spreadsheet_url": "https://docs.google.com/spreadsheets/d/1AbC-xyz_09/edit", "error": ""}
    # a damaged spreadsheet.json reads as "no spreadsheet yet", never as an exception
    for bad in ("{oops", "[]", json.dumps({"id": None}), json.dumps({"title": "x"})):
        acct.sheet_file.write_text(bad, encoding="utf-8")
        assert acct.spreadsheet_id() == "" and acct.spreadsheet_url() == ""
        assert acct.status()["spreadsheet_id"] == ""


# ==================================================================================================
# credentials()
# ==================================================================================================


def test_credentials_without_token_is_not_signed_in(tmp_path):
    acct = account(tmp_path)
    with pytest.raises(NotSignedIn, match="not signed in") as ei:
        acct.credentials()
    assert isinstance(ei.value, StoreError)
    with pytest.raises(NotSignedIn):  # the gspread client needs the same login
        acct.client()
    with pytest.raises(NotSignedIn):
        acct.spreadsheet()


@pytest.mark.parametrize("text", [
    "{not json",
    json.dumps({"token": "t", "client_id": "c"}),  # refresh_token / client_secret missing
], ids=["invalid-json", "missing-fields"])
def test_unreadable_token_is_not_signed_in(tmp_path, text):
    acct = account(tmp_path)
    acct.token_file.parent.mkdir(parents=True)
    acct.token_file.write_text(text, encoding="utf-8")
    with pytest.raises(NotSignedIn, match="unreadable"):
        acct.credentials()


def test_valid_token_is_used_without_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(Credentials, "refresh", lambda self, request: pytest.fail("refreshed a valid token"))
    acct = account(tmp_path)
    write_token(acct, expired=False)
    before = acct.token_file.read_text(encoding="utf-8")
    creds = acct.credentials()
    assert creds.token == "old-access" and creds.valid
    assert acct.token_file.read_text(encoding="utf-8") == before  # not rewritten


def test_expired_token_without_refresh_token_is_not_signed_in(tmp_path):
    acct = account(tmp_path)
    write_token(acct, refresh_token=None)
    with pytest.raises(NotSignedIn, match="expired"):
        acct.credentials()


def test_expired_token_is_refreshed_and_saved(tmp_path, monkeypatch):
    seen = []

    def ok(self, request):
        seen.append(type(request).__module__)
        self.token = "new-access"
        self.expiry = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(hours=1)

    monkeypatch.setattr(Credentials, "refresh", ok)
    acct = account(tmp_path)
    write_token(acct)
    creds = acct.credentials()
    assert creds.token == "new-access" and seen == ["google.auth.transport.requests"]
    saved = json.loads(acct.token_file.read_text(encoding="utf-8"))
    assert saved["token"] == "new-access" and saved["refresh_token"] == "r-token"
    assert saved["client_id"] == CLIENT["client_id"]
    assert leftovers(acct.token_file.parent) == []
    if os.name == "posix":
        assert acct.token_file.stat().st_mode & 0o777 == 0o600
    # the saved token is valid now: the next call does not refresh again
    assert acct.credentials().token == "new-access" and len(seen) == 1


def test_refreshed_token_that_cannot_be_saved_is_still_used(tmp_path, monkeypatch, caplog):
    def ok(self, request):
        self.token = "new-access"
        self.expiry = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(hours=1)

    monkeypatch.setattr(Credentials, "refresh", ok)
    acct = account(tmp_path)
    write_token(acct)
    before = acct.token_file.read_text(encoding="utf-8")
    real_replace = os.replace

    def failing_replace(src, dst, *a, **k):
        if os.path.abspath(dst) == os.path.abspath(acct.token_file):
            raise PermissionError(13, "Permission denied", str(dst))
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(ga.os, "replace", failing_replace)
    with caplog.at_level("WARNING", logger="otp_server.google_account"):
        assert acct.credentials().token == "new-access"
    assert "could not save the refreshed Google token" in caplog.text
    assert acct.token_file.read_text(encoding="utf-8") == before  # old file intact
    assert leftovers(acct.token_file.parent) == []  # temp file removed


def test_revoked_token_is_not_signed_in(tmp_path, monkeypatch):
    def revoked(self, request):
        raise RefreshError("invalid_grant: Token has been expired or revoked.")

    monkeypatch.setattr(Credentials, "refresh", revoked)
    acct = account(tmp_path)
    write_token(acct)
    with pytest.raises(NotSignedIn, match="rejected the saved login") as ei:
        acct.credentials()
    assert "sign in again" in str(ei.value) and "invalid_grant" in str(ei.value)


@pytest.mark.parametrize("exc", [
    TransportError("Failed to establish a new connection"),
    RefreshError("Internal server error", retryable=True),
    requests.exceptions.ConnectionError("connection refused"),
], ids=["transport", "retryable-refresh", "requests-connection"])
def test_refresh_network_error_is_a_store_error_not_a_logout(tmp_path, monkeypatch, exc):
    def offline(self, request):
        raise exc

    monkeypatch.setattr(Credentials, "refresh", offline)
    acct = account(tmp_path)
    write_token(acct)
    with pytest.raises(StoreError, match="cannot reach Google") as ei:
        acct.credentials()
    assert not isinstance(ei.value, NotSignedIn)
    assert acct.token_file.is_file()  # the login is kept for the next try


# ==================================================================================================
# client() / spreadsheet()
# ==================================================================================================


def test_client_is_authorized_with_an_http_timeout_and_cached(tmp_path):
    acct = account(tmp_path)
    write_token(acct, expired=False)
    gc = acct.client()
    assert isinstance(gc, gspread.Client)
    assert gc.http_client.timeout == HTTP_TIMEOUT
    assert all(t is not None and t > 0 for t in HTTP_TIMEOUT)
    assert gc.http_client.auth.token == "old-access"  # authorized with the saved login
    assert acct.client() is gc
    acct.drop_connection()
    assert acct.client() is not gc


def test_spreadsheet_opens_the_saved_id(tmp_path):
    factory = Factory(FakeClient("SHEETKEY"))
    acct = account(tmp_path, client_factory=factory)
    write_sheet_id(acct, "SHEETKEY")
    sh = acct.spreadsheet()
    assert sh is factory.client.sheets["SHEETKEY"]
    assert factory.client.opened == ["SHEETKEY"] and factory.client.created == []
    assert acct.spreadsheet() is sh and factory.client.opened == ["SHEETKEY"]  # cached
    assert sh.sheet1.title == "Sheet1"  # an existing spreadsheet is not renamed


def test_spreadsheet_is_created_on_first_use(tmp_path):
    factory = Factory(FakeClient(new_id="1NewSheetId"))
    acct = account(tmp_path, client_factory=factory)
    sh = acct.spreadsheet()
    assert factory.client.created == [SPREADSHEET_TITLE] == ["OTP_Provisioner"]
    assert sh.id == "1NewSheetId" and sh.sheet1.title == "modules"
    assert json.loads(acct.sheet_file.read_text(encoding="utf-8")) == {
        "id": "1NewSheetId", "title": "OTP_Provisioner", "email": "", "accounts": {}}   # fake client: no e-mail
    assert leftovers(acct.sheet_file.parent) == []  # written atomically
    if os.name == "posix":
        assert acct.sheet_file.stat().st_mode & 0o777 == 0o600
    assert acct.spreadsheet_url() == "https://docs.google.com/spreadsheets/d/1NewSheetId/edit"
    assert acct.spreadsheet() is sh and factory.client.created == ["OTP_Provisioner"]
    # the next server start opens it by id instead of creating another one
    acct2 = account(tmp_path, client_factory=Factory(factory.client))
    assert acct2.spreadsheet() is sh
    assert factory.client.created == ["OTP_Provisioner"] and factory.client.opened == ["1NewSheetId"]


def test_spreadsheet_rename_failure_is_cosmetic(tmp_path):
    client = FakeClient(new_id="NEWID")
    acct = account(tmp_path, client_factory=Factory(client))
    real_create = client.create

    def create(*a, **k):
        sh = real_create(*a, **k)

        def refuse(*a, **k):
            raise api_error(500, "backend error")

        sh.first.update_title = refuse
        return sh

    client.create = create
    sh = acct.spreadsheet()
    assert sh.id == "NEWID" and acct.spreadsheet_id() == "NEWID"


@pytest.mark.parametrize("error", [None, "api404"], ids=["SpreadsheetNotFound", "APIError-404"])
def test_missing_saved_spreadsheet_is_an_actionable_store_error(tmp_path, error):
    client = FakeClient()
    if error == "api404":
        def open_by_key(*a, **k):
            client.opened.append(a)
            raise api_error(404, "Requested entity was not found.")

        client.open_by_key = open_by_key
    acct = account(tmp_path, client_factory=Factory(client))
    write_sheet_id(acct, "GONE123")
    with pytest.raises(StoreError) as ei:
        acct.spreadsheet()
    msg = str(ei.value)
    assert "GONE123" in msg and "gone" in msg and "Drive trash" in msg and str(acct.sheet_file) in msg
    assert client.created == []  # never silently replaced by a new, empty spreadsheet
    assert acct.spreadsheet_id() == "GONE123"


def test_other_open_errors_propagate_for_explain(tmp_path):
    client = FakeClient()

    def forbidden(*a, **k):
        raise PermissionError()  # gspread's HTTP 403

    client.open_by_key = forbidden
    acct = account(tmp_path, client_factory=Factory(client))
    write_sheet_id(acct, "SHEETKEY")
    with pytest.raises(PermissionError) as ei:
        acct.spreadsheet()
    assert "HTTP 403" in acct.explain(ei.value)


# ==================================================================================================
# browser login: begin_login / finish_login
# ==================================================================================================


@pytest.fixture
def token_endpoint(monkeypatch):
    """Google's token endpoint, as seen by requests-oauthlib: records the exchange, returns a token."""
    calls = []

    def fetch_token(self, token_url, code=None, **kw):
        calls.append({"url": token_url, "code": code, "redirect_uri": self.redirect_uri, **kw})
        if code == "bad-code":
            raise ValueError("(invalid_grant) Bad Request")
        self.token = {"access_token": "acc-1", "refresh_token": "ref-1", "token_type": "Bearer",
                      "expires_in": 3599, "expires_at": time.time() + 3599, "scope": list(SCOPES)}
        return self.token

    monkeypatch.setattr(OAuth2Session, "fetch_token", fetch_token)
    return calls


def test_begin_login_without_client_file(tmp_path):
    acct = account(tmp_path)
    with pytest.raises(StoreError, match="google-oauth-client.json") as ei:
        acct.begin_login(REDIRECT)
    assert str(acct.client_file) in str(ei.value) and "Desktop app" in str(ei.value)
    with pytest.raises(StoreError, match="google-oauth-client.json"):
        acct.login_interactive(open_browser=False)


def test_browser_login_round_trip(tmp_path, monkeypatch, token_endpoint):
    monkeypatch.setitem(os.environ, "OAUTHLIB_RELAX_TOKEN_SCOPE", "x")
    monkeypatch.delitem(os.environ, "OAUTHLIB_RELAX_TOKEN_SCOPE")  # restored (absent) after the test
    factory = Factory(FakeClient("SHEETKEY"))
    acct = account(tmp_path, client_factory=factory)
    write_client(acct)
    write_sheet_id(acct, "SHEETKEY")
    gc_before, sh_before = acct.client(), acct.spreadsheet()
    assert factory.calls == 1 and factory.client.opened == ["SHEETKEY"]
    acct.explain(TransportError("offline"))
    assert acct.status()["error"]

    url = acct.begin_login(REDIRECT)
    u = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    assert f"{u.scheme}://{u.netloc}{u.path}" == CLIENT["auth_uri"]
    assert q["client_id"] == CLIENT["client_id"] and q["redirect_uri"] == REDIRECT
    assert q["response_type"] == "code" and q["access_type"] == "offline" and q["prompt"] == "consent"
    assert q["include_granted_scopes"] == "true"
    assert set(q["scope"].split()) == set(SCOPES)
    assert q["code_challenge_method"] == "S256" and q["code_challenge"]
    state = q["state"]
    assert acct.pending_login(state) and not acct.pending_login("other-state")
    assert not acct.token_file.exists()

    acct.finish_login(state, "the-code")
    # the code was exchanged once, at the client's token endpoint, with the PKCE verifier of this login
    assert len(token_endpoint) == 1
    call = token_endpoint[0]
    assert call["url"] == CLIENT["token_uri"] and call["code"] == "the-code" and call["redirect_uri"] == REDIRECT
    challenge = base64.urlsafe_b64encode(hashlib.sha256(call["code_verifier"].encode()).digest()).decode().rstrip("=")
    assert challenge == q["code_challenge"]
    assert os.environ.get("OAUTHLIB_RELAX_TOKEN_SCOPE") == "1"
    # the token is saved (atomically) and is a usable login
    saved = json.loads(acct.token_file.read_text(encoding="utf-8"))
    assert saved["token"] == "acc-1" and saved["refresh_token"] == "ref-1"
    assert saved["client_id"] == CLIENT["client_id"] and saved["client_secret"] == CLIENT["client_secret"]
    assert leftovers(acct.token_file.parent) == []
    assert acct.credentials().token == "acc-1"
    assert not acct.pending_login(state) and acct.status()["error"] == ""
    # the cached client and spreadsheet were dropped: the next use reconnects with the new login
    assert acct.client() is gc_before and factory.calls == 2
    assert acct.spreadsheet() is sh_before and factory.client.opened == ["SHEETKEY", "SHEETKEY"]
    # the same callback cannot be replayed
    with pytest.raises(StoreError, match="unknown or has expired"):
        acct.finish_login(state, "the-code")
    assert len(token_endpoint) == 1


def test_finish_login_with_unknown_state(tmp_path, token_endpoint):
    acct = account(tmp_path)
    write_client(acct)
    acct.begin_login(REDIRECT)
    with pytest.raises(StoreError, match="unknown or has expired"):
        acct.finish_login("forged-state", "the-code")
    assert token_endpoint == [] and not acct.token_file.exists()


def test_finish_login_rejected_code(tmp_path, token_endpoint):
    acct = account(tmp_path)
    write_client(acct, kind="web")
    state = parse_qs(urlsplit(acct.begin_login(REDIRECT)).query)["state"][0]
    with pytest.raises(StoreError, match="Google did not accept the login") as ei:
        acct.finish_login(state, "bad-code")
    assert "invalid_grant" in str(ei.value)
    assert not acct.token_file.exists() and not acct.pending_login(state)  # the flow is used up


def test_expired_pending_logins_are_dropped(tmp_path, token_endpoint):
    clock = Clock()
    acct = account(tmp_path, clock=clock)
    write_client(acct)

    def begin():
        return parse_qs(urlsplit(acct.begin_login(REDIRECT)).query)["state"][0]

    s1 = begin()
    clock.advance(FLOW_TTL - 1)
    s2 = begin()
    assert acct.pending_login(s1) and acct.pending_login(s2)  # still young enough
    clock.advance(2)  # s1 is now older than FLOW_TTL, s2 is not
    s3 = begin()
    assert not acct.pending_login(s1) and acct.pending_login(s2) and acct.pending_login(s3)
    with pytest.raises(StoreError, match="unknown or has expired"):
        acct.finish_login(s1, "the-code")
    acct.finish_login(s2, "the-code")
    assert acct.credentials().token == "acc-1"


# ==================================================================================================
# terminal login, save_credentials, logout
# ==================================================================================================


class FlowCreds:
    def to_json(self):
        return json.dumps({"token": "t", "refresh_token": "r", "client_id": "c", "client_secret": "s"})


def test_login_interactive_runs_the_loopback_flow_with_a_timeout(tmp_path, monkeypatch):
    seen = {}

    class Flow:
        def run_local_server(self, **k):
            seen.update(k)
            return FlowCreds()

    def from_file(cls, client_file, scopes, **k):
        seen.update(client_file=client_file, scopes=scopes)
        return Flow()

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(from_file))
    factory = Factory()
    acct = account(tmp_path, client_factory=factory)
    write_client(acct)
    gc = acct.client()
    acct.login_interactive(timeout=42, open_browser=False)
    assert seen == {"client_file": str(acct.client_file), "scopes": SCOPES, "port": 0, "timeout_seconds": 42,
                    "open_browser": False}
    assert json.loads(acct.token_file.read_text(encoding="utf-8"))["refresh_token"] == "r"
    assert acct.client() is gc and factory.calls == 2  # reconnects with the new login


@pytest.mark.parametrize("exc, text", [
    (WSGITimeoutError("Timed out waiting for response from authorization server"), "no answer from the browser within 5 s"),
    (OSError("address in use"), "Google login failed (OSError: address in use)"),
], ids=["timeout", "other"])
def test_login_interactive_failures_are_store_errors(tmp_path, monkeypatch, exc, text):
    class Flow:
        def run_local_server(self, **k):
            raise exc

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(lambda cls, f, s, **k: Flow()))
    acct = account(tmp_path)
    write_client(acct)
    with pytest.raises(StoreError) as ei:
        acct.login_interactive(timeout=5, open_browser=False)
    assert text in str(ei.value)
    assert not acct.token_file.exists()


def test_save_credentials_keeps_the_old_token_when_the_write_fails(tmp_path, monkeypatch):
    acct = account(tmp_path)
    write_token(acct)
    before = acct.token_file.read_text(encoding="utf-8")

    real_replace = os.replace

    def failing_replace(src, dst, *a, **k):
        if os.path.abspath(dst) == os.path.abspath(acct.token_file):
            raise PermissionError(13, "Permission denied", str(dst))
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(ga.os, "replace", failing_replace)
    with pytest.raises(PermissionError):
        acct.save_credentials(FlowCreds())
    assert acct.token_file.read_text(encoding="utf-8") == before
    assert leftovers(acct.token_file.parent) == []


def test_logout_forgets_the_token_but_keeps_the_spreadsheet(tmp_path):
    factory = Factory(FakeClient("SHEETKEY"))
    acct = account(tmp_path, client_factory=factory)
    write_token(acct)
    write_sheet_id(acct, "SHEETKEY")
    acct.spreadsheet()
    acct.explain(PermissionError())
    assert acct.status()["error"]
    acct.logout()
    assert not acct.token_file.exists()
    assert acct.spreadsheet_id() == "SHEETKEY" and acct.sheet_file.is_file()
    assert acct.status()["error"] == ""
    acct.logout()  # idempotent
    acct.spreadsheet()
    assert factory.calls == 2  # the cached connection was dropped too
    # without a test client the account is signed out
    plain = account(tmp_path)
    assert plain.has_token() is False and plain.status()["signed_in"] is False
    with pytest.raises(NotSignedIn):
        plain.credentials()


# ==================================================================================================
# explain() and the helpers
# ==================================================================================================


@pytest.mark.parametrize("exc, expected, drops", [
    (RefreshError("invalid_grant: Token has been expired or revoked."),
     "Google rejected the saved login (invalid_grant: Token has been expired or revoked.); sign in again", True),
    (NotSignedIn("not signed in to Google: open the page and sign in"),
     "not signed in to Google: open the page and sign in", True),
    (TransportError("Failed to establish a new connection"),
     "Google unreachable (TransportError: Failed to establish a new connection); check the network -- retrying",
     False),
    (requests.exceptions.ReadTimeout("read timed out"),
     "Google unreachable (ReadTimeout: read timed out); check the network -- retrying", False),
    (ConnectionResetError(10054, "reset by peer"),
     "Google unreachable (ConnectionResetError: [Errno 10054] reset by peer); check the network -- retrying", False),
    (TimeoutError("timed out"), "Google unreachable (TimeoutError: timed out); check the network -- retrying", False),
    (api_error(500, "Internal error encountered."), "Google Sheets API error: APIError: [500]: Internal error encountered.",
     False),
    (api_error(429, "Quota exceeded"), "Google Sheets API error: APIError: [429]: Quota exceeded", False),
    (api_error(401, "Request had invalid authentication credentials."),
     "Google Sheets API error: APIError: [401]: Request had invalid authentication credentials.", True),
    (PermissionError(),
     "Google refused access to the station spreadsheet (HTTP 403); sign in again with the account that created it",
     False),
    (StoreError("the station spreadsheet X is gone"), "the station spreadsheet X is gone", False),
    (ValueError("bad"), "Google Sheets error: ValueError: bad", False),
], ids=["refresh-revoked", "not-signed-in", "transport", "read-timeout", "conn-reset", "timeout", "api-500",
        "api-429", "api-401", "http-403", "store-error", "other"])
def test_explain(tmp_path, exc, expected, drops):
    factory = Factory()
    acct = account(tmp_path, client_factory=factory)
    acct.client()
    assert acct.explain(exc) == expected
    assert acct.last_error == expected and acct.status()["error"] == expected
    acct.client()
    assert factory.calls == (2 if drops else 1)  # auth failures drop the cached connection


def test_explain_local_permission_error_is_not_an_http_403(tmp_path):
    acct = account(tmp_path)
    text = acct.explain(PermissionError(13, "Permission denied", str(tmp_path / "token.json")))
    assert "HTTP 403" not in text and text.startswith("Google Sheets error: PermissionError")


def test_explain_retryable_refresh_error_does_not_ask_for_a_new_login(tmp_path):
    factory = Factory()
    acct = account(tmp_path, client_factory=factory)
    acct.client()
    text = acct.explain(RefreshError("Internal server error", retryable=True))
    acct.client()
    assert factory.calls == 1  # a transient failure keeps the connection (this part already holds)
    assert "sign in again" not in text  # ... but the text sends the operator to log in again


class HttpErrorLike(Exception):
    """googleapiclient-style: ``.resp.status`` (a string there)."""

    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.resp = type("Resp", (), {"status": status})()


class Coded(Exception):
    def __init__(self, code):
        super().__init__(f"code {code}")
        self.code = code


def test_http_status():
    assert http_status(api_error(404)) == 404
    assert http_status(HttpErrorLike("403")) == 403
    assert http_status(HttpErrorLike(500)) == 500
    assert http_status(Coded(401)) == 401
    assert http_status(Coded("not-a-number")) is None
    assert http_status(ValueError("x")) is None
    assert http_status(requests.exceptions.ReadTimeout("x")) is None  # .response is None
    resp = requests.Response()
    resp.status_code = 503
    err = requests.exceptions.HTTPError("503", response=resp)
    assert http_status(err) == 503


def test_is_auth_failure_and_is_network_error():
    assert is_auth_failure(NotSignedIn("x")) is True
    assert is_auth_failure(RefreshError("invalid_grant")) is True
    assert is_auth_failure(RefreshError("server busy", retryable=True)) is False
    assert is_auth_failure(api_error(401)) is True and is_auth_failure(Coded(401)) is True
    assert is_auth_failure(api_error(403)) is False and is_auth_failure(PermissionError()) is False
    assert is_auth_failure(StoreError("x")) is False and is_auth_failure(TransportError("x")) is False
    for exc in (TransportError("x"), requests.exceptions.ConnectTimeout("x"), requests.exceptions.ConnectionError("x"),
                TimeoutError("x"), ConnectionRefusedError("x")):
        assert is_network_error(exc), exc
    for exc in (RefreshError("x"), api_error(500), PermissionError(), ValueError("x")):
        assert not is_network_error(exc), exc


def test_exc_named_matches_subclasses_by_name():
    class SpreadsheetNotFoundSubclass(SpreadsheetNotFound):
        pass

    assert exc_named(SpreadsheetNotFoundSubclass("x"), "SpreadsheetNotFound")
    assert exc_named(RefreshError("x"), "GoogleAuthError")
    assert not exc_named(ValueError("x"), "SpreadsheetNotFound", "RefreshError")


def test_only_the_non_sensitive_drive_file_scope_is_requested():
    # drive.file is enough for the spreadsheet the station creates, and being non-sensitive it lets the OAuth
    # app be published without Google's verification (no test users, no 7-day expiry)
    assert SCOPES == ["https://www.googleapis.com/auth/drive.file"]


# --------------------------------------------------------------------------------------------------
# One spreadsheet per Google account (several operators on one station, one operator on several)
# --------------------------------------------------------------------------------------------------


class Drive:
    """Google as seen through the drive.file scope: every spreadsheet has an owner, an account only ever
    sees (and can open) the ones the app created for it."""

    def __init__(self):
        self.sheets: dict[str, tuple[str, FakeSpreadsheet]] = {}
        self.trashed: set[str] = set()
        self.queries: list[dict] = []
        self.n = 0

    def add(self, owner: str) -> str:
        self.n += 1
        sid = f"{owner.split('@')[0]}-{self.n}"
        self.sheets[sid] = (owner, FakeSpreadsheet(sid))
        return sid


class Response:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class AccountHttp:
    def __init__(self, drive: Drive, email: str):
        self.drive, self.email = drive, email

    def request(self, method, endpoint, params=None, **kw):
        assert method == "get"
        if endpoint == "https://www.googleapis.com/drive/v3/about":
            assert params == {"fields": "user(emailAddress)"}
            return Response({"user": {"emailAddress": self.email.upper()}})   # case must not matter
        assert endpoint == "https://www.googleapis.com/drive/v3/files"
        self.drive.queries.append(dict(params))
        q = params["q"]
        assert "name = 'OTP_Provisioner'" in q and "application/vnd.google-apps.spreadsheet" in q
        assert "trashed = false" in q and params["orderBy"] == "modifiedTime desc"
        mine = [sid for sid, (owner, _) in self.drive.sheets.items()
                if owner == self.email and sid not in self.drive.trashed]
        return Response({"files": [{"id": sid, "name": "OTP_Provisioner"} for sid in reversed(mine)]})


class AccountClient:
    """gspread-shaped client logged in as ``email``."""

    def __init__(self, drive: Drive, email: str):
        self.drive, self.email = drive, email
        self.http_client = AccountHttp(drive, email)
        self.opened, self.created = [], []

    def open_by_key(self, *a, **k):
        key = bind(RealClient.open_by_key, *a, **k)["key"]
        self.opened.append(key)
        owner, sh = self.drive.sheets.get(key, (None, None))
        if owner != self.email:
            raise SpreadsheetNotFound(key)      # drive.file: another account's file does not exist for us
        return sh

    def create(self, *a, **k):
        title = bind(RealClient.create, *a, **k)["title"]
        self.created.append(title)
        return self.drive.sheets[self.drive.add(self.email)][1]


class Station:
    """One station (one work dir) on which operators sign in and out."""

    def __init__(self, tmp_path, drive: Drive):
        self.drive = drive
        self.user = ""
        self.clients: dict[str, AccountClient] = {}
        self.acct = account(tmp_path, client_factory=self.client)

    def client(self):
        return self.clients.setdefault(self.user, AccountClient(self.drive, self.user))

    def sign_in(self, email: str):
        class Creds:
            def to_json(self):
                return json.dumps({"token": "t", "refresh_token": "r"})

        self.user = email
        self.acct.save_credentials(Creds())

    def remembered(self) -> dict:
        return json.loads(self.acct.sheet_file.read_text(encoding="utf-8"))


def test_each_account_gets_its_own_spreadsheet_on_one_station(tmp_path):
    drive = Drive()
    st = Station(tmp_path, drive)
    st.sign_in("alice@example.com")
    sh_a = st.acct.spreadsheet()
    assert drive.sheets[sh_a.id][0] == "alice@example.com" and sh_a.sheet1.title == "modules"
    assert st.acct.status()["email"] == "alice@example.com" and st.acct.spreadsheet_id() == sh_a.id

    st.sign_in("bob@example.com")                                  # alice signs out, bob signs in
    assert st.acct.spreadsheet_id() == "" and st.acct.status()["email"] == ""   # alice's sheet is not shown to bob
    sh_b = st.acct.spreadsheet()
    assert sh_b.id != sh_a.id and drive.sheets[sh_b.id][0] == "bob@example.com"
    assert st.clients["bob@example.com"].opened == []             # never even tried alice's spreadsheet
    assert st.remembered()["accounts"] == {"alice@example.com": sh_a.id, "bob@example.com": sh_b.id}

    st.sign_in("alice@example.com")                                # alice is back: her own sheet, nothing new
    assert st.acct.spreadsheet().id == sh_a.id
    assert st.clients["alice@example.com"].created == ["OTP_Provisioner"]       # only the first time
    assert st.remembered()["id"] == sh_a.id and st.remembered()["email"] == "alice@example.com"


def test_a_spreadsheet_created_on_another_station_is_found(tmp_path):
    drive = Drive()
    other = Station(tmp_path / "station-1", drive)
    other.sign_in("alice@example.com")
    sid = other.acct.spreadsheet().id
    st = Station(tmp_path / "station-2", drive)                    # a fresh station, same operator
    st.sign_in("alice@example.com")
    assert st.acct.spreadsheet().id == sid
    assert st.clients["alice@example.com"].created == []
    assert st.remembered()["accounts"] == {"alice@example.com": sid}


def test_trashed_spreadsheets_are_not_reused(tmp_path):
    drive = Drive()
    st = Station(tmp_path, drive)
    old = drive.add("alice@example.com")
    drive.trashed.add(old)
    st.sign_in("alice@example.com")
    sh = st.acct.spreadsheet()
    assert sh.id != old and st.clients["alice@example.com"].created == ["OTP_Provisioner"]


def test_old_single_spreadsheet_file_is_adopted_by_its_owner(tmp_path):
    drive = Drive()
    st = Station(tmp_path, drive)
    sid = drive.add("alice@example.com")
    write_sheet_id(st.acct, sid)                                   # written before accounts were recorded
    st.sign_in("alice@example.com")
    assert st.acct.spreadsheet().id == sid
    assert st.remembered()["accounts"] == {"alice@example.com": sid}


def test_old_single_spreadsheet_file_of_someone_else_is_left_alone(tmp_path):
    drive = Drive()
    st = Station(tmp_path, drive)
    sid = drive.add("alice@example.com")
    write_sheet_id(st.acct, sid)
    st.sign_in("bob@example.com")
    sh = st.acct.spreadsheet()
    assert sh.id != sid and drive.sheets[sh.id][0] == "bob@example.com"   # bob gets his own, no error
    assert drive.sheets[sid][0] == "alice@example.com"                   # alice's is untouched


def test_an_accounts_own_spreadsheet_that_is_gone_is_an_error_not_a_new_registry(tmp_path):
    drive = Drive()
    st = Station(tmp_path, drive)
    st.sign_in("alice@example.com")
    sid = st.acct.spreadsheet().id
    del drive.sheets[sid]                                          # deleted for good
    st.sign_in("alice@example.com")
    with pytest.raises(StoreError, match=rf"{sid} of alice@example.com is gone"):
        st.acct.spreadsheet()
    assert st.clients["alice@example.com"].created == ["OTP_Provisioner"]   # no second, empty registry
