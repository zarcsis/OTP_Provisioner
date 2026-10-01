"""Module registry storage: the record schema and the Google Sheets store.

The Sheets store is exercised with gspread-shaped fakes whose methods are checked against the real
gspread 6.x signatures, behind the *real* :class:`~otp_server.google_account.GoogleAccount` (a test
``client_factory`` stands in for the OAuth login), so opening the station spreadsheet by its saved id
and explaining Google errors to the operator run the product code. No test touches the network or
opens a browser."""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re

import pytest

import otp_server.storage as storage_pkg
from otp_server.google_account import GoogleAccount
from otp_server.storage import (
    FIELDS,
    GoogleSheetsStore,
    ModuleStore,
    StoreError,
    make_store,
    normalize_record,
    utc_now_iso,
)
from otp_server.storage.base import LOWER_FIELDS, MAX_EVENTS, encode_cell

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nAAAA\n-----END PRIVATE KEY-----\n"
SHEET_URL = "https://docs.google.com/spreadsheets/d/SHEETKEY/edit"


def sample(serial="a7eb274c", **kw):
    rec = {
        "serial": serial,
        "stage": "eeprom",
        "created": "2026-09-30T12:00:00Z",
        "updated": "2026-09-30T12:34:56Z",
        "chip": "BCM2712",
        "mac": "2c:cf:67:70:76:f3",
        "boardrev": "b04170",
        "customer_key_hash": "1e10" + "0" * 60,  # numeric-looking on purpose
        "otp_key_hash": "0" * 64,
        "secure_boot_provisioned": True,
        "rsa_private_pem": PEM,
        "device_secret": "ab" * 32,
        "metadata": {"EEPROM_UPDATE": "success", "USER_SERIAL_NUM": "0001"},
        "facts": {"usb": {"vendor_id": 2652}},
        "events": [{"t": "2026-09-30T12:00:00Z", "kind": "hello", "note": "created"}],
    }
    rec.update(kw)
    return rec


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture(autouse=True)
def _no_browser_no_network(monkeypatch):
    """Every test: opening a browser, the loopback OAuth server or any real HTTP request fails loudly."""

    def refuse(*a, **k):
        raise AssertionError("a test tried to open a browser or reach the network")

    import webbrowser

    for name in ("open", "open_new", "open_new_tab"):
        monkeypatch.setattr(webbrowser, name, refuse)
    try:
        import requests
    except ImportError:  # pragma: no cover
        pass
    else:
        monkeypatch.setattr(requests.Session, "send", refuse)
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:  # pragma: no cover
        pass
    else:
        monkeypatch.setattr(InstalledAppFlow, "run_local_server", refuse)


# ==================================================================================================
# base / normalize
# ==================================================================================================


#: The header the first released version wrote (sheets in the field still carry it).
FIELDS_V1 = ("serial", "stage", "created", "updated", "chip", "board", "duid", "mac", "factory_uuid", "boardrev",
             "customer_key_hash", "otp_key_hash", "secure_boot_provisioned", "device_key_pem", "rsa_public_pem",
             "rsa_private_pem", "device_secret", "metadata", "facts", "events")


def test_fields_only_grow_at_the_end():
    # an older sheet header must stay a prefix of the current one (it is extended in place)
    assert FIELDS[: len(FIELDS_V1)] == FIELDS_V1
    assert FIELDS[len(FIELDS_V1): len(FIELDS_V1) + 2] == ("device_private_pem", "mode")
    assert len(FIELDS) == len(set(FIELDS))
    assert "mode" in LOWER_FIELDS and "device_private_pem" not in LOWER_FIELDS


def test_normalize_record_defaults_and_coercion():
    r = normalize_record({"serial": " A7EB274C ", "stage": "bogus", "extra": 1, "secure_boot_provisioned": "TRUE",
                          "metadata": '{"a": "b"}', "events": json.dumps([{"t": "x", "kind": "k"}, "junk"]),
                          "chip": None, "duid": "ABCDEF", "mode": " Secure ", "device_private_pem": PEM})
    assert list(r) == list(FIELDS)
    assert r["serial"] == "a7eb274c" and r["stage"] == "new" and "extra" not in r
    assert r["secure_boot_provisioned"] is True
    assert r["metadata"] == {"a": "b"} and r["facts"] == {}
    assert r["events"] == [{"t": "x", "kind": "k", "note": ""}]
    assert r["chip"] == "" and r["duid"] == "abcdef"
    assert r["mode"] == "secure"  # lowercased and stripped
    assert r["device_private_pem"] == PEM  # PEM kept verbatim (case and newlines)
    assert normalize_record({})["mode"] == "" and normalize_record({})["device_private_pem"] == ""
    for v in ("false", "", "0", None):
        assert normalize_record({"secure_boot_provisioned": v})["secure_boot_provisioned"] is False
    many = [{"t": str(i), "kind": "k", "note": ""} for i in range(150)]
    assert [e["t"] for e in normalize_record({"events": many})["events"]] == [str(i) for i in range(50, 150)]
    assert len(normalize_record({"events": many})["events"]) == MAX_EVENTS


def test_utc_now_iso_format():
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", utc_now_iso())


def test_encode_cell():
    assert encode_cell("secure_boot_provisioned", True) == "true"
    assert encode_cell("secure_boot_provisioned", False) == "false"
    assert encode_cell("metadata", {"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert encode_cell("chip", "BCM2712") == "BCM2712"
    assert encode_cell("mode", "secure") == "secure"
    assert encode_cell("device_private_pem", PEM) == PEM
    assert encode_cell("chip", None) == ""


# ==================================================================================================
# the package: Google Sheets only
# ==================================================================================================


def test_storage_package_has_no_local_or_drive_backend():
    for name in ("LocalJsonStore", "GoogleDriveStore"):
        assert not hasattr(storage_pkg, name), name
        assert name not in storage_pkg.__all__
    for mod in ("otp_server.storage.local", "otp_server.storage.gdrive"):
        assert importlib.util.find_spec(mod) is None, mod


def test_make_store_returns_a_lazy_google_sheets_store(tmp_path):
    account = GoogleAccount(tmp_path / "repo", tmp_path / "work")
    st = make_store(account)
    assert isinstance(st, GoogleSheetsStore) and isinstance(st, ModuleStore)
    assert st.account is account and st.worksheet == "modules" and st.backend == "gsheets"
    # constructing it neither connects nor writes anything locally
    assert not (tmp_path / "work").exists()
    assert st.location == "Google Sheets (not created yet) / modules"


def test_google_libraries_are_imported_lazily(tmp_path):
    import subprocess
    import sys

    code = (
        "import sys, pathlib; "
        "import otp_server.storage, otp_server.google_account, otp_server.settings, otp_server.modules; "
        "from otp_server.google_account import GoogleAccount; from otp_server.storage import make_store; "
        f"tmp = pathlib.Path({str(tmp_path)!r}); "
        "acct = GoogleAccount(tmp / 'repo', tmp / 'work'); acct.status(); "
        "st = make_store(acct); st.location; "
        "print(sorted(m for m in ('gspread', 'googleapiclient', 'google_auth_oauthlib', 'google.oauth2', "
        "'google.auth', 'requests_oauthlib') if m in sys.modules))"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("OTP_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"  # keep bytecode out of the repository tree
    out = subprocess.run([sys.executable, "-B", "-c", code], cwd=str(REPO), env=env, capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


# ==================================================================================================
# Google Sheets (fakes bound to the real gspread 6.x signatures)
# ==================================================================================================

gspread = pytest.importorskip("gspread")
from gspread.cell import Cell as RealCell  # noqa: E402
from gspread.client import Client as RealClient  # noqa: E402
from gspread.exceptions import SpreadsheetNotFound, WorksheetNotFound  # noqa: E402
from gspread.spreadsheet import Spreadsheet as RealSpreadsheet  # noqa: E402
from gspread.utils import a1_to_rowcol, rowcol_to_a1  # noqa: E402
from gspread.worksheet import Worksheet as RealWorksheet  # noqa: E402


def bind(real, *args, **kwargs):
    """Fail the test when a call does not match the real gspread signature."""
    return inspect.signature(real).bind(None, *args, **kwargs).arguments


class FakeWorksheet:
    def __init__(self, title, rows=1000, cols=26, grid=None):
        self.title = title
        self.rows, self.cols = rows, cols
        self.grid = [list(r) for r in (grid or [])]
        self.calls = []

    @property
    def col_count(self):
        return self.cols

    def _set(self, r, c, v):
        while len(self.grid) < r:
            self.grid.append([])
        row = self.grid[r - 1]
        while len(row) < c:
            row.append("")
        row[c - 1] = v

    def get_all_values(self, *a, **k):
        bind(RealWorksheet.get_all_values, *a, **k)
        self.calls.append("get_all_values")
        rows = [list(r) for r in self.grid]
        while rows and not any(str(c) for c in rows[-1]):
            rows.pop()
        width = max((len(r) for r in rows), default=0)
        return [r + [""] * (width - len(r)) for r in rows]

    def update(self, *a, **k):
        args = bind(RealWorksheet.update, *a, **k)
        self.calls.append("update")
        assert args.get("value_input_option") == "RAW"
        values, rng = args["values"], args["range_name"]
        start = rng.split(":")[0]
        r0, c0 = a1_to_rowcol(start)
        if ":" in rng:
            r1, c1 = a1_to_rowcol(rng.split(":")[1])
            assert r1 - r0 + 1 == len(values) and c1 - c0 + 1 == len(values[0]), (rng, len(values[0]))
        for i, row in enumerate(values):
            for j, v in enumerate(row):
                assert isinstance(v, str) and len(v) <= 50000
                assert c0 + j <= self.cols, "range exceeds grid limits"
                self._set(r0 + i, c0 + j, v)
        return {"updatedRange": f"{self.title}!{rng}"}

    def append_row(self, *a, **k):
        args = bind(RealWorksheet.append_row, *a, **k)
        self.calls.append("append_row")
        assert args.get("value_input_option") == "RAW"
        values = args["values"]
        r = len(self.get_all_values()) + 1
        self.calls.pop()  # the internal read is not an API call
        for j, v in enumerate(values):
            assert isinstance(v, str) and len(v) <= 50000
            self._set(r, j + 1, v)
        last = rowcol_to_a1(r, len(values))
        return {"spreadsheetId": "sid", "tableRange": f"{self.title}!A1:{rowcol_to_a1(r - 1, len(values))}",
                "updates": {"spreadsheetId": "sid", "updatedRange": f"{self.title}!A{r}:{last}", "updatedRows": 1}}

    def acell(self, *a, **k):
        args = bind(RealWorksheet.acell, *a, **k)
        self.calls.append("acell")
        r, c = a1_to_rowcol(args["label"])
        row = self.grid[r - 1] if r <= len(self.grid) else []
        return RealCell(r, c, row[c - 1] if c <= len(row) else "")

    def resize(self, *a, **k):
        args = bind(RealWorksheet.resize, *a, **k)
        self.calls.append("resize")
        if args.get("cols"):
            self.cols = args["cols"]


class FakeSpreadsheet:
    def __init__(self, sid):
        self.id = sid
        self.sheets: dict[str, FakeWorksheet] = {}
        self.calls = []

    def worksheet(self, *a, **k):
        args = bind(RealSpreadsheet.worksheet, *a, **k)
        self.calls.append("worksheet")
        if args["title"] not in self.sheets:
            raise WorksheetNotFound(args["title"])
        return self.sheets[args["title"]]

    def add_worksheet(self, *a, **k):
        args = bind(RealSpreadsheet.add_worksheet, *a, **k)
        self.calls.append("add_worksheet")
        ws = FakeWorksheet(args["title"], args["rows"], args["cols"])
        self.sheets[args["title"]] = ws
        return ws


class FakeGspreadClient:
    def __init__(self, sid="SHEETKEY"):
        self.spreadsheet = FakeSpreadsheet(sid)
        self.opened = []

    def open_by_key(self, *a, **k):
        args = bind(RealClient.open_by_key, *a, **k)
        self.opened.append(args["key"])
        if args["key"] != self.spreadsheet.id:
            raise SpreadsheetNotFound("not found")
        return self.spreadsheet

    def create(self, *a, **k):  # the account must never create a spreadsheet when an id is saved
        bind(RealClient.create, *a, **k)
        raise AssertionError("a new spreadsheet was created although its id is saved")


class FakeAccount(GoogleAccount):
    """The real :class:`GoogleAccount` (opens the saved spreadsheet id, explains errors, drops the connection
    on auth failures) on fake gspread clients instead of an OAuth login. ``clients`` are handed out one per
    (re)connect, the last one repeating; ``built`` counts the connects."""

    def __init__(self, tmp_path, *clients, sid="SHEETKEY"):
        self._clients = list(clients)
        self.built = 0
        super().__init__(tmp_path / "repo", tmp_path / "work", client_factory=self._next_client)
        self.sheet_file.parent.mkdir(parents=True, exist_ok=True)
        self.sheet_file.write_text(json.dumps({"id": sid, "title": "OTP_Provisioner"}), encoding="utf-8")

    def _next_client(self):
        self.built += 1
        return self._clients[min(self.built, len(self._clients)) - 1]


def sheets_store(tmp_path, *clients, clock=None, worksheet="modules"):
    return GoogleSheetsStore(FakeAccount(tmp_path, *clients), worksheet=worksheet, clock=clock or Clock())


def test_sheets_creates_worksheet_and_round_trips(tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake)
    assert st.get("a7eb274c") is None
    assert fake.opened == ["SHEETKEY"]  # the saved spreadsheet id
    ws = fake.spreadsheet.sheets["modules"]
    assert ws.grid[0] == list(FIELDS) and ws.cols == len(FIELDS)
    st.put(sample())
    st.put(sample("00001234", stage="new", secure_boot_provisioned=False))
    st.put(sample("cccccccc", mode="Secure", device_private_pem=PEM))
    assert len(ws.grid) == 4
    # the stored cells are RAW strings: serials / hex stay text, PEM keeps its newlines
    row = dict(zip(FIELDS, ws.grid[1]))
    assert row["serial"] == "a7eb274c" and row["secure_boot_provisioned"] == "true"
    assert row["rsa_private_pem"] == PEM and json.loads(row["metadata"])["EEPROM_UPDATE"] == "success"
    assert row["mode"] == "" and row["device_private_pem"] == ""
    assert ws.grid[2][0] == "00001234"
    row3 = dict(zip(FIELDS, ws.grid[3]))
    assert row3["mode"] == "secure" and row3["device_private_pem"] == PEM
    # a second store instance (another server start) reads the same data back
    st2 = sheets_store(tmp_path / "b", fake)
    assert st2.get("a7eb274c") == normalize_record(sample())
    assert st2.get("00001234")["secure_boot_provisioned"] is False
    assert st2.get("cccccccc")["mode"] == "secure" and st2.get("cccccccc")["device_private_pem"] == PEM
    assert [r["serial"] for r in st2.list()] == ["a7eb274c", "00001234", "cccccccc"]
    # upsert updates the row in place
    st2.put(sample(stage="flashed", chip="X"))
    assert len(ws.grid) == 4 and ws.grid[1][FIELDS.index("stage")] == "flashed"
    d = st2.describe()
    assert d == {"backend": "gsheets", "ok": True, "location": f"Google Sheets {SHEET_URL} / modules",
                 "detail": "3 module record(s) cached"}
    assert fake.spreadsheet.calls.count("add_worksheet") == 1


def test_sheets_custom_worksheet_name(tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake, worksheet="registry")
    st.put(sample())
    assert set(fake.spreadsheet.sheets) == {"registry"}
    assert st.describe()["location"].endswith("/ registry")


def test_sheets_caching_and_quota(tmp_path):
    fake = FakeGspreadClient()
    clock = Clock()
    st = sheets_store(tmp_path, fake, clock=clock)
    st.put(sample())  # connect (1 read) + miss refresh is suppressed (<2 s) + append
    ws = fake.spreadsheet.sheets["modules"]
    reads = lambda: ws.calls.count("get_all_values")  # noqa: E731
    n0 = reads()
    for _ in range(20):
        assert st.get("a7eb274c")["stage"] == "eeprom"
        st.list()
        st.describe()
    assert reads() == n0  # all served from cache
    assert fake.opened == ["SHEETKEY"]  # the spreadsheet is opened once
    st.put(sample(stage="gadget"))
    assert ws.calls[-1] == "update" and reads() == n0  # known row: no re-read
    # external edit (another station) becomes visible after the cache ages
    ws.grid[1][FIELDS.index("chip")] = "EXTERNAL"
    clock.advance(11)
    assert st.list()[0]["chip"] == "EXTERNAL"
    assert reads() == n0 + 1
    clock.advance(5)
    assert st.get("a7eb274c")["chip"] == "EXTERNAL" and reads() == n0 + 1
    # a miss refreshes (rate-limited)
    ws.grid.append(["deadbeef", "gadget"] + [""] * (len(FIELDS) - 2))
    clock.advance(3)
    assert st.get("deadbeef")["stage"] == "gadget"
    assert reads() == n0 + 2
    assert st.get("cafe0000") is None and reads() == n0 + 2  # within 2 s of the last read


def test_sheets_reset_forgets_the_cache_and_the_retry_throttle(tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake)
    st.put(sample())
    ws = fake.spreadsheet.sheets["modules"]
    ws.grid[1][FIELDS.index("chip")] = "EXTERNAL"
    assert st.get("a7eb274c")["chip"] == "BCM2712"  # cached
    lookups = fake.spreadsheet.calls.count("worksheet")
    st.reset()
    assert st.get("a7eb274c")["chip"] == "EXTERNAL"  # reconnected and re-read without waiting
    assert fake.spreadsheet.calls.count("worksheet") == lookups + 1

    # a failed connect is retried at most every 10 s ... unless reset() (a new login) says otherwise
    broken = FakeGspreadClient(sid="OTHER")
    st2 = sheets_store(tmp_path / "2", broken)
    assert st2.describe()["ok"] is False and len(broken.opened) == 1
    broken.spreadsheet.id = "SHEETKEY"
    assert st2.describe()["ok"] is False and len(broken.opened) == 1  # throttled
    st2.reset()
    assert st2.describe()["ok"] is True and len(broken.opened) == 2


def test_sheets_row_index_survives_unknown_append_response(tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake)
    st.get("x0000000")
    ws = fake.spreadsheet.sheets["modules"]
    orig = ws.append_row

    def append_no_range(*a, **k):
        orig(*a, **k)
        return {}

    ws.append_row = append_no_range
    st.put(sample())
    st.put(sample(stage="gadget"))  # must re-read and update row 2, not append a duplicate
    assert len(ws.grid) == 2 and ws.grid[1][1] == "gadget"


def test_sheets_header_rules(tmp_path):
    # wrong header, no data -> canonical header written (grid widened when too narrow)
    fake = FakeGspreadClient()
    fake.spreadsheet.sheets["modules"] = FakeWorksheet("modules", cols=5, grid=[["foo", "bar"]])
    st = sheets_store(tmp_path, fake)
    st.put(sample())
    ws = fake.spreadsheet.sheets["modules"]
    assert ws.grid[0] == list(FIELDS) and "resize" in ws.calls
    # an empty worksheet gets the header too
    fake_e = FakeGspreadClient()
    fake_e.spreadsheet.sheets["modules"] = FakeWorksheet("modules")
    sheets_store(tmp_path / "e", fake_e).put(sample())
    assert fake_e.spreadsheet.sheets["modules"].grid[0] == list(FIELDS)
    # canonical header + extra operator columns is fine
    fake2 = FakeGspreadClient()
    fake2.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[list(FIELDS) + ["notes"]])
    st2 = sheets_store(tmp_path / "2", fake2)
    st2.put(sample())
    assert st2.get("a7eb274c")["chip"] == "BCM2712"
    assert fake2.spreadsheet.sheets["modules"].grid[0][-1] == "notes"
    # wrong header with data -> refuse
    fake3 = FakeGspreadClient()
    fake3.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[["serial", "name"], ["a7eb274c", "x"]])
    st3 = sheets_store(tmp_path / "3", fake3)
    with pytest.raises(StoreError, match="different header"):
        st3.get("a7eb274c")
    d = st3.describe()
    assert d["ok"] is False and "different header" in d["detail"]
    assert fake3.spreadsheet.sheets["modules"].grid[1] == ["a7eb274c", "x"]  # untouched
    # an old header followed by an operator column is not "extended": that would overwrite the column
    old = list(FIELDS_V1)
    fake4 = FakeGspreadClient()
    data = [encode_cell(f, normalize_record(sample())[f]) for f in old] + ["operator note"]
    fake4.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[old + ["notes"], data])
    with pytest.raises(StoreError, match="different header"):
        sheets_store(tmp_path / "4", fake4).list()
    ws4 = fake4.spreadsheet.sheets["modules"]
    assert ws4.grid == [old + ["notes"], data] and "update" not in ws4.calls


@pytest.mark.parametrize("n_old, cols", [(len(FIELDS_V1), len(FIELDS_V1)), (len(FIELDS_V1) + 1, 26)],
                         ids=["v1-header-narrow-grid", "one-field-short-wide-grid"])
def test_sheets_old_header_prefix_is_extended_in_place(tmp_path, n_old, cols):
    """A header written by an older version (a strict prefix of FIELDS) gets the new columns appended;
    existing rows keep their cells and read back with the new fields empty."""
    old = list(FIELDS[:n_old])
    rec_a, rec_b = normalize_record(sample()), normalize_record(sample("bbbbbbbb", chip="B"))
    row_a = [encode_cell(f, rec_a[f]) for f in old]
    row_b = [encode_cell(f, rec_b[f]) for f in old]
    fake = FakeGspreadClient()
    fake.spreadsheet.sheets["modules"] = FakeWorksheet("modules", cols=cols, grid=[old, row_a, row_b])
    ws = fake.spreadsheet.sheets["modules"]
    clock = Clock()
    st = sheets_store(tmp_path, fake, clock=clock)
    assert st.get("a7eb274c") == rec_a  # device_private_pem / mode read back empty
    assert st.get("bbbbbbbb")["chip"] == "B" and st.get("bbbbbbbb")["mode"] == ""
    assert ws.grid[0] == list(FIELDS)
    assert ws.cols >= len(FIELDS)
    assert ("resize" in ws.calls) is (cols < len(FIELDS))  # widened only when the grid is too narrow
    assert ws.grid[1] == row_a and ws.grid[2] == row_b  # the data rows were not rewritten
    assert "add_worksheet" not in fake.spreadsheet.calls
    # the new columns are used from now on, in place
    st.put(sample(mode="secure", device_private_pem=PEM))
    assert len(ws.grid) == 3 and ws.calls[-2:] == ["acell", "update"]
    row = dict(zip(FIELDS, ws.grid[1]))
    assert row["mode"] == "secure" and row["device_private_pem"] == PEM and row["chip"] == "BCM2712"
    # a later re-read (cache aged) accepts the extended header, and a fresh start reads it back
    clock.advance(31)
    assert {r["serial"]: r["mode"] for r in st.list()} == {"a7eb274c": "secure", "bbbbbbbb": ""}
    st2 = sheets_store(tmp_path / "b", fake)
    assert st2.get("a7eb274c")["device_private_pem"] == PEM and ws.grid[0] == list(FIELDS)


def test_sheets_missing_spreadsheet_is_actionable_and_throttled(tmp_path):
    fake = FakeGspreadClient(sid="OTHER")  # the saved id SHEETKEY no longer opens
    clock = Clock()
    st = sheets_store(tmp_path, fake, clock=clock)
    with pytest.raises(StoreError, match="SHEETKEY is gone") as ei:
        st.list()
    assert "Drive trash" in str(ei.value) and str(st.account.sheet_file) in str(ei.value)
    d = st.describe()
    assert d["ok"] is False and "SHEETKEY is gone" in d["detail"]
    assert len(fake.opened) == 1  # retry throttled
    clock.advance(11)
    st.describe()
    assert len(fake.opened) == 2
    # nothing was created in its place, and the saved id is kept for the operator to fix
    assert st.account.spreadsheet_id() == "SHEETKEY"


def test_sheets_permission_errors_are_explained(tmp_path):
    def detail(exc, sub):
        class Raising(FakeGspreadClient):
            def open_by_key(self, *a, **k):
                bind(RealClient.open_by_key, *a, **k)
                raise exc

        st = sheets_store(tmp_path / sub, Raising())
        d = st.describe()
        assert d["ok"] is False
        assert st.account.status()["error"] == d["detail"]  # the account remembers it for /api/status
        return d["detail"]

    d = detail(PermissionError(), "a")  # what gspread raises for an HTTP 403
    assert "HTTP 403" in d and "sign in again" in d
    d = detail(PermissionError(13, "Permission denied", str(tmp_path / "x.json")), "b")  # a local file problem
    assert "HTTP 403" not in d and "PermissionError" in d


def test_sheets_cell_budget(tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake)
    big_events = [{"t": utc_now_iso(), "kind": "k", "note": "n" * 490} for _ in range(100)]
    st.put(sample(events=big_events))  # ~51 KB of events -> oldest dropped
    ws = fake.spreadsheet.sheets["modules"]
    cell = ws.grid[1][FIELDS.index("events")]
    assert len(cell) <= 45000 and 0 < len(json.loads(cell)) < 100
    assert st.get("a7eb274c")["events"] == json.loads(cell)
    with pytest.raises(StoreError, match="metadata"):
        st.put(sample("bbbbbbbb", metadata={"x": "y" * 46000}))
    assert [r[0] for r in ws.grid[1:]] == ["a7eb274c"]  # nothing written for the refused record


def test_sheets_put_never_overwrites_a_row_that_moved(tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake)
    st.put(sample("aaaaaaaa", chip="A"))
    st.put(sample("bbbbbbbb", chip="B", device_secret="cd" * 32))
    ws = fake.spreadsheet.sheets["modules"]
    assert [r[0] for r in ws.grid[1:]] == ["aaaaaaaa", "bbbbbbbb"]
    # an operator deletes row 2 by hand: bbbbbbbb moves up into it, the cache still says row 2 = aaaaaaaa
    del ws.grid[1]
    st.put(sample("aaaaaaaa", stage="gadget", chip="A2"))  # within the 30 s cache window
    rows = {r[0]: dict(zip(FIELDS, r)) for r in ws.grid[1:]}
    assert rows["bbbbbbbb"]["chip"] == "B" and rows["bbbbbbbb"]["device_secret"] == "cd" * 32
    assert rows["aaaaaaaa"]["stage"] == "gadget" and len(ws.grid) == 3  # re-appended, not overwritten
    # the operator sorts the sheet: both rows swap places
    ws.grid[1], ws.grid[2] = ws.grid[2], ws.grid[1]
    st.put(sample("bbbbbbbb", stage="flashed", chip="B2", device_secret="cd" * 32))
    rows = {r[0]: dict(zip(FIELDS, r)) for r in ws.grid[1:]}
    assert rows["aaaaaaaa"]["chip"] == "A2" and rows["bbbbbbbb"]["stage"] == "flashed" and len(ws.grid) == 3
    # a row that did not move costs one key-cell read, no full re-read
    reads = ws.calls.count("get_all_values")
    st.put(sample("bbbbbbbb", stage="flashed", chip="B3"))
    assert ws.calls[-2:] == ["acell", "update"] and ws.calls.count("get_all_values") == reads


def test_sheets_timeout_is_a_store_error_and_throttled(tmp_path):
    import requests

    class TimingOut(FakeGspreadClient):
        def open_by_key(self, *a, **k):
            bind(RealClient.open_by_key, *a, **k)
            self.opened.append(a)
            raise requests.exceptions.ReadTimeout("read timed out (read timeout=60)")

    fake = TimingOut()
    clock = Clock()
    st = sheets_store(tmp_path, fake, clock=clock)
    with pytest.raises(StoreError, match="unreachable") as ei:
        st.list()
    assert "ReadTimeout" in str(ei.value) and "sign in" not in str(ei.value)
    assert st.describe()["ok"] is False and len(fake.opened) == 1
    clock.advance(11)
    assert st.describe()["ok"] is False and len(fake.opened) == 2
    assert st.account.built == 1  # a network hiccup keeps the login / client


def test_sheets_write_failure_is_a_store_error_and_forces_a_reread(tmp_path):
    import requests

    fake = FakeGspreadClient()
    st = sheets_store(tmp_path, fake)
    st.put(sample())
    ws = fake.spreadsheet.sheets["modules"]

    def offline(*a, **k):
        raise requests.exceptions.ConnectionError("connection reset")

    ws.update = offline
    with pytest.raises(StoreError, match="unreachable"):
        st.put(sample(stage="gadget"))
    del ws.update  # back online
    reads = ws.calls.count("get_all_values")
    st.put(sample(stage="flashed"))
    assert ws.calls.count("get_all_values") == reads + 1  # the cache was invalidated by the failure
    assert len(ws.grid) == 2 and ws.grid[1][FIELDS.index("stage")] == "flashed"


def test_sheets_not_signed_in_asks_for_login_without_a_browser(tmp_path):
    account = GoogleAccount(tmp_path / "repo", tmp_path / "work")  # no token, no test client
    st = make_store(account)
    d = st.describe()  # the /api/status poll path
    assert d["ok"] is False and "not signed in" in d["detail"] and "sign in" in d["detail"]
    with pytest.raises(StoreError, match="not signed in"):
        st.list()
    with pytest.raises(StoreError, match="not signed in"):
        st.put(sample())


def test_sheets_auth_failure_drops_the_connection_and_a_new_login_takes_effect(tmp_path):
    """A token revoked mid-run: the store explains it, the account forgets its client, and the next call
    after the operator signs in again reconnects by itself (no server restart)."""
    from google.auth.exceptions import RefreshError

    clock = Clock()
    first, good = FakeGspreadClient(), FakeGspreadClient()
    account = FakeAccount(tmp_path, first, good)
    st = GoogleSheetsStore(account, clock=clock)
    st.put(sample())
    assert account.built == 1

    # the token gets revoked: every Sheets call of the first client now fails with a non-retryable RefreshError
    def revoked(*a, **k):
        raise RefreshError("invalid_grant: Token has been expired or revoked.")

    first.spreadsheet.sheets["modules"].get_all_values = revoked
    clock.advance(31)
    with pytest.raises(StoreError, match="rejected the saved login") as ei:
        st.list()
    assert "sign in again" in str(ei.value)
    assert "rejected" in account.status()["error"]

    # signed in again: the next call reconnects with a fresh client, without waiting for the retry throttle
    good.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[list(FIELDS)])
    assert st.list() == [] and account.built == 2
    st.put(sample("bbbbbbbb"))
    assert good.spreadsheet.sheets["modules"].grid[1][0] == "bbbbbbbb"
