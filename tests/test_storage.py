"""Storage backends: local JSON (real files), Google Sheets (gspread-shaped fakes whose methods are
checked against the real gspread 6.x signatures) and Google Drive (the real googleapiclient Drive v3
client built from its bundled discovery document, talking to an in-memory fake HTTP transport)."""

from __future__ import annotations

import email
import email.policy
import inspect
import json
import os
import re
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from otp_server.storage import (
    FIELDS,
    GoogleDriveStore,
    GoogleSheetsStore,
    LocalJsonStore,
    StoreError,
    make_store,
    normalize_record,
    utc_now_iso,
)
from otp_server.storage.base import MAX_EVENTS, encode_cell

REPO = __import__("pathlib").Path(__file__).resolve().parent.parent
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nAAAA\n-----END PRIVATE KEY-----\n"


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


# ==================================================================================================
# base / normalize
# ==================================================================================================


def test_normalize_record_defaults_and_coercion():
    r = normalize_record({"serial": " A7EB274C ", "stage": "bogus", "extra": 1, "secure_boot_provisioned": "TRUE",
                          "metadata": '{"a": "b"}', "events": json.dumps([{"t": "x", "kind": "k"}, "junk"]),
                          "chip": None, "duid": "ABCDEF"})
    assert list(r) == list(FIELDS)
    assert r["serial"] == "a7eb274c" and r["stage"] == "new" and "extra" not in r
    assert r["secure_boot_provisioned"] is True
    assert r["metadata"] == {"a": "b"} and r["facts"] == {}
    assert r["events"] == [{"t": "x", "kind": "k", "note": ""}]
    assert r["chip"] == "" and r["duid"] == "abcdef"
    for v in ("false", "", "0", None):
        assert normalize_record({"secure_boot_provisioned": v})["secure_boot_provisioned"] is False
    many = [{"t": str(i), "kind": "k", "note": ""} for i in range(150)]
    assert [e["t"] for e in normalize_record({"events": many})["events"]] == [str(i) for i in range(50, 150)]
    assert len(normalize_record({"events": many})["events"]) == MAX_EVENTS


def test_utc_now_iso_format():
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", utc_now_iso())


def test_encode_cell():
    assert encode_cell("secure_boot_provisioned", True) == "true"
    assert encode_cell("metadata", {"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert encode_cell("chip", "BCM2712") == "BCM2712"


# ==================================================================================================
# local
# ==================================================================================================


def test_local_round_trip(tmp_path):
    st = LocalJsonStore(tmp_path / "reg")
    assert st.get("a7eb274c") is None and st.list() == []
    st.put(sample())
    got = st.get("a7eb274c")
    assert got == normalize_record(sample())
    assert got["rsa_private_pem"] == PEM
    st.put(sample(stage="gadget"))
    assert st.get("A7EB274C")["stage"] == "gadget"
    st.put(sample("00001234"))
    assert [r["serial"] for r in st.list()] == ["00001234", "a7eb274c"]
    files = sorted(p.name for p in (tmp_path / "reg").iterdir())
    assert files == ["00001234.json", "a7eb274c.json"]  # no temp files left behind
    d = st.describe()
    assert d["backend"] == "local" and d["ok"] is True and d["location"] == str(tmp_path / "reg")
    assert "2" in d["detail"]
    if os.name == "posix":
        assert (tmp_path / "reg" / "a7eb274c.json").stat().st_mode & 0o777 == 0o600


def test_local_rejects_path_tricks(tmp_path):
    st = LocalJsonStore(tmp_path / "reg")
    for bad in ("../x", "a/b", "", "a\\b", "x" * 80):
        with pytest.raises(StoreError):
            st.put(sample(bad))
        with pytest.raises(StoreError):
            st.get(bad)


def test_local_corrupt_file(tmp_path):
    st = LocalJsonStore(tmp_path)
    st.put(sample())
    (tmp_path / "deadbeef.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(StoreError, match="corrupt"):
        st.get("deadbeef")
    assert [r["serial"] for r in st.list()] == ["a7eb274c"]  # corrupt one skipped


def test_local_threaded_writes(tmp_path):
    st = LocalJsonStore(tmp_path)
    errors = []

    def worker(i):
        try:
            for j in range(10):
                st.put(sample(f"{i:08x}", chip=f"c{j}"))
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    assert len(st.list()) == 8 and all(r["chip"] == "c9" for r in st.list())


def test_local_accepts_config(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    st = LocalJsonStore(cfg)
    assert st.dir == cfg.storage.local_dir


def test_make_store(make_cfg, tmp_path):
    cfg = make_cfg(tmp_path)
    st = make_store(cfg)
    assert isinstance(st, LocalJsonStore) and st.backend == "local"
    with pytest.raises(StoreError, match="spreadsheet"):
        make_store(make_cfg(tmp_path, storage={"backend": "gsheets"}))
    with pytest.raises(StoreError, match="credentials"):
        make_store(make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": {"spreadsheet": "K"}}))
    with pytest.raises(StoreError, match="not found"):
        make_store(make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": {
            "spreadsheet": "K", "credentials": str(tmp_path / "missing.json")}}))
    with pytest.raises(StoreError, match="oauth"):
        make_store(make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": {"spreadsheet": "K", "auth": "oauth"}}))
    with pytest.raises(StoreError, match="folder_id"):
        make_store(make_cfg(tmp_path, storage={"backend": "gdrive"}))
    sa = tmp_path / "sa.json"
    sa.write_text("{}", encoding="utf-8")
    # valid config: constructed without touching the network or importing anything heavy
    st = make_store(make_cfg(tmp_path, storage={"backend": "gdrive", "gdrive": {"folder_id": "F", "credentials": str(sa)}}))
    assert isinstance(st, GoogleDriveStore)
    st = make_store(make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": {"spreadsheet": "K", "credentials": str(sa)}}))
    assert isinstance(st, GoogleSheetsStore)


def test_google_libraries_are_imported_lazily(tmp_path):
    import subprocess
    import sys

    code = (
        "import sys; from otp_server.config import load_config; from otp_server.storage import make_store; "
        "from otp_server.modules import ModuleService; "
        f"cfg = load_config(overrides={{'paths': {{'work': {str(tmp_path)!r}}}}}); "
        "st = make_store(cfg); st.put({'serial': 'a7eb274c'}); st.list(); "
        "print(sorted(m for m in ('gspread', 'googleapiclient', 'google_auth_oauthlib', 'google.oauth2') if m in sys.modules))"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("OTP_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"  # keep bytecode out of the repository tree
    env["OTP_CONFIG"] = str(tmp_path / "c.yaml")
    (tmp_path / "c.yaml").write_text("{}", encoding="utf-8")
    out = subprocess.run([sys.executable, "-B", "-c", code], cwd=str(REPO), env=env, capture_output=True, text=True, timeout=120)
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
from gspread.utils import a1_to_rowcol, extract_id_from_url  # noqa: E402
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
        return {"spreadsheetId": "sid", "tableRange": f"{self.title}!A1:T{r - 1}",
                "updates": {"spreadsheetId": "sid", "updatedRange": f"{self.title}!A{r}:T{r}", "updatedRows": 1}}

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

    def open_by_url(self, *a, **k):
        args = bind(RealClient.open_by_url, *a, **k)
        return self.open_by_key(extract_id_from_url(args["url"]))


def sheets_store(make_cfg, tmp_path, client, clock=None, **gs):
    g = {"spreadsheet": "SHEETKEY", "worksheet": "modules"}
    g.update(gs)
    cfg = make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": g})
    return GoogleSheetsStore(cfg, client=client, clock=clock or Clock())


def test_sheets_creates_worksheet_and_round_trips(make_cfg, tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(make_cfg, tmp_path, fake)
    assert st.get("a7eb274c") is None
    ws = fake.spreadsheet.sheets["modules"]
    assert ws.grid[0] == list(FIELDS)
    st.put(sample())
    st.put(sample("00001234", stage="new", secure_boot_provisioned=False))
    assert len(ws.grid) == 3
    # the stored cells are RAW strings: serials / hex stay text, PEM keeps its newlines
    row = dict(zip(FIELDS, ws.grid[1]))
    assert row["serial"] == "a7eb274c" and row["secure_boot_provisioned"] == "true"
    assert row["rsa_private_pem"] == PEM and json.loads(row["metadata"])["EEPROM_UPDATE"] == "success"
    assert ws.grid[2][0] == "00001234"
    # a second store instance (another server start) reads the same data back
    st2 = sheets_store(make_cfg, tmp_path / "b", fake)
    assert st2.get("a7eb274c") == normalize_record(sample())
    assert st2.get("00001234")["secure_boot_provisioned"] is False
    assert [r["serial"] for r in st2.list()] == ["a7eb274c", "00001234"]
    # upsert updates the row in place
    st2.put(sample(stage="flashed", chip="X"))
    assert len(ws.grid) == 3 and ws.grid[1][FIELDS.index("stage")] == "flashed"
    d = st2.describe()
    assert d == {"backend": "gsheets", "ok": True, "location": "Google Sheets SHEETKEY / modules",
                 "detail": "2 module record(s) cached"}


def test_sheets_open_by_url(make_cfg, tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(make_cfg, tmp_path, fake, spreadsheet="https://docs.google.com/spreadsheets/d/SHEETKEY/edit#gid=0")
    st.put(sample())
    assert fake.opened == ["SHEETKEY"]


def test_sheets_caching_and_quota(make_cfg, tmp_path):
    fake = FakeGspreadClient()
    clock = Clock()
    st = sheets_store(make_cfg, tmp_path, fake, clock=clock)
    st.put(sample())  # connect (1 read) + miss refresh is suppressed (<2 s) + append
    ws = fake.spreadsheet.sheets["modules"]
    reads = lambda: ws.calls.count("get_all_values")  # noqa: E731
    n0 = reads()
    for _ in range(20):
        assert st.get("a7eb274c")["stage"] == "eeprom"
        st.list()
    assert reads() == n0  # all served from cache
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


def test_sheets_row_index_survives_unknown_append_response(make_cfg, tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(make_cfg, tmp_path, fake)
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


def test_sheets_header_rules(make_cfg, tmp_path):
    # wrong header, no data -> canonical header written (grid widened when too narrow)
    fake = FakeGspreadClient()
    fake.spreadsheet.sheets["modules"] = FakeWorksheet("modules", cols=5, grid=[["foo", "bar"]])
    st = sheets_store(make_cfg, tmp_path, fake)
    st.put(sample())
    ws = fake.spreadsheet.sheets["modules"]
    assert ws.grid[0] == list(FIELDS) and "resize" in ws.calls
    # canonical header + extra operator columns is fine
    fake2 = FakeGspreadClient()
    fake2.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[list(FIELDS) + ["notes"]])
    st2 = sheets_store(make_cfg, tmp_path / "2", fake2)
    st2.put(sample())
    assert st2.get("a7eb274c")["chip"] == "BCM2712"
    # wrong header with data -> refuse
    fake3 = FakeGspreadClient()
    fake3.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[["serial", "name"], ["a7eb274c", "x"]])
    st3 = sheets_store(make_cfg, tmp_path / "3", fake3)
    with pytest.raises(StoreError, match="different header"):
        st3.get("a7eb274c")
    d = st3.describe()
    assert d["ok"] is False and "different header" in d["detail"]
    assert fake3.spreadsheet.sheets["modules"].grid[1] == ["a7eb274c", "x"]  # untouched


def test_sheets_not_shared_is_actionable_and_throttled(make_cfg, tmp_path):
    fake = FakeGspreadClient(sid="OTHER")
    clock = Clock()
    st = sheets_store(make_cfg, tmp_path, fake, clock=clock)
    with pytest.raises(StoreError, match="client_email"):
        st.list()
    d = st.describe()
    assert d["ok"] is False and "not shared" in d["detail"]
    assert len(fake.opened) == 1  # retry throttled
    clock.advance(11)
    st.describe()
    assert len(fake.opened) == 2


def test_sheets_cell_budget(make_cfg, tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(make_cfg, tmp_path, fake)
    big_events = [{"t": utc_now_iso(), "kind": "k", "note": "n" * 490} for _ in range(100)]
    st.put(sample(events=big_events))  # ~51 KB of events -> oldest dropped
    ws = fake.spreadsheet.sheets["modules"]
    cell = ws.grid[1][FIELDS.index("events")]
    assert len(cell) <= 45000 and 0 < len(json.loads(cell)) < 100
    assert st.get("a7eb274c")["events"] == json.loads(cell)
    with pytest.raises(StoreError, match="metadata"):
        st.put(sample("bbbbbbbb", metadata={"x": "y" * 46000}))


# ==================================================================================================
# Google Drive: real googleapiclient Drive v3 client over a fake HTTP transport
# ==================================================================================================

httplib2 = pytest.importorskip("httplib2")
discovery = pytest.importorskip("googleapiclient.discovery")


class FakeDriveHttp:
    """In-memory Drive v3 server speaking the HTTP the real client library produces."""

    FOLDER = "FOLDER1"

    def __init__(self, page_limit=2):
        self.files = {self.FOLDER: {"id": self.FOLDER, "name": "otp-registry", "mimeType": "application/vnd.google-apps.folder",
                                    "parents": [], "trashed": False, "content": b"", "modifiedTime": ""}}
        self.page_limit = page_limit
        self.log = []
        self._n = 0

    def _mtime(self):
        self._n += 1
        return f"2026-09-30T00:{self._n // 60:02d}:{self._n % 60:02d}.000Z"

    def add_file(self, name, content: bytes, parent=None):
        fid = f"id{len(self.files)}"
        self.files[fid] = {"id": fid, "name": name, "mimeType": "application/json", "parents": [parent or self.FOLDER],
                           "trashed": False, "content": content, "modifiedTime": self._mtime()}
        return fid

    def touch(self, fid, content: bytes):
        self.files[fid]["content"] = content
        self.files[fid]["modifiedTime"] = self._mtime()

    @staticmethod
    def _resp(status, obj):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        return httplib2.Response({"status": str(status), "content-type": "application/json"}), body

    def _err(self, status, msg):
        return self._resp(status, {"error": {"code": status, "message": msg, "errors": [{"reason": "notFound"}]}})

    @staticmethod
    def _meta(f, fields):
        keys = re.findall(r"[a-zA-Z]+", fields.replace("files(", "")) if fields else ["id", "name", "mimeType"]
        return {k: f[k] for k in keys if k in f and k != "content"}

    def _match(self, f, q):
        for clause in q.split(" and "):
            clause = clause.strip()
            if m := re.fullmatch(r"'(.+)' in parents", clause):
                if m.group(1) not in f["parents"]:
                    return False
            elif clause == "trashed = false":
                if f["trashed"]:
                    return False
            elif m := re.fullmatch(r"name contains '(.+)'", clause):
                if m.group(1) not in f["name"]:
                    return False
            elif m := re.fullmatch(r"name = '(.+)'", clause):
                if f["name"] != m.group(1):
                    return False
            else:
                raise AssertionError(f"unsupported query clause {clause!r}")
        return True

    def request(self, uri, method="GET", body=None, headers=None, redirections=5, connection_type=None):
        u = urlsplit(uri)
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        self.log.append((method, u.path, qs))
        assert qs.get("supportsAllDrives") == "true", uri
        path = u.path
        if method == "GET" and path == "/drive/v3/files":
            assert qs.get("includeItemsFromAllDrives") == "true"
            hits = [f for f in self.files.values() if f["id"] != self.FOLDER and self._match(f, qs["q"])]
            start = int(qs.get("pageToken", "0"))
            size = min(int(qs.get("pageSize", "100")), self.page_limit)
            page = hits[start:start + size]
            out = {"files": [self._meta(f, qs.get("fields", "")) for f in page]}
            if start + size < len(hits):
                out["nextPageToken"] = str(start + size)
            return self._resp(200, out)
        m = re.fullmatch(r"/drive/v3/files/([^/]+)", path)
        if method == "GET" and m:
            f = self.files.get(m.group(1))
            if f is None or f["trashed"]:
                return self._err(404, "File not found")
            if qs.get("alt") == "media":
                return self._resp(200, f["content"])
            return self._resp(200, self._meta(f, qs.get("fields", "")))
        if method == "POST" and path == "/upload/drive/v3/files":
            assert qs.get("uploadType") == "multipart"
            ctype = headers.get("content-type") or headers.get("Content-Type")
            raw = body if isinstance(body, bytes) else body.encode()
            msg = email.message_from_bytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + raw,
                                           policy=email.policy.HTTP)
            parts = list(msg.iter_parts())
            meta = json.loads(parts[0].get_content())
            assert parts[1].get_content_type() == "application/json"
            content = parts[1].get_payload(decode=True)
            fid = self.add_file(meta["name"], content, parent=meta["parents"][0])
            assert meta.get("mimeType") == "application/json"
            return self._resp(200, self._meta(self.files[fid], qs.get("fields", "")))
        m = re.fullmatch(r"/upload/drive/v3/files/([^/]+)", path)
        if method == "PATCH" and m:
            assert qs.get("uploadType") == "media"
            f = self.files.get(m.group(1))
            if f is None or f["trashed"]:
                return self._err(404, "File not found")
            self.touch(f["id"], body if isinstance(body, bytes) else body.encode())
            return self._resp(200, self._meta(f, qs.get("fields", "")))
        raise AssertionError(f"unexpected request {method} {uri}")


def drive_service(http):
    return discovery.build("drive", "v3", http=http, static_discovery=True)


def drive_store(make_cfg, tmp_path, http, clock=None, folder=FakeDriveHttp.FOLDER):
    cfg = make_cfg(tmp_path, storage={"backend": "gdrive", "gdrive": {"folder_id": folder}})
    return GoogleDriveStore(cfg, client=drive_service(http), clock=clock or Clock())


def by_name(http, name):
    return [f for f in http.files.values() if f["name"] == name and not f["trashed"]]


def test_drive_round_trip(make_cfg, tmp_path):
    http = FakeDriveHttp()
    st = drive_store(make_cfg, tmp_path, http)
    assert st.get("a7eb274c") is None
    st.put(sample())
    files = by_name(http, "a7eb274c.json")
    assert len(files) == 1 and files[0]["parents"] == [FakeDriveHttp.FOLDER]
    assert json.loads(files[0]["content"])["rsa_private_pem"] == PEM
    assert st.get("a7eb274c") == normalize_record(sample())
    st.put(sample(stage="flashed"))
    files = by_name(http, "a7eb274c.json")
    assert len(files) == 1 and json.loads(files[0]["content"])["stage"] == "flashed"  # updated, not duplicated
    for i in range(5):
        st.put(sample(f"0000000{i}"))
    st2 = drive_store(make_cfg, tmp_path / "b", http)  # fresh instance; listing is paginated (2 per page)
    got = st2.list()
    assert [r["serial"] for r in got] == ["00000000", "00000001", "00000002", "00000003", "00000004", "a7eb274c"]
    assert got[-1]["stage"] == "flashed"
    d = st2.describe()
    assert d == {"backend": "gdrive", "ok": True, "location": "Google Drive folder otp-registry (FOLDER1)",
                 "detail": "6 module record(s) cached"}


def test_drive_cache_and_changed_files(make_cfg, tmp_path):
    http = FakeDriveHttp(page_limit=100)
    fid = http.add_file("a7eb274c.json", json.dumps(sample()).encode())
    http.add_file("notes.txt.json", b"{}")  # not a serial -> ignored
    http.add_file("bbbbbbbb.json", b"garbage")  # bad JSON -> ignored
    http.add_file("cccccccc.json", json.dumps(sample("cccccccc")).encode(), parent="OTHER")  # other folder
    clock = Clock()
    st = drive_store(make_cfg, tmp_path, http, clock=clock)
    assert [r["serial"] for r in st.list()] == ["a7eb274c"]
    downloads = lambda: sum(1 for m, p, q in http.log if q.get("alt") == "media")  # noqa: E731
    n0 = downloads()
    calls0 = len(http.log)
    for _ in range(10):
        st.get("a7eb274c")
        st.list()
    assert len(http.log) == calls0  # served from cache
    clock.advance(11)
    st.list()
    assert downloads() == n0  # listed again, content unchanged -> not downloaded again
    http.touch(fid, json.dumps(sample(chip="EXTERNAL")).encode())
    clock.advance(31)
    assert st.get("a7eb274c")["chip"] == "EXTERNAL"
    assert downloads() == n0 + 1


def test_drive_recreates_deleted_file(make_cfg, tmp_path):
    http = FakeDriveHttp()
    st = drive_store(make_cfg, tmp_path, http)
    st.put(sample())
    http.files[by_name(http, "a7eb274c.json")[0]["id"]]["trashed"] = True
    st.put(sample(stage="gadget"))
    files = by_name(http, "a7eb274c.json")
    assert len(files) == 1 and json.loads(files[0]["content"])["stage"] == "gadget"


def test_drive_folder_errors(make_cfg, tmp_path):
    http = FakeDriveHttp()
    st = drive_store(make_cfg, tmp_path, http, folder="NOPE")
    with pytest.raises(StoreError, match="client_email"):
        st.get("a7eb274c")
    d = st.describe()
    assert d["ok"] is False and "not found" in d["detail"]
    fid = http.add_file("x.json", b"{}")
    st2 = drive_store(make_cfg, tmp_path / "2", http, folder=fid)
    with pytest.raises(StoreError, match="not a folder"):
        st2.list()


# ==================================================================================================
# review fixes: moved rows, HTTP timeout, no browser login on request threads, advice per auth mode
# ==================================================================================================

import otp_server.storage.gsheets as gsheets_mod  # noqa: E402


def test_sheets_put_never_overwrites_a_row_that_moved(make_cfg, tmp_path):
    fake = FakeGspreadClient()
    st = sheets_store(make_cfg, tmp_path, fake)
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


def test_sheets_client_gets_an_http_timeout(make_cfg, tmp_path, monkeypatch):
    from google.auth.credentials import AnonymousCredentials

    sa = tmp_path / "sa.json"
    sa.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(gspread, "service_account", lambda **k: gspread.Client(auth=AnonymousCredentials()))
    cfg = make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": {"spreadsheet": "K", "credentials": str(sa)}})
    gc = GoogleSheetsStore(cfg)._make_client()
    assert gc.http_client.timeout == gsheets_mod.HTTP_TIMEOUT
    assert all(t is not None and t > 0 for t in gsheets_mod.HTTP_TIMEOUT)


def test_sheets_timeout_is_a_store_error_and_throttled(make_cfg, tmp_path):
    import requests

    class TimingOut(FakeGspreadClient):
        def open_by_key(self, *a, **k):
            self.opened.append(a)
            raise requests.exceptions.ReadTimeout("read timed out (read timeout=60)")

    fake = TimingOut()
    st = sheets_store(make_cfg, tmp_path, fake)
    with pytest.raises(StoreError, match="unreachable"):
        st.list()
    assert st.describe()["ok"] is False and len(fake.opened) == 1


def _oauth_token(path, *, expired=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "token": "old-access", "refresh_token": "r-token", "client_id": "cid.apps.googleusercontent.com",
        "client_secret": "csecret", "token_uri": "https://oauth2.googleapis.com/token",
        "expiry": "2020-01-01T00:00:00Z" if expired else "2999-01-01T00:00:00Z",
    }), encoding="utf-8")
    return path


def _oauth_cfg(make_cfg, tmp_path, backend, *, token=True, expired=True):
    client = tmp_path / "client.json"
    client.write_text(json.dumps({"installed": {"client_id": "cid", "client_secret": "s",
                                                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                                                "token_uri": "https://oauth2.googleapis.com/token",
                                                "redirect_uris": ["http://localhost"]}}), encoding="utf-8")
    tok = tmp_path / "tok" / f"{backend}-token.json"
    if token:
        _oauth_token(tok, expired=expired)
    g = {"auth": "oauth", "credentials": str(client), "token": str(tok)}
    g.update({"spreadsheet": "SHEETKEY"} if backend == "gsheets" else {"folder_id": FakeDriveHttp.FOLDER})
    return make_cfg(tmp_path, storage={"backend": backend, backend: g})


_BROWSER_FLOWS: list = []


@pytest.fixture(autouse=True)
def _never_open_a_real_browser(monkeypatch):
    """No test may ever reach the real loopback OAuth server (it would open a browser and wait)."""
    _BROWSER_FLOWS.clear()

    def refuse(*a, **k):
        _BROWSER_FLOWS.append(a)
        raise AssertionError("interactive OAuth flow started outside 'login'")

    monkeypatch.setattr(gspread, "oauth", refuse)
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:  # pragma: no cover
        return refuse
    monkeypatch.setattr(InstalledAppFlow, "run_local_server", refuse)
    return refuse


@pytest.fixture
def no_browser(monkeypatch, _never_open_a_real_browser):
    """Any interactive login attempt (including our own login flow) is recorded and fails."""
    monkeypatch.setattr(gsheets_mod, "run_oauth_flow", _never_open_a_real_browser)
    return _BROWSER_FLOWS


@pytest.mark.parametrize("backend", ["gsheets", "gdrive"])
def test_oauth_missing_token_asks_for_login_and_never_opens_a_browser(make_cfg, tmp_path, no_browser, backend):
    cfg = _oauth_cfg(make_cfg, tmp_path, backend, token=False)
    st = make_store(cfg)
    d = st.describe()  # the /api/status poll path
    assert d["ok"] is False and "python -m otp_server login" in d["detail"]
    with pytest.raises(StoreError, match="otp_server login"):
        st.list()
    assert no_browser == []


@pytest.mark.parametrize("backend", ["gsheets", "gdrive"])
def test_oauth_refresh_network_error_is_retryable_store_error(make_cfg, tmp_path, no_browser, monkeypatch, backend):
    from google.auth.exceptions import TransportError
    from google.oauth2.credentials import Credentials

    calls = []

    def offline(self, request):
        calls.append(1)
        raise TransportError("Failed to establish a new connection")

    monkeypatch.setattr(Credentials, "refresh", offline)
    clock = Clock()
    cfg = _oauth_cfg(make_cfg, tmp_path, backend)
    st = GoogleSheetsStore(cfg, clock=clock) if backend == "gsheets" else GoogleDriveStore(cfg, clock=clock)
    d = st.describe()
    assert d["ok"] is False and "cannot reach Google" in d["detail"] and "login" not in d["detail"]
    st.describe()
    assert len(calls) == 1  # throttled
    clock.advance(11)
    st.describe()
    assert len(calls) == 2 and no_browser == []


@pytest.mark.parametrize("backend", ["gsheets", "gdrive"])
def test_oauth_revoked_token_asks_for_login(make_cfg, tmp_path, no_browser, monkeypatch, backend):
    from google.auth.exceptions import RefreshError
    from google.oauth2.credentials import Credentials

    def revoked(self, request):
        raise RefreshError("invalid_grant: Token has been expired or revoked.")

    monkeypatch.setattr(Credentials, "refresh", revoked)
    st = make_store(_oauth_cfg(make_cfg, tmp_path, backend))
    d = st.describe()
    assert d["ok"] is False and "rejected" in d["detail"] and "python -m otp_server login" in d["detail"]
    assert no_browser == []


def test_oauth_refreshed_token_is_saved(make_cfg, tmp_path, no_browser, monkeypatch):
    import datetime as dt

    from google.oauth2.credentials import Credentials

    def ok(self, request):
        self.token = "new-access"
        self.expiry = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(hours=1)

    monkeypatch.setattr(Credentials, "refresh", ok)
    fake = FakeGspreadClient()
    fake.http_client = gspread.http_client.HTTPClient(auth=None, session=object())
    got = []
    monkeypatch.setattr(gspread, "authorize", lambda creds, **k: got.append(creds) or fake)
    cfg = _oauth_cfg(make_cfg, tmp_path, "gsheets")
    st = GoogleSheetsStore(cfg)
    assert st.describe()["ok"] is True
    assert got[0].token == "new-access" and fake.http_client.timeout == gsheets_mod.HTTP_TIMEOUT
    assert json.loads(cfg.storage.gsheets.token.read_text(encoding="utf-8"))["token"] == "new-access"
    assert no_browser == []


class _FlowCreds:
    def to_json(self):
        return json.dumps({"token": "t", "refresh_token": "r", "client_id": "c", "client_secret": "s"})


def test_sheets_login_oauth_runs_the_flow_with_a_timeout(make_cfg, tmp_path, monkeypatch):
    seen = {}

    def flow(client_file, scopes, *, timeout, open_browser=True):
        seen.update(client=client_file, scopes=scopes, timeout=timeout)
        return _FlowCreds()

    monkeypatch.setattr(gsheets_mod, "run_oauth_flow", flow)
    fake = FakeGspreadClient()
    monkeypatch.setattr(gspread, "authorize", lambda creds, **k: fake)
    cfg = _oauth_cfg(make_cfg, tmp_path, "gsheets", token=False)
    st = make_store(cfg)
    assert st.describe()["ok"] is False  # not logged in yet
    msg = st.login(timeout=42)
    assert seen["timeout"] == 42 and "https://www.googleapis.com/auth/spreadsheets" in seen["scopes"]
    assert "token saved" in msg and "reachable" in msg
    assert json.loads(cfg.storage.gsheets.token.read_text(encoding="utf-8"))["refresh_token"] == "r"
    assert st.describe()["ok"] is True  # the throttled earlier failure does not stick


def test_login_timeout_is_a_store_error(make_cfg, tmp_path, monkeypatch):
    class WSGITimeoutError(AttributeError):
        pass

    def slow(*a, **k):
        raise WSGITimeoutError("Timed out waiting for response from authorization server")

    monkeypatch.setattr(gsheets_mod, "run_oauth_flow", slow)
    st = make_store(_oauth_cfg(make_cfg, tmp_path, "gdrive", token=False))
    with pytest.raises(StoreError, match="no answer from the browser within 5 s"):
        st.login(timeout=5)


def test_run_oauth_flow_passes_a_timeout(monkeypatch, tmp_path):
    from google_auth_oauthlib.flow import InstalledAppFlow

    seen = {}

    class Flow:
        def run_local_server(self, **k):
            seen.update(k)
            return _FlowCreds()

    monkeypatch.setattr(InstalledAppFlow, "from_client_secrets_file", classmethod(lambda cls, f, s: Flow()))
    gsheets_mod.run_oauth_flow(tmp_path / "c.json", ["s"], timeout=30, open_browser=False)
    assert seen["timeout_seconds"] == 30 and seen["port"] == 0 and seen["open_browser"] is False


def test_sheets_login_service_account_checks_access(make_cfg, tmp_path):
    sa = tmp_path / "sa.json"
    sa.write_text(json.dumps({"client_email": "otp@proj.iam.gserviceaccount.com"}), encoding="utf-8")
    fake = FakeGspreadClient(sid="OTHER")
    cfg = make_cfg(tmp_path, storage={"backend": "gsheets", "gsheets": {"spreadsheet": "SHEETKEY", "credentials": str(sa)}})
    st = GoogleSheetsStore(cfg, client=fake)
    with pytest.raises(StoreError, match="client_email"):
        st.login()
    fake.spreadsheet.id = "SHEETKEY"
    msg = st.login()  # no 10 s retry throttle for an explicit login
    assert msg.startswith("service account otp@proj.iam.gserviceaccount.com") and "reachable" in msg


def test_sheets_explain_per_auth_mode(make_cfg, tmp_path):
    from google.auth.exceptions import RefreshError

    def detail(exc, auth, sub):
        class Raising(FakeGspreadClient):
            def open_by_key(self, *a, **k):
                raise exc

        st = sheets_store(make_cfg, tmp_path / sub, Raising(), auth=auth, token=str(tmp_path / "tok.json"))
        return st.describe()["detail"]

    d = detail(RefreshError("invalid_grant: Invalid JWT Signature."), "service_account", "a")
    assert "service-account key" in d and "new JSON key" in d and "tok.json" not in d and "login" not in d
    d = detail(RefreshError("invalid_grant: Token has been expired or revoked."), "oauth", "b")
    assert "OAuth token" in d and "python -m otp_server login" in d
    d = detail(PermissionError(13, "Permission denied", str(tmp_path / "tok.json")), "oauth", "c")
    assert "file-system" in d and "share" not in d
    d = detail(PermissionError(), "service_account", "d")  # gspread's HTTP 403
    assert "share it with the service account's client_email" in d
    d = detail(PermissionError(), "oauth", "e")
    assert "logged in with" in d and "client_email" not in d


class QuotaDriveHttp(FakeDriveHttp):
    """A folder in a user's My Drive: a service account may read it but every create is refused."""

    def request(self, uri, method="GET", body=None, headers=None, redirections=5, connection_type=None):
        if method == "POST" and urlsplit(uri).path == "/upload/drive/v3/files":
            msg = ("Service Accounts do not have storage quota. Leverage shared drives "
                   "(https://developers.google.com/workspace/drive/api/guides/about-shareddrives), "
                   "or use OAuth delegation instead.")
            return self._resp(403, {"error": {"code": 403, "message": msg, "errors": [
                {"message": msg, "domain": "usageLimits", "reason": "storageQuotaExceeded"}]}})
        return super().request(uri, method, body, headers, redirections, connection_type)


def test_drive_service_account_in_my_drive_explains_storage_quota(make_cfg, tmp_path, caplog):
    http = QuotaDriveHttp()
    st = drive_store(make_cfg, tmp_path, http)
    with caplog.at_level("WARNING", logger="otp_server.storage.gdrive"):
        assert st.get("a7eb274c") is None  # reading works
    assert "My Drive" in caplog.text
    with pytest.raises(StoreError) as ei:
        st.put(sample())
    msg = str(ei.value)
    assert "storage quota" in msg and "Shared Drive" in msg and "oauth" in msg
    assert "share the folder with the account as Editor" not in msg


def test_drive_storage_full_with_oauth(make_cfg, tmp_path):
    http = QuotaDriveHttp()
    cfg = make_cfg(tmp_path, storage={"backend": "gdrive", "gdrive": {
        "folder_id": FakeDriveHttp.FOLDER, "auth": "oauth", "token": str(tmp_path / "t.json")}})
    st = GoogleDriveStore(cfg, client=drive_service(http), clock=Clock())
    with pytest.raises(StoreError, match="storage of the logged-in account is full"):
        st.put(sample())


def test_drive_login_service_account_warns_outside_shared_drive(make_cfg, tmp_path):
    http = FakeDriveHttp()
    st = drive_store(make_cfg, tmp_path, http)
    msg = st.login()
    assert "reachable" in msg and "not in a Shared Drive" in msg
    http.files[FakeDriveHttp.FOLDER]["driveId"] = "0AShared"
    msg = drive_store(make_cfg, tmp_path / "b", http).login()
    assert "reachable" in msg and "WARNING" not in msg


def test_drive_login_oauth(make_cfg, tmp_path, monkeypatch):
    http = FakeDriveHttp()
    monkeypatch.setattr(gsheets_mod, "run_oauth_flow", lambda *a, **k: _FlowCreds())
    monkeypatch.setattr(GoogleDriveStore, "_build", staticmethod(lambda creds: drive_service(http)))
    cfg = _oauth_cfg(make_cfg, tmp_path, "gdrive", token=False)
    st = make_store(cfg)
    msg = st.login()
    assert "token saved" in msg and "otp-registry" in msg and "WARNING" not in msg
    assert cfg.storage.gdrive.token.is_file()
    st.put(sample())
    assert by_name(http, "a7eb274c.json")


def test_sheets_login_during_run_takes_effect_without_restart(make_cfg, tmp_path, no_browser, monkeypatch):
    """A token revoked mid-run: after 'python -m otp_server login' the running store rebuilds its own
    client on the next connect (it must not keep the rejected one until a server restart)."""
    from google.auth.exceptions import RefreshError

    clock = Clock()
    st = GoogleSheetsStore(_oauth_cfg(make_cfg, tmp_path, "gsheets", expired=False), clock=clock)
    good = FakeGspreadClient()
    built = []

    def make_client():
        built.append(1)
        return good if len(built) != 1 else first

    first = FakeGspreadClient()
    monkeypatch.setattr(st, "_make_client", make_client)
    st.put(normalize_record({"serial": "a7eb274c", "stage": "new", "created": "x", "updated": "x"}))
    assert len(built) == 1

    # the token gets revoked: every Sheets call of the first client now fails with a non-retryable RefreshError
    def revoked(*a, **k):
        raise RefreshError("invalid_grant: Token has been expired or revoked.")
    for ws in first.spreadsheet.sheets.values():
        ws.get_all_values = revoked
    clock.advance(31)
    with pytest.raises(StoreError, match="otp_server login"):
        st.list()

    # the operator logs in (new token on disk); after the retry throttle the store reconnects by itself
    good.spreadsheet.sheets = first.spreadsheet.sheets.copy()
    good.spreadsheet.sheets["modules"] = FakeWorksheet("modules", grid=[list(FIELDS)])
    clock.advance(11)
    assert st.list() == [] and len(built) == 2
    assert no_browser == []


def test_drive_auth_failure_drops_the_service(make_cfg, tmp_path):
    """A 401 from Drive forgets an own service (rebuilt on the next connect); an injected one is kept."""
    http = FakeDriveHttp()
    st = drive_store(make_cfg, tmp_path, http)
    st._connected = True

    class Unauthorized(Exception):
        def __init__(self):
            super().__init__("401 Unauthorized")
            self.resp = type("R", (), {"status": 401})()

    st._explain(Unauthorized())
    assert st._connected is False and st._svc is not None   # injected client is not dropped
    st._own_client = True
    st._connected = True
    st._explain(Unauthorized())
    assert st._connected is False and st._svc is None
