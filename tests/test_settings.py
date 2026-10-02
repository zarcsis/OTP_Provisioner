"""otp_server.settings: the ``settings`` worksheet that replaced the configuration file.

The Google side is faked with small in-memory classes that follow the gspread calls SettingsSheet makes:
``spreadsheet().worksheet(name)``, ``add_worksheet(title=, rows=, cols=)``, ``ws.update(values, range,
value_input_option=)``, ``ws.get_all_values()`` and ``ws.append_rows(rows, value_input_option=, table_range=)``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from otp_server.config import DEFAULT_BOOT_CONF, DEFAULTS, load_config
from otp_server.google_account import GoogleAccount, NotSignedIn
from otp_server.settings import (
    BOOTSTRAP,
    DESCRIPTIONS,
    HEADER,
    WORKSHEET,
    SettingsSheet,
    decode_rows,
    encode_value,
    setting_defaults,
)
from otp_server.storage.base import StoreError


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for n in ("OTP_WORK_DIR", "OTP_PORT"):
        monkeypatch.delenv(n, raising=False)


# --------------------------------------------------------------------------------------------------
# Fakes (named like the gspread exceptions: the product recognises them by class name)
# --------------------------------------------------------------------------------------------------


class WorksheetNotFound(Exception):
    pass


class APIError(Exception):
    def __init__(self, msg: str, code: int = 500):
        super().__init__(msg)
        self.code = code


class FakeWorksheet:
    def __init__(self, title: str, rows: list[list[Any]] | None = None, *, nrows: int = 1000, ncols: int = 26):
        self.title = title
        self.rows: list[list[Any]] = [list(r) for r in (rows or [])]
        self.nrows, self.ncols = nrows, ncols
        self.calls: list[tuple] = []
        self.fail: dict[str, BaseException] = {}

    def _call(self, name: str, *args: Any) -> None:
        self.calls.append((name, *args))
        if name in self.fail:
            raise self.fail[name]

    def writes(self) -> list[tuple]:
        return [c for c in self.calls if c[0] in ("update", "append_rows", "delete_rows")]

    def delete_rows(self, start_index, end_index=None):
        self._call("delete_rows", start_index, end_index)
        end = start_index if end_index is None else end_index
        del self.rows[start_index - 1:end]

    def get_all_values(self) -> list[list[str]]:
        """Like the Sheets API + gspread: trailing empty rows are not returned, rows are padded."""
        self._call("get_all_values")
        rows = [[str(c) for c in r] for r in self.rows]
        while rows and not any(c.strip() for c in rows[-1]):
            rows.pop()
        width = max((len(r) for r in rows), default=0)
        return [r + [""] * (width - len(r)) for r in rows]

    def update(self, values, range_name=None, *, value_input_option=None):
        self._call("update", [list(v) for v in values], range_name, value_input_option)
        start = (range_name or "A1").split(":")[0]
        col, row = ord(start[0].upper()) - ord("A"), int(start[1:]) - 1
        for i, vals in enumerate(values):
            while len(self.rows) <= row + i:
                self.rows.append([])
            line = self.rows[row + i]
            for j, v in enumerate(vals):
                while len(line) <= col + j:
                    line.append("")
                line[col + j] = v

    def append_rows(self, values, value_input_option=None, insert_data_option=None, table_range=None):
        self._call("append_rows", [list(v) for v in values], value_input_option, table_range)
        while self.rows and not any(str(c).strip() for c in self.rows[-1]):
            self.rows.pop()
        self.rows.extend(list(v) for v in values)


class FakeSpreadsheet:
    def __init__(self, sid: str = "SHEET-ID", worksheets: dict[str, FakeWorksheet] | None = None):
        self.id = sid
        self.worksheets: dict[str, FakeWorksheet] = dict(worksheets or {})
        self.added: list[dict] = []
        self.fail: dict[str, BaseException] = {}

    @property
    def sheet1(self) -> Any:
        sh = self

        class _First:
            def update_title(self, title: str) -> None:
                sh.worksheets.setdefault(title, FakeWorksheet(title))

        return _First()

    def worksheet(self, title: str) -> FakeWorksheet:
        if "worksheet" in self.fail:
            raise self.fail["worksheet"]
        try:
            return self.worksheets[title]
        except KeyError:
            raise WorksheetNotFound(title) from None

    def add_worksheet(self, title: str, rows: int, cols: int, index: int | None = None) -> FakeWorksheet:
        self.added.append({"title": title, "rows": rows, "cols": cols})
        if "add_worksheet" in self.fail:
            raise self.fail["add_worksheet"]
        ws = FakeWorksheet(title, nrows=rows, ncols=cols)
        self.worksheets[title] = ws
        return ws


class FakeAccount:
    """What SettingsSheet needs from a GoogleAccount: ``spreadsheet()`` and ``explain(exc)``."""

    def __init__(self, sh: FakeSpreadsheet | None = None):
        self.sh = sh if sh is not None else FakeSpreadsheet()
        self.fail: BaseException | None = None
        self.explained: list[BaseException] = []

    def spreadsheet(self) -> FakeSpreadsheet:
        if self.fail is not None:
            raise self.fail
        return self.sh

    def explain(self, exc: BaseException) -> str:
        self.explained.append(exc)
        return f"explained: {type(exc).__name__}: {exc}"


def sheet_with(rows: list[list[Any]], *, title: str = WORKSHEET) -> tuple[FakeAccount, FakeWorksheet]:
    ws = FakeWorksheet(title, rows)
    return FakeAccount(FakeSpreadsheet(worksheets={title: ws})), ws


def default_rows() -> list[list[str]]:
    return [[k, encode_value(v), DESCRIPTIONS[k]] for k, v in setting_defaults()]


def flatten(node: dict, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for k, v in node.items():
        if isinstance(v, dict):
            out.extend(flatten(v, f"{prefix}{k}."))
        else:
            out.append((f"{prefix}{k}", v))
    return out


def load(tmp_path: Path, tree: dict | None = None):
    return load_config(settings=tree, overrides={"paths": {"work": str(tmp_path / "w")}})


# --------------------------------------------------------------------------------------------------
# setting_defaults / DESCRIPTIONS
# --------------------------------------------------------------------------------------------------


def test_setting_defaults_are_defaults_without_bootstrap():
    items = setting_defaults()
    keys = [k for k, _ in items]
    assert BOOTSTRAP == ("server", "paths.work")
    assert len(keys) == len(set(keys))
    assert not [k for k in keys if k == "server" or k.startswith("server.")]
    assert "paths.work" not in keys
    assert "paths.droneos" not in keys and "builds.image.config" not in keys     # retired
    assert [k for k in keys if k.startswith("image.")] == [
        "image.name", "image.hostname", "image.timezone", "image.user", "image.password_hash", "image.ssh",
        "image.ssh_password_login", "image.ssh_authorized_keys", "image.wifi_ssid", "image.wifi_password",
        "image.wifi_country", "image.wifi_hidden"]
    # exactly the leaves of DEFAULTS, in DEFAULTS order, with the DEFAULTS values
    expected = [(k, v) for k, v in flatten(DEFAULTS) if not k.startswith("server.") and k != "paths.work"]
    assert items == expected
    assert keys[0] == "provisioning.default_mode"
    assert (keys.index("provisioning.default_mode") < keys.index("image.hostname") < keys.index("builds.auto")
            < keys.index("docker.binary"))
    d = dict(items)
    assert d["provisioning.default_mode"] == "open"
    assert d["provisioning.boot_conf"] == DEFAULT_BOOT_CONF
    assert d["builds.image.overrides"] == []
    assert d["docker.desktop_path"] is None
    # retired keys are not settings
    assert not {"provisioning.secure_boot", "provisioning.mode", "builds.gadget.source"} & set(keys)
    assert not [k for k in keys if k.startswith("storage.")]


def test_every_setting_has_a_description():
    keys = [k for k, _ in setting_defaults()]
    assert set(DESCRIPTIONS) == set(keys)          # none missing, none stale
    for k in keys:
        assert isinstance(DESCRIPTIONS[k], str) and DESCRIPTIONS[k].strip(), k
    assert "open" in DESCRIPTIONS["provisioning.default_mode"] and "secure" in DESCRIPTIONS["provisioning.default_mode"]
    assert "IGconf_image_pmap" in DESCRIPTIONS["builds.image.overrides"]


# --------------------------------------------------------------------------------------------------
# encode_value / decode_rows
# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("value, text", [
    (True, "true"), (False, "false"), (None, ""),
    (0, "0"), (1, "1"), (268435456, "268435456"),
    ("open", "open"), ("", ""),
    ([], ""), (["A=1"], "A=1"), (["A=1", "B=2"], "A=1\nB=2"), (("a", "b"), "a\nb"),
    ("x\ny\n", "x\ny\n"), (DEFAULT_BOOT_CONF, DEFAULT_BOOT_CONF),
])
def test_encode_value(value, text):
    assert encode_value(value) == text


def test_decode_empty():
    assert decode_rows({}) == ({}, [])


def test_empty_cells_mean_default(tmp_path):
    rows = {"provisioning.default_mode": "", "provisioning.jtag_lock": "   ", "builds.image.overrides": "\n",
            "provisioning.boot_conf": " \r\n ", "docker.desktop_path": None}
    assert decode_rows(rows) == ({}, [])
    assert load(tmp_path, decode_rows(rows)[0]) == load(tmp_path)


def test_decode_builds_a_nested_text_tree():
    tree, unknown = decode_rows({
        "provisioning.default_mode": " secure ",
        "provisioning.jtag_lock": "TRUE",
        "builds.image.config": "configs/x.yaml",        # retired: neither a value nor an unknown key
        "builds.image.keep_raw_image": "yes",
        "docker.idle_timeout": " 60 ",
        "paths.droneos": "../dos",                       # retired
        "image.hostname": " drone7 ",
        "image.wifi_password": "  spaced pass ",         # kept exactly
    })
    assert unknown == []
    assert tree == {
        "provisioning": {"default_mode": "secure", "jtag_lock": "TRUE"},
        "builds": {"image": {"keep_raw_image": "yes"}},
        "docker": {"idle_timeout": "60"},     # stays text: load_config validates it
        "image": {"hostname": "drone7", "wifi_password": "  spaced pass "},
    }


@pytest.mark.parametrize("text, items", [
    ("A=1", ["A=1"]),
    ("A=1\nB=2", ["A=1", "B=2"]),
    ("A=1\r\nB=2\r\n", ["A=1", "B=2"]),
    ("  A=1  \n\n   B=2 \n", ["A=1", "B=2"]),
    ("A=1,B=2", ["A=1,B=2"]),               # lists are split by lines only: a comma stays in its item
    (" A=1 , B=2 ,", ["A=1 , B=2 ,"]),
    ("X=a,b\nY=c", ["X=a,b", "Y=c"]),      # one per line: commas inside a line are kept
])
def test_decode_lists(text, items, tmp_path):
    tree, unknown = decode_rows({"builds.image.overrides": text})
    assert unknown == []
    assert tree == {"builds": {"image": {"overrides": items}}}
    assert load(tmp_path, tree).builds.image.overrides == items


def test_decode_keeps_multiline_boot_conf(tmp_path):
    text = "[all]\r\nBOOT_UART=0\r\n\r\n[cm5]\r\nBOOT_ORDER=0xf1\r\n"
    tree, unknown = decode_rows({"provisioning.boot_conf": text})
    assert unknown == []
    assert tree == {"provisioning": {"boot_conf": "[all]\nBOOT_UART=0\n\n[cm5]\nBOOT_ORDER=0xf1\n"}}
    assert load(tmp_path, tree).provisioning.boot_conf == "[all]\nBOOT_UART=0\n\n[cm5]\nBOOT_ORDER=0xf1\n"
    # a single line (no newline at the end) is still a valid block
    tree, _ = decode_rows({"provisioning.boot_conf": "[all]"})
    assert load(tmp_path, tree).provisioning.boot_conf == "[all]\n"


def test_decode_reports_unknown_keys():
    rows = {
        "server.port": "9000",                 # bootstrap, not a setting
        "paths.work": "C:/w",                  # bootstrap, not a setting
        "provisioning.secure_boot": "true",    # retired
        "storage.backend": "local",            # retired
        "builds.gadget.source": "build",       # retired
        "provisioning": "x",                   # a section, not a setting
        "provisioning.default_mod": "",        # typo, even with an empty value
        "provisioning.default_mode": "secure",
    }
    tree, unknown = decode_rows(rows)
    assert unknown == ["server.port", "paths.work", "provisioning.secure_boot", "storage.backend",
                       "builds.gadget.source", "provisioning", "provisioning.default_mod"]
    assert tree == {"provisioning": {"default_mode": "secure"}}


def test_decoded_values_are_validated_end_to_end(tmp_path):
    rows = {
        "provisioning.default_mode": "SECURE",
        "provisioning.jtag_lock": "true",
        "provisioning.recovery_passphrase": "yes",
        "provisioning.confirm_irreversible": "FALSE",
        "provisioning.erase_storage": "0",
        "provisioning.firmware_channel": "latest",
        "provisioning.max_piece_size": "0x8000000",
        "builds.auto": "no",
        "builds.image.overrides": "A=1\nB=2",
        "image.hostname": "Drone7",
        "image.ssh": "yes",
        "image.ssh_authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD a@b",
        "image.wifi_ssid": "Field",
        "image.wifi_password": "pass word!",
        "image.wifi_country": "de",
        "builds.image.keep_raw_image": "on",
        "docker.binary": "podman",
        "docker.start_desktop": "off",
        "docker.idle_timeout": "0",
    }
    tree, unknown = decode_rows(rows)
    assert unknown == []
    cfg = load(tmp_path, tree)
    p = cfg.provisioning
    assert p.default_mode == "secure" and p.firmware_channel == "latest" and p.max_piece_size == 0x8000000
    assert (p.jtag_lock, p.recovery_passphrase, p.confirm_irreversible, p.erase_storage) == (True, True, False, False)
    assert cfg.builds.auto is False and cfg.builds.image.keep_raw_image is True
    assert cfg.builds.image.overrides == ["A=1", "B=2"]
    i = cfg.image
    assert i.hostname == "drone7" and i.ssh is True and len(i.ssh_authorized_keys) == 1
    assert (i.wifi_ssid, i.wifi_password, i.wifi_country) == ("Field", "pass word!", "DE")
    assert cfg.docker.binary == "podman" and cfg.docker.start_desktop is False and cfg.docker.idle_timeout == 0
    assert cfg.unknown_keys == []


@pytest.mark.parametrize("key, text, needle", [
    ("provisioning.default_mode", "paranoid", "provisioning.default_mode"),
    ("provisioning.firmware_channel", "beta", "provisioning.firmware_channel"),
    ("provisioning.jtag_lock", "perhaps", "provisioning.jtag_lock"),
    ("provisioning.max_piece_size", "1k", "provisioning.max_piece_size"),
    ("provisioning.max_piece_size", "4096", "provisioning.max_piece_size"),
    ("builds.auto", "2", "builds.auto"),
    ("docker.idle_timeout", "-1", "docker.idle_timeout"),
    ("builds.image.overrides", "A=1\nIGconf_image_pmap=clear", "IGconf_image_pmap"),
])
def test_decoded_bad_values_rejected_by_load_config(tmp_path, key, text, needle):
    tree, unknown = decode_rows({key: text})
    assert unknown == []
    with pytest.raises(ValueError) as ei:
        load(tmp_path, tree)
    assert needle in str(ei.value)


def test_defaults_round_trip_through_cells(tmp_path):
    """Every default, written to a cell by the server and read back, yields the default configuration."""
    rows = {k: encode_value(v) for k, v in setting_defaults()}
    tree, unknown = decode_rows(rows)
    assert unknown == []
    assert load(tmp_path, tree) == load(tmp_path)


def test_custom_values_round_trip_through_cells(tmp_path):
    values = {"provisioning.default_mode": "secure", "provisioning.jtag_lock": True,
              "provisioning.max_piece_size": 1 << 24, "provisioning.boot_conf": "[all]\nBOOT_ORDER=0xf1\n",
              "builds.image.overrides": ["A=1", "B=x,y"], "docker.idle_timeout": 0,
              "docker.start_desktop": False}
    tree, unknown = decode_rows({k: encode_value(v) for k, v in values.items()})
    assert unknown == []
    cfg = load(tmp_path, tree)
    assert cfg.provisioning.default_mode == "secure" and cfg.provisioning.jtag_lock is True
    assert cfg.provisioning.max_piece_size == 1 << 24
    assert cfg.provisioning.boot_conf == "[all]\nBOOT_ORDER=0xf1\n"
    assert cfg.builds.image.overrides == ["A=1", "B=x,y"]
    assert cfg.docker.idle_timeout == 0 and cfg.docker.start_desktop is False


def test_single_override_with_a_comma_round_trips():
    tree, _ = decode_rows({"builds.image.overrides": encode_value(["IGconf_x=a,b"])})
    assert tree == {"builds": {"image": {"overrides": ["IGconf_x=a,b"]}}}


# --------------------------------------------------------------------------------------------------
# SettingsSheet
# --------------------------------------------------------------------------------------------------


def test_read_creates_the_worksheet_with_header_and_defaults():
    account = FakeAccount()
    rows = SettingsSheet(account).read()
    sh = account.sh
    assert [a["title"] for a in sh.added] == ["settings"]
    added = sh.added[0]
    assert added["cols"] == len(HEADER) == 3
    assert added["rows"] >= len(setting_defaults()) + 1          # room for the header and every setting
    ws = sh.worksheets["settings"]
    assert ws.writes()[0] == ("update", [HEADER], "A1:C1", "RAW")
    assert ws.rows[0] == ["key", "value", "description"]
    assert ws.rows[1:] == default_rows()                          # DEFAULTS order, default text, description
    appends = [c for c in ws.calls if c[0] == "append_rows"]
    assert len(appends) == 1
    assert appends[0][2:] == ("RAW", "A1")                        # RAW: cells keep exactly this text
    assert rows == {k: encode_value(v) for k, v in setting_defaults()}
    assert account.explained == []


def test_custom_worksheet_name():
    account = FakeAccount()
    SettingsSheet(account, worksheet="station-settings").read()
    assert list(account.sh.worksheets) == ["station-settings"]
    assert account.sh.worksheets["station-settings"].rows[0] == HEADER


def test_missing_keys_are_appended_exactly_once():
    account = FakeAccount()
    sheet = SettingsSheet(account)
    first = sheet.read()
    ws = account.sh.worksheets["settings"]
    n_rows, n_writes = len(ws.rows), len(ws.writes())
    second = sheet.read()
    assert second == first
    assert len(ws.rows) == n_rows and len(ws.writes()) == n_writes   # nothing written the second time
    assert len(account.sh.added) == 1                                # the worksheet is not created again
    keys = [r[0] for r in ws.rows[1:]]
    assert len(keys) == len(set(keys))


def test_operator_values_are_never_overwritten(tmp_path):
    operator = [
        ["key", "value", "description"],
        ["provisioning.default_mode", "secure", "my own note"],
        ["builds.image.overrides", "A=1\nB=2", ""],
        ["provisioning.firmware_channel", "", "left empty on purpose"],   # empty = default, not re-added
        ["docker.idle_timeout", "90"],                                    # no description column
    ]
    account, ws = sheet_with([list(r) for r in operator])
    rows = SettingsSheet(account).read()
    # the operator's rows are untouched, only the missing settings were added below them
    assert ws.rows[:len(operator)] == operator
    assert not [c for c in ws.calls if c[0] == "update"]                # the header was right: not rewritten
    appended = [c for c in ws.calls if c[0] == "append_rows"]
    assert len(appended) == 1
    present = {r[0] for r in operator[1:]}
    assert appended[0][1] == [r for r in default_rows() if r[0] not in present]
    assert rows["provisioning.default_mode"] == "secure"
    assert rows["builds.image.overrides"] == "A=1\nB=2"
    assert rows["provisioning.firmware_channel"] == ""
    assert rows["docker.idle_timeout"] == "90"
    assert set(rows) == {k for k, _ in setting_defaults()}
    # and the values reach the configuration
    tree, unknown = decode_rows(rows)
    assert unknown == []
    cfg = load(tmp_path, tree)
    assert cfg.provisioning.default_mode == "secure"
    assert cfg.provisioning.firmware_channel == "default"
    assert cfg.builds.image.overrides == ["A=1", "B=2"]
    assert cfg.docker.idle_timeout == 90


def test_complete_sheet_is_left_alone():
    full = [list(HEADER)] + default_rows()
    full[1][1] = "secure"
    account, ws = sheet_with([list(r) for r in full])
    rows = SettingsSheet(account).read()
    assert ws.writes() == []
    assert ws.rows == full
    assert rows["provisioning.default_mode"] == "secure"


def test_retired_rows_are_removed_from_the_sheet(caplog):
    caplog.set_level(logging.INFO, logger="otp_server.settings")
    full = [list(HEADER)] + default_rows()
    full.insert(1, ["paths.droneos", "external/droneos", "droneos checkout"])
    full.insert(9, ["builds.image.config", "droneos.yaml", "rpi-image-gen config inside the droneos checkout"])
    full.append(["paths.droneos", "again", "a duplicate further down"])
    account, ws = sheet_with([list(r) for r in full])
    rows = SettingsSheet(account).read()
    assert "paths.droneos" not in rows and "builds.image.config" not in rows
    deletes = [c for c in ws.calls if c[0] == "delete_rows"]
    assert [c[1] for c in deletes] == [len(full), 10, 2]           # bottom up: the row numbers stay valid
    assert ws.rows == [list(HEADER)] + default_rows()
    assert any("removed the retired setting paths.droneos" in r.getMessage() for r in caplog.records)
    assert SettingsSheet(account).read() == rows                     # nothing left to remove
    assert [c for c in ws.calls if c[0] == "delete_rows"] == deletes


def test_write_updates_value_cells_and_appends_missing_rows():
    full = [list(HEADER)] + [r for r in default_rows() if r[0] != "image.wifi_ssid"]
    account, ws = sheet_with([list(r) for r in full])
    sheet = SettingsSheet(account)
    written = sheet.write({"image.hostname": "drone7", "image.ssh": True, "image.wifi_country": "00",
                           "image.ssh_authorized_keys": ["k1", "k2"], "image.wifi_ssid": "=SUM(A1)",
                           "image.wifi_password": "  spaced  "})
    assert written == {"image.hostname": "drone7", "image.ssh": "true", "image.wifi_country": "00",
                       "image.ssh_authorized_keys": "k1\nk2", "image.wifi_ssid": "=SUM(A1)",
                       "image.wifi_password": "  spaced  "}
    updates = [c for c in ws.calls if c[0] == "update"]
    assert all(c[3] == "RAW" for c in updates)                        # 00 stays text, =... is no formula
    row_of = {r[0]: n for n, r in enumerate(ws.rows, start=1)}
    assert ("update", [["drone7"]], f"B{row_of['image.hostname']}", "RAW") in ws.calls
    appended = [c for c in ws.calls if c[0] == "append_rows"]
    assert appended == [("append_rows", [["image.wifi_ssid", "=SUM(A1)", DESCRIPTIONS["image.wifi_ssid"]]], "RAW", "A1")]
    rows = sheet.read()
    assert rows["image.hostname"] == "drone7" and rows["image.wifi_country"] == "00"
    assert rows["image.ssh_authorized_keys"] == "k1\nk2" and rows["image.wifi_password"] == "  spaced  "
    tree, unknown = decode_rows(rows)
    assert unknown == [] and tree["image"]["wifi_password"] == "  spaced  "


def test_write_refuses_unknown_keys_and_maps_google_errors():
    account, ws = sheet_with([list(HEADER)] + default_rows())
    sheet = SettingsSheet(account)
    with pytest.raises(ValueError, match="not a setting: image.nope, paths.droneos"):
        sheet.write({"image.nope": 1, "paths.droneos": "x", "image.user": "pi"})
    assert ws.writes() == []
    assert sheet.write({}) == {}
    ws.fail["update"] = ConnectionError("reset")
    with pytest.raises(StoreError):
        sheet.write({"image.user": "op"})


def test_comments_blank_rows_and_duplicates_ignored(caplog):
    caplog.set_level(logging.WARNING, logger="otp_server.settings")
    account, ws = sheet_with([
        ["Key", " VALUE ", "Notes"],                         # header: case/whitespace and column 3 free
        ["# scenario settings", "whatever", ""],
        ["#provisioning.jtag_lock", "true", "commented out"],
        ["", "orphan value", ""],
        [],
        ["provisioning.default_mode", "secure", ""],
        ["  provisioning.erase_storage  ", "false", ""],     # key cell trimmed
        ["provisioning.default_mode", "open", "duplicate"],  # the first one wins
        ["provisioning.recovery_passphrase"],                # key only: empty value
    ])
    rows = SettingsSheet(account).read()
    assert rows["provisioning.default_mode"] == "secure"
    assert rows["provisioning.erase_storage"] == "false"
    assert rows["provisioning.recovery_passphrase"] == ""
    assert rows["provisioning.jtag_lock"] == "false"         # the commented row does not count: default added
    assert not [k for k in rows if k.startswith("#") or not k]
    appended = [r[0] for c in ws.calls if c[0] == "append_rows" for r in c[1]]
    assert "provisioning.jtag_lock" in appended
    assert "provisioning.default_mode" not in appended and "provisioning.erase_storage" not in appended
    assert "provisioning.recovery_passphrase" not in appended
    assert not [c for c in ws.calls if c[0] == "update"]
    assert any("duplicate key provisioning.default_mode ignored" in r.getMessage() for r in caplog.records)
    assert decode_rows(rows)[1] == []


@pytest.mark.parametrize("existing", [[], [["", "", ""]], [[""], [], ["", " "]]])
def test_blank_existing_worksheet_gets_the_header(existing):
    account, ws = sheet_with(existing)
    rows = SettingsSheet(account).read()
    assert account.sh.added == []
    assert ws.writes()[0] == ("update", [HEADER], "A1:C1", "RAW")
    assert ws.rows[0] == HEADER
    assert ws.rows[1:] == default_rows()
    assert rows == {k: encode_value(v) for k, v in setting_defaults()}


@pytest.mark.parametrize("existing", [
    [["name", "value"], ["provisioning.default_mode", "secure"]],
    [["provisioning.default_mode", "secure"]],                     # no header row at all
    [["", "", ""], ["provisioning.default_mode", "secure"]],       # data below an empty row 1
    [["value", "key"], ["secure", "provisioning.default_mode"]],   # columns swapped
])
def test_wrong_header_with_data_is_refused(existing):
    account, ws = sheet_with([list(r) for r in existing])
    with pytest.raises(StoreError) as ei:
        SettingsSheet(account).read()
    assert "row 1 must be: key | value | description" in str(ei.value)
    assert "'settings'" in str(ei.value)
    assert ws.writes() == []                                      # nothing of the operator's is touched
    assert ws.rows == existing
    assert account.explained == []                                # our own message, not a Google error


@pytest.mark.parametrize("where", ["spreadsheet", "worksheet", "add_worksheet", "get_all_values",
                                   "header_update", "append_rows"])
def test_google_errors_become_store_errors_via_explain(where):
    exc = APIError(f"boom in {where}", code=503) if where != "get_all_values" else ConnectionError("reset")
    if where == "header_update":
        account, ws = sheet_with([])
        ws.fail["update"] = exc
    elif where in ("get_all_values", "append_rows"):
        account, ws = sheet_with([])
        ws.fail[where] = exc
    else:
        account = FakeAccount()
        if where == "spreadsheet":
            account.fail = exc
        else:
            account.sh.fail[where] = exc
    with pytest.raises(StoreError) as ei:
        SettingsSheet(account).read()
    assert account.explained == [exc]
    assert str(ei.value) == f"explained: {type(exc).__name__}: {exc}"


def test_store_errors_from_the_account_pass_through():
    account = FakeAccount()
    account.fail = NotSignedIn("not signed in to Google: open the page and sign in")
    with pytest.raises(NotSignedIn) as ei:
        SettingsSheet(account).read()
    assert ei.value is account.fail
    assert account.explained == []


def test_read_recovers_after_a_failure():
    account, ws = sheet_with([])
    sheet = SettingsSheet(account)
    ws.fail["get_all_values"] = ConnectionError("reset")
    with pytest.raises(StoreError):
        sheet.read()
    del ws.fail["get_all_values"]
    assert sheet.read() == {k: encode_value(v) for k, v in setting_defaults()}


class FakeClient:
    """gspread client for a real GoogleAccount (``client_factory``)."""

    def __init__(self) -> None:
        self.sh = FakeSpreadsheet("SID-1")
        self.created: list[str] = []
        self.opened: list[str] = []

    def create(self, title: str) -> FakeSpreadsheet:
        self.created.append(title)
        return self.sh

    def open_by_key(self, key: str) -> FakeSpreadsheet:
        self.opened.append(key)
        assert key == self.sh.id
        return self.sh


def test_with_a_real_google_account(tmp_path):
    client = FakeClient()
    account = GoogleAccount(tmp_path / "repo", tmp_path / "work", client_factory=lambda: client)
    sheet = SettingsSheet(account)
    rows = sheet.read()
    assert client.created == ["OTP_Provisioner"]
    assert set(client.sh.worksheets) == {"modules", "settings"}
    assert rows == {k: encode_value(v) for k, v in setting_defaults()}

    ws = client.sh.worksheets["settings"]
    # an auth failure: the operator text comes from GoogleAccount.explain, the cached connection is dropped
    ws.fail["get_all_values"] = APIError("Request had invalid authentication credentials", code=401)
    with pytest.raises(StoreError) as ei:
        sheet.read()
    assert str(ei.value).startswith("Google Sheets API error: ")
    assert account.last_error == str(ei.value)
    ws.fail["get_all_values"] = ConnectionError("connection reset")
    with pytest.raises(StoreError, match="Google unreachable"):
        sheet.read()
    del ws.fail["get_all_values"]
    assert sheet.read() == rows
    assert client.opened == ["SID-1"]            # reopened by the saved id after the dropped connection
    assert client.created == ["OTP_Provisioner"]
