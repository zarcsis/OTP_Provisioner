"""Time zones and Wi-Fi countries of the OS image (otp_server.image_choices and its data file)."""
from __future__ import annotations

import json
import struct

import pytest

from otp_server import image_choices as ic
from otp_server.config import load_config


def test_data_file_shape():
    d = ic.data()
    assert d["source"].startswith("Debian trixie: tzdata ")
    assert len(d["timezones"]) == 313 and d["timezones"] == sorted(d["timezones"])
    assert not set(d["timezones"]) & set(d["timezones_valid"])
    assert [c for c, _ in d["countries"]] == sorted(c for c, _ in d["countries"]) and d["countries"][0][0] == "00"
    assert all(len(c) == 2 and name for c, name in d["countries"])


@pytest.mark.parametrize("name, ok", [
    ("Europe/Kyiv", True), ("UTC", True), ("Europe/Warsaw", True), ("America/Argentina/Buenos_Aires", True),
    ("Etc/GMT-3", True), ("Etc/UTC", True), ("GMT", True),
    ("Europe/Kiev", False), ("US/Eastern", False), ("UCT", False),   # tzdata-legacy, not in the image
    ("Factory", False), ("posixrules", False), ("zone.tab", False), ("", False), ("Kyiv", False),
])
def test_is_timezone(name, ok):
    assert ic.is_timezone(name) is ok


@pytest.mark.parametrize("code, ok", [("UA", True), ("PL", True), ("00", True), ("AN", True), ("XX", False),
                                      ("ua", False), ("UKR", False), ("", False)])
def test_is_country(code, ok):
    assert ic.is_country(code) is ok


def test_page_view():
    v = ic.page_view()
    assert "UTC" in v["timezones"] and ["UA", "Ukraine"] in v["countries"] and ["00", "World (most restrictive)"] in v["countries"]
    assert "timezones_valid" not in v
    assert ["us", "English (US)"] in v["keyboards"] and ["gb", "English (UK)"] in v["keyboards"]
    assert ["ua", "Ukrainian"] in v["keyboards"] and len(v["keyboards"]) > 50


@pytest.mark.parametrize("layout, ok", [("us", True), ("gb", True), ("ua", True), ("latam", True), ("US", False),
                                        ("us(intl)", False), ("", False)])
def test_is_keyboard(layout, ok):
    assert ic.is_keyboard(layout) is ok


def test_xkb_layouts():
    lst = ("! model\n  pc105           Generic 105-key PC\n\n! layout\n  us              English (US)\n"
           "  gb              English (UK)\n\n! variant\n  intl            us: English (US, intl., with dead keys)\n")
    assert ic.xkb_layouts(lst) == [["us", "English (US)"], ["gb", "English (UK)"]]
    with pytest.raises(ValueError, match="no layouts"):
        ic.xkb_layouts("! model\n  pc105 Generic\n")


def test_settings_are_checked_against_the_lists(tmp_path):
    cfg = lambda **img: load_config(overrides={"paths": {"work": str(tmp_path)}, "image": img})  # noqa: E731
    assert cfg(timezone="Etc/GMT-3", wifi_country="pl").image.wifi_country == "PL"
    with pytest.raises(ValueError, match="image.timezone: time zone 'Europe/Kiev' is not in the image's tzdata"):
        cfg(timezone="Europe/Kiev")
    with pytest.raises(ValueError, match="image.wifi_country: Wi-Fi country 'XX' is not in wireless-regdb"):
        cfg(wifi_country="XX")
    assert cfg(keyboard=" ua ").image.keyboard == "ua"
    with pytest.raises(ValueError, match="image.keyboard: keyboard layout 'xx' is not in the image's xkb-data"):
        cfg(keyboard="xx")


# ------------------------------------------------------------------ generation
def regdb(codes: list[str]) -> bytes:
    body = b"".join(c.encode() + struct.pack(">H", 0x10 + i) for i, c in enumerate(codes))
    return struct.pack(">II", 0x52474442, 20) + body + b"\0\0\0\0" + b"rules..."


def test_regdb_countries():
    assert ic.regdb_countries(regdb(["00", "AD", "UA"])) == ["00", "AD", "UA"]
    with pytest.raises(ValueError, match="RGDB"):
        ic.regdb_countries(b"XXXX" + b"\0" * 20)
    with pytest.raises(ValueError, match="unexpected country entry"):
        ic.regdb_countries(struct.pack(">II", 0x52474442, 20) + b"\xff\xfe\0\x01")


LISTING = """\
drwxr-xr-x root/root         0 2026-08-16 19:05 ./usr/share/zoneinfo/
drwxr-xr-x root/root         0 2026-08-16 19:05 ./usr/share/zoneinfo/Europe/
-rw-r--r-- root/root      2120 2026-08-16 19:05 ./usr/share/zoneinfo/Europe/Kyiv
-rw-r--r-- root/root      2120 2026-08-16 19:05 ./usr/share/zoneinfo/Europe/Warsaw
-rw-r--r-- root/root       111 2026-08-16 19:05 ./usr/share/zoneinfo/Etc/UTC
lrwxrwxrwx root/root         0 2026-08-16 19:05 ./usr/share/zoneinfo/UTC -> Etc/UTC
-rw-r--r-- root/root       111 2026-08-16 19:05 ./usr/share/zoneinfo/Factory
-rw-r--r-- root/root     17596 2026-08-16 19:05 ./usr/share/zoneinfo/zone1970.tab
-rw-r--r-- root/root    111358 2026-08-16 19:05 ./usr/share/zoneinfo/tzdata.zi
-rw-r--r-- root/root       654 2026-08-16 19:05 ./usr/share/zoneinfo/right/Etc/UTC
-rw-r--r-- root/root       100 2026-08-16 19:05 ./usr/share/doc/tzdata/README
"""


def test_tzdata_zones_from_the_package_listing():
    assert ic.tzdata_zones(LISTING) == {"Europe/Kyiv", "Europe/Warsaw", "Etc/UTC", "UTC"}


def test_generate(tmp_path):
    root = tmp_path / "root"
    z = root / "usr/share/zoneinfo"
    z.mkdir(parents=True)
    (z / "tzdata.zi").write_text("# version 2026c\nZ Europe/Kyiv 2:2:4 - LMT 1880\nL Europe/Kyiv Europe/Kiev\n",
                                 encoding="utf-8")
    (z / "zone1970.tab").write_text("# comment\nUA\t+5026+03031\tEurope/Kyiv\tmost of Ukraine\n"
                                    "PL\t+5215+02100\tEurope/Warsaw\n", encoding="utf-8")
    fw = root / "usr/lib/firmware"
    fw.mkdir(parents=True)
    (fw / "regulatory.db-debian").write_bytes(regdb(["00", "AN", "PL", "UA"]))
    iso = root / "usr/share/iso-codes/json"
    iso.mkdir(parents=True)
    (iso / "iso_3166-1.json").write_text(json.dumps({"3166-1": [
        {"alpha_2": "UA", "name": "Ukraine"}, {"alpha_2": "PL", "name": "Poland"},
        {"alpha_2": "TW", "name": "Taiwan, Province of China", "common_name": "Taiwan"}]}), encoding="utf-8")
    xkb = root / "usr/share/X11/xkb/rules"
    xkb.mkdir(parents=True)
    (xkb / "base.lst").write_text("! layout\n  us   English (US)\n  ua   Ukrainian\n", encoding="utf-8")
    d = ic.generate(root, LISTING, "tzdata 2026c-0+deb13u1")
    assert d["keyboards"] == [["us", "English (US)"], ["ua", "Ukrainian"]]
    assert d["timezones"] == ["Europe/Kyiv", "Europe/Warsaw", "UTC"]       # Europe/Kiev is only in tzdata.zi
    assert d["timezones_valid"] == ["Etc/UTC"]
    assert d["countries"] == [["00", "World (most restrictive)"], ["AN", "Netherlands Antilles"], ["PL", "Poland"],
                              ["UA", "Ukraine"]]
    assert d["source"] == "Debian trixie: tzdata 2026c; tzdata 2026c-0+deb13u1"
    (fw / "regulatory.db-debian").write_bytes(regdb(["ZZ"]))
    with pytest.raises(ValueError, match="no name for regulatory.db country ZZ"):
        ic.generate(root, LISTING)
    (z / "zone1970.tab").write_text("XX\t+0+0\tMars/Olympus\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not install.*Mars/Olympus"):
        ic.generate(root, LISTING)
