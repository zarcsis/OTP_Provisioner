"""What the OS image settings choose from: time zones and Wi-Fi countries (``image_choices.json``).

The lists come from the Debian trixie packages the image installs, so whatever the page offers, the board
understands:

* ``tzdata`` -- every zone file the package installs under ``/usr/share/zoneinfo`` is a valid time zone; the
  page lists the canonical zones of ``zone1970.tab`` plus ``UTC``. Legacy names (``Europe/Kiev``,
  ``US/Eastern``, ``UCT``) are in Debian's ``tzdata-legacy``, which the image does not install, so they are not
  valid here either (``tzdata.zi`` still lists them: it is not the list of installed files);
* ``wireless-regdb`` -- the countries of ``regulatory.db`` (``00`` = the world domain) are the Wi-Fi countries;
* ``iso-codes`` -- the country names.

Regenerate after a Debian update (from the repository root, with Docker)::

    docker run --rm -v "$PWD/build-choices:/out" debian:trixie-slim sh -c \\
        'cd /tmp && apt-get update && apt-get download tzdata wireless-regdb iso-codes &&
         for d in *.deb; do dpkg-deb -x $d /out/root; dpkg-deb -f $d Package Version >> /out/versions; done &&
         dpkg-deb -c tzdata_*.deb > /out/tzdata.list'
    python -m otp_server.image_choices build-choices > otp_server/image_choices.json
"""

from __future__ import annotations

import functools
import json
import struct
import sys
from pathlib import Path

DATA = Path(__file__).with_name("image_choices.json")
#: Files under /usr/share/zoneinfo that are not time zones.
NOT_ZONES = frozenset({"iso3166.tab", "leap-seconds.list", "leapseconds", "tzdata.zi", "zone.tab", "zone1970.tab",
                       "zonenow.tab", "localtime", "posixrules", "Factory"})
#: Names of regulatory.db entries that ISO 3166-1 no longer has.
EXTRA_COUNTRY_NAMES = {"00": "World (most restrictive)", "AN": "Netherlands Antilles"}


@functools.lru_cache(maxsize=1)
def data() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=1)
def _valid_timezones() -> frozenset:
    d = data()
    return frozenset(d["timezones"]) | frozenset(d["timezones_valid"])


@functools.lru_cache(maxsize=1)
def _countries() -> dict:
    return {code: name for code, name in data()["countries"]}


def timezones() -> list[str]:
    """The time zones the page lists (canonical zones and UTC), sorted."""
    return list(data()["timezones"])


def is_timezone(name: str) -> bool:
    """Any zone or link of the image's tzdata."""
    return name in _valid_timezones()


def countries() -> list[list[str]]:
    """``[[code, name], ...]`` of the Wi-Fi countries, by code (``00`` first)."""
    return [list(c) for c in data()["countries"]]


def is_country(code: str) -> bool:
    return code in _countries()


def page_view() -> dict:
    """What the page needs for its two lists."""
    return {"timezones": timezones(), "countries": countries()}


# ------------------------------------------------------------------ generation
def regdb_countries(blob: bytes) -> list[str]:
    """The alpha2 codes of a ``regulatory.db`` (magic ``RGDB``, version, then 4-byte country entries)."""
    magic, version = struct.unpack(">II", blob[:8])
    if magic != 0x52474442:
        raise ValueError("not a regulatory.db (no RGDB magic)")
    codes, off = [], 8
    while off + 4 <= len(blob):
        alpha2 = blob[off:off + 2]
        if alpha2 == b"\0\0":
            break
        code = alpha2.decode("ascii", "replace")
        if len(code) != 2 or not (code.isascii() and code.isalnum()):
            raise ValueError(f"unexpected country entry {alpha2!r} at offset {off}")
        codes.append(code)
        off += 4
    return codes


def tzdata_zones(listing: str) -> set[str]:
    """Zone names from ``dpkg-deb -c tzdata_*.deb``: files and symlinks under usr/share/zoneinfo (symlinks do not
    survive an extraction onto a Windows disk, the listing has them all)."""
    names = set()
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0].startswith("d"):
            continue
        path = parts[5]
        prefix = "./usr/share/zoneinfo/"
        if not path.startswith(prefix):
            continue
        name = path[len(prefix):]
        if not name or name in NOT_ZONES or name.split("/")[0] in ("posix", "right"):
            continue
        names.add(name)
    return names


def generate(root: Path, listing: str, versions: str = "") -> dict:
    """The data file from the extracted Debian packages under ``root`` (``dpkg-deb -x`` of each) and the
    ``dpkg-deb -c`` listing of tzdata."""
    zi = (root / "usr/share/zoneinfo/tzdata.zi").read_text(encoding="utf-8").splitlines()
    names = tzdata_zones(listing)
    canonical = set()
    for line in (root / "usr/share/zoneinfo/zone1970.tab").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            canonical.add(line.split("\t")[2])
    canonical.add("UTC")
    missing = canonical - names
    if missing:
        raise ValueError(f"zone1970.tab names that the tzdata package does not install: {sorted(missing)}")
    regdb = root / "usr/lib/firmware/regulatory.db-debian"
    if not regdb.is_file():
        regdb = root / "lib/firmware/regulatory.db"
    codes = regdb_countries(regdb.read_bytes())
    iso = json.loads((root / "usr/share/iso-codes/json/iso_3166-1.json").read_text(encoding="utf-8"))["3166-1"]
    iso_names = {c["alpha_2"]: c.get("common_name") or c["name"] for c in iso}
    countries = []
    for code in codes:
        name = EXTRA_COUNTRY_NAMES.get(code) or iso_names.get(code)
        if not name:
            raise ValueError(f"no name for regulatory.db country {code}")
        countries.append([code, name])
    version = next((ln.split()[-1] for ln in zi if ln.startswith("# version")), "")
    return {
        "source": f"Debian trixie: tzdata {version}; {versions}".strip().rstrip(";"),
        "timezones": sorted(canonical),
        "timezones_valid": sorted(names - canonical),
        "countries": countries,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    base = Path(argv[0])
    versions_file = base / "versions"
    versions = ""
    if versions_file.is_file():
        lines = [ln.split(":", 1)[1].strip() for ln in versions_file.read_text(encoding="utf-8").splitlines() if ":" in ln]
        versions = ", ".join(f"{p} {v}" for p, v in zip(lines[0::2], lines[1::2]))
    listing = (base / "tzdata.list").read_text(encoding="utf-8")
    text = json.dumps(generate(base / "root", listing, versions), ensure_ascii=False, indent=1) + "\n"
    sys.stdout.flush()
    sys.stdout.buffer.write(text.encode("utf-8"))      # LF on every platform (text stdout writes CRLF on Windows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
