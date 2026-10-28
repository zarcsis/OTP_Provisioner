"""Debian binary packages as the station reads them: the control fields, the maintainer scripts there are, the
file list, and a few files read out of the data archive. Nothing is unpacked to disk and nothing from the
package runs.

A ``.deb`` is an ``ar`` archive: ``debian-binary`` ("2.0"), ``control.tar[.gz|.xz|.zst]``,
``data.tar[.gz|.xz|.zst|.bz2]``. zstd (Ubuntu's default) needs Python's ``compression.zstd`` (3.14+); without it
such a package is refused with a message saying so.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

AR_MAGIC = b"!<arch>\n"
#: Fields of a binary package's control file the station needs.
REQUIRED_FIELDS = ("Package", "Version", "Architecture")
MAINTAINER_SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config", "triggers")
#: Architectures the board runs (Raspberry Pi 5, 64-bit Raspberry Pi OS).
BOARD_ARCHES = ("arm64", "all")
_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+~:-]+$")
#: Characters of a dependency field (names, versions, alternatives, architecture qualifiers).
_DEPENDS_RE = re.compile(r"^[A-Za-z0-9+.,|()<>=:~\[\]! \-_]*$")
MAX_MEMBER = 1 << 30            # bytes of one ar member
MAX_CONTROL = 16 << 20          # bytes of the unpacked control archive
MAX_READ_FILE = 1 << 20         # bytes of one file read out of the data archive


class DebError(ValueError):
    """The file is not a Debian binary package the station takes."""


@dataclass
class DebInfo:
    """What a package is, from its control archive and its data archive's file list."""

    fields: dict[str, str]
    scripts: list[str]
    files: list[str]
    data_bytes: int
    read: dict[str, bytes] = field(default_factory=dict)

    @property
    def package(self) -> str:
        return self.fields["Package"]

    @property
    def version(self) -> str:
        return self.fields["Version"]

    @property
    def architecture(self) -> str:
        return self.fields["Architecture"]

    def depends(self) -> str:
        """Pre-Depends and Depends as one dependency expression ("" when there are none)."""
        parts = [self.fields.get(k, "").strip() for k in ("Pre-Depends", "Depends")]
        return ", ".join(p for p in parts if p)

    def summary(self) -> str:
        return self.fields.get("Description", "").split("\n", 1)[0].strip()

    def to_dict(self) -> dict:
        return {"package": self.package, "version": self.version, "architecture": self.architecture,
                "summary": self.summary(), "depends": self.depends(), "fields": dict(self.fields),
                "scripts": list(self.scripts), "files": len(self.files), "data_bytes": self.data_bytes}


def parse_control(text: str) -> dict[str, str]:
    """The fields of a control file (one paragraph; continuation lines joined with "\\n")."""
    fields: dict[str, str] = {}
    key = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            if fields:
                break
            continue
        if line[0] in " \t":
            if key is None:
                raise DebError("control file starts with a continuation line")
            fields[key] += "\n" + line.strip()
            continue
        if ":" not in line:
            raise DebError(f"control file line without a field name: {line[:60]!r}")
        key, value = line.split(":", 1)
        key = key.strip()
        if not key or key in fields:
            raise DebError(f"control file field {key!r} empty or repeated")
        fields[key] = value.strip()
    return fields


def _ar_members(f: BinaryIO) -> list[tuple[str, int, int]]:
    """(name, offset, size) of every member of an ar archive."""
    if f.read(8) != AR_MAGIC:
        raise DebError("not a Debian package (no ar archive header)")
    out = []
    while True:
        head = f.read(60)
        if not head:
            break
        if len(head) != 60 or head[58:60] != b"`\n":
            raise DebError("damaged ar archive (member header)")
        name = head[0:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(head[48:58].decode("ascii").strip())
        except ValueError:
            raise DebError("damaged ar archive (member size)") from None
        if size < 0 or size > MAX_MEMBER:
            raise DebError(f"ar member {name!r} of {size} bytes")
        out.append((name, f.tell(), size))
        f.seek(size + (size & 1), io.SEEK_CUR)
    return out


def _decompressor(name: str, raw: BinaryIO) -> BinaryIO:
    if name.endswith(".tar"):
        return raw
    if name.endswith(".gz"):
        return gzip.GzipFile(fileobj=raw)
    if name.endswith(".xz"):
        return lzma.LZMAFile(raw)
    if name.endswith(".bz2"):
        return bz2.BZ2File(raw)
    if name.endswith(".zst"):
        try:
            from compression import zstd       # Python 3.14+
        except ImportError:
            raise DebError(f"{name} is zstd-compressed and this Python has no zstd (3.14+ has); rebuild the package "
                           "with xz (dpkg-deb -Zxz)") from None
        return zstd.ZstdFile(raw)
    raise DebError(f"unknown compression of {name}")


class _Window(io.RawIOBase):
    """``size`` bytes of ``f`` from ``offset``."""

    def __init__(self, f: BinaryIO, offset: int, size: int):
        self.f, self.pos, self.end = f, offset, offset + size

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        n = min(len(b), self.end - self.pos)
        if n <= 0:
            return 0
        self.f.seek(self.pos)
        data = self.f.read(n)
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def _norm(name: str) -> str:
    return name[2:] if name.startswith("./") else name.lstrip("/")


def read(path: str | Path, *, want: tuple[str, ...] = ()) -> DebInfo:
    """Read a package's metadata; ``want``: glob-like prefixes (``usr/share/vn-apps/permissions/``) of files whose
    content is returned in ``DebInfo.read`` (regular files of at most 1 MiB each)."""
    with open(path, "rb") as f:
        members = {name: (off, size) for name, off, size in _ar_members(f)}
        if "debian-binary" not in members:
            raise DebError("not a Debian package (no debian-binary member)")
        off, size = members["debian-binary"]
        f.seek(off)
        if not f.read(size).startswith(b"2."):
            raise DebError("unsupported Debian package format (debian-binary is not 2.x)")
        control_name = next((n for n in members if n.startswith("control.tar")), None)
        data_name = next((n for n in members if n.startswith("data.tar")), None)
        if control_name is None or data_name is None:
            raise DebError("not a Debian binary package (control.tar or data.tar missing)")

        fields: dict[str, str] | None = None
        scripts: list[str] = []
        total = 0
        with tarfile.open(fileobj=_decompressor(control_name, _Window(f, *members[control_name])), mode="r|") as t:
            for m in t:
                name = _norm(m.name)
                if not m.isfile():
                    continue
                total += m.size
                if total > MAX_CONTROL:
                    raise DebError("the control archive is too large")
                if name == "control":
                    fields = parse_control(t.extractfile(m).read().decode("utf-8", "replace"))
                elif name in MAINTAINER_SCRIPTS:
                    scripts.append(name)
        if fields is None:
            raise DebError("the package has no control file")
        for k in REQUIRED_FIELDS:
            if not fields.get(k):
                raise DebError(f"the control file has no {k} field")
        if not _PACKAGE_RE.fullmatch(fields["Package"]):
            raise DebError(f"package name {fields['Package']!r} is not a Debian package name")
        if not _VERSION_RE.fullmatch(fields["Version"]):
            raise DebError(f"version {fields['Version']!r} is not a Debian version")
        for k in ("Pre-Depends", "Depends"):
            if not _DEPENDS_RE.fullmatch(fields.get(k, "").replace("\n", " ")):
                raise DebError(f"the {k} field has characters a dependency never has")

        files: list[str] = []
        got: dict[str, bytes] = {}
        data_bytes = 0
        with tarfile.open(fileobj=_decompressor(data_name, _Window(f, *members[data_name])), mode="r|") as t:
            for m in t:
                name = _norm(m.name)
                if not name:
                    continue
                files.append(name + ("/" if m.isdir() else ""))
                if m.isfile():
                    data_bytes += m.size
                    if m.size <= MAX_READ_FILE and any(name.startswith(w) for w in want):
                        got[name] = t.extractfile(m).read()
    return DebInfo(fields=fields, scripts=sorted(scripts), files=files, data_bytes=data_bytes, read=got)


__all__ = ["BOARD_ARCHES", "DebError", "DebInfo", "parse_control", "read"]
