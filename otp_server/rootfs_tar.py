"""Root file systems of sandboxed apps as tar archives: the check every one passes on its way into an image,
and the shift of its owners into the app's own range of host UIDs.

An app's root file system is installed in a throwaway VM (:mod:`otp_server.artifacts.apps`): whatever the
package's maintainer scripts did there, the archive the VM wrote is untrusted. :func:`sanitize` reads it
member by member and writes a new archive that is safe to unpack as root into the board's image:

* names: relative, normalised, no ``..``, no NUL, no member twice, every parent an earlier directory member
  (so nothing is ever unpacked through a symbolic link);
* types: regular files, directories, symbolic links, hard links to an earlier regular file, FIFOs; device
  nodes are dropped (podman gives every container its own ``/dev``), and so is everything below ``dev/``,
  ``proc/`` and ``sys/`` (the runtime mounts its own there);
* owners: container IDs 0..65535 only, written as ``uid_base`` + ID, without user and group names;
* mode: the permission bits with set-user-ID, set-group-ID and sticky;
* extended attributes: file capabilities only, rewritten as namespaced (v3) capabilities whose root is
  ``uid_base`` + the root they had, so they work inside the app's container and nowhere on the host (a
  plain v2 capability on a file the host can reach is a real capability on the host); everything else
  (ACLs, SELinux labels, ``user.*``) is dropped.

The station runs it twice: with ``uid_base=0`` on the VM's archive (the prepared rootfs keeps container IDs)
and with the app's base UID when an image is built. Limits keep a hostile archive from filling the
station's memory or disk.
"""
from __future__ import annotations

import io
import struct
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

#: IDs inside a container: one user namespace of 65536 IDs per app.
ID_RANGE = 65536
CAP_XATTR = "security.capability"
_PAX_XATTR = "SCHILY.xattr."
#: Top-level directories kept empty: the container runtime mounts its own file systems there.
MOUNT_POINTS = ("dev", "proc", "sys")

VFS_CAP_REVISION_MASK = 0xFF000000
VFS_CAP_REVISION_1 = 0x01000000
VFS_CAP_REVISION_2 = 0x02000000
VFS_CAP_REVISION_3 = 0x03000000
VFS_CAP_FLAGS_EFFECTIVE = 0x000001
_CAP_SIZES = {VFS_CAP_REVISION_1: 12, VFS_CAP_REVISION_2: 20, VFS_CAP_REVISION_3: 24}

_REGULAR = (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE, tarfile.GNUTYPE_SPARSE)
_DEVICES = (tarfile.CHRTYPE, tarfile.BLKTYPE)
_CHUNK = 1 << 20


class RootfsError(ValueError):
    """The archive is not a root file system the station takes."""


@dataclass(frozen=True)
class Limits:
    """What one archive may hold."""

    members: int = 400_000
    bytes: int = 8 * 1024 ** 3          # file data in total
    name: int = 4096                    # bytes of one name or link target
    header: int = 1 << 20               # one read of the archive (a pax or GNU long-name header)


@dataclass
class Report:
    """What :func:`sanitize` kept and dropped."""

    members: int = 0
    bytes: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    setid: list[str] = field(default_factory=list)

    def drop(self, why: str) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + 1

    def to_dict(self) -> dict:
        return {"members": self.members, "bytes": self.bytes, "dropped": dict(sorted(self.dropped.items())),
                "capabilities": list(self.capabilities), "setid": list(self.setid)}


class _Guard(io.RawIOBase):
    """A seekable file that refuses any single read larger than ``limit``: tarfile reads a pax or GNU
    long-name header in one piece, sized by the archive itself."""

    def __init__(self, f: BinaryIO, limit: int):
        self.f = f
        self.limit = limit

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > self.limit:
            raise RootfsError(f"the archive asks for a header of {size} bytes")
        return self.f.read(size)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.f.seek(offset, whence)

    def tell(self) -> int:
        return self.f.tell()


def namespaced_capability(raw: bytes, rootid_base: int) -> bytes:
    """A ``security.capability`` value as a v3 (namespaced) one whose root is ``rootid_base`` + its old root
    (v1 and v2 values have root 0). RootfsError for a value the kernel would not take either."""
    if len(raw) < 4:
        raise RootfsError(f"file capability of {len(raw)} bytes")
    magic = struct.unpack_from("<I", raw)[0]
    rev = magic & VFS_CAP_REVISION_MASK
    flags = magic & ~VFS_CAP_REVISION_MASK
    if rev not in _CAP_SIZES or len(raw) != _CAP_SIZES[rev] or flags & ~VFS_CAP_FLAGS_EFFECTIVE:
        raise RootfsError(f"file capability with header 0x{magic:08x} and {len(raw)} bytes")
    if rev == VFS_CAP_REVISION_1:
        perm0, inh0 = struct.unpack_from("<II", raw, 4)
        perm1 = inh1 = root = 0
    elif rev == VFS_CAP_REVISION_2:
        perm0, inh0, perm1, inh1 = struct.unpack_from("<IIII", raw, 4)
        root = 0
    else:
        perm0, inh0, perm1, inh1, root = struct.unpack_from("<IIIII", raw, 4)
    if root >= ID_RANGE:
        raise RootfsError(f"file capability for the user namespace of UID {root}")
    return struct.pack("<IIIIII", VFS_CAP_REVISION_3 | flags, perm0, inh0, perm1, inh1, rootid_base + root)


def _relative(name: str, limits: Limits) -> str:
    """``name`` as a normalised relative path ("" = the root directory)."""
    if "\x00" in name:
        raise RootfsError(f"member name with a NUL byte: {name!r}")
    if len(name.encode("utf-8", "surrogateescape")) > limits.name:
        raise RootfsError(f"member name longer than {limits.name} bytes: {name[:80]!r}...")
    if name.startswith("/"):
        raise RootfsError(f"absolute member name: {name!r}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise RootfsError(f"member name with '..': {name!r}")
    return "/".join(parts)


def _out_name(rel: str) -> str:
    return f"./{rel}" if rel else "."


def sanitize(src: BinaryIO | str | Path, dst: BinaryIO | str | Path, *, uid_base: int = 0,
             limits: Limits = Limits()) -> Report:
    """Read the root file system archive ``src`` and write the checked one to ``dst`` (see the module).
    ``src`` may be a raw disk holding a tar archive (anything after the archive's end is ignored).
    RootfsError says what is wrong; ``dst`` is then incomplete."""
    if not 0 <= uid_base <= 0xFFFFFFFF - ID_RANGE:
        raise ValueError(f"UID base {uid_base} out of range")
    if isinstance(src, (str, Path)):
        with open(src, "rb") as f:
            return sanitize(f, dst, uid_base=uid_base, limits=limits)
    if isinstance(dst, (str, Path)):
        with open(dst, "wb") as f:
            return sanitize(src, f, uid_base=uid_base, limits=limits)
    report = Report()
    try:
        tin = tarfile.open(fileobj=_Guard(src, limits.header), mode="r:", encoding="utf-8",
                           errors="surrogateescape")
    except tarfile.TarError as exc:
        raise RootfsError(f"not a tar archive: {exc}") from None
    seen: set[str] = set()
    dirs: set[str] = {""}                 # the root may come late (mmdebstrap puts ./dev/ first), but must come
    files: set[str] = set()
    with tin, tarfile.open(fileobj=dst, mode="w|", format=tarfile.PAX_FORMAT, encoding="utf-8",
                           errors="surrogateescape") as tout:
        while True:
            try:
                m = tin.next()
            except tarfile.TarError as exc:
                raise RootfsError(f"unreadable archive after {report.members} members: {exc}") from None
            if m is None:
                break
            tin.members.clear()           # tarfile keeps every member it read; this one is all we need
            if report.members + sum(report.dropped.values()) >= limits.members:
                raise RootfsError(f"more than {limits.members} members")
            _copy_member(tin, tout, m, uid_base, limits, report, seen, dirs, files)
        # tarfile also stops quietly at a damaged header after the first member: only the two zero blocks
        # of a proper end count as one (a VM that ran out of disk would leave half a root file system).
        src.seek(tin.offset)
        if src.read(2 * tarfile.BLOCKSIZE) != bytes(2 * tarfile.BLOCKSIZE):
            raise RootfsError(f"the archive does not end properly after {report.members} members "
                              "(truncated or damaged)")
    if "" not in seen:
        raise RootfsError("the archive has no root directory member ('.')")
    for top in ("usr", "etc"):
        if top not in dirs:
            raise RootfsError(f"the archive has no /{top} directory: not a root file system")
    return report


def _copy_member(tin: tarfile.TarFile, tout: tarfile.TarFile, m: tarfile.TarInfo, uid_base: int,
                 limits: Limits, report: Report, seen: set[str], dirs: set[str], files: set[str]) -> None:
    rel = _relative(m.name, limits)
    if rel in seen:
        raise RootfsError(f"member {_out_name(rel)} appears twice")
    parts = rel.split("/") if rel else []
    parent = "/".join(parts[:-1])
    if rel and parent not in dirs:
        raise RootfsError(f"member {_out_name(rel)} comes before its directory {_out_name(parent)} "
                          "(or that is not a directory)")
    if len(parts) >= 2 and parts[0] in MOUNT_POINTS:
        report.drop(f"below /{parts[0]}")
        return
    if m.type in _DEVICES:
        report.drop("device node")
        return
    if len(parts) == 1 and parts[0] in MOUNT_POINTS and m.type != tarfile.DIRTYPE:
        raise RootfsError(f"/{parts[0]} is not a directory")
    for what, value in (("UID", m.uid), ("GID", m.gid)):
        if not 0 <= int(value) < ID_RANGE:
            raise RootfsError(f"member {_out_name(rel)} has {what} {value}, outside the container's 0..{ID_RANGE - 1}")
    o = tarfile.TarInfo(_out_name(rel))
    o.mode = m.mode & 0o7777
    o.uid = uid_base + int(m.uid)
    o.gid = uid_base + int(m.gid)
    o.uname = o.gname = ""
    o.mtime = max(0, int(m.mtime))
    pax: dict[str, str] = {}
    for key, value in (m.pax_headers or {}).items():
        if key.startswith(_PAX_XATTR):
            name = key[len(_PAX_XATTR):]
            if name == CAP_XATTR and m.type in _REGULAR:
                raw = value.encode("utf-8", "surrogateescape")
                pax[key] = namespaced_capability(raw, uid_base).decode("utf-8", "surrogateescape")
                report.capabilities.append(_out_name(rel))
            else:
                report.drop(f"extended attribute {name.split('.')[0]}.*")
        elif key.startswith(("SCHILY.acl.", "LIBARCHIVE.xattr.", "RHT.security.selinux")):
            report.drop("ACL or label")
    o.pax_headers = pax
    data = None
    if m.type in _REGULAR:
        o.type = tarfile.REGTYPE
        o.size = int(m.size)
        if report.bytes + o.size > limits.bytes:
            raise RootfsError(f"more than {limits.bytes} bytes of file data")
        report.bytes += o.size
        data = tin.extractfile(m)
        files.add(rel)
        if o.mode & 0o6000:
            report.setid.append(_out_name(rel))
    elif m.type == tarfile.DIRTYPE:
        o.type = tarfile.DIRTYPE
        dirs.add(rel)
    elif m.type == tarfile.SYMTYPE:
        if not m.linkname or "\x00" in m.linkname or len(m.linkname.encode("utf-8", "surrogateescape")) > limits.name:
            raise RootfsError(f"symbolic link {_out_name(rel)} with an unusable target")
        o.type = tarfile.SYMTYPE
        o.linkname = m.linkname
    elif m.type == tarfile.LNKTYPE:
        target = _relative(m.linkname, limits)
        if target not in files:
            raise RootfsError(f"hard link {_out_name(rel)} to {m.linkname!r}, which is not an earlier regular file")
        o.type = tarfile.LNKTYPE
        o.linkname = _out_name(target)
    elif m.type == tarfile.FIFOTYPE:
        o.type = tarfile.FIFOTYPE
    else:
        raise RootfsError(f"member {_out_name(rel)} of tar type {m.type!r}")
    if not rel and o.type != tarfile.DIRTYPE:
        raise RootfsError("the archive's root is not a directory")
    seen.add(rel)
    report.members += 1
    if data is None:
        tout.addfile(o)
        return
    with data:
        tout.addfile(o, _Exact(data, o.size, _out_name(rel)))


class _Exact(io.RawIOBase):
    """A member's data, read in bounded chunks, exactly ``size`` bytes or RootfsError."""

    def __init__(self, f: BinaryIO, size: int, name: str):
        self.f = f
        self.left = size
        self.name = name

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        n = self.left if size is None or size < 0 else min(size, self.left)
        out = bytearray()
        while len(out) < n:
            try:
                b = self.f.read(min(_CHUNK, n - len(out)))
            except tarfile.TarError as exc:
                raise RootfsError(f"{self.name}: {exc}") from None
            if not b:
                raise RootfsError(f"{self.name}: the archive ends inside the file")
            out += b
        self.left -= len(out)
        return bytes(out)


__all__ = ["ID_RANGE", "Limits", "Report", "RootfsError", "namespaced_capability", "sanitize"]
