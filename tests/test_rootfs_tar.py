"""The check of an app's root file system archive and the shift of its owners (otp_server.rootfs_tar)."""
from __future__ import annotations

import io
import struct
import tarfile

import pytest

from otp_server.rootfs_tar import ID_RANGE, Limits, RootfsError, namespaced_capability, sanitize

BASE = 0x110000
CAP_V2 = struct.pack("<IIIII", 0x02000001, 1 << 13, 0, 0, 0)        # cap_net_raw+ep
XATTR = "SCHILY.xattr.security.capability"


def member(name, kind=tarfile.DIRTYPE, data=b"", uid=0, gid=0, mode=0o755, link="", pax=None):
    i = tarfile.TarInfo(name)
    i.type, i.uid, i.gid, i.mode, i.linkname, i.mtime = kind, uid, gid, mode, link, 1700000000
    i.pax_headers = dict(pax or {})
    if kind == tarfile.REGTYPE:
        i.size = len(data)
    return i, data


def archive(*members, end=True) -> bytes:
    buf = io.BytesIO()
    t = tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT, encoding="utf-8", errors="surrogateescape")
    for info, data in members:
        t.addfile(info, io.BytesIO(data) if info.type == tarfile.REGTYPE else None)
    if end:
        t.close()
    else:
        t.fileobj.flush()
    return buf.getvalue()


def rootfs(*extra, end=True):
    """mmdebstrap's order: ./dev first, the root after it."""
    return archive(member("./dev/"), member("./dev/null", tarfile.CHRTYPE, mode=0o666), member("./"),
                   member("./etc/"), member("./usr/"), member("./usr/bin/"), *extra, end=end)


def run(raw: bytes, base=BASE, limits=Limits()):
    out = io.BytesIO()
    report = sanitize(io.BytesIO(raw), out, uid_base=base, limits=limits)
    out.seek(0)
    t = tarfile.open(fileobj=out, encoding="utf-8", errors="surrogateescape")
    return report, {m.name: m for m in t.getmembers()}, t


def test_owners_are_shifted_and_names_dropped():
    raw = rootfs(member("./usr/bin/tool", tarfile.REGTYPE, b"#!/bin/sh\n", uid=997, gid=997, mode=0o755),
                 member("./etc/passwd", tarfile.REGTYPE, b"root:x:0:0::/root:/bin/sh\n", mode=0o644))
    report, ms, t = run(raw)
    assert ms["./usr/bin/tool"].uid == BASE + 997 and ms["./usr/bin/tool"].gid == BASE + 997
    assert ms["./etc/passwd"].uid == BASE and ms["."].uid == BASE and ms["."].isdir()
    assert all(m.uname == "" and m.gname == "" for m in ms.values())
    assert t.extractfile("./usr/bin/tool").read() == b"#!/bin/sh\n"
    assert report.members == len(ms)
    assert report.bytes == len(b"#!/bin/sh\n") + len(b"root:x:0:0::/root:/bin/sh\n")


def test_zero_base_keeps_container_ids_and_output_is_reproducible():
    raw = rootfs(member("./etc/x", tarfile.REGTYPE, b"x", uid=5, gid=6, mode=0o640))
    a, b = io.BytesIO(), io.BytesIO()
    sanitize(io.BytesIO(raw), a, uid_base=0)
    sanitize(io.BytesIO(raw), b, uid_base=0)
    assert a.getvalue() == b.getvalue()
    _, ms, _ = run(a.getvalue(), base=0)
    assert (ms["./etc/x"].uid, ms["./etc/x"].gid, ms["./etc/x"].mode) == (5, 6, 0o640)


def test_devices_and_mount_point_contents_are_dropped():
    raw = rootfs(member("./usr/bin/dev", tarfile.BLKTYPE, mode=0o666), member("./proc/"),
                 member("./proc/1/"), member("./etc/fifo", tarfile.FIFOTYPE, mode=0o600))
    report, ms, _ = run(raw)
    assert "./dev" in ms and "./proc" in ms and "./etc/fifo" in ms
    assert "./dev/null" not in ms and "./usr/bin/dev" not in ms and "./proc/1" not in ms
    assert report.dropped == {"below /dev": 1, "device node": 1, "below /proc": 1}


def test_setid_bits_kept_and_reported():
    report, ms, _ = run(rootfs(member("./usr/bin/su", tarfile.REGTYPE, b"x", mode=0o4755)))
    assert ms["./usr/bin/su"].mode == 0o4755 and report.setid == ["./usr/bin/su"]


def test_capabilities_become_namespaced_to_the_base():
    v2 = CAP_V2.decode("utf-8", "surrogateescape")
    raw = rootfs(member("./usr/bin/ping", tarfile.REGTYPE, b"x", pax={XATTR: v2,
                                                                       "SCHILY.xattr.user.note": "hi",
                                                                       "SCHILY.acl.access": "user::rwx"}))
    report, ms, _ = run(raw)
    cap = ms["./usr/bin/ping"].pax_headers[XATTR].encode("utf-8", "surrogateescape")
    assert cap == struct.pack("<IIIIII", 0x03000001, 1 << 13, 0, 0, 0, BASE)
    assert "SCHILY.xattr.user.note" not in ms["./usr/bin/ping"].pax_headers
    assert report.capabilities == ["./usr/bin/ping"]
    assert report.dropped == {"below /dev": 1, "extended attribute user.*": 1, "ACL or label": 1}


@pytest.mark.parametrize("raw, root", [
    (struct.pack("<III", 0x01000000, 1, 2), 0),
    (CAP_V2, 0),
    (struct.pack("<IIIIII", 0x03000000, 1, 0, 0, 0, 7), 7),
])
def test_namespaced_capability_revisions(raw, root):
    out = namespaced_capability(raw, BASE)
    assert len(out) == 24 and struct.unpack_from("<I", out)[0] & 0xFF000000 == 0x03000000
    assert struct.unpack_from("<I", out, 20)[0] == BASE + root


@pytest.mark.parametrize("raw", [b"", b"\x00\x00\x00\x02" + b"\0" * 4, struct.pack("<IIIII", 0x02000002, 0, 0, 0, 0),
                                 struct.pack("<IIIIII", 0x03000000, 0, 0, 0, 0, ID_RANGE)])
def test_namespaced_capability_refuses_what_the_kernel_would(raw):
    with pytest.raises(RootfsError):
        namespaced_capability(raw, BASE)


@pytest.mark.parametrize("extra, what", [
    ((member("/etc/abs", tarfile.REGTYPE, b"x"),), "absolute"),
    ((member("./etc/../../x", tarfile.REGTYPE, b"x"),), "'..'"),
    ((member("./etc/x", tarfile.REGTYPE, b"x"), member("./etc/x", tarfile.REGTYPE, b"y")), "twice"),
    ((member("./var/lib/x", tarfile.REGTYPE, b"x"),), "before its directory"),
    ((member("./lnk", tarfile.SYMTYPE, link="/etc"), member("./lnk/passwd", tarfile.REGTYPE, b"x")),
     "before its directory"),
    ((member("./etc/h", tarfile.LNKTYPE, link="./etc/missing"),), "not an earlier regular file"),
    ((member("./etc/h", tarfile.LNKTYPE, link="./usr"),), "not an earlier regular file"),
    ((member("./etc/big", tarfile.REGTYPE, b"x", uid=ID_RANGE),), "outside the container"),
    ((member("./etc/g", tarfile.REGTYPE, b"x", gid=-1 & 0x7FFFFFFF),), "outside the container"),
])
def test_refused_archives(extra, what):
    with pytest.raises(RootfsError, match=what):
        run(rootfs(*extra))


def test_symlinks_and_hard_links_kept():
    raw = rootfs(member("./etc/a", tarfile.REGTYPE, b"a"), member("./etc/b", tarfile.LNKTYPE, link="./etc/a"),
                 member("./bin", tarfile.SYMTYPE, link="usr/bin"),
                 member("./etc/abs", tarfile.SYMTYPE, link="/etc/alternatives/x"))
    _, ms, _ = run(raw)
    assert ms["./etc/b"].islnk() and ms["./etc/b"].linkname == "./etc/a"
    assert ms["./bin"].linkname == "usr/bin" and ms["./etc/abs"].linkname == "/etc/alternatives/x"


def test_truncated_archive_is_refused():
    raw = rootfs(member("./etc/a", tarfile.REGTYPE, b"a" * 4000), end=False)
    with pytest.raises(RootfsError):
        run(raw[:-1024])                                  # cut inside the last file
    with pytest.raises(RootfsError, match="does not end properly"):
        run(raw + b"\x01" * 1024)                         # garbage instead of the end blocks


def test_archive_on_a_raw_disk_ends_at_its_end_blocks():
    report, ms, _ = run(rootfs() + b"\0" * 65536 + b"leftover bytes of the disk")
    assert "./usr/bin" in ms and report.members == len(ms)


def test_not_a_root_file_system():
    with pytest.raises(RootfsError, match="no /usr"):
        run(archive(member("./"), member("./etc/")))
    with pytest.raises(RootfsError, match="no root directory"):
        run(archive(member("./etc/"), member("./usr/")))
    with pytest.raises(RootfsError, match="not a tar archive"):
        run(b"hello" * 200)


def test_limits():
    with pytest.raises(RootfsError, match="more than 3 members"):
        run(rootfs(), limits=Limits(members=3))
    with pytest.raises(RootfsError, match="bytes of file data"):
        run(rootfs(member("./etc/a", tarfile.REGTYPE, b"a" * 100)), limits=Limits(bytes=50))
    long = {"path": "./etc/" + "x" * 5000}
    with pytest.raises(RootfsError, match="longer than"):
        run(rootfs(member("./etc/y", tarfile.REGTYPE, b"x", pax=long)))
    huge_header = rootfs(member("./etc/" + "y" * 3000, tarfile.REGTYPE, b"x"))
    with pytest.raises(RootfsError, match="header"):
        run(huge_header, limits=Limits(header=1024))
