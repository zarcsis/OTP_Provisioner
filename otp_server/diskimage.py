"""Raw disk images: what the station accepts as a custom OS image, and the image file it hands out.

* :func:`read_layout` checks an uploaded ``.img`` before anything else is done with it: an MBR (no GPT,
  no compressed file) with exactly two primary partitions, a FAT boot partition and an ext4 root, both
  inside the file. That is what Raspberry Pi OS and pi-gen produce; ``docker/scripts/custom-image.sh``
  repeats the checks with the real tools.
* :class:`DiskPlan` is a disk image that is never written out: an MBR, then each partition as the sparse
  pieces the station already has for it (expanded on the fly, gaps and DONT_CARE as zeros). The station
  streams it to the page as the ``.img`` Raspberry Pi Imager writes to an SD card (:meth:`DiskPlan.iter_bytes`).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from . import sparse

SECTOR = 512
MiB = 1024 * 1024
#: MBR partition types of a FAT boot partition (FAT32 LBA, FAT32, FAT16 LBA, FAT16).
FAT_TYPES = (0x0C, 0x0B, 0x0E, 0x06)
LINUX_TYPE = 0x83
#: The smallest file that can hold a bootable Raspberry Pi OS image.
MIN_IMAGE_BYTES = 64 * MiB
#: Magic numbers of compressed files an operator may upload by mistake.
_COMPRESSED = {b"\xfd7zXZ\x00": "xz", b"\x1f\x8b": "gzip", b"PK\x03\x04": "zip", b"\x28\xb5\x2f\xfd": "zstd",
               b"BZh": "bzip2", b"7z\xbc\xaf\x27\x1c": "7z"}
_SIZE_RE = re.compile(r"^\s*(\d+)\s*([KMGkmg]?)\s*(?:i?[Bb])?\s*$")


def parse_size(value: str | int) -> int:
    """``"8M"`` -> 8388608 (K, M, G are powers of 1024; a bare number is bytes)."""
    if isinstance(value, int):
        return value
    m = _SIZE_RE.match(str(value))
    if not m:
        raise ValueError(f"unreadable size {value!r}")
    return int(m.group(1)) * {"": 1, "k": 1024, "m": MiB, "g": 1024 * MiB}[m.group(2).lower()]


def align_up(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def read_layout(path: str | Path) -> dict:
    """The partition table of an uploaded image, checked: ``{"label": "dos", "id": "0x8a438930", "bytes",
    "partitions": [{"n", "start", "sectors", "type"}, ...]}`` (start and sectors in 512-byte sectors, type
    as hex without ``0x``). ValueError says what is wrong in words the operator can act on."""
    p = Path(path)
    size = p.stat().st_size
    with open(p, "rb") as f:
        mbr = f.read(SECTOR)
        for magic, kind in _COMPRESSED.items():
            if mbr.startswith(magic):
                raise ValueError(f"the file is {kind}-compressed: unpack it and upload the .img inside")
        if size < MIN_IMAGE_BYTES:
            raise ValueError(f"the file has {size} bytes, too small for a Raspberry Pi OS image")
        if len(mbr) < SECTOR or mbr[510:512] != b"\x55\xaa":
            raise ValueError("the file has no MBR partition table: it is not a raw disk image (.img)")
        parts = []
        for i in range(4):
            e = mbr[446 + 16 * i: 446 + 16 * (i + 1)]
            ptype = e[4]
            start, count = struct.unpack("<II", e[8:16])
            if ptype == 0xEE:
                raise ValueError("the image has a GPT partition table; the station takes MBR images only")
            if ptype:
                parts.append({"n": i + 1, "start": start, "sectors": count, "type": f"{ptype:x}"})
        if len(parts) != 2 or [x["n"] for x in parts] != [1, 2]:
            raise ValueError(f"the image has {len(parts)} partitions; expected exactly two primary ones: "
                             "a FAT boot partition and an ext4 root (as Raspberry Pi OS has)")
        boot, root = parts
        if int(boot["type"], 16) not in FAT_TYPES:
            raise ValueError(f"partition 1 has type 0x{boot['type']}, expected a FAT boot partition")
        if int(root["type"], 16) != LINUX_TYPE:
            raise ValueError(f"partition 2 has type 0x{root['type']}, expected a Linux root partition (0x83)")
        for x in parts:
            if x["start"] == 0 or x["sectors"] == 0:
                raise ValueError(f"partition {x['n']} is empty")
            if (x["start"] + x["sectors"]) * SECTOR > size:
                raise ValueError(f"partition {x['n']} ends past the end of the file: the upload is truncated")
        if root["start"] < boot["start"] + boot["sectors"]:
            raise ValueError("the root partition overlaps the boot partition")
        f.seek(boot["start"] * SECTOR)
        bs = f.read(SECTOR)
        if bs[510:512] != b"\x55\xaa" or not (bs[0x36:0x39] == b"FAT" or bs[0x52:0x55] == b"FAT"):
            raise ValueError("partition 1 does not hold a FAT file system")
        f.seek(root["start"] * SECTOR + 1024)
        sb = f.read(1024)
        if len(sb) < 64 or struct.unpack("<H", sb[56:58])[0] != 0xEF53:
            raise ValueError("partition 2 does not hold an ext2/3/4 file system")
        incompat = struct.unpack("<I", sb[96:100])[0]
        if not incompat & 0x40:                   # INCOMPAT_EXTENTS: ext4 (ext2/ext3 lack it)
            raise ValueError("partition 2 holds ext2 or ext3; the station takes an ext4 root")
    disk_id = struct.unpack("<I", mbr[440:444])[0]
    return {"label": "dos", "id": f"0x{disk_id:08x}", "bytes": size, "partitions": parts}


# ---------------------------------------------------------------------------------------- the image file
@dataclass
class Partition:
    """One partition of a :class:`DiskPlan`: its MBR type, place and size (bytes), and the sparse pieces
    of what it holds (the pieces may cover less than the partition: the rest reads as zeros)."""

    type: int
    start: int
    size: int
    pieces: list[Path]
    content: int = 0               # bytes the pieces cover
    bootable: bool = False


@dataclass
class DiskPlan:
    """An MBR disk image assembled from sparse pieces; ``size`` is the length of the file."""

    disk_id: int
    partitions: list[Partition] = field(default_factory=list)

    @property
    def size(self) -> int:
        return max((p.start + p.size for p in self.partitions), default=SECTOR)

    @classmethod
    def build(cls, disk_id: int, align: int, parts: list[tuple[int, int, list[Path], bool]]) -> "DiskPlan":
        """Partitions one after the other, each starting and ending on ``align`` (the first at ``align``),
        the way rpi-fastbootd lays out an IDP image. ``parts`` = ``[(mbr type, minimum size, pieces,
        bootable)]``; a partition is at least as large as what its pieces expand to."""
        if align < MiB or align % MiB:
            raise ValueError(f"partition alignment {align} is not a whole number of MiB")
        if len(parts) > 4:
            raise ValueError("an MBR holds at most four primary partitions")
        plan = cls(disk_id=disk_id)
        pos = align
        for ptype, min_size, pieces, bootable in parts:
            info = sparse.check_pieces(pieces)
            content = int(info["expanded_size"])
            size = align_up(max(int(min_size), content), align)
            plan.partitions.append(Partition(type=ptype, start=pos, size=size, pieces=list(pieces),
                                             content=content, bootable=bootable))
            pos += size
        if pos // SECTOR > 0xFFFFFFFF:
            raise ValueError("the image is larger than an MBR can describe (2 TiB)")
        return plan

    def mbr(self) -> bytes:
        """The first sector: no boot code (the Raspberry Pi firmware does not run it), the disk signature,
        the partition entries with LBA-only CHS fields, 0x55AA."""
        b = bytearray(SECTOR)
        struct.pack_into("<I", b, 440, self.disk_id & 0xFFFFFFFF)
        for i, p in enumerate(self.partitions):
            if p.start % SECTOR or p.size % SECTOR:
                raise ValueError("partitions must be sector aligned")
            struct.pack_into("<B3sB3sII", b, 446 + 16 * i, 0x80 if p.bootable else 0x00, b"\xfe\xff\xff",
                             p.type, b"\xfe\xff\xff", p.start // SECTOR, p.size // SECTOR)
        b[510:512] = b"\x55\xaa"
        return bytes(b)

    def iter_bytes(self, chunk: int = 4 * MiB) -> Iterator[bytes]:
        """The whole image, in pieces of at most ``chunk`` bytes; exactly :attr:`size` bytes in total."""
        yield self.mbr()
        pos = SECTOR
        for p in self.partitions:
            yield from _zeros(p.start - pos, chunk)
            pos = p.start
            n = 0
            for data in sparse.expand(p.pieces, chunk=chunk):
                n += len(data)
                yield data
            if n != p.content:
                raise RuntimeError(f"the pieces of the partition at {p.start} expanded to {n} bytes, not {p.content}")
            yield from _zeros(p.size - p.content, chunk)
            pos = p.start + p.size
        if pos != self.size:
            raise RuntimeError(f"the image came out {pos} bytes long, not {self.size}")


def _zeros(n: int, chunk: int) -> Iterator[bytes]:
    block = bytes(min(n, chunk)) if n > 0 else b""
    while n > 0:
        k = min(n, chunk)
        yield block if k == len(block) else bytes(k)
        n -= k
