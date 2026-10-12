#!/usr/bin/env python3
"""An ext4 file system image as an Android sparse image that leaves its free blocks unwritten.

    ext4_sparse.py IMAGE OUT

``IMAGE`` is a raw ext4 file system (exactly the file system, no partition table). The allocation
bitmaps (``dumpe2fs``) decide what is written: every block in use becomes RAW (or FILL when the whole
4096-byte block is zero, e.g. the journal), every free block becomes DONT_CARE. A free block may hold
anything on the card, which is what ext4 assumes of it; a block in use is always written, even when it
is all zeros. That is the difference from ``img2simg -s`` over a file with holes, which would also skip
the zero blocks of files and of metadata in use.

The output block size is 4096 (what fastbootd and luks_encrypt.py expect), whatever the file system's
block size: a 4096-byte block is written when any file system block in it is in use. The file system
size must be a multiple of 4096. Prints one line of JSON: ``{"fs_bytes", "fs_block_size", "used_bytes",
"raw_bytes", "fill_bytes", "chunks"}``.
"""
from __future__ import annotations

import json
import re
import struct
import subprocess
import sys
from pathlib import Path

MAGIC = 0xED26FF3A
RAW, FILL, DONT_CARE = 0xCAC1, 0xCAC2, 0xCAC3
FILE_HDR = struct.Struct("<IHHHHIIII")
CHUNK_HDR = struct.Struct("<HHII")
BLOCK = 4096
#: Largest RAW chunk written at once (blocks).
MAX_RAW_BLOCKS = 16 * 1024 * 1024 // BLOCK
ZERO = bytes(BLOCK)


class Error(Exception):
    pass


def dumpe2fs(image: Path) -> str:
    r = subprocess.run(["dumpe2fs", str(image)], capture_output=True, text=True)
    if r.returncode != 0:
        raise Error(f"dumpe2fs failed: {r.stderr.strip() or r.returncode}")
    return r.stdout


def free_ranges(text: str) -> tuple[int, int, list[tuple[int, int]]]:
    """``(block_size, block_count, [(first, last), ...])`` of the free blocks, from dumpe2fs output."""
    head = {}
    for line in text.splitlines():
        m = re.match(r"^(Block size|Block count|First block):\s+(\d+)\s*$", line)
        if m:
            head[m.group(1)] = int(m.group(2))
        if line.startswith("Group 0:"):
            break
    if "Block size" not in head or "Block count" not in head:
        raise Error("dumpe2fs printed no block size / block count")
    ranges = []
    for m in re.finditer(r"^\s+Free blocks:[ \t]*([0-9, \t-]*)$", text, re.M):
        for part in m.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            a, _, b = part.partition("-")
            ranges.append((int(a), int(b or a)))
    if not ranges and "Free blocks:" not in text:
        raise Error("dumpe2fs printed no per-group free block lists")
    ranges.sort()
    return head["Block size"], head["Block count"], ranges


def used_4k_runs(block_size: int, block_count: int, free: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """``[(first, count), ...]`` of the 4096-byte blocks that hold any file system block in use."""
    fs_bytes = block_size * block_count
    if fs_bytes % BLOCK:
        raise Error(f"the file system is {fs_bytes} bytes, not a multiple of {BLOCK}")
    total = fs_bytes // BLOCK
    # free byte ranges -> whole free 4096-byte blocks (a partly used one stays used)
    free_4k = []
    for a, b in free:
        if b < a or b >= block_count:
            raise Error(f"free block range {a}-{b} outside the file system ({block_count} blocks)")
        start = (a * block_size + BLOCK - 1) // BLOCK
        end = ((b + 1) * block_size) // BLOCK            # exclusive
        if end > start:
            free_4k.append((start, end))
    runs = []
    pos = 0
    for start, end in sorted(free_4k):
        if start > pos:
            runs.append((pos, start - pos))
        pos = max(pos, end)
    if pos < total:
        runs.append((pos, total - pos))
    return runs


class Writer:
    def __init__(self, path: Path, total: int):
        self.f = open(path, "wb")
        self.total = total
        self.block = 0
        self.chunks = 0
        self.raw_bytes = 0
        self.fill_bytes = 0
        self.f.write(b"\0" * FILE_HDR.size)

    def gap_to(self, block: int) -> None:
        if block > self.block:
            self.f.write(CHUNK_HDR.pack(DONT_CARE, 0, block - self.block, CHUNK_HDR.size))
            self.chunks += 1
            self.block = block

    def raw(self, data: bytes) -> None:
        n = len(data) // BLOCK
        self.f.write(CHUNK_HDR.pack(RAW, 0, n, CHUNK_HDR.size + len(data)))
        self.f.write(data)
        self.chunks += 1
        self.block += n
        self.raw_bytes += len(data)

    def zeros(self, n: int) -> None:
        self.f.write(CHUNK_HDR.pack(FILL, 0, n, CHUNK_HDR.size + 4) + b"\0\0\0\0")
        self.chunks += 1
        self.block += n
        self.fill_bytes += n * BLOCK

    def close(self) -> None:
        self.gap_to(self.total)
        self.f.seek(0)
        self.f.write(FILE_HDR.pack(MAGIC, 1, 0, FILE_HDR.size, CHUNK_HDR.size, BLOCK, self.total, self.chunks, 0))
        self.f.close()


def convert(image: Path, out: Path, text: str | None = None) -> dict:
    block_size, block_count, free = free_ranges(text if text is not None else dumpe2fs(image))
    fs_bytes = block_size * block_count
    if image.stat().st_size < fs_bytes:
        raise Error(f"{image.name} is {image.stat().st_size} bytes, the file system says {fs_bytes}")
    runs = used_4k_runs(block_size, block_count, free)
    w = Writer(out, fs_bytes // BLOCK)
    with open(image, "rb") as f:
        for first, count in runs:
            w.gap_to(first)
            f.seek(first * BLOCK)
            left = count
            pending = bytearray()        # RAW blocks not written yet
            zeros = 0                    # FILL(0) blocks not written yet
            while left:
                n = min(left, MAX_RAW_BLOCKS)
                buf = f.read(n * BLOCK)
                if len(buf) != n * BLOCK:
                    raise Error(f"{image.name}: short read at block {first + count - left}")
                mv = memoryview(buf)
                for i in range(n):
                    blk = mv[i * BLOCK:(i + 1) * BLOCK]
                    if blk == ZERO:
                        if pending:
                            w.raw(bytes(pending))
                            pending.clear()
                        zeros += 1
                    else:
                        if zeros:
                            w.zeros(zeros)
                            zeros = 0
                        pending += blk
                        if len(pending) >= MAX_RAW_BLOCKS * BLOCK:
                            w.raw(bytes(pending))
                            pending.clear()
                left -= n
            if pending:
                w.raw(bytes(pending))
            if zeros:
                w.zeros(zeros)
    w.close()
    used = sum(c for _, c in runs) * BLOCK
    return {"fs_bytes": fs_bytes, "fs_block_size": block_size, "used_bytes": used, "raw_bytes": w.raw_bytes,
            "fill_bytes": w.fill_bytes, "chunks": w.chunks}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    try:
        st = convert(Path(argv[0]), Path(argv[1]))
    except (Error, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(st))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
