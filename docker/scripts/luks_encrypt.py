#!/usr/bin/env python3
"""Turn a plain file-system sparse image into the sparse image of a LUKS2 container holding it.

    luks_encrypt.py --header HDR --volume-key VK --data-offset BYTES --sector-size 4096 --out OUT PIECE...

``HDR`` is a LUKS2 header made by ``cryptsetup luksFormat`` on a file (with ``--offset`` = the data offset
and ``--volume-key-file`` = ``VK``, 64 bytes, AES-256-XTS); its first ``--data-offset`` bytes become the
start of the container. The ``PIECE`` files are the self-contained sparse pieces of the plain image (in
flashing order, as image-collect.sh splits them); their RAW and FILL chunks are encrypted the way dm-crypt
would write them through ``/dev/mapper/<name>`` and placed ``--data-offset`` bytes further on.

dm-crypt's ``aes-xts-plain64`` with LUKS2 sector size 4096: every 4096-byte sector is encrypted on its own
with the XTS tweak = the sector's offset in the data segment counted in 512-byte units (little-endian
64-bit, zero-padded to 16 bytes); LUKS2 does not set ``iv_large_sectors``. Verified against dm-crypt.

DONT_CARE chunks stay DONT_CARE: those blocks are never written, exactly as when the plain image is
written through dm-crypt. FILL chunks become RAW (the same plaintext gives different ciphertext per
sector). The header region is written whole (zero runs as FILL chunks), because the LUKS2 checksums
cover its padding. Output: one sparse file, block size 4096, covering data offset + plain image size.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = 0xED26FF3A
RAW, FILL, DONT_CARE, CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
FILE_HDR = struct.Struct("<IHHHHIIII")
CHUNK_HDR = struct.Struct("<HHII")
BLOCK = 4096
#: Largest RAW chunk written at once (bytes).
MAX_RAW = 64 * 1024 * 1024


class Error(Exception):
    pass


def read_chunks(path: Path):
    """``(block_size, total_blocks, [(first_block, blocks, kind, file_pos, fill_word)])`` of a sparse file."""
    with open(path, "rb") as f:
        hdr = f.read(FILE_HDR.size)
        if len(hdr) < FILE_HDR.size:
            raise Error(f"{path.name}: short file")
        magic, major, _minor, fhs, chs, blk, total, nchunks, _crc = FILE_HDR.unpack(hdr)
        if magic != MAGIC or major != 1:
            raise Error(f"{path.name}: not an Android sparse image")
        f.seek(fhs)
        out, block = [], 0
        for _ in range(nchunks):
            ch = f.read(chs)
            if len(ch) < CHUNK_HDR.size:
                raise Error(f"{path.name}: truncated chunk header")
            kind, _r, blocks, total_sz = CHUNK_HDR.unpack(ch[:CHUNK_HDR.size])
            pos = f.tell()
            fill = None
            if kind == FILL:
                fill = f.read(4)
            elif kind not in (RAW, DONT_CARE, CRC32):
                raise Error(f"{path.name}: unknown chunk type {kind:#x}")
            if kind in (RAW, FILL):
                out.append((block, blocks, kind, pos, fill))
            if kind != CRC32:
                block += blocks
            f.seek(pos + total_sz - chs)
        if block != total:
            raise Error(f"{path.name}: chunks cover {block} blocks, header says {total}")
        return blk, total, out


class SparseWriter:
    """Writes a sparse file chunk by chunk (block size 4096), gaps as DONT_CARE."""

    def __init__(self, path: Path, total_blocks: int):
        self.f = open(path, "wb")
        self.total = total_blocks
        self.block = 0
        self.chunks = 0
        self.f.write(b"\0" * FILE_HDR.size)

    def _gap_to(self, block: int) -> None:
        if block < self.block:
            raise Error(f"overlapping data at block {block} (already at {self.block})")
        if block > self.block:
            self.f.write(CHUNK_HDR.pack(DONT_CARE, 0, block - self.block, CHUNK_HDR.size))
            self.chunks += 1
            self.block = block

    def raw(self, block: int, data: bytes) -> None:
        self._gap_to(block)
        n = len(data) // BLOCK
        self.f.write(CHUNK_HDR.pack(RAW, 0, n, CHUNK_HDR.size + len(data)))
        self.f.write(data)
        self.chunks += 1
        self.block += n

    def zeros(self, block: int, blocks: int) -> None:
        self._gap_to(block)
        self.f.write(CHUNK_HDR.pack(FILL, 0, blocks, CHUNK_HDR.size + 4) + b"\0\0\0\0")
        self.chunks += 1
        self.block += blocks

    def close(self) -> None:
        self._gap_to(self.total)
        self.f.seek(0)
        self.f.write(FILE_HDR.pack(MAGIC, 1, 0, FILE_HDR.size, CHUNK_HDR.size, BLOCK, self.total, self.chunks, 0))
        self.f.close()


def encrypt_sectors(volume_key: bytes, data: bytes, offset: int, sector_size: int) -> bytes:
    """dm-crypt aes-xts-plain64 of ``data`` lying ``offset`` bytes into the data segment."""
    if offset % sector_size or len(data) % sector_size:
        raise Error("data is not sector aligned")
    out = bytearray(len(data))
    aes = algorithms.AES(volume_key)
    for i in range(0, len(data), sector_size):
        tweak = ((offset + i) // 512).to_bytes(16, "little")
        enc = Cipher(aes, modes.XTS(tweak)).encryptor()
        out[i:i + sector_size] = enc.update(data[i:i + sector_size]) + enc.finalize()
    return bytes(out)


def write_header(w: SparseWriter, header: bytes) -> None:
    """The header region, whole: non-zero blocks as RAW, zero runs as FILL."""
    n = len(header) // BLOCK
    i = 0
    while i < n:
        zero = header[i * BLOCK:(i + 1) * BLOCK].count(0) == BLOCK
        j = i
        while j < n and (header[j * BLOCK:(j + 1) * BLOCK].count(0) == BLOCK) == zero:
            j += 1
        if zero:
            w.zeros(i, j - i)
        else:
            w.raw(i, header[i * BLOCK:j * BLOCK])
        i = j


def build(pieces: list[Path], header_file: Path, volume_key: bytes, data_offset: int, sector_size: int,
          out: Path) -> dict:
    if len(volume_key) != 64:
        raise Error("the volume key must be 64 bytes (AES-256-XTS)")
    if sector_size % 512 or BLOCK % sector_size or data_offset % BLOCK:
        raise Error("sector size must divide 4096 and the data offset must be a multiple of 4096")
    header = header_file.read_bytes()[:data_offset]
    if len(header) != data_offset or header[:6] != b"LUKS\xba\xbe":
        raise Error(f"{header_file.name} does not hold a LUKS header of {data_offset} bytes")
    regions = []
    total = None
    for p in pieces:
        blk, tot, chunks = read_chunks(p)
        if blk != BLOCK:
            raise Error(f"{p.name}: block size {blk}, expected {BLOCK}")
        if total is None:
            total = tot
        elif tot != total:
            raise Error(f"{p.name} covers {tot} blocks, the first piece {total}")
        regions += [(first, blocks, kind, pos, fill, p) for first, blocks, kind, pos, fill in chunks]
    if total is None:
        raise Error("no input pieces")
    regions.sort(key=lambda r: r[0])
    head_blocks = data_offset // BLOCK
    w = SparseWriter(out, head_blocks + total)
    write_header(w, header)
    written = 0
    handles: dict[Path, object] = {}
    try:
        for first, blocks, kind, pos, fill, p in regions:
            for b0 in range(first, first + blocks, MAX_RAW // BLOCK):
                n = min(MAX_RAW // BLOCK, first + blocks - b0)
                if kind == RAW:
                    f = handles.get(p) or handles.setdefault(p, open(p, "rb"))
                    f.seek(pos + (b0 - first) * BLOCK)
                    plain = f.read(n * BLOCK)
                    if len(plain) != n * BLOCK:
                        raise Error(f"{p.name}: truncated RAW chunk")
                else:
                    plain = fill * (n * BLOCK // 4)
                w.raw(head_blocks + b0, encrypt_sectors(volume_key, plain, b0 * BLOCK, sector_size))
                written += n * BLOCK
    finally:
        for f in handles.values():
            f.close()
    w.close()
    return {"blocks": head_blocks + total, "encrypted_bytes": written, "chunks": w.chunks}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--header", required=True, type=Path)
    ap.add_argument("--volume-key", required=True, type=Path)
    ap.add_argument("--data-offset", required=True, type=int)
    ap.add_argument("--sector-size", type=int, default=4096)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("pieces", nargs="+", type=Path)
    a = ap.parse_args(argv)
    try:
        st = build(a.pieces, a.header, a.volume_key.read_bytes(), a.data_offset, a.sector_size, a.out)
    except (Error, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"    {a.out.name}: {st['blocks']} blocks, {st['encrypted_bytes']} bytes encrypted, {st['chunks']} chunks")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
