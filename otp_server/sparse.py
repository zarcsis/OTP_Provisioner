"""Android sparse image parsing (the format rpi-image-gen/genimage emits and fastbootd flashes).

Layout (all little-endian):

* file header, 28 bytes: magic u32 (0xED26FF3A), major u16, minor u16, file_hdr_sz u16,
  chunk_hdr_sz u16, blk_sz u32, total_blks u32, total_chunks u32, image_checksum u32
* per chunk, 12 bytes: chunk_type u16, reserved u16, chunk_sz u32 (output blocks),
  total_sz u32 (bytes of this chunk in the file, header included), followed by the payload:
  RAW 0xCAC1 = chunk_sz * blk_sz bytes, FILL 0xCAC2 = 4 bytes, DONT_CARE 0xCAC3 = none,
  CRC32 0xCAC4 = 4 bytes (covers no output blocks).

The server uses this to validate the IDP pieces it serves: every piece must be a complete sparse
file whose ``total_blocks`` equals the original image's (a split piece starts with a DONT_CARE
chunk for the part written by earlier pieces).
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

MAGIC = 0xED26FF3A
FILE_HEADER_SIZE = 28
CHUNK_HEADER_SIZE = 12

CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4

_FILE_HDR = struct.Struct("<IHHHHIIII")
_CHUNK_HDR = struct.Struct("<HHII")


class SparseError(ValueError):
    """The file is not a well-formed Android sparse image."""


def is_sparse(path: str | Path) -> bool:
    """True when the file starts with the Android sparse magic (header not otherwise checked)."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return len(head) == 4 and struct.unpack("<I", head)[0] == MAGIC


def sparse_info(path: str | Path) -> dict:
    """Parse and validate a sparse image.

    Returns ``{"block_size", "total_blocks", "total_chunks", "expanded_size"}``.
    Walks every chunk header (payloads are skipped, not read) and raises :class:`SparseError`
    when the header is invalid, a chunk size is inconsistent with its type, the file is truncated
    or has trailing bytes, or the chunks do not add up to ``total_blocks``.
    """
    p = Path(path)
    try:
        file_size = p.stat().st_size
    except OSError as exc:
        raise SparseError(f"{p.name}: cannot stat: {exc}") from exc
    with open(p, "rb") as f:
        head = f.read(FILE_HEADER_SIZE)
        if len(head) < FILE_HEADER_SIZE:
            raise SparseError(f"{p.name}: too short for a sparse header ({len(head)} bytes)")
        (magic, major, _minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks, total_chunks,
         _checksum) = _FILE_HDR.unpack(head)
        if magic != MAGIC:
            raise SparseError(f"{p.name}: bad magic 0x{magic:08x} (not an Android sparse image)")
        if major != 1:
            raise SparseError(f"{p.name}: unsupported sparse major version {major}")
        if file_hdr_sz < FILE_HEADER_SIZE or chunk_hdr_sz < CHUNK_HEADER_SIZE:
            raise SparseError(f"{p.name}: header sizes too small ({file_hdr_sz}/{chunk_hdr_sz})")
        if blk_sz == 0 or blk_sz % 4 != 0:
            raise SparseError(f"{p.name}: invalid block size {blk_sz}")

        pos = file_hdr_sz
        blocks = 0
        for i in range(total_chunks):
            f.seek(pos)
            ch = f.read(CHUNK_HEADER_SIZE)
            if len(ch) < CHUNK_HEADER_SIZE:
                raise SparseError(f"{p.name}: truncated at chunk {i} header (offset {pos})")
            ctype, _res, csz, tsz = _CHUNK_HDR.unpack(ch)
            if ctype == CHUNK_RAW:
                expect = chunk_hdr_sz + csz * blk_sz
            elif ctype in (CHUNK_FILL, CHUNK_CRC32):
                expect = chunk_hdr_sz + 4
            elif ctype == CHUNK_DONT_CARE:
                expect = chunk_hdr_sz
            else:
                raise SparseError(f"{p.name}: chunk {i} has unknown type 0x{ctype:04x}")
            if tsz != expect:
                raise SparseError(
                    f"{p.name}: chunk {i} (type 0x{ctype:04x}) total_sz {tsz} != expected {expect}")
            if ctype == CHUNK_CRC32 and csz != 0:
                raise SparseError(f"{p.name}: CRC32 chunk {i} covers {csz} blocks (must be 0)")
            if ctype != CHUNK_CRC32:
                blocks += csz
            pos += tsz
            if pos > file_size:
                raise SparseError(f"{p.name}: truncated in chunk {i} (needs {pos} bytes, file has {file_size})")
        if pos != file_size:
            raise SparseError(f"{p.name}: {file_size - pos} trailing bytes after the last chunk")
        if blocks != total_blks:
            raise SparseError(f"{p.name}: chunks cover {blocks} blocks, header says {total_blks}")
    return {
        "block_size": blk_sz,
        "total_blocks": total_blks,
        "total_chunks": total_chunks,
        "expanded_size": blk_sz * total_blks,
    }


def check_pieces(paths: Iterable[str | Path]) -> dict:
    """Validate the pieces of one (possibly split) sparse image.

    Every piece must be a valid sparse file and all pieces must describe the same output
    (equal ``block_size`` and ``total_blocks``). Returns the info dict of the first piece plus
    ``"pieces"`` (count). Raises :class:`SparseError`.
    """
    infos = []
    for path in paths:
        infos.append((Path(path).name, sparse_info(path)))
    if not infos:
        raise SparseError("no pieces")
    first_name, first = infos[0]
    for name, info in infos[1:]:
        if (info["block_size"], info["total_blocks"]) != (first["block_size"], first["total_blocks"]):
            raise SparseError(
                f"{name}: {info['total_blocks']} x {info['block_size']} B blocks, but {first_name} has "
                f"{first['total_blocks']} x {first['block_size']} B (pieces of different images?)")
    out = dict(first)
    out["pieces"] = len(infos)
    return out
