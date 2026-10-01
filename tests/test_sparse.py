"""Android sparse image parser (otp_server.sparse) against synthetic files."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from otp_server import sparse

BLK = 4096


def make_sparse(path: Path, chunks, blk: int = BLK, total_blocks: int | None = None,
                n_chunks: int | None = None, tail: bytes = b"") -> Path:
    """Write a sparse file from [("raw", n) | ("fill", n) | ("dc", n) | ("crc", 0)]."""
    body = b""
    blocks = 0
    for kind, n in chunks:
        if kind == "raw":
            data = bytes([0x5A]) * (n * blk)
            body += struct.pack("<HHII", 0xCAC1, 0, n, 12 + len(data)) + data
            blocks += n
        elif kind == "fill":
            body += struct.pack("<HHII", 0xCAC2, 0, n, 16) + b"\xff\xff\xff\xff"
            blocks += n
        elif kind == "dc":
            body += struct.pack("<HHII", 0xCAC3, 0, n, 12)
            blocks += n
        elif kind == "crc":
            body += struct.pack("<HHII", 0xCAC4, 0, 0, 16) + b"\0\0\0\0"
        else:
            raise ValueError(kind)
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk,
                      blocks if total_blocks is None else total_blocks,
                      len(chunks) if n_chunks is None else n_chunks, 0)
    path.write_bytes(hdr + body + tail)
    return path


def test_valid_file_info(tmp_path):
    p = make_sparse(tmp_path / "a.sparse", [("raw", 2), ("dc", 10), ("fill", 3), ("crc", 0)])
    assert sparse.is_sparse(p)
    info = sparse.sparse_info(p)
    assert info == {"block_size": BLK, "total_blocks": 15, "total_chunks": 4, "expanded_size": 15 * BLK}


def test_is_sparse_false_for_other_files(tmp_path):
    (tmp_path / "raw.img").write_bytes(b"\0" * 64)
    (tmp_path / "short").write_bytes(b"\x3a")
    assert not sparse.is_sparse(tmp_path / "raw.img")
    assert not sparse.is_sparse(tmp_path / "short")
    assert not sparse.is_sparse(tmp_path / "missing")
    with pytest.raises(sparse.SparseError, match="bad magic"):
        sparse.sparse_info(tmp_path / "raw.img")
    with pytest.raises(sparse.SparseError, match="too short"):
        sparse.sparse_info(tmp_path / "short")


def test_blocks_mismatch(tmp_path):
    p = make_sparse(tmp_path / "b.sparse", [("raw", 1), ("dc", 4)], total_blocks=9)
    with pytest.raises(sparse.SparseError, match="chunks cover 5 blocks, header says 9"):
        sparse.sparse_info(p)


def test_truncated_and_trailing(tmp_path):
    p = make_sparse(tmp_path / "c.sparse", [("raw", 2)])
    data = p.read_bytes()
    p.write_bytes(data[:-100])
    with pytest.raises(sparse.SparseError, match="truncated"):
        sparse.sparse_info(p)
    make_sparse(p, [("raw", 1)], tail=b"junk")
    with pytest.raises(sparse.SparseError, match="trailing"):
        sparse.sparse_info(p)
    make_sparse(p, [("raw", 1)], n_chunks=2)
    with pytest.raises(sparse.SparseError, match="truncated at chunk 1"):
        sparse.sparse_info(p)


def test_bad_chunk_sizes(tmp_path):
    p = tmp_path / "d.sparse"
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, BLK, 1, 1, 0)
    p.write_bytes(hdr + struct.pack("<HHII", 0xCAC2, 0, 1, 20) + b"\0" * 8)   # FILL must be 16 bytes
    with pytest.raises(sparse.SparseError, match="total_sz 20 != expected 16"):
        sparse.sparse_info(p)
    p.write_bytes(hdr + struct.pack("<HHII", 0xBEEF, 0, 1, 12))
    with pytest.raises(sparse.SparseError, match="unknown type"):
        sparse.sparse_info(p)
    bad_blk = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 0, 0, 0, 0)
    p.write_bytes(bad_blk)
    with pytest.raises(sparse.SparseError, match="block size"):
        sparse.sparse_info(p)


def test_check_pieces_split_image(tmp_path):
    # A 20-block image split in two self-contained pieces (the second starts with DONT_CARE).
    a = make_sparse(tmp_path / "root.ext4.sparse.0", [("raw", 8), ("dc", 12)])
    b = make_sparse(tmp_path / "root.ext4.sparse.1", [("dc", 8), ("raw", 4), ("fill", 8)])
    info = sparse.check_pieces([a, b])
    assert info["total_blocks"] == 20 and info["pieces"] == 2 and info["expanded_size"] == 20 * BLK


def test_check_pieces_rejects_mixed_images(tmp_path):
    a = make_sparse(tmp_path / "x.0", [("raw", 8), ("dc", 12)])
    b = make_sparse(tmp_path / "x.1", [("dc", 8), ("raw", 4)])
    with pytest.raises(sparse.SparseError, match="different images"):
        sparse.check_pieces([a, b])
    with pytest.raises(sparse.SparseError, match="no pieces"):
        sparse.check_pieces([])
