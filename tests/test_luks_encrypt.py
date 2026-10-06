"""docker/scripts/luks_encrypt.py: a plain sparse image -> the sparse image of a LUKS2 container (dm-crypt)."""
from __future__ import annotations

import hashlib
import importlib.util
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from otp_server import sparse
from otp_server.config import REPO_ROOT

#: Captured from dm-crypt (LUKS2, aes-xts-plain64, 512-bit key, sector size 4096): this volume key, the
#: plaintext bytes(range(256)) * 64 written through /dev/mapper at 4096-byte sectors 5..8 of the data segment.
DM_VK = bytes.fromhex("fdafad95463d19c3e7a084daee83bf813cad20573fee8b26169634a41abfd39a"
                      "bfa7412acae64f372adc512c604c2d2cb99c997a9e3439b44f0a8986fca29a9d")
DM_PLAIN = bytes(range(256)) * 64
DM_CIPHER_SHA = "a0062375e8d857072c2be06086fce1282aace5303d227f5eadee2ec54e1828d6"
BLK = 4096


@pytest.fixture(scope="module")
def le():
    spec = importlib.util.spec_from_file_location("luks_encrypt", REPO_ROOT / "docker" / "scripts" / "luks_encrypt.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_encryption_matches_dm_crypt(le):
    """The XTS tweak counts 512-byte units even with 4096-byte sectors (LUKS2 sets no iv_large_sectors)."""
    out = le.encrypt_sectors(DM_VK, DM_PLAIN, 5 * BLK, 4096)
    assert hashlib.sha256(out).hexdigest() == DM_CIPHER_SHA
    assert le.encrypt_sectors(DM_VK, DM_PLAIN, 5 * BLK, 512) != out          # a sector size is part of it


def sparse_file(path, total: int, chunks: list[tuple[str, int, bytes | int]]):
    """chunks: ("raw", first_block, data) | ("fill", first_block, (blocks, word)); gaps are DONT_CARE."""
    body, n, at = b"", 0, 0
    for kind, first, payload in chunks:
        if first > at:
            body += struct.pack("<HHII", 0xCAC3, 0, first - at, 12)
            n += 1
        if kind == "raw":
            blocks = len(payload) // BLK
            body += struct.pack("<HHII", 0xCAC1, 0, blocks, 12 + len(payload)) + payload
        else:
            blocks, word = payload
            body += struct.pack("<HHII", 0xCAC2, 0, blocks, 16) + word
        n += 1
        at = first + blocks
    if at < total:
        body += struct.pack("<HHII", 0xCAC3, 0, total - at, 12)
        n += 1
    path.write_bytes(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, BLK, total, n, 0) + body)


def expand(path) -> bytes:
    data = bytearray()
    with open(path, "rb") as f:
        _m, _a, _b, fhs, chs, blk, total, n, _c = struct.unpack("<IHHHHIIII", f.read(28))
        data = bytearray(total * blk)
        f.seek(fhs)
        at = 0
        for _ in range(n):
            t, _r, blocks, tsz = struct.unpack("<HHII", f.read(12))
            if t == 0xCAC1:
                data[at * blk:(at + blocks) * blk] = f.read(blocks * blk)
            elif t == 0xCAC2:
                data[at * blk:(at + blocks) * blk] = f.read(4) * (blocks * blk // 4)
            at += blocks
    return bytes(data)


def test_build_places_the_header_and_encrypts_only_written_blocks(le, tmp_path):
    vk = bytes(range(64))
    header = bytearray(16 * BLK)
    header[:6] = b"LUKS\xba\xbe"
    header[5 * BLK:5 * BLK + 3] = b"key"                  # a keyslot area somewhere; the rest is zero padding
    (tmp_path / "hdr").write_bytes(bytes(header) + b"\0" * BLK)      # luksFormat's file is larger than the offset
    a = bytes([7]) * (2 * BLK)
    b = bytes(range(256)) * 16
    # two self-contained pieces of one 40-block file system, as image-collect.sh splits it
    sparse_file(tmp_path / "p0", 40, [("raw", 0, a), ("fill", 3, (2, b"\0\0\0\0"))])
    sparse_file(tmp_path / "p1", 40, [("raw", 10, b), ("fill", 20, (1, b"\x01\x02\x03\x04"))])
    st = le.build([tmp_path / "p0", tmp_path / "p1"], tmp_path / "hdr", vk, 16 * BLK, 4096, tmp_path / "out")
    assert st["blocks"] == 16 + 40
    info = sparse.check_pieces([tmp_path / "out"])
    assert info["expanded_size"] == (16 + 40) * BLK
    img = expand(tmp_path / "out")
    assert img[:16 * BLK] == bytes(header)                 # the header region exactly, zero padding included
    payload = img[16 * BLK:]

    def dec(offset, n):
        out = b""
        for i in range(0, n, 4096):
            tweak = ((offset + i) // 512).to_bytes(16, "little")
            d = Cipher(algorithms.AES(vk), modes.XTS(tweak)).decryptor()
            out += d.update(payload[offset + i:offset + i + 4096]) + d.finalize()
        return out
    assert dec(0, 2 * BLK) == a and payload[:2 * BLK] != a
    assert dec(3 * BLK, 2 * BLK) == b"\0" * (2 * BLK)     # a zero FILL is written encrypted, not left as zeros
    assert payload[3 * BLK:5 * BLK] != b"\0" * (2 * BLK)
    assert dec(10 * BLK, BLK) == b and dec(20 * BLK, BLK) == b"\x01\x02\x03\x04" * 1024
    assert payload[30 * BLK:] == b"\0" * (10 * BLK)        # never written: DONT_CARE stays DONT_CARE
    # chunk kinds in the output: no RAW for the unwritten tail
    assert st["encrypted_bytes"] == (2 + 2 + 1 + 1) * BLK


def test_build_refuses_bad_input(le, tmp_path):
    (tmp_path / "hdr").write_bytes(b"NOTLUKS" + b"\0" * (16 * BLK))
    sparse_file(tmp_path / "p0", 8, [("raw", 0, b"\0" * BLK)])
    with pytest.raises(le.Error, match="LUKS header"):
        le.build([tmp_path / "p0"], tmp_path / "hdr", bytes(64), 16 * BLK, 4096, tmp_path / "out")
    (tmp_path / "hdr").write_bytes(b"LUKS\xba\xbe" + b"\0" * (16 * BLK))
    with pytest.raises(le.Error, match="64 bytes"):
        le.build([tmp_path / "p0"], tmp_path / "hdr", bytes(32), 16 * BLK, 4096, tmp_path / "out")
    sparse_file(tmp_path / "p1", 9, [("raw", 0, b"\0" * BLK)])
    with pytest.raises(le.Error, match="covers 9 blocks"):
        le.build([tmp_path / "p0", tmp_path / "p1"], tmp_path / "hdr", bytes(range(64)), 16 * BLK, 4096,
                 tmp_path / "out")
