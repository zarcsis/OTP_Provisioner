from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from otp_server import secrets_gen as sg

REPO = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = REPO / "external" / "usbboot" / "secure-boot-example"
# usbboot Readme.md metadata example / secure-boot-recovery README ("OTP updated for key ...")
EXAMPLE_HASH = "8251a63a2edee9d8f710d63e9da5d639064929ce15a2238986a189ac6fcd3cee"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture(scope="module")
def keypair():
    return sg.generate_rsa_keypair()


@pytest.mark.skipif(not (EXAMPLE_DIR / "example-public.pem").is_file(), reason="usbboot submodule not checked out")
def test_customer_key_hash_known_vector():
    pub = (EXAMPLE_DIR / "example-public.pem").read_text(encoding="ascii")
    assert sg.customer_key_hash(pub) == EXAMPLE_HASH


@pytest.mark.skipif(not (EXAMPLE_DIR / "example-private.pem").is_file(), reason="usbboot submodule not checked out")
def test_customer_key_hash_from_private_pem():
    priv = (EXAMPLE_DIR / "example-private.pem").read_text(encoding="ascii")
    assert sg.customer_key_hash(priv) == EXAMPLE_HASH


def test_generate_rsa_keypair(keypair):
    priv, pub = keypair
    assert priv.startswith("-----BEGIN PRIVATE KEY-----\n")  # PKCS#8
    assert pub.startswith("-----BEGIN PUBLIC KEY-----\n")  # SPKI
    assert "\r" not in priv and "\r" not in pub
    key = serialization.load_pem_private_key(priv.encode(), password=None)
    assert key.key_size == 2048
    assert key.public_key().public_numbers().e == 65537
    assert key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode() == pub


def test_customer_key_hash_definition(keypair):
    _, pub = keypair
    nums = serialization.load_pem_public_key(pub.encode()).public_numbers()
    blob = nums.n.to_bytes(256, "little") + nums.e.to_bytes(8, "little")
    assert len(blob) == 264
    h = sg.customer_key_hash(pub)
    assert HEX64.match(h)
    assert h == hashlib.sha256(blob).hexdigest()
    # Not the hash of the PEM or of the DER (a classic mistake)
    der = serialization.load_pem_public_key(pub.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert h != hashlib.sha256(der).hexdigest()
    assert h != hashlib.sha256(pub.encode()).hexdigest()


def test_customer_key_hash_rejects_non_rsa2048():
    ecpub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(ValueError):
        sg.customer_key_hash(ecpub)
    with pytest.raises(ValueError):
        sg.customer_key_hash("not a pem")


def test_device_secret():
    a, b = sg.generate_device_secret(), sg.generate_device_secret()
    assert HEX64.match(a) and HEX64.match(b) and a != b


def test_luks_passphrase():
    secret = "11" * 32
    got = sg.luks_passphrase(secret, "osroot_crypt", "a7eb274c")
    want = hmac.new(bytes.fromhex(secret), b"osroot_crypt:a7eb274c", hashlib.sha256).hexdigest()
    assert got == want and HEX64.match(got)
    assert sg.luks_passphrase(secret.upper(), "osroot_crypt", "a7eb274c") == got
    assert sg.luks_passphrase(secret, "osroot_crypt", "a7eb274d") != got
    assert sg.luks_passphrase(secret, "other", "a7eb274c") != got
    for bad in ("", "abc", "zz" * 32):
        with pytest.raises(ValueError):
            sg.luks_passphrase(bad, "l", "s")


def test_new_module_secrets():
    s = sg.new_module_secrets()
    assert set(s) == {"rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret"}
    assert s["customer_key_hash"] == sg.customer_key_hash(s["rsa_public_pem"])
    assert sg.customer_key_hash(s["rsa_private_pem"]) == s["customer_key_hash"]
    assert HEX64.match(s["device_secret"])
    assert sg.public_pem_from_private(s["rsa_private_pem"]) == s["rsa_public_pem"]


def test_public_key_fingerprint(keypair):
    priv, pub = keypair
    der = serialization.load_pem_public_key(pub.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = sg.public_key_fingerprint(pub)
    assert fp == hashlib.sha256(der).hexdigest()
    assert sg.public_key_fingerprint(priv) == fp
    # EC device key (what getvar:public-key returns) works too
    ecpub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert HEX64.match(sg.public_key_fingerprint(ecpub))
    with pytest.raises(ValueError):
        sg.public_key_fingerprint("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")


# --------------------------------------------------------------------------------------------------
# OTP device key (rpi-fw-crypto key-id 1) exported by the fastboot gadget in the secure scenario
# --------------------------------------------------------------------------------------------------

# FIPS 186-4 D.1.2.3 / SEC 2: order n of the NIST P-256 base point.
P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
# design.md known-answer vector: d = bytes 1..32, SD card CID as sysfs prints it (with the newline).
KAT_D = int.from_bytes(bytes(range(1, 33)), "big")
KAT_CID = b"035344534333324780b6e2a8d9012d00\n"
KAT_LUKS = "4fd7384feb1d5f4fa4319227475a01eb4719e1194dd3d88aad182b4cf5cfb0e3"


def _spki_pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _der(key, fmt) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, fmt, serialization.NoEncryption())


def _zero_words_reference(d: int) -> int:
    """Independent count: the 32-byte big-endian key split into 8 four-byte OTP rows."""
    raw = d.to_bytes(32, "big")
    return sum(1 for i in range(0, 32, 4) if raw[i:i + 4] == b"\0\0\0\0")


@pytest.fixture(scope="module")
def p256():
    return ec.generate_private_key(ec.SECP256R1())


def test_p256_order():
    assert sg.P256_ORDER == P256_N
    # cryptography agrees: n - 1 is the largest valid scalar, n itself is not a private key
    ec.derive_private_key(sg.P256_ORDER - 1, ec.SECP256R1())
    with pytest.raises(ValueError):
        ec.derive_private_key(sg.P256_ORDER, ec.SECP256R1())


@pytest.mark.parametrize("fmt", [serialization.PrivateFormat.TraditionalOpenSSL,   # SEC1 ECPrivateKey
                                 serialization.PrivateFormat.PKCS8],
                         ids=["sec1", "pkcs8"])
def test_parse_device_private_key_der(p256, fmt):
    der = _der(p256, fmt)
    d, priv, pub = sg.parse_device_private_key(der)
    assert d == p256.private_numbers().private_value
    assert priv.startswith("-----BEGIN PRIVATE KEY-----\n") and priv.endswith("-----END PRIVATE KEY-----\n")
    assert pub.startswith("-----BEGIN PUBLIC KEY-----\n") and pub.endswith("-----END PUBLIC KEY-----\n")
    assert "\r" not in priv and "\r" not in pub
    assert "EC PRIVATE KEY" not in priv  # PKCS#8, not SEC1 PEM
    assert pub == _spki_pem(p256)
    back = serialization.load_pem_private_key(priv.encode(), password=None)
    assert isinstance(back, ec.EllipticCurvePrivateKey) and back.curve.name == "secp256r1"
    assert back.private_numbers().private_value == d
    # bytearray / memoryview input is fine too
    assert sg.parse_device_private_key(bytearray(der))[0] == d


@pytest.mark.parametrize("d", [1, 2, KAT_D, P256_N - 1, 0xFFFFFFFF << 64],
                         ids=["1", "2", "kat", "n-1", "leading-zero-bytes"])
def test_parse_device_private_key_raw_scalar(d):
    raw = d.to_bytes(32, "big")
    got_d, priv, pub = sg.parse_device_private_key(raw)
    assert got_d == d
    want = ec.derive_private_key(d, ec.SECP256R1())
    assert pub == _spki_pem(want)
    assert priv.startswith("-----BEGIN PRIVATE KEY-----\n") and "\r" not in priv
    assert serialization.load_pem_private_key(priv.encode(), password=None).private_numbers().private_value == d
    # the raw scalar and the DER of the same key give the same result
    assert sg.parse_device_private_key(_der(want, serialization.PrivateFormat.PKCS8)) == (got_d, priv, pub)


@pytest.mark.parametrize("d", [0, P256_N, P256_N + 1, (1 << 256) - 1], ids=["0", "n", "n+1", "max"])
def test_parse_device_private_key_rejects_out_of_range_scalars(d):
    raw = d.to_bytes(32, "big")
    with pytest.raises(ValueError, match="not a valid P-256 private scalar") as ei:
        sg.parse_device_private_key(raw)
    if d:
        assert raw.hex() not in str(ei.value).lower()  # never key material in the message


def test_parse_device_private_key_rejects_other_curves_and_types(keypair):
    p384 = ec.generate_private_key(ec.SECP384R1())
    rsa_priv = serialization.load_pem_private_key(keypair[0].encode(), password=None)
    for der in (_der(p384, serialization.PrivateFormat.PKCS8),
                _der(p384, serialization.PrivateFormat.TraditionalOpenSSL),
                _der(rsa_priv, serialization.PrivateFormat.PKCS8)):
        with pytest.raises(ValueError, match="not an ECDSA P-256 key"):
            sg.parse_device_private_key(der)


@pytest.mark.parametrize("data", [b"", None, b"not a key at all", b"\x30\x03\x02\x01\x01", b"\x01" * 31, b"\x01" * 33,
                                  b"-----BEGIN PRIVATE KEY-----\n"],
                         ids=["empty", "none", "text", "short-der", "31", "33", "pem-header"])
def test_parse_device_private_key_rejects_garbage(data):
    with pytest.raises(ValueError):
        sg.parse_device_private_key(data)


def test_parse_device_private_key_rejects_public_der(p256):
    spki = p256.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError):
        sg.parse_device_private_key(spki)


def test_device_key_scalar(p256, keypair):
    _d, priv, _pub = sg.parse_device_private_key(_der(p256, serialization.PrivateFormat.PKCS8))
    assert sg.device_key_scalar(priv) == p256.private_numbers().private_value
    # a SEC1 PEM ("EC PRIVATE KEY") of the same key works too
    sec1 = p256.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()).decode()
    assert sg.device_key_scalar(sec1) == p256.private_numbers().private_value
    p384 = ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    for bad in (p384, keypair[0]):
        with pytest.raises(ValueError, match="not an ECDSA P-256 key"):
            sg.device_key_scalar(bad)
    with pytest.raises(ValueError):
        sg.device_key_scalar("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")


def test_otp_zero_words():
    assert sg.otp_zero_words(KAT_D) == 0
    assert sg.otp_zero_words(1) == 7
    assert sg.otp_zero_words(P256_N - 1) == 1  # n has an all-zero second row (FFFFFFFF 00000000 ...)
    words = [0x11111111 * (i + 1) for i in range(8)]  # w0 (least significant) .. w7
    for zero_at in ([], [0], [7], [3], [1, 6], [0, 2, 4]):
        ws = [0 if i in zero_at else w for i, w in enumerate(words)]
        d = sum(w << (32 * i) for i, w in enumerate(ws))
        assert sg.otp_zero_words(d) == len(zero_at) == _zero_words_reference(d), zero_at
    # a word is a whole 32-bit row: zero bytes inside a non-zero row do not count
    d = int.from_bytes(bytes.fromhex("00000001" "01000000" "00010000" "00000100") * 2, "big")
    assert sg.otp_zero_words(d) == 0 == _zero_words_reference(d)


def test_same_public_key(p256, keypair):
    priv_pem = p256.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
    pub_pem = _spki_pem(p256)
    assert sg.same_public_key(pub_pem, priv_pem)
    assert sg.same_public_key(priv_pem, pub_pem)
    assert sg.same_public_key(pub_pem, pub_pem.replace("\n", "\r\n"))
    assert sg.same_public_key(pub_pem.encode(), priv_pem)
    other = _spki_pem(ec.generate_private_key(ec.SECP256R1()))
    assert not sg.same_public_key(pub_pem, other)
    assert not sg.same_public_key(priv_pem, other)
    assert not sg.same_public_key(pub_pem, keypair[1])  # RSA vs EC
    for garbage in ("", "garbage", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
                    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"):
        assert sg.same_public_key(pub_pem, garbage) is False
        assert sg.same_public_key(garbage, pub_pem) is False
    assert sg.same_public_key("garbage", "garbage") is False


def test_luks_key_known_answer():
    assert sg.luks_key(KAT_D, KAT_CID) == KAT_LUKS
    # definition: HMAC-SHA256 keyed with d as 32 big-endian bytes over the exact sysfs text
    assert hmac.new(bytes(range(1, 33)), KAT_CID, hashlib.sha256).hexdigest() == KAT_LUKS
    # the trailing newline is part of the id: dropping it gives another key
    no_nl = sg.luks_key(KAT_D, KAT_CID.rstrip(b"\n"))
    assert HEX64.match(no_nl) and no_nl != KAT_LUKS
    assert sg.luks_key(KAT_D, KAT_CID.upper()) != KAT_LUKS


def test_luks_key_small_d_is_padded_to_32_bytes():
    got = sg.luks_key(1, KAT_CID)
    assert got == hmac.new(b"\0" * 31 + b"\1", KAT_CID, hashlib.sha256).hexdigest()
    assert got != hmac.new(b"\1", KAT_CID, hashlib.sha256).hexdigest()


def test_luks_key_from_an_exported_key(p256):
    _d, priv, _pub = sg.parse_device_private_key(_der(p256, serialization.PrivateFormat.TraditionalOpenSSL))
    d = sg.device_key_scalar(priv)
    want = hmac.new(p256.private_numbers().private_value.to_bytes(32, "big"), KAT_CID, hashlib.sha256).hexdigest()
    assert sg.luks_key(d, KAT_CID) == want


@pytest.mark.parametrize("d", [0, -1, P256_N, P256_N + 5, 1 << 256])
def test_luks_key_rejects_invalid_scalars(d):
    with pytest.raises(ValueError, match="not a valid P-256 private scalar"):
        sg.luks_key(d, KAT_CID)
