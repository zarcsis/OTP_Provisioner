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
