"""Per-board secrets (SPEC section 5).

* RSA-2048 boot-signing key (PKCS#8 private PEM / SPKI public PEM).
* ``customer_key_hash``: what the BCM2712 recovery firmware burns into OTP with ``program_pubkey=1``
  and reports as ``CUSTOMER_KEY_HASH``: SHA-256 over the 264-byte bootloader key blob
  (modulus as 256 little-endian bytes followed by the exponent as 8 little-endian bytes). Hashing the
  PEM or the DER SubjectPublicKeyInfo gives a different value.
* ``device_secret``: 32 random bytes (hex), root of the LUKS recovery passphrases
  ``HMAC-SHA256(device_secret, "<label>:<serial>")``.

Nothing in this module logs key material.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets as _secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def generate_rsa_keypair(bits: int = 2048) -> tuple[str, str]:
    """Generate an RSA key pair (e = 65537).

    :returns: ``(private_pem, public_pem)``: PKCS#8 unencrypted private key and SPKI public key,
        both ``str`` with ``\\n`` line endings.
    """
    # Note: the BCM2712 secure boot chain only accepts RSA-2048 (customer_key_hash enforces it).
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv.replace("\r\n", "\n"), pub.replace("\r\n", "\n")


def _load_public_key(pem: str | bytes):
    """Load a public key from a public PEM (SPKI or PKCS#1) or derive it from a private PEM."""
    data = pem.encode("ascii") if isinstance(pem, str) else bytes(pem)
    if b"PRIVATE KEY" in data:
        try:
            return serialization.load_pem_private_key(data, password=None).public_key()
        except (ValueError, TypeError) as exc:
            raise ValueError(f"not a usable private key PEM: {type(exc).__name__}") from None
    try:
        return serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"not a usable public key PEM: {type(exc).__name__}") from None


def customer_key_hash(public_pem: str) -> str:
    """SHA-256 of the bootloader key blob ``n (256 B LE) || e (8 B LE)``, 64 lowercase hex chars.

    Accepts a public PEM or a private PEM (its public half is used). Raises ``ValueError`` for
    anything that is not an RSA-2048 key.
    """
    key = _load_public_key(public_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("customer_key_hash needs an RSA public key")
    if key.key_size != 2048:
        raise ValueError(f"customer_key_hash needs an RSA-2048 key, got {key.key_size} bits")
    nums = key.public_numbers()
    blob = nums.n.to_bytes(256, "little") + nums.e.to_bytes(8, "little")
    return hashlib.sha256(blob).hexdigest()


def generate_device_secret() -> str:
    """32 random bytes from the OS CSPRNG, as 64 lowercase hex chars."""
    return _secrets.token_bytes(32).hex()


def luks_passphrase(device_secret_hex: str, label: str, serial: str) -> str:
    """LUKS recovery passphrase: ``HMAC-SHA256(bytes.fromhex(secret), f"{label}:{serial}")`` hex.

    ``label`` is the dm mapper name of the container (``osroot_crypt``), ``serial`` the 8-hex board
    serial. Deterministic, so the server can re-derive it to open a card offline.
    """
    s = (device_secret_hex or "").strip()
    if not s or len(s) % 2 or not _HEX_RE.match(s):
        raise ValueError("device secret must be a non-empty hex string")
    msg = f"{label}:{serial}".encode("utf-8")
    return hmac.new(bytes.fromhex(s), msg, hashlib.sha256).hexdigest()


def new_module_secrets() -> dict:
    """Fresh secrets for a new board.

    :returns: ``{"rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret"}``
    """
    priv, pub = generate_rsa_keypair()
    return {
        "rsa_private_pem": priv,
        "rsa_public_pem": pub,
        "customer_key_hash": customer_key_hash(pub),
        "device_secret": generate_device_secret(),
    }


def public_key_fingerprint(pem: str) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex (any key type: RSA, EC, ...).

    Used for display of the board RSA key and of the OTP device key (``getvar:public-key``).
    A private PEM is accepted (its public half is fingerprinted). Raises ``ValueError`` on bad input.
    """
    key = _load_public_key(pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def public_pem_from_private(private_pem: str) -> str:
    """SPKI public PEM for a private PEM (used to repair records that lack ``rsa_public_pem``)."""
    key = _load_public_key(private_pem)
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
