"""SHA-512 crypt (``$6$``), the hash ``openssl passwd -6`` and ``chpasswd -e`` use.

Python 3.13 dropped the ``crypt`` module, and the station needs the hash on Windows, where the image
build is not running yet: this is Ulrich Drepper's "Unix crypt using SHA-256 and SHA-512" (the
algorithm glibc implements), checked against the specification's test vectors and ``openssl passwd -6``.
"""

from __future__ import annotations

import hashlib
import re
import secrets

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ROUNDS_DEFAULT = 5000
ROUNDS_MIN = 1000
ROUNDS_MAX = 999_999_999
SALT_MAX = 16

#: A crypt(3) hash ``chpasswd -e`` accepts: ``$<id>$...`` without whitespace or ``:`` (the passwd separator).
CRYPT_HASH_RE = re.compile(r"^\$[0-9a-z]{1,4}\$[^\s:]+$")


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(ITOA64[w & 0x3F])
        w >>= 6
    return "".join(out)


def _encode(final: bytes) -> str:
    out = []
    for i in range(21):
        a, b, c = i, i + 21, i + 42
        if i % 3 == 1:
            a, b, c = b, c, a
        elif i % 3 == 2:
            a, b, c = c, a, b
        out.append(_b64_from_24bit(final[a], final[b], final[c], 4))
    out.append(_b64_from_24bit(0, 0, final[63], 2))
    return "".join(out)


def _repeat(digest: bytes, length: int) -> bytes:
    return (digest * (length // len(digest) + 1))[:length]


def sha512_crypt(password: str | bytes, salt: str | None = None, rounds: int | None = None) -> str:
    """``$6$[rounds=N$]<salt>$<hash>`` of ``password``.

    :param salt: up to 16 characters (longer is cut, like glibc); default: 16 random ones from ``./0-9A-Za-z``.
    :param rounds: None = the default 5000 (not written into the hash); otherwise clamped to [1000, 999999999]
        and written as ``rounds=N``.
    """
    key = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if salt is None:
        salt = "".join(secrets.choice(ITOA64) for _ in range(SALT_MAX))
    salt_b = salt.encode("utf-8")[:SALT_MAX]
    custom = rounds is not None
    n_rounds = ROUNDS_DEFAULT if rounds is None else max(ROUNDS_MIN, min(ROUNDS_MAX, int(rounds)))

    b = hashlib.sha512(key + salt_b + key).digest()
    a = hashlib.sha512(key + salt_b)
    klen = len(key)
    for _ in range(klen // 64):
        a.update(b)
    a.update(b[: klen % 64])
    n = klen
    while n > 0:
        a.update(b if n & 1 else key)
        n >>= 1
    a_digest = a.digest()

    p = _repeat(hashlib.sha512(key * klen).digest(), klen)
    s = _repeat(hashlib.sha512(salt_b * (16 + a_digest[0])).digest(), len(salt_b))

    c = a_digest
    for i in range(n_rounds):
        h = hashlib.sha512()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(s)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()

    head = "$6$" + (f"rounds={n_rounds}$" if custom else "") + salt_b.decode("utf-8", "replace")
    return f"{head}${_encode(c)}"


def verify(password: str | bytes, hashed: str) -> bool:
    """Whether ``password`` matches a ``$6$`` hash (other schemes: False)."""
    m = re.fullmatch(r"^\$6\$(?:rounds=(\d+)\$)?([^$]*)\$[./0-9A-Za-z]{86}$", hashed or "")
    if not m:
        return False
    rounds = int(m.group(1)) if m.group(1) else None
    return secrets.compare_digest(sha512_crypt(password, m.group(2), rounds), hashed)


def is_crypt_hash(value: str) -> bool:
    """A string ``chpasswd -e`` would take as a hash (``$id$...``, no whitespace or ``:``)."""
    return bool(CRYPT_HASH_RE.fullmatch(value or ""))
