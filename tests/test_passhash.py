"""SHA-512 crypt (``$6$``): the specification's test vectors and the formats chpasswd -e takes."""
from __future__ import annotations

import pytest

from otp_server.passhash import ITOA64, is_crypt_hash, sha512_crypt, verify

# Ulrich Drepper, "Unix crypt using SHA-256 and SHA-512", SHA-512 test vectors.
SPEC = [
    ("saltstring", None, "Hello world!",
     "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
    ("saltstringsaltstring", 10000, "Hello world!",
     "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/"
     "YTBmSK6H9qs/y3RnOaw5v."),
    ("toolongsaltstring", 5000, "This is just a test",
     "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/"
     "e1JSbq3y6JMxxl8audkUEm0"),
]


@pytest.mark.parametrize("salt, rounds, password, want", SPEC)
def test_specification_vectors(salt, rounds, password, want):
    assert sha512_crypt(password, salt, rounds) == want
    assert verify(password, want)


def test_matches_openssl_passwd_6():
    # openssl passwd -6 -salt abcdefgh12345678 'pässwörd $x'  (OpenSSL 3, Debian trixie)
    assert sha512_crypt("pässwörd $x", "abcdefgh12345678") == (
        "$6$abcdefgh12345678$f09JUzli4aAC3/JLP1yWVXQYWWWJ7UED7idNMmnuiUK.DCYoztGohS/8y7RMmh3tecM1FjBCqR1ZaIrHRjtTd1")


def test_random_salt_and_verify():
    a, b = sha512_crypt("secret"), sha512_crypt("secret")
    assert a != b                                        # a fresh salt every time
    for h in (a, b):
        salt = h.split("$")[2]
        assert h.startswith("$6$") and len(salt) == 16 and set(salt) <= set(ITOA64)
        assert len(h.split("$")[3]) == 86
        assert verify("secret", h) and not verify("Secret", h) and not verify("", h)


def test_rounds_are_clamped_and_written():
    assert sha512_crypt("x", "s", 10).startswith("$6$rounds=1000$s$")
    assert sha512_crypt("x", "s", 5000).startswith("$6$rounds=5000$s$")
    assert sha512_crypt("x", "s").startswith("$6$s$")
    assert sha512_crypt("x", "s", 5000).split("$")[-1] == sha512_crypt("x", "s").split("$")[-1]


def test_empty_and_long_passwords():
    for pw in ("", "a" * 200, "пароль"):
        assert verify(pw, sha512_crypt(pw, "salt"))


@pytest.mark.parametrize("value, ok", [
    ("$6$salt$" + "a" * 86, True),
    ("$y$j9T$abc$def", True),
    ("$5$rounds=6000$x$y", True),
    ("$1$abc$def", True),
    ("", False),
    ("plain", False),
    ("$6$a b$c", False),
    ("$6$a:b$c", False),
    ("$6$abc$def\n", False),
    ("6$abc$def", False),
])
def test_is_crypt_hash(value, ok):
    assert is_crypt_hash(value) is ok


def test_verify_rejects_other_schemes_and_junk():
    assert not verify("x", "$y$j9T$abc$def")
    assert not verify("x", "garbage")
    assert not verify("x", "")
