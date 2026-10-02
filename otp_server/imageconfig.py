"""The rpi-image-gen config of the station image, written from the ``image.*`` settings.

Two kinds of output (:func:`render`):

* the config YAML: layers and plain values (hostname, user name, time zone, Wi-Fi country, ...);
* files for everything secret -- ``secrets/user1.passhash``, ``secrets/iwd/<network>.psk|.open`` and
  ``secrets/authorized_keys`` -- which the config only points at. rpi-image-gen runs every config value
  through ``os.path.expandvars`` and its layers through the shell, so a crypt hash (``$6$...``) or a
  passphrase with ``$`` in it must never be a value.

The station layers live in ``image/layer``: ``otp-minbase`` (rpi-image-gen's trixie-minbase without
openssh-server, with the user account) and ``otp-image`` (applies the secret files). The upstream
``openssh-server`` layer is added only when SSH is switched on. The provisioning map
(``IGconf_image_pmap``, clear or crypt) is not part of the config: it is an override per image variant.

The value checks (``check_*``) are shared with :mod:`otp_server.config`, which validates the settings.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from . import image_choices
from .passhash import is_crypt_hash

CONFIG_NAME = "otp-image.yaml"
SECRETS_DIR = "secrets"
#: Partition sizes of the image (rpi-image-gen image-rpios layer, as the earlier droneos config set them).
BOOT_PART_SIZE = "200%"
ROOT_PART_SIZE = "300%"

_IMAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
              "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
_KEY_RE = re.compile(r"(?:^|\s)(?:" + "|".join(re.escape(t) for t in _KEY_TYPES) + r") [A-Za-z0-9+/]{16,}={0,3}(?:\s|$)")
#: Users rpi-image-gen or Debian already own: user1 must be a new account.
RESERVED_USERS = frozenset({"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
                            "proxy", "www-data", "backup", "list", "irc", "_apt", "nobody", "systemd-network",
                            "systemd-timesync", "messagebus", "sshd", "polkitd"})


# ------------------------------------------------------------------ checks (raise ValueError)
def check_image_name(v: str) -> str:
    if not _IMAGE_NAME_RE.fullmatch(v):
        raise ValueError(f"image name {v!r}: letters, digits, '.', '_' and '-' only (up to 64)")
    return v


def check_hostname(v: str) -> str:
    v = v.strip().lower()
    if not _HOSTNAME_RE.fullmatch(v):
        raise ValueError(f"hostname {v!r}: lower-case letters, digits and '-' (not at either end), up to 63")
    return v


def check_user(v: str) -> str:
    v = v.strip()
    if not _USER_RE.fullmatch(v):
        raise ValueError(f"user name {v!r}: starts with a lower-case letter or '_', then lower-case letters, "
                         "digits, '_' or '-' (up to 32)")
    if v in RESERVED_USERS:
        raise ValueError(f"user name {v!r} is a system account; pick another")
    return v


def check_timezone(v: str) -> str:
    v = v.strip()
    if not image_choices.is_timezone(v):
        raise ValueError(f"time zone {v!r} is not in the image's tzdata: pick one from the list (Europe/Kyiv, UTC, ...)")
    return v


def check_password_hash(v: str) -> str:
    v = v.strip()
    if v and not is_crypt_hash(v):
        raise ValueError("the password hash must be a crypt(3) hash such as $6$... (set the password on the page, "
                         "or paste the output of: openssl passwd -6)")
    return v


def check_ssid(v: str) -> str:
    if v != v.strip():
        raise ValueError("Wi-Fi network name: no spaces at either end")
    if len(v.encode("utf-8")) > 32:
        raise ValueError(f"Wi-Fi network name {v!r} is longer than 32 bytes")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in v):
        raise ValueError("Wi-Fi network name: control characters are not allowed")
    return v


def check_wifi_password(v: str) -> str:
    """Empty (open network), an 8..63 character passphrase (printable ASCII) or a 64-digit hex PSK."""
    if not v:
        return v
    if _HEX64_RE.fullmatch(v):
        return v.lower()
    if not 8 <= len(v) <= 63:
        raise ValueError("Wi-Fi password: 8 to 63 characters (or a 64-digit hex key; empty = open network)")
    if any(not 0x20 <= ord(ch) <= 0x7E for ch in v):
        raise ValueError("Wi-Fi password: printable ASCII characters only (WPA passphrase)")
    return v


def check_country(v: str) -> str:
    v = v.strip().upper()
    if not image_choices.is_country(v):
        raise ValueError(f"Wi-Fi country {v!r} is not in wireless-regdb: pick one from the list (UA, PL, ...; 00 = world)")
    return v


def check_authorized_key(line: str) -> str:
    line = line.strip()
    if not _KEY_RE.search(line):
        raise ValueError(f"not an OpenSSH public key line: {line[:40]!r}... (expected 'ssh-ed25519 AAAA... comment')")
    return line


# ------------------------------------------------------------------ Wi-Fi (iwd)
def iwd_file_name(ssid: str, kind: str) -> str:
    """iwd's file name for a network (iwd.network(5), NAMING): the SSID verbatim when it holds only ASCII
    letters, digits, spaces, '_' and '-', else '=' and its lower-case hex; then ``.psk`` / ``.open``."""
    if ssid and all((ch.isascii() and ch.isalnum()) or ch in " _-" for ch in ssid):
        stem = ssid
    else:
        stem = "=" + ssid.encode("utf-8").hex()
    return f"{stem}.{kind}"


def iwd_escape(value: str) -> str:
    """A value for an iwd settings file: backslash escaped, every space as ``\\s`` (iwd.network(5))."""
    return (value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")
            .replace(" ", "\\s"))


def wpa_psk(passphrase: str, ssid: str) -> str:
    """WPA2 pre-shared key: PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 rounds, 32 bytes), hex."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32).hex()


def iwd_profile(ssid: str, password: str, hidden: bool) -> tuple[str, bytes]:
    """``(file name, content)`` of the iwd profile of one network.

    A passphrase is written both as ``Passphrase`` (WPA3/SAE needs it) and as the derived
    ``PreSharedKey`` (WPA2 then does not depend on how the passphrase is escaped); a 64-digit hex key is
    a ``PreSharedKey`` only; no password is an open network.
    """
    lines: list[str] = []
    if password:
        lines.append("[Security]")
        if _HEX64_RE.fullmatch(password):
            lines.append(f"PreSharedKey={password.lower()}")
        else:
            lines.append(f"Passphrase={iwd_escape(password)}")
            lines.append(f"PreSharedKey={wpa_psk(password, ssid)}")
    if hidden:
        if lines:
            lines.append("")
        lines += ["[Settings]", "Hidden=true"]
    text = "\n".join(lines) + ("\n" if lines else "")
    return iwd_file_name(ssid, "psk" if password else "open"), text.encode("utf-8")


# ------------------------------------------------------------------ rendering
@dataclass
class RenderedConfig:
    """The config text, the secret files (path relative to the config dir -> bytes) and a public summary."""

    text: str
    files: dict[str, bytes] = field(default_factory=dict)
    summary: dict = field(default_factory=dict)

    def digest(self) -> str:
        """sha256 over the config and every file (names and contents): changes whenever the image would."""
        h = hashlib.sha256(self.text.encode("utf-8"))
        for name in sorted(self.files):
            h.update(b"\0" + name.encode("utf-8") + b"\0" + self.files[name])
        return h.hexdigest()


def sudo_mode(img: Any) -> str:
    """``passwd`` with a password; ``nopasswd`` for a key-only account (SSH keys, no password); else ``none``."""
    if img.password_hash:
        return "passwd"
    if img.ssh and img.ssh_authorized_keys:
        return "nopasswd"
    return "none"


def public_view(img: Any) -> dict:
    """The settings without secrets (status, manifests, logs)."""
    return {
        "name": img.name,
        "hostname": img.hostname,
        "timezone": img.timezone,
        "user": img.user,
        "password_set": bool(img.password_hash),
        "sudo": sudo_mode(img),
        "ssh": bool(img.ssh),
        "ssh_password_login": bool(img.ssh_password_login),
        "ssh_authorized_keys": len(img.ssh_authorized_keys),
        "wifi_ssid": img.wifi_ssid,
        "wifi_password_set": bool(img.wifi_password),
        "wifi_country": img.wifi_country,
        "wifi_hidden": bool(img.wifi_hidden),
    }


def warnings(img: Any) -> list[str]:
    """What the operator should know about these settings (nothing here stops a build)."""
    out: list[str] = []
    keys = bool(img.ssh and img.ssh_authorized_keys)
    if not img.password_hash and not keys:
        out.append(f"no password and no SSH key: nobody can log in as {img.user} (console or SSH)")
    if img.ssh and not img.ssh_password_login and not img.ssh_authorized_keys:
        out.append("SSH is on but password login is off and there is no key: SSH lets nobody in")
    if img.ssh and img.ssh_password_login and not img.password_hash and img.ssh_authorized_keys:
        out.append("SSH password login is on but no password is set: only the keys work")
    if img.wifi_ssid and not img.wifi_password:
        out.append(f"Wi-Fi {img.wifi_ssid!r} has no password: the board joins it as an open network")
    if img.wifi_ssid and img.wifi_country == "00":
        out.append("Wi-Fi country 00 (world) limits channels and power; set the country the boards fly in")
    return out


def _q(value: str) -> str:
    """A YAML double-quoted scalar of an already validated plain value (no quotes, backslashes, controls)."""
    if any(ch in value for ch in '"\\') or any(ord(ch) < 0x20 for ch in value):
        raise ValueError(f"unexpected character in config value {value!r}")
    return f'"{value}"'


def render(img: Any, *, mount: str = "/cfg") -> RenderedConfig:
    """The rpi-image-gen config of ``img`` (a :class:`otp_server.config.ImageCfg`) for a container that sees
    the config dir at ``mount``."""
    secrets_dir = f"{mount}/{SECRETS_DIR}"
    files: dict[str, bytes] = {}
    if img.password_hash:
        files[f"{SECRETS_DIR}/user1.passhash"] = (img.password_hash + "\n").encode("utf-8")
    if img.wifi_ssid:
        name, content = iwd_profile(img.wifi_ssid, img.wifi_password, img.wifi_hidden)
        files[f"{SECRETS_DIR}/iwd/{name}"] = content
    keys = list(img.ssh_authorized_keys) if img.ssh else []
    if keys:
        files[f"{SECRETS_DIR}/authorized_keys"] = ("\n".join(keys) + "\n").encode("utf-8")

    lines = [
        "# rpi-image-gen config written by OTP_Provisioner from the station settings (image.*).",
        "# Secrets are files in secrets/ next to this config, never values: rpi-image-gen expands $ in values.",
        "device:",
        "  layer: rpi5",
        f"  hostname: {_q(img.hostname)}",
        f"  user1: {_q(img.user)}",
        f"  user1sudo: {_q(sudo_mode(img))}",
        "",
        "image:",
        "  layer: image-rpios",
        f"  boot_part_size: {_q(BOOT_PART_SIZE)}",
        f"  root_part_size: {_q(ROOT_PART_SIZE)}",
        f"  name: {_q(img.name)}",
        "",
        "layer:",
        "  base: otp-minbase",
        "  station: otp-image",
    ]
    if img.ssh:
        lines.append("  ssh: openssh-server")
    lines += [
        "",
        "locale:",
        f"  timezone: {_q(img.timezone)}",
        "",
        "ieee80211:",
        f"  regdom: {_q(img.wifi_country)}",
    ]
    if any(k.startswith(f"{SECRETS_DIR}/user1") or k.startswith(f"{SECRETS_DIR}/iwd/") for k in files):
        lines += ["", "otp:", f"  secrets: {_q(secrets_dir)}"]
    if img.ssh:
        lines += ["", "ssh:"]
        if keys:
            lines.append(f"  pubkey_user1: {_q(secrets_dir + '/authorized_keys')}")
        lines.append(f"  pubkey_only: {_q('n' if img.ssh_password_login else 'y')}")
    text = "\n".join(lines) + "\n"
    return RenderedConfig(text=text, files=files, summary=public_view(img))
