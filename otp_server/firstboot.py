"""A board's first-boot settings: the cloud-init NoCloud seed stage 3 writes to its boot partition.

The station image is Raspberry Pi OS Lite (``image/layer/otp-rpios-*``). Like the official image it is the
same for every board, with the first user locked, SSH off and Wi-Fi off; cloud-init sets the board up at
its first boot from ``user-data``, ``network-config`` and ``meta-data`` in the boot partition
(``/boot/firmware``). Stage 3 writes those files for each board from the ``image.*`` settings, the way
Raspberry Pi Imager customises Raspberry Pi OS (its ``cloudinit-rpi`` format), and adds Imager's kernel
parameters to ``cmdline.txt``: ``cfg80211.ieee80211_regdom=<country>`` and ``ds=nocloud;i=<instance>``. So
the settings apply to every board flashed after they are saved, with no image rebuild.

Differences from Imager, all on purpose:

* no ``packages: [avahi-daemon]`` / apt settings: avahi is in the image, and a first boot without a
  network must not wait for apt;
* the keyboard layout is always written (Imager writes it when a locale is set): Raspberry Pi OS defaults
  to the British layout, where a password typed on a US keyboard at the console comes out different
  (Shift+2 is ``"``, Shift+' is ``@``, Shift+3 is ``£``);
* the Wi-Fi radio is switched on by ``raspi-config nonint do_wifi_country`` at the end of the first boot.
  The image keeps Wi-Fi off until a country is set (``WirelessEnabled=false``, as pi-gen leaves it), and
  nothing in Imager's cloud-init files undoes that when a network is configured;
* sudo: with a password the account asks for it (``sudo: null``, the ``sudo`` group); a key-only account
  (no password) gets passwordless sudo, otherwise it could not use sudo at all;
* no account at all (no password and no SSH key): no ``user:`` section, so Raspberry Pi OS's first-boot
  wizard asks for a user name and password on the console, as on an image nobody customised;
* the instance id is derived from the board serial and the files, not from the clock: flashing the same
  board twice with the same settings writes the same bytes.

Secrets in the files: the account's crypt hash and the Wi-Fi key as a PMK (PBKDF2 of the passphrase and
the network name, as Imager writes it). They stay on the boot partition, which is a plain FAT file system
on every board, the secure ones included (their root file system is encrypted, the boot partition is not).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

#: The files, in the root of the boot partition.
USER_DATA = "user-data"
NETWORK_CONFIG = "network-config"
META_DATA = "meta-data"
SERIAL_PLACEHOLDER = "{serial}"

_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}")
_COUNTRY_RE = re.compile(r"[A-Z]{2}")


@dataclass(frozen=True)
class Seed:
    """The first-boot files of one board (name in the boot partition -> bytes), the parameters appended to
    ``cmdline.txt`` (space-separated, no leading space) and what was set, without secrets."""

    files: dict[str, bytes]
    cmdline: str
    instance_id: str
    summary: dict = field(default_factory=dict)

    def digest(self) -> str:
        """sha256 over every file (name and bytes) and the cmdline additions."""
        h = hashlib.sha256(b"cmdline\0" + self.cmdline.encode("utf-8"))
        for name in sorted(self.files):
            h.update(b"\0" + name.encode("utf-8") + b"\0" + self.files[name])
        return h.hexdigest()


# ------------------------------------------------------------------ helpers
def hostname_for(template: str, serial: str) -> str:
    """The board's host name: ``template`` with ``{serial}`` replaced by the 8-hex board serial."""
    return template.replace(SERIAL_PLACEHOLDER, serial.lower())


def wifi_psk(ssid: str, password: str) -> str:
    """The WPA key as 64 hex digits: a 64-digit hex key as it is, else PBKDF2-HMAC-SHA1(passphrase, SSID,
    4096, 32) -- the PMK Imager writes instead of the passphrase."""
    if _HEX64_RE.fullmatch(password):
        return password.lower()
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), ssid.encode("utf-8"), 4096, 32).hex()


def yaml_str(value: str) -> str:
    """A YAML double-quoted scalar (Imager's escaping: UTF-8 as it is, ``\\`` and ``"`` escaped, control
    characters, C1 controls, line separators and non-characters as ``\\x``/``\\u`` escapes)."""
    out = []
    for ch in value:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp < 0xA0:
            out.append(f"\\x{cp:02x}")
        elif cp in (0x2028, 0x2029, 0xFEFF, 0xFFFE, 0xFFFF):
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def shell_quote(value: str) -> str:
    """``value`` as one POSIX shell word (single quotes)."""
    return "'" + value.replace("'", "'\\''") + "'"


def _country(img: Any) -> str:
    """The Wi-Fi country when it is an ISO 3166 code (two letters); "" for ``00`` (world)."""
    c = str(img.wifi_country or "").upper()
    return c if _COUNTRY_RE.fullmatch(c) else ""


def has_account(img: Any) -> bool:
    """Whether the files set up the first user (a password, or SSH on with keys)."""
    return bool(img.password_hash) or bool(img.ssh and img.ssh_authorized_keys)


def sudo_mode(img: Any) -> str:
    """``passwd`` with a password; ``nopasswd`` for a key-only account; ``wizard`` when the first-boot
    wizard creates the account (it is in the ``sudo`` group and asks for its password)."""
    if img.password_hash:
        return "passwd"
    if img.ssh and img.ssh_authorized_keys:
        return "nopasswd"
    return "wizard"


# ------------------------------------------------------------------ the files
def user_data(img: Any, hostname: str) -> bytes:
    """``user-data``: Imager's cloudinit-rpi document for these settings (see the module doc)."""
    lines = ["#cloud-config", "manage_resolv_conf: false", "",
             f"hostname: {yaml_str(hostname)}", "manage_etc_hosts: true", "",
             f"timezone: {yaml_str(img.timezone)}",
             "keyboard:", "  model: pc105", f"  layout: {yaml_str(img.keyboard)}"]
    keys = list(img.ssh_authorized_keys) if img.ssh else []
    mode = sudo_mode(img)
    if has_account(img):
        lines += ["", "user:", f"  name: {yaml_str(img.user)}", "  shell: /bin/bash"]
        if img.password_hash:
            lines += ["  lock_passwd: false", f"  passwd: {yaml_str(img.password_hash)}"]
        else:
            lines.append("  lock_passwd: true")
        if keys:
            lines.append("  ssh_authorized_keys:")
            lines += [f"    - {yaml_str(k)}" for k in keys]
        # cloud.cfg's default user has NOPASSWD sudo; null keeps its groups (sudo among them) without it.
        lines.append("  sudo: ALL=(ALL) NOPASSWD:ALL" if mode == "nopasswd" else "  sudo: null")
    if img.ssh:
        if img.ssh_password_login:
            lines += ["", "ssh_pwauth: true"]
        elif keys:
            lines += ["", "ssh_pwauth: false"]

    def sh(command: str) -> str:
        return f"  - [ sh, -c, {yaml_str(command)} ]"

    run: list[str] = []
    if img.ssh:
        run.append("  - [ systemctl, enable, --now, ssh ]")
    if has_account(img) and mode == "nopasswd":
        sudoers = f"/etc/sudoers.d/010_{img.user}-nopasswd"
        run.append(sh(f"echo {shell_quote(img.user + ' ALL=(ALL) NOPASSWD:ALL')} >{shell_quote(sudoers)}"))
        run.append(sh(f"chmod 0440 {shell_quote(sudoers)}"))
    run.append("  - [ rfkill, unblock, wifi ]")
    run.append(sh('for f in /var/lib/systemd/rfkill/*:wlan; do echo 0 > "$f"; done'))
    country = _country(img)
    if country:
        run.append(f"  - [ raspi-config, nonint, do_wifi_country, {yaml_str(country)} ]")
    else:
        run.append('  - [ nmcli, radio, wifi, "on" ]')       # bare on is true in YAML 1.1
    lines += ["", "runcmd:", *run]
    return ("\n".join(lines) + "\n").encode("utf-8")


def network_config(img: Any) -> bytes | None:
    """``network-config`` (netplan v2, Imager's layout) for the Wi-Fi network; None without one."""
    if not img.wifi_ssid:
        return None
    lines = ["network:", "  version: 2", "  ethernets:", "    eth0:", "      dhcp4: true", "      dhcp6: true",
             "      optional: true", "  wifis:", "    wlan0:", "      dhcp4: true"]
    country = _country(img)
    if country:
        lines.append(f"      regulatory-domain: {yaml_str(country)}")
    lines += ["      access-points:", f"        {yaml_str(img.wifi_ssid)}:"]
    if img.wifi_hidden:
        lines.append("          hidden: true")
    if img.wifi_password:
        lines.append(f"          password: {yaml_str(wifi_psk(img.wifi_ssid, img.wifi_password))}")
    else:
        lines += ["          auth:", "            key-management: none"]
    lines.append("      optional: true")
    return ("\n".join(lines) + "\n").encode("utf-8")


def render(img: Any, serial: str) -> Seed:
    """The first-boot files of board ``serial`` for the settings ``img`` (:class:`otp_server.config.ImageCfg`)."""
    hostname = hostname_for(img.hostname, serial)
    files = {USER_DATA: user_data(img, hostname)}
    net = network_config(img)
    if net is not None:
        files[NETWORK_CONFIG] = net
    h = hashlib.sha256(serial.encode("utf-8"))
    for name in sorted(files):
        h.update(b"\0" + name.encode("utf-8") + b"\0" + files[name])
    instance_id = f"otp-{serial.lower()}-{h.hexdigest()[:12]}"
    files[META_DATA] = f"instance-id: {instance_id}\n".encode("utf-8")
    cmdline = []
    country = _country(img)
    if country:
        cmdline.append(f"cfg80211.ieee80211_regdom={country}")
    cmdline.append(f"ds=nocloud;i={instance_id}")
    summary = {
        "hostname": hostname,
        "user": img.user if has_account(img) else "",
        "account": "cloud-init" if has_account(img) else "first-boot wizard",
        "sudo": sudo_mode(img),
        "ssh": bool(img.ssh),
        "wifi_ssid": img.wifi_ssid,
        "wifi_country": img.wifi_country,
        "timezone": img.timezone,
        "keyboard": img.keyboard,
        "instance_id": instance_id,
        "files": sorted(files),
    }
    return Seed(files=files, cmdline=" ".join(cmdline), instance_id=instance_id, summary=summary)
