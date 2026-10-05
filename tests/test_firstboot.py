"""A board's first-boot files (otp_server.firstboot): Raspberry Pi Imager's cloud-init files for Raspberry Pi OS."""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from otp_server import firstboot as fb
from otp_server.config import load_config
from otp_server.passhash import sha512_crypt

SERIAL = "a7eb274c"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD op@station"
PW = sha512_crypt("pw", "salt")


def image(**kw):
    return replace(load_config().image, **kw)


def user_data(**kw) -> str:
    return fb.render(image(**kw), SERIAL).files[fb.USER_DATA].decode("utf-8")


def yaml_doc(data: bytes):
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(data.decode("utf-8"))


def test_defaults_leave_the_account_to_the_wizard():
    seed = fb.render(image(), SERIAL)
    assert sorted(seed.files) == ["meta-data", "user-data"]          # no Wi-Fi network: no network-config
    ud = seed.files["user-data"].decode()
    assert ud.startswith("#cloud-config\nmanage_resolv_conf: false\n\n")
    assert f'hostname: "pi5-{SERIAL}"\nmanage_etc_hosts: true\n' in ud
    assert 'timezone: "Europe/Kyiv"\nkeyboard:\n  model: pc105\n  layout: "us"\n' in ud
    assert "\nuser:" not in ud and "ssh_pwauth" not in ud and "systemctl, enable" not in ud
    assert ud.endswith('runcmd:\n  - [ rfkill, unblock, wifi ]\n'
                       '  - [ sh, -c, "for f in /var/lib/systemd/rfkill/*:wlan; do echo 0 > \\"$f\\"; done" ]\n'
                       '  - [ raspi-config, nonint, do_wifi_country, "UA" ]\n')
    assert seed.summary["account"] == "first-boot wizard" and seed.summary["user"] == ""
    assert seed.summary["sudo"] == "wizard"


def test_user_data_parses_as_cloud_config():
    doc = yaml_doc(fb.render(image(password_hash=PW, ssh=True, ssh_authorized_keys=[KEY]), SERIAL).files["user-data"])
    assert doc["hostname"] == f"pi5-{SERIAL}" and doc["manage_etc_hosts"] is True and doc["timezone"] == "Europe/Kyiv"
    assert doc["keyboard"] == {"model": "pc105", "layout": "us"}
    assert doc["user"] == {"name": "pi", "shell": "/bin/bash", "lock_passwd": False, "passwd": PW,
                           "ssh_authorized_keys": [KEY], "sudo": None}
    assert doc["ssh_pwauth"] is True and doc["manage_resolv_conf"] is False
    assert doc["runcmd"][0] == ["systemctl", "enable", "--now", "ssh"]
    assert doc["runcmd"][-1] == ["raspi-config", "nonint", "do_wifi_country", "UA"]


def test_key_only_account_gets_passwordless_sudo():
    doc = yaml_doc(fb.render(image(user="op", ssh=True, ssh_password_login=False, ssh_authorized_keys=[KEY]),
                             SERIAL).files["user-data"])
    assert doc["user"]["lock_passwd"] is True and "passwd" not in doc["user"]
    assert doc["user"]["sudo"] == "ALL=(ALL) NOPASSWD:ALL" and doc["ssh_pwauth"] is False
    assert ["sh", "-c", "echo 'op ALL=(ALL) NOPASSWD:ALL' >'/etc/sudoers.d/010_op-nopasswd'"] in doc["runcmd"]
    assert ["sh", "-c", "chmod 0440 '/etc/sudoers.d/010_op-nopasswd'"] in doc["runcmd"]


def test_keys_without_ssh_do_not_make_an_account():
    ud = user_data(ssh=False, ssh_authorized_keys=[KEY])
    assert "\nuser:" not in ud and KEY not in ud


def test_password_only_account_without_ssh():
    doc = yaml_doc(fb.render(image(password_hash=PW), SERIAL).files["user-data"])
    assert doc["user"]["passwd"] == PW and doc["user"]["sudo"] is None and "ssh_authorized_keys" not in doc["user"]
    assert "ssh_pwauth" not in doc and ["systemctl", "enable", "--now", "ssh"] not in doc["runcmd"]


def test_world_country_switches_the_radio_on_without_raspi_config():
    seed = fb.render(image(wifi_country="00", wifi_ssid="N", wifi_password="password1"), SERIAL)
    doc = yaml_doc(seed.files["user-data"])
    assert doc["runcmd"][-1] == ["nmcli", "radio", "wifi", "on"]
    assert "regulatory-domain" not in seed.files["network-config"].decode()
    assert not seed.cmdline.startswith("cfg80211")          # Imager drops what is not two letters


# ------------------------------------------------------------------ network-config
def test_network_config_is_imagers_netplan_with_a_pmk():
    seed = fb.render(image(wifi_ssid="Field Net", wifi_password="p$ss \\w0rd", wifi_country="PL", wifi_hidden=True),
                     SERIAL)
    nc = seed.files["network-config"].decode()
    pmk = hashlib.pbkdf2_hmac("sha1", b"p$ss \\w0rd", b"Field Net", 4096, 32).hex()
    assert nc == ("network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n      dhcp6: true\n"
                  "      optional: true\n  wifis:\n    wlan0:\n      dhcp4: true\n      regulatory-domain: \"PL\"\n"
                  "      access-points:\n        \"Field Net\":\n          hidden: true\n"
                  f"          password: \"{pmk}\"\n      optional: true\n")
    doc = yaml_doc(seed.files["network-config"])
    assert doc["network"]["wifis"]["wlan0"]["access-points"] == {"Field Net": {"hidden": True, "password": pmk}}


def test_network_config_of_an_open_network_and_a_hex_key():
    open_nc = yaml_doc(fb.render(image(wifi_ssid="Open"), SERIAL).files["network-config"])
    assert open_nc["network"]["wifis"]["wlan0"]["access-points"] == {"Open": {"auth": {"key-management": "none"}}}
    hexkey = "ab" * 32
    nc = yaml_doc(fb.render(image(wifi_ssid="N", wifi_password=hexkey), SERIAL).files["network-config"])
    assert nc["network"]["wifis"]["wlan0"]["access-points"]["N"]["password"] == hexkey   # a raw key stays as it is


def test_wifi_psk_matches_wpa_passphrase():
    # wpa_passphrase "IEEE" "password" (IEEE 802.11i-2004 test vector)
    assert fb.wifi_psk("IEEE", "password") == "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    assert fb.wifi_psk("x", "AB" * 32) == "ab" * 32


@pytest.mark.parametrize("value, want", [
    ('a"b\\c', '"a\\"b\\\\c"'),
    ("Café", '"Café"'),
    ("x\u0085y ", '"x\\x85y\\u2028"'),
    ("tab\there", '"tab\\there"'),
])
def test_yaml_str_escapes_like_imager(value, want):
    assert fb.yaml_str(value) == want


def test_awkward_ssid_survives_yaml():
    ssid = 'Café "5G" \\ #1: {x}'
    doc = yaml_doc(fb.render(image(wifi_ssid=ssid, wifi_password="password1"), SERIAL).files["network-config"])
    assert list(doc["network"]["wifis"]["wlan0"]["access-points"]) == [ssid]


# ------------------------------------------------------------------ meta-data, cmdline, identity
def test_meta_data_and_cmdline():
    seed = fb.render(image(wifi_country="pl"), SERIAL)
    assert seed.instance_id.startswith(f"otp-{SERIAL}-") and len(seed.instance_id) == len(f"otp-{SERIAL}-") + 12
    assert seed.files["meta-data"] == f"instance-id: {seed.instance_id}\n".encode()
    assert seed.cmdline == f"cfg80211.ieee80211_regdom=PL ds=nocloud;i={seed.instance_id}"


def test_seed_is_deterministic_and_follows_every_setting():
    a = fb.render(image(), SERIAL)
    assert fb.render(image(), SERIAL) == a
    others = [fb.render(image(), "0000beef"), fb.render(image(wifi_ssid="N", wifi_password="password1"), SERIAL),
              fb.render(image(wifi_ssid="N", wifi_password="password2"), SERIAL),
              fb.render(image(password_hash=PW), SERIAL), fb.render(image(timezone="UTC"), SERIAL),
              fb.render(image(keyboard="ua"), SERIAL),
              fb.render(image(hostname="other"), SERIAL)]
    digests = {a.digest()} | {o.digest() for o in others}
    assert len(digests) == 1 + len(others)
    assert len({o.instance_id for o in others} | {a.instance_id}) == 1 + len(others)


def test_hostname_template():
    assert fb.hostname_for("pi5-{serial}", "A7EB274C") == "pi5-a7eb274c"
    assert fb.hostname_for("drone", SERIAL) == "drone"
    assert fb.render(image(hostname="x-{serial}-y"), SERIAL).summary["hostname"] == f"x-{SERIAL}-y"


def test_summary_has_no_secrets():
    seed = fb.render(image(password_hash=PW, wifi_ssid="N", wifi_password="password1", ssh=True,
                           ssh_authorized_keys=[KEY]), SERIAL)
    text = repr(seed.summary)
    assert PW not in text and "password1" not in text and KEY not in text
    assert seed.summary["user"] == "pi" and seed.summary["sudo"] == "passwd" and seed.summary["ssh"] is True
