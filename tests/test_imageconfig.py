"""The rpi-image-gen config of the station image (otp_server.imageconfig) and the station layers."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from otp_server import imageconfig as ic
from otp_server.config import REPO_ROOT, load_config
from otp_server.passhash import sha512_crypt

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD op@station"


def image(**kw):
    return replace(load_config().image, **kw)


def test_example_yaml_is_the_default_render():
    """image/example.yaml (build.sh's default config) is exactly what the station writes for the defaults."""
    text = (REPO_ROOT / "image" / "example.yaml").read_bytes().decode("utf-8")
    assert text == ic.render(load_config().image).text


def test_default_render():
    r = ic.render(image())
    assert r.files == {}
    assert "  layer: rpi5\n" in r.text and "  layer: image-rpios\n" in r.text
    assert "  base: otp-minbase\n  station: otp-image\n" in r.text
    assert "openssh-server" not in r.text and "otp:" not in r.text and "\nssh:" not in r.text
    assert '  user1sudo: "none"' in r.text and '  regdom: "UA"' in r.text and '  timezone: "Europe/Kyiv"' in r.text
    assert r.summary == ic.public_view(image())


def test_render_with_everything():
    pw = sha512_crypt("pw", "salt")
    r = ic.render(image(hostname="drone7", password_hash=pw, ssh=True, ssh_password_login=False,
                        ssh_authorized_keys=[KEY], wifi_ssid="Field Net", wifi_password="p$ss word",
                        wifi_country="PL", wifi_hidden=True), mount="/x")
    assert set(r.files) == {"secrets/user1.passhash", "secrets/iwd/Field Net.psk", "secrets/authorized_keys"}
    assert r.files["secrets/user1.passhash"] == (pw + "\n").encode()
    assert r.files["secrets/authorized_keys"] == (KEY + "\n").encode()
    assert '  secrets: "/x/secrets"' in r.text and '  pubkey_user1: "/x/secrets/authorized_keys"' in r.text
    assert "  ssh: openssh-server" in r.text and '  pubkey_only: "y"' in r.text
    assert '  user1sudo: "passwd"' in r.text
    for secret in (pw, "p$ss", KEY.split()[1]):
        assert secret not in r.text                       # secrets are files, never config values


def test_render_is_valid_yaml_with_the_expected_variables():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(ic.render(image(ssh=True, ssh_authorized_keys=[KEY], wifi_ssid="N",
                                         password_hash="$6$a$b", wifi_country="00")).text)
    assert doc["device"] == {"layer": "rpi5", "hostname": "pi5", "user1": "pi", "user1sudo": "passwd"}
    assert doc["layer"] == {"base": "otp-minbase", "station": "otp-image", "ssh": "openssh-server"}
    assert doc["ieee80211"] == {"regdom": "00"}                     # quoted: not the number 0
    assert doc["ssh"] == {"pubkey_user1": "/cfg/secrets/authorized_keys", "pubkey_only": "n"}
    assert doc["image"]["boot_part_size"] == "200%" and doc["image"]["name"] == "deb13-arm64-min"


def test_digest_follows_every_secret():
    base = ic.render(image(wifi_ssid="N", wifi_password="password1")).digest()
    assert ic.render(image(wifi_ssid="N", wifi_password="password1")).digest() == base
    assert ic.render(image(wifi_ssid="N", wifi_password="password2")).digest() != base
    assert ic.render(image(wifi_ssid="N", wifi_password="password1", password_hash="$6$a$b")).digest() != base


@pytest.mark.parametrize("pw, keys, ssh, mode", [
    ("$6$a$b", [], False, "passwd"),
    ("$6$a$b", [KEY], True, "passwd"),
    ("", [KEY], True, "nopasswd"),          # a key-only account administers with sudo
    ("", [KEY], False, "none"),             # keys without SSH do not count
    ("", [], True, "none"),
])
def test_sudo_mode(pw, keys, ssh, mode):
    assert ic.sudo_mode(image(password_hash=pw, ssh_authorized_keys=keys, ssh=ssh)) == mode


def test_keys_are_ignored_without_ssh():
    r = ic.render(image(ssh=False, ssh_authorized_keys=[KEY]))
    assert "secrets/authorized_keys" not in r.files and "\nssh:" not in r.text


# ------------------------------------------------------------------ Wi-Fi
@pytest.mark.parametrize("ssid, name", [
    ("Field", "Field.psk"),
    ("Field Net_2-a", "Field Net_2-a.psk"),            # alnum, space, '_' and '-' stay verbatim
    ("Café", "=436166c3a9.psk"),                         # non-ASCII: '=' + lower-case hex of UTF-8
    ("a.b", "=612e62.psk"),
    ("x/y", "=782f79.psk"),
])
def test_iwd_file_names(ssid, name):
    assert ic.iwd_file_name(ssid, "psk") == name


def test_wpa_psk_ieee_vector():
    # IEEE 802.11i-2004, H.4.3 test vector
    assert ic.wpa_psk("password", "IEEE") == "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"


@pytest.mark.parametrize("value, escaped", [
    ("plain", "plain"),
    (" lead", "\\slead"),
    ("a b", "a\\sb"),
    ("back\\slash", "back\\\\slash"),
    ("tail ", "tail\\s"),
])
def test_iwd_escape(value, escaped):
    assert ic.iwd_escape(value) == escaped


def test_iwd_profiles():
    name, data = ic.iwd_profile("Field", "pass word", False)
    assert name == "Field.psk"
    assert data.decode() == f"[Security]\nPassphrase=pass\\sword\nPreSharedKey={ic.wpa_psk('pass word', 'Field')}\n"
    name, data = ic.iwd_profile("Field", "AB" * 32, True)
    assert data.decode() == "[Security]\nPreSharedKey=" + "ab" * 32 + "\n\n[Settings]\nHidden=true\n"
    assert ic.iwd_profile("Open", "", False) == ("Open.open", b"")
    assert ic.iwd_profile("Open", "", True) == ("Open.open", b"[Settings]\nHidden=true\n")


def test_no_wifi_profile_without_ssid():
    r = ic.render(image(wifi_ssid="", wifi_password="ignored-pass"))
    assert not [f for f in r.files if "/iwd/" in f] and "otp:" not in r.text


# ------------------------------------------------------------------ warnings / public view
def test_warnings():
    assert ic.warnings(image()) == ["no password and no SSH key: nobody can log in as pi (console or SSH)"]
    assert ic.warnings(image(password_hash="$6$a$b")) == []
    w = ic.warnings(image(ssh=True, ssh_password_login=False))
    assert any("SSH lets nobody in" in x for x in w)
    w = ic.warnings(image(ssh=True, ssh_authorized_keys=[KEY]))
    assert w == ["SSH password login is on but no password is set: only the keys work"]
    w = ic.warnings(image(password_hash="$6$a$b", wifi_ssid="Open"))
    assert w == ["Wi-Fi 'Open' has no password: the board joins it as an open network"]
    w = ic.warnings(image(password_hash="$6$a$b", wifi_ssid="N", wifi_password="password1", wifi_country="00"))
    assert len(w) == 1 and "country 00" in w[0]


def test_public_view_has_no_secrets():
    v = ic.public_view(image(password_hash="$6$a$b", wifi_password="password1", wifi_ssid="N",
                             ssh=True, ssh_authorized_keys=[KEY]))
    assert v["password_set"] is True and v["wifi_password_set"] is True and v["ssh_authorized_keys"] == 1
    text = repr(v)
    assert "$6$a$b" not in text and "password1" not in text and KEY not in text


# ------------------------------------------------------------------ the station layers
LAYERS = REPO_ROOT / "image" / "layer"
RIG_LAYERS = REPO_ROOT / "image" / "rpi-image-gen" / "layer"


def _meta(path: Path) -> dict:
    meta, key = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# X-Env-"):
            key, _, value = line[2:].partition(":")
            meta[key] = value.strip()
        elif line.startswith("#  ") and key:
            meta[key] += " " + line[3:].strip()
        elif line.startswith("---"):
            break
    return meta


def test_otp_minbase_is_trixie_minbase_without_ssh():
    upstream = RIG_LAYERS / "suite" / "debian" / "trixie-minbase.yaml"
    if not upstream.is_file():
        pytest.skip("image/rpi-image-gen is not checked out")
    req = lambda p: [x.strip() for x in _meta(p)["X-Env-Layer-Requires"].split(",") if x.strip()]  # noqa: E731
    ours, theirs = req(LAYERS / "otp-minbase.yaml"), req(upstream)
    assert set(theirs) - set(ours) == {"openssh-server"}
    assert set(ours) - set(theirs) == {"device-user-admin"}          # the account exists without SSH too
    assert _meta(LAYERS / "otp-minbase.yaml")["X-Env-Layer-Name"] == "otp-minbase"


def test_otp_image_layer_reads_the_secret_files():
    meta = _meta(LAYERS / "otp-image.yaml")
    assert meta["X-Env-Layer-Name"] == "otp-image" and meta["X-Env-VarPrefix"] == "otp"
    assert set(x.strip() for x in meta["X-Env-Layer-Requires"].split(",")) == {"device-user-admin", "iwd"}
    text = (LAYERS / "otp-image.yaml").read_text(encoding="utf-8")
    assert '"$d/user1.passhash"' in text and "chpasswd -e" in text
    assert '"$d"/iwd/*' in text and "/var/lib/iwd/" in text and "install -m 0600" in text
    # the names the renderer writes are the names the layer reads
    r = ic.render(image(password_hash="$6$a$b", wifi_ssid="N", wifi_password="password1"))
    assert {"secrets/user1.passhash", "secrets/iwd/N.psk"} <= set(r.files)
