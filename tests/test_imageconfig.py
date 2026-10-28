"""The rpi-image-gen config of the station image (otp_server.imageconfig) and the station layers."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from otp_server import imageconfig as ic
from otp_server.config import REPO_ROOT, load_config

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD op@station"


def image(**kw):
    return replace(load_config().image, **kw)


def test_example_yaml_is_the_default_render():
    """image/example.yaml (build.sh's default config) is exactly what the station writes for the defaults."""
    text = (REPO_ROOT / "image" / "example.yaml").read_bytes().decode("utf-8")
    assert text == ic.render(load_config().image).text


def test_render_is_raspberry_pi_os_lite():
    r = ic.render(image())
    assert r.files == {}
    assert "  layer: rpi5\n" in r.text and "  layer: image-rpios\n" in r.text
    assert "  base: otp-rpios-lite\n  station: otp-rpios-setup\n" in r.text
    assert r.summary == {"name": "rpios-trixie-arm64-lite", "base": "Raspberry Pi OS Lite"}


def test_render_ignores_the_board_settings():
    """Account, SSH, Wi-Fi, host name and time zone are written per board at stage 3, never into the image."""
    base = ic.render(image())
    other = ic.render(image(hostname="drone-{serial}", password_hash="$6$a$b", ssh=True, ssh_authorized_keys=[KEY],
                            wifi_ssid="Field", wifi_password="password1", wifi_country="PL", timezone="UTC",
                            user="op", keyboard="ua"))
    assert other.text == base.text and other.digest() == base.digest()
    assert ic.render(image(name="rpios-other")).digest() != base.digest()


def test_render_is_valid_yaml_with_the_expected_variables():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(ic.render(image()).text)
    assert doc["device"] == {"layer": "rpi5", "hostname": "raspberrypi", "user1": "pi", "user1sudo": "passwd",
                             "user1groups": ic.IMAGE_USER_GROUPS}
    assert "sudo" not in ic.IMAGE_USER_GROUPS.split(",")      # rpi-image-gen: user1sudo adds it, a listed one conflicts
    assert doc["layer"] == {"base": "otp-rpios-lite", "station": "otp-rpios-setup"}
    assert doc["image"] == {"layer": "image-rpios", "boot_part_size": "200%", "root_part_size": "300%",
                            "name": "rpios-trixie-arm64-lite"}
    assert set(doc) == {"device", "image", "layer"}           # locale: rpi-image-gen's defaults are pi-gen's


# ------------------------------------------------------------------ checks
@pytest.mark.parametrize("value, want", [
    ("pi5", "pi5"), (" Drone7 ", "drone7"), ("pi5-{serial}", "pi5-{serial}"), ("{serial}", "{serial}"),
    ("{SERIAL}-x", "{serial}-x"),
])
def test_check_hostname(value, want):
    assert ic.check_hostname(value) == want


@pytest.mark.parametrize("value", ["", "-pi", "pi-", "pi_5", "pi5-{serial", "pi5-{id}", "a" * 56 + "{serial}",
                                   "pi5-{serial}-"])
def test_check_hostname_rejects(value):
    with pytest.raises(ValueError):
        ic.check_hostname(value)


@pytest.mark.parametrize("name", ["root", "sudo", "gpio", "audio", "avahi", "netdev", "_ssh"])
def test_user_must_not_be_a_system_account_or_group(name):
    """userconf renames the first user and its group: neither may clash with Raspberry Pi OS's own."""
    with pytest.raises(ValueError, match="system account"):
        ic.check_user(name)


# ------------------------------------------------------------------ warnings / public view
def test_warnings():
    tpl = {"hostname": "pi5-{serial}"}
    assert ic.warnings(image(**tpl)) == [
        "no password and no SSH key: the board's first boot stops at the Raspberry Pi OS wizard on its console "
        "(screen and keyboard), which asks for a user name and password"]
    assert ic.warnings(image(password_hash="$6$a$b", **tpl)) == []
    w = ic.warnings(image(ssh=True, ssh_password_login=False, **tpl))
    assert any("SSH lets nobody in" in x for x in w)
    w = ic.warnings(image(ssh=True, ssh_authorized_keys=[KEY], **tpl))
    assert w == ["SSH password login is on but no password is set: only the keys work"]
    w = ic.warnings(image(password_hash="$6$a$b", wifi_ssid="Open", **tpl))
    assert w == ["Wi-Fi 'Open' has no password: the board joins it as an open network"]
    w = ic.warnings(image(password_hash="$6$a$b", wifi_country="00", **tpl))
    assert len(w) == 1 and "country 00" in w[0]
    w = ic.warnings(image(password_hash="$6$a$b", hostname="pi5"))
    assert w == ["every board gets the host name 'pi5'; put {serial} in it (e.g. pi5-{serial}) to tell them apart "
                 "on the network"]


def test_public_view_has_no_secrets():
    v = ic.public_view(image(password_hash="$6$a$b", wifi_password="password1", wifi_ssid="N",
                             ssh=True, ssh_authorized_keys=[KEY]))
    assert v["password_set"] is True and v["wifi_password_set"] is True and v["ssh_authorized_keys"] == 1
    assert v["sudo"] == "passwd" and v["keyboard"] == "us"
    text = repr(v)
    assert "$6$a$b" not in text and "password1" not in text and KEY not in text


# ------------------------------------------------------------------ the station layers
LAYERS = REPO_ROOT / "image" / "layer"
RIG = REPO_ROOT / "image" / "rpi-image-gen"


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


def _requires(path: Path) -> set[str]:
    return {x.strip() for x in _meta(path).get("X-Env-Layer-Requires", "").split(",") if x.strip()}


def _layer_names() -> set[str]:
    names = set()
    for base in (RIG / "layer", RIG / "device", RIG / "image", LAYERS):
        for f in base.rglob("*.yaml"):
            name = _meta(f).get("X-Env-Layer-Name")
            if name:
                names.add(name)
    return names


def test_station_layers_require_layers_that_exist():
    if not (RIG / "layer").is_dir():
        pytest.skip("image/rpi-image-gen is not checked out")
    names = _layer_names()
    for f in LAYERS.glob("*.yaml"):
        assert _requires(f) <= names, f.name
    assert {"otp-rpios-lite", "otp-rpios-setup", "otp-rpios-packages"} <= names


def test_otp_rpios_lite_layer():
    path = LAYERS / "otp-rpios-lite.yaml"
    meta = _meta(path)
    assert meta["X-Env-Layer-Name"] == "otp-rpios-lite" and meta["X-Env-Layer-Category"] == "suite"
    req = _requires(path)
    assert {"otp-rpios-packages", "network-manager", "debian-trixie-arm64-multi", "rpi-debian-trixie"} <= req
    # not rpi-image-gen's: no fixed regulatory domain (per board), no openssh-server layer (pi-gen turns SSH off)
    assert not req & {"wireless-regulatory", "openssh-server", "iwd", "systemd-net-min"}
    text = path.read_text(encoding="utf-8")
    for d in ("man", "locale", "doc"):                        # what the Debian base layer excludes
        assert f"- path-include=/usr/share/{d}/*" in text
    assert '> "$1/etc/resolv.conf"' in text and '[ ! -L "$1/etc/resolv.conf" ]' in text


def test_otp_rpios_setup_layer():
    path = LAYERS / "otp-rpios-setup.yaml"
    meta = _meta(path)
    assert meta["X-Env-Layer-Name"] == "otp-rpios-setup"
    assert _requires(path) == {"device-user-admin", "otp-rpios-lite"}   # its hooks run after the account exists
    text = path.read_text(encoding="utf-8")
    assert "usermod --shell /usr/sbin/nologin --password '!'" in text   # locked until cloud-init / the wizard
    assert "systemctl disable ssh.service" in text and 'rm -f "$1"/etc/ssh/ssh_host_*_key*' in text
    assert "WirelessEnabled=false" in text and "99-default.link" in text
    assert "systemctl disable rpi-eeprom-update.service" in text and '"${IGconf_image_pmap:-clear}" = crypt' in text
    assert "systemctl enable apparmor.service" in text and "cmdline.d/60-apparmor" in text   # + the fragment
    assert (LAYERS / "otp-rpios-setup.d" / "for" / "linux-base" / "cmdline.d" / "60-apparmor").is_file()
    for name in ("meta-data", "network-config", "user-data"):
        assert f'"$1/boot/firmware/{name}"' in text
    assert 'rm -f "$1/etc/apt/apt.conf.d/99mmdebstrap" "$1/etc/dpkg/dpkg.cfg.d/99mmdebstrap"' in text


SH = shutil.which("sh")

CHROOT_STUB = """#!/bin/sh
shift
printf '%s\\n' "$*" >> "$HOOK_CALLS"
"""


@pytest.mark.skipif(SH is None, reason="no POSIX sh on PATH (on Windows Git Bash provides one)")
def test_otp_rpios_setup_enables_apparmor_service(tmp_path):
    """apparmor.service loads the profiles at boot (the kernel command line is the fragment's job, below)."""
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load((LAYERS / "otp-rpios-setup.yaml").read_text(encoding="utf-8"))
    hook = next(h for h in doc["mmdebstrap"]["customize-hooks"] if "apparmor.service" in h)
    assert "cmdline.txt\n" not in hook and "boot/firmware/cmdline" not in hook   # not there yet at customize time
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "chroot").write_bytes(CHROOT_STUB.encode())
    (bindir / "chroot").chmod(0o755)
    calls = tmp_path / "calls"
    calls.write_bytes(b"")
    env = dict(os.environ, HOOK_CALLS=str(calls).replace("\\", "/"),
               PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run([SH, "-c", hook, "sh", str(tmp_path / "root").replace("\\", "/")], capture_output=True,
                       env=env, timeout=60)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert calls.read_text().splitlines() == ["systemctl enable apparmor.service"]


#: rpi-image-gen's linux-base assembles /etc/kernel/cmdline from every layer's cmdline.d fragments (late hook,
#: after all customize hooks); rpi-linux-base installs it as /boot/firmware/cmdline.txt.
CMDLINE_HOOK = REPO_ROOT / "image" / "rpi-image-gen" / "layer" / "base" / "linux-base.d" / "hooks" / "late" / "preimage10-cmdline"
BASH = shutil.which("bash")
CMDLINE_FRAGMENTS = {
    "apparmor": LAYERS / "otp-rpios-setup.d" / "for" / "linux-base" / "cmdline.d" / "60-apparmor",
    "memcg": LAYERS / "otp-apps.d" / "for" / "linux-base" / "cmdline.d" / "60-memcg",
}


def assemble_cmdline(tmp_path: Path, *fragments: Path) -> str:
    """The kernel command line rpi-image-gen's own assembler makes of these fragments, in this order."""
    if not CMDLINE_HOOK.is_file():
        pytest.skip(f"{CMDLINE_HOOK} not available (image/rpi-image-gen submodule not checked out)")
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    out = root / "etc" / "kernel" / "cmdline"
    out.unlink(missing_ok=True)
    wrapper = ('die() { echo "$*" >&2; exit 1; }; msg() { :; }\n'
               'foreach_dropin() { local f; for f in $FRAGS; do "$4" "$f"; done; }\n'
               'LAYER_NAME=linux-base LAYER_VERSION=1.0.0\n'
               '. "$HOOK" "$ROOT"\n')
    posix = lambda p: str(p).replace("\\", "/")  # noqa: E731
    env = dict(os.environ, HOOK=posix(CMDLINE_HOOK), ROOT=posix(root), FRAGS=" ".join(posix(f) for f in fragments))
    r = subprocess.run([BASH, "-c", wrapper], capture_output=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    return out.read_bytes().decode("utf-8")


@pytest.mark.skipif(BASH is None, reason="no bash on PATH (on Windows Git Bash provides one)")
def test_cmdline_fragments_turn_apparmor_and_the_memory_cgroup_on(tmp_path):
    """The Raspberry Pi kernel has AppArmor built in but an empty default LSM list (CONFIG_LSM=""), and the
    firmware disables the memory cgroup: the station's fragments select AppArmor (replacing any earlier LSM
    choice) and turn the memory cgroup on (layer otp-apps only), through rpi-image-gen's own assembler."""
    for f in CMDLINE_FRAGMENTS.values():
        assert len(f.read_bytes().decode("utf-8").splitlines()) == 1, f     # linux-base: one line per fragment
    base = tmp_path / "10-base"
    base.write_bytes(b"console=serial0,115200 console=tty1 root=ROOTDEV lsm=yama security=selinux fsck.repair=yes "
                     b"rootwait\n")
    plain = "console=serial0,115200 console=tty1 root=ROOTDEV fsck.repair=yes rootwait"
    assert assemble_cmdline(tmp_path, base, CMDLINE_FRAGMENTS["apparmor"]) == f"{plain} apparmor=1 security=apparmor\n"
    apps = assemble_cmdline(tmp_path, base, CMDLINE_FRAGMENTS["apparmor"], CMDLINE_FRAGMENTS["memcg"],
                            CMDLINE_FRAGMENTS["memcg"])                    # the same word only once
    assert apps == f"{plain} apparmor=1 security=apparmor cgroup_enable=memory\n"


def test_layers_are_valid_yaml():
    yaml = pytest.importorskip("yaml")
    for f in LAYERS.glob("*.yaml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert isinstance(doc.get("mmdebstrap"), dict), f.name
        for kind in ("customize-hooks", "cleanup-hooks"):
            assert all(isinstance(h, str) for h in doc["mmdebstrap"].get(kind, [])), f.name
