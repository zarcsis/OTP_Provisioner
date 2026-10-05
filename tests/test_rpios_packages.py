"""image/rpios_packages.py: the Raspberry Pi OS Lite package layer, generated from a release's .info file."""
from __future__ import annotations

import importlib.util

import pytest

from otp_server.config import REPO_ROOT

SCRIPT = REPO_ROOT / "image" / "rpios_packages.py"
LAYER = REPO_ROOT / "image" / "layer" / "otp-rpios-packages.yaml"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("rpios_packages", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def info(names: list[tuple[str, str]]) -> str:
    head = ["Raspberry Pi reference 2099-01-01",
            "Generated using pi-gen, https://github.com/RPi-Distro/pi-gen, abc, stage2", "", "Packages:",
            "Desired=Unknown/Install/Remove/Purge/Hold", "||/ Name Version Architecture Description", "+++-===-===-===-==="]
    rows = [f"ii  {n}  1.0  {a}  some description" for n, a in names]
    filler = [f"ii  lib{i}  1.0  arm64  filler" for i in range(120)]
    return "\n".join(head + rows + filler) + "\n"


def test_parse_drops_versioned_and_other_board_kernels(gen):
    text = info([("linux-image-rpi-2712", "arm64"), ("linux-image-6.18.50+rpt-rpi-2712", "arm64"),
                 ("linux-headers-6.18.50+rpt-common-rpi", "all"), ("linux-kbuild-6.18.50+rpt", "arm64"),
                 ("linux-image-rpi-v8", "arm64"), ("linux-headers-rpi-v8", "arm64"),
                 ("binutils-common:arm64", "arm64"), ("libc6:armhf", "armhf"), ("foo", "armhf"), ("bar", "all")])
    release, generator, keep, drop = gen.parse(text)
    assert release == "Raspberry Pi reference 2099-01-01" and "pi-gen" in generator
    assert {"linux-image-rpi-2712", "binutils-common", "libc6:armhf", "foo:armhf", "bar"} <= set(keep)
    assert drop == sorted(["linux-image-6.18.50+rpt-rpi-2712", "linux-headers-6.18.50+rpt-common-rpi",
                           "linux-kbuild-6.18.50+rpt", "linux-image-rpi-v8", "linux-headers-rpi-v8"])
    assert keep == sorted(set(keep))


def test_parse_rejects_other_files(gen):
    with pytest.raises(SystemExit):
        gen.parse("hello\n")
    with pytest.raises(SystemExit):                          # a .info with almost nothing in it
        gen.parse("Raspberry Pi reference 2099-01-01\nx\nii  a  1  arm64  d\n")


def test_committed_layer_is_what_the_generator_writes(gen):
    """The layer in the repo is the generator's output (re-rendered from its own header and list)."""
    yaml = pytest.importorskip("yaml")
    text = LAYER.read_bytes().decode("utf-8")
    lines = text.splitlines()
    release, generator = lines[9][2:], lines[10][2:]
    drop = [ln[4:] for ln in lines if ln.startswith("#   ")]
    keep = yaml.safe_load(text)["mmdebstrap"]["packages"]
    assert gen.render(release, generator, keep, drop) == text
    assert release.startswith("Raspberry Pi reference ")
    for name in ("raspi-config", "network-manager", "cloud-init", "rpi-cloud-init-mods", "userconf-pi",
                 "linux-image-rpi-2712", "openssh-server", "avahi-daemon", "raspberrypi-sys-mods"):
        assert name in keep, name
    assert "linux-image-rpi-v8" not in keep and not [n for n in keep if gen.VERSIONED_KERNEL.match(n)]
