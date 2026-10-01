"""image.json helpers against the real rpi-image-gen provisioning maps (image-rpios / image-rota)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from otp_server import imagejson

REPO = Path(__file__).resolve().parent.parent
RIG = (REPO.parent / "droneos" / "rpi-image-gen").resolve()
RPIOS_DEV = RIG / "image" / "mbr" / "simple_dual" / "device"
ROTA_DEV = RIG / "image" / "gpt" / "ab_userdata" / "device"

SUBST = {"LUKS_KEYSIZE": "512", "LUKS_CIPHER": "aes-xts-plain64", "LUKS_HASH": "sha256",
         "CRYPT_UUID": "0b7f3c1e-5d9a-4c7e-9f59-1f6c2a8d9e11", "BOOT_UUID": "1A2B-3C4D",
         "SYSTEM_UUID": "8d5e2a44-0c1f-4c61-a3f4-7f8a1b2c3d4e", "ROOT_UUID": "5f1e9e2c-1111-4a3b-9c2d-0e6f7a8b9c0d",
         "BOOT_LABEL": "BOOT"}


def load_pmap(path: Path) -> list:
    """Read a provisionmap template the way customize10-pmap renders it (envsubst of ${VARS})."""
    if not path.is_file():
        pytest.skip(f"{path} not available (droneos checkout missing)")
    text = re.sub(r"\$\{(\w+)\}", lambda m: SUBST[m.group(1)], path.read_text(encoding="utf-8"))
    return json.loads(text)


def rpios_image_json(pmap: list, storage: str = "sd") -> dict:
    """A realistic image2json 2.2.0 document for droneos (image-rpios, MBR boot + root)."""
    return {
        "IGversion": "2.2.0",
        "IGmeta": {"IGconf_device_class": "pi5", "IGconf_device_variant": "8G",
                   "IGconf_device_storage_type": storage, "IGconf_device_sector_size": 512,
                   "IGconf_image_version": "v0.3-4-gabcdef0", "IGconf_image_outputdir": "/work/image-deb13-arm64-min"},
        "attributes": {"image-name": "deb13-arm64-min.img", "image-size": 1677721600, "image-palign-bytes": "8M"},
        "layout": {
            "partitiontable": {"label": "dos", "id": "0x1234abcd"},
            "partitionimages": {
                "boot": {"name": "boot", "in-partition-table": "true", "partition-type": "0xC",
                         "image": "boot.vfat", "bootable": "true", "type": "vfat", "simage": "boot.vfat.sparse",
                         "mountpoint": "/boot/firmware", "fs_label": "BOOT", "size": 209715200},
                "root": {"name": "root", "in-partition-table": "true", "partition-type": "0x83",
                         "image": "root.ext4", "type": "ext4", "simage": "root.ext4.sparse",
                         "mountpoint": "/", "fs_label": "ROOT", "size": 1459617792},
            },
            "provisionmap": pmap,
        },
    }


def test_rpios_crypt_containers_real_pmap(tmp_path):
    ij = rpios_image_json(load_pmap(RPIOS_DEV / "provisionmap-crypt.json"))
    p = tmp_path / "image.json"
    p.write_text(json.dumps(ij), encoding="utf-8")
    ij = imagejson.load(p)
    assert imagejson.crypt_containers(ij) == [
        {"index": 2, "mname": "osroot_crypt", "label": "OSROOT_CRYPT", "etype": "raw"}]
    assert imagejson.is_encrypted(ij)
    assert imagejson.storage_device(ij) == "mmcblk0"
    assert imagejson.partition_name(imagejson.storage_device(ij), 2) == "mmcblk0p2"
    assert imagejson.simages(ij) == ["boot.vfat.sparse", "root.ext4.sparse"]
    # image-rpios has no static.role -> fall back to the bootable partition
    assert imagejson.boot_simages(ij) == ["boot.vfat.sparse"]
    assert imagejson.simage_partition_size(ij, "root.ext4.sparse") == 1459617792


def test_rpios_clear_is_not_encrypted():
    ij = rpios_image_json(load_pmap(RPIOS_DEV / "provisionmap-clear.json"))
    assert not imagejson.is_encrypted(ij)
    assert imagejson.crypt_containers(ij) == []


def test_rota_ab_crypt_real_pmap():
    pmap = load_pmap(ROTA_DEV / "provisionmap-crypt.json")
    parts = {name: {"name": name, "image": f"{name}.img", "simage": s, "size": 1 << 20}
             for name, s in (("bootconfig", "bootconfig.sparse"), ("boot_a", "boot.sparse"),
                             ("boot_b", "boot.sparse"), ("system_a", "system.sparse"),
                             ("system_b", "system.sparse"), ("persistent", "data.sparse"))}
    ij = {"IGmeta": {"IGconf_device_storage_type": "nvme"},
          "layout": {"partitionimages": parts, "provisionmap": pmap}}
    # bootconfig (1), boot_a (2), boot_b (3), then the LUKS container (4) holding system_a/b + persistent
    assert imagejson.crypt_containers(ij) == [
        {"index": 4, "mname": "osdata_crypt", "label": "OSDATA_CRYPT", "etype": "partitioned"}]
    assert imagejson.boot_simages(ij) == ["boot.sparse"]            # static.role == boot, deduplicated
    assert imagejson.simages(ij) == ["bootconfig.sparse", "boot.sparse", "system.sparse", "data.sparse"]
    assert imagejson.storage_device(ij) == "nvme0n1"
    assert imagejson.partition_name("nvme0n1", 4) == "nvme0n1p4"


@pytest.mark.parametrize("st,disk", [("sd", "mmcblk0"), ("emmc", "mmcblk0"), ("nvme", "nvme0n1"),
                                     ("SD", "mmcblk0")])
def test_storage_device(st, disk):
    assert imagejson.storage_device({"IGmeta": {"IGconf_device_storage_type": st}, "layout": {}}) == disk


def test_storage_device_default_and_bad():
    assert imagejson.storage_device({"layout": {}}) == "mmcblk0"
    with pytest.raises(ValueError, match="usb"):
        imagejson.storage_device({"IGmeta": {"IGconf_device_storage_type": "usb"}, "layout": {}})


def test_partition_name():
    assert imagejson.partition_name("mmcblk0", 2) == "mmcblk0p2"
    assert imagejson.partition_name("nvme0n1", 1) == "nvme0n1p1"
    assert imagejson.partition_name("sda", 2) == "sda2"
    with pytest.raises(ValueError):
        imagejson.partition_name("sda", 0)


def test_load_rejects_non_idp(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="not an IDP"):
        imagejson.load(p)


def test_partitionimages_list_form_and_bool_bootable():
    ij = {"layout": {"partitionimages": [
        {"name": "boot", "simage": "b.sparse", "bootable": True},
        {"name": "root", "simage": "r.sparse"}], "provisionmap": [{"partitions": [{"image": "boot"}, {"image": "root"}]}]}}
    assert imagejson.simages(ij) == ["b.sparse", "r.sparse"]
    assert imagejson.boot_simages(ij) == ["b.sparse"]
    assert not imagejson.is_encrypted(ij)
