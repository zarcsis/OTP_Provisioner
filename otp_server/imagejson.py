"""Helpers for rpi-image-gen's IDP document (``image.json``, image2json 2.2.0 / PMAP v1).

Relevant structure::

    {"IGmeta": {"IGconf_device_class": "pi5", "IGconf_device_storage_type": "sd", ...},
     "attributes": {"image-name": "deb13-arm64-min.img", ...},
     "layout": {"partitionimages": {"boot": {"image": "boot.vfat", "simage": "boot.vfat.sparse",
                                             "bootable": "true", ...}, "root": {...}},
                "provisionmap": [{"attributes": {...}}, {"partitions": [{"image": "boot"}]},
                                 {"encrypted": {"luks2": {"mname": "osroot_crypt", ...},
                                                "partitions": [{"image": "root"}]}}]}}

Provisionmap entries reference ``partitionimages`` keys (partition names) through ``image``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

_DISKS = {"sd": "mmcblk0", "emmc": "mmcblk0", "nvme": "nvme0n1"}


def load(path: str | Path) -> dict:
    """Read and parse an image.json file (UTF-8)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "layout" not in data:
        raise ValueError(f"{path}: not an IDP image.json (no 'layout')")
    return data


def meta(image_json: dict) -> dict:
    """IGmeta as a dict ({} when missing)."""
    m = image_json.get("IGmeta") or {}
    return m if isinstance(m, dict) else {}


def storage_type(image_json: dict) -> str:
    """IGconf_device_storage_type (default "sd" when the document does not say)."""
    return str(meta(image_json).get("IGconf_device_storage_type") or "sd").strip().lower()


def storage_device(image_json: dict) -> str:
    """Whole-disk device name the gadget sees: sd|emmc -> "mmcblk0", nvme -> "nvme0n1"."""
    st = storage_type(image_json)
    try:
        return _DISKS[st]
    except KeyError:
        raise ValueError(f"unsupported IGconf_device_storage_type {st!r} (expected sd, emmc or nvme)") from None


def partition_name(disk: str, n: int) -> str:
    """Partition device name: mmcblk0 + 2 -> mmcblk0p2, nvme0n1 + 2 -> nvme0n1p2, sda + 2 -> sda2."""
    if n < 1:
        raise ValueError(f"partition number must be >= 1, got {n}")
    return f"{disk}p{n}" if disk[-1:].isdigit() else f"{disk}{n}"


def partition_images(image_json: dict) -> dict[str, dict]:
    """layout.partitionimages as {partition name: attrs} (a list form is keyed by its 'name')."""
    pi = (image_json.get("layout") or {}).get("partitionimages") or {}
    if isinstance(pi, list):
        return {str(p.get("name", i)): p for i, p in enumerate(pi) if isinstance(p, dict)}
    return {str(k): v for k, v in pi.items() if isinstance(v, dict)}


def provisionmap(image_json: dict) -> list:
    pm = (image_json.get("layout") or {}).get("provisionmap") or []
    return pm if isinstance(pm, list) else []


def _slot_partitions(slots: Any) -> Iterator[dict]:
    if not isinstance(slots, dict):
        return
    for slot in slots.values():
        if isinstance(slot, dict):
            for p in slot.get("partitions") or []:
                if isinstance(p, dict):
                    yield p


def crypt_containers(image_json: dict) -> list[dict]:
    """LUKS containers with their 1-based partition index on the disk.

    Walks the provisionmap in order: ``partitions`` -> +1 per entry, ``slots`` -> +1 per partition
    of every slot, ``encrypted`` -> +1 (the container partition; its inner partitions live inside it),
    ``attributes`` -> skipped. Returns ``[{"index", "mname", "label", "etype"}]``.
    """
    out: list[dict] = []
    index = 0
    for entry in provisionmap(image_json):
        if not isinstance(entry, dict):
            continue
        if "partitions" in entry:
            index += sum(1 for p in entry.get("partitions") or [] if isinstance(p, dict))
        if "slots" in entry:
            slots = entry.get("slots")
            index += sum(1 for _ in _slot_partitions(slots))
            # A slot may itself carry an encrypted container (schema allows it).
            if isinstance(slots, dict):
                for slot in slots.values():
                    if isinstance(slot, dict) and isinstance(slot.get("encrypted"), dict):
                        index += 1
                        out.append(_container(slot["encrypted"], index))
        if isinstance(entry.get("encrypted"), dict):
            index += 1
            out.append(_container(entry["encrypted"], index))
    return out


def _container(enc: dict, index: int) -> dict:
    luks = enc.get("luks2") or {}
    return {
        "index": index,
        "mname": str(luks.get("mname") or ""),
        "label": str(luks.get("label") or ""),
        "etype": str(luks.get("etype") or "raw"),
    }


def simages(image_json: dict) -> list[str]:
    """layout.partitionimages[*].simage in document order, deduplicated."""
    seen: list[str] = []
    for attrs in partition_images(image_json).values():
        s = attrs.get("simage")
        if s and s not in seen:
            seen.append(str(s))
    return seen


def _walk_refs(entries: Any) -> Iterator[dict]:
    """Every partitionRef in the provisionmap (top level, slots, and inside containers)."""
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for p in entry.get("partitions") or []:
            if isinstance(p, dict):
                yield p
        yield from _slot_partitions(entry.get("slots"))
        enc = entry.get("encrypted")
        if isinstance(enc, dict):
            yield from _walk_refs([enc])
        if isinstance(entry.get("slots"), dict):
            for slot in entry["slots"].values():
                if isinstance(slot, dict) and isinstance(slot.get("encrypted"), dict):
                    yield from _walk_refs([slot["encrypted"]])


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "yes", "1")


def boot_simages(image_json: dict) -> list[str]:
    """simage names of the boot partitions.

    Partitions whose provisionmap entry has ``static.role == "boot"``; when no entry declares a role,
    partitionimages with ``bootable == "true"``.
    """
    parts = partition_images(image_json)
    out: list[str] = []
    for ref in _walk_refs(provisionmap(image_json)):
        static = ref.get("static") or {}
        if isinstance(static, dict) and static.get("role") == "boot":
            s = (parts.get(str(ref.get("image"))) or {}).get("simage")
            if s and s not in out:
                out.append(str(s))
    if out:
        return out
    for attrs in parts.values():
        if _truthy(attrs.get("bootable")) and attrs.get("simage") and attrs["simage"] not in out:
            out.append(str(attrs["simage"]))
    return out


def is_encrypted(image_json: dict) -> bool:
    """True when the provisionmap has any encrypted container."""
    def has(obj: Any) -> bool:
        if isinstance(obj, dict):
            return "encrypted" in obj or any(has(v) for v in obj.values())
        if isinstance(obj, list):
            return any(has(v) for v in obj)
        return False
    return has(provisionmap(image_json))


def simage_partition_size(image_json: dict, simage: str) -> int | None:
    """Partition size in bytes (from sfdisk) of the partition whose simage is ``simage``."""
    for attrs in partition_images(image_json).values():
        if attrs.get("simage") == simage:
            try:
                return int(attrs.get("size"))
            except (TypeError, ValueError):
                return None
    return None
