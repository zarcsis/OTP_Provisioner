"""The board families the station provisions, and what differs between them.

Two families, told apart by the SoC the boot ROM reports (its USB product id, ``chip`` in the board record):

* ``pi5``: BCM2712 -- Raspberry Pi 5, Compute Module 5, Raspberry Pi 500. The family the station was built for.
* ``cm4``: BCM2711 -- Compute Module 4 only. The other BCM2711 boards (Pi 4 Model B, Pi 400, CM4S) have no
  RPIBOOT jumper or no USB device port the gadget can use; the station refuses them once the board's own report
  (``USER_BOARDREV`` in the stage-1 metadata) says what it is.

What differs (each user of a :class:`Family` reads it from here, never from the chip name):

* the second stage the boot ROM asks for (``bootcode5.bin`` / ``bootcode4.bin``) and the rpi-eeprom firmware
  directory and EEPROM size (2 MiB / 512 KiB);
* the BCM2712 boot ROM runs a second stage counter-signed with the customer key once OTP holds its hash and refuses
  the plain one (and the other way round), so stage 1 picks the variant from the OTP lock state; the BCM2711 boot
  ROM only checks Raspberry Pi's signature and runs the plain ``recovery.bin`` in both states (usbboot
  ``docs/secure-boot.md``, "Pi 4 vs Pi 5 secure-boot differences");
* ``set_reboot_order`` (BCM2712 only) brings a Pi 5 back into RPIBOOT after stage 1; a CM4 comes back because its
  nRPIBOOT jumper is fitted, which is also why it boots its OS only once the jumper is removed;
* the OS image: rpi-image-gen's device layer (``rpi5`` with the 16 KiB-page kernel_2712, ``rpi-cm4`` with the
  4 KiB-page kernel8) and our kernel package layer; the ext4 block size follows the page size;
* the boot.img a signed boot partition carries (``rpi-make-boot-image -b``) and what a custom image's signed boot
  partition leaves out (``PRUNE``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Family:
    key: str
    #: The SoC name the page reports (``OTP.CHIPS`` in js/bootdir.js) and the rpi-eeprom / usbboot directory.
    chip: str
    soc: str
    title: str
    #: What the boot ROM asks for over rpiboot (stage 1 serves recovery.bin under this name).
    second_stage: str
    pieeprom_size: int
    #: The boot ROM runs only a customer counter-signed second stage once OTP holds the key hash (BCM2712).
    countersigned_recovery: bool
    #: ``set_reboot_order=0x3`` in the stage-1 config.txt brings the board back into RPIBOOT (BCM2712).
    reboot_order: bool
    #: rpi-image-gen device layer and our kernel package layer (image/layer) of the station image.
    device_layer: str
    kernel_layer: str
    #: ``IGconf_device_class`` of the station image.
    device_class: str
    #: ``rpi-make-boot-image -b`` and boot-slot.sh ``BOARD`` / ``PRUNE`` value.
    boot_board: str
    #: pi-gen-micro targets of which one must be in ``builds.gadget.targets`` for the gadget to boot this family.
    gadget_targets: frozenset[str]
    #: ``USER_BOARDREV`` board types this family accepts (empty = any).
    board_types: frozenset[int]
    #: How the operator puts the board into RPIBOOT mode (page and notes).
    rpiboot_how: str
    #: What the operator does after stage 3 so that the board boots its new OS.
    after_flash: str
    #: Image layer that puts Arm Trusted Firmware in as the armstub when ``builds.image.cm4_tfa`` is on (empty: the
    #: family's own boot firmware already runs TF-A, as a Raspberry Pi 5's does).
    tfa_layer: str = ""


PI5 = Family(
    key="pi5", chip="BCM2712", soc="2712", title="Raspberry Pi 5 / CM5 / Pi 500",
    second_stage="bootcode5.bin", pieeprom_size=2 * 1024 * 1024, countersigned_recovery=True, reboot_order=True,
    device_layer="rpi5", kernel_layer="otp-rpios-kernel-2712", device_class="pi5", boot_board="pi5",
    gadget_targets=frozenset({"pi5-family", "pi5", "cm5", "500"}), board_types=frozenset(),
    rpiboot_how="hold the power button while plugging in USB-C",
    after_flash="unplug it and power it from its own supply",
)
CM4 = Family(
    key="cm4", chip="BCM2711", soc="2711", title="Compute Module 4",
    second_stage="bootcode4.bin", pieeprom_size=512 * 1024, countersigned_recovery=False, reboot_order=False,
    device_layer="rpi-cm4", kernel_layer="otp-rpios-kernel-v8", device_class="cm4", boot_board="cm4",
    gadget_targets=frozenset({"pi4-family", "cm4"}), board_types=frozenset({0x14}),
    rpiboot_how="fit the nRPIBOOT jumper (CM4 IO Board: J2 'disable eMMC boot'; carriers with a BOOT switch: "
                "switch it on) and power the board on",
    after_flash="remove the nRPIBOOT jumper (or switch BOOT off), then power-cycle it on its own supply",
    tfa_layer="otp-tfa-rpi4",
)
FAMILIES: dict[str, Family] = {f.key: f for f in (PI5, CM4)}
_BY_CHIP = {f.chip: f for f in FAMILIES.values()}

#: Board types of new-style revision codes (``(rev >> 4) & 0xff``) the station names in its messages.
BOARD_TYPES = {
    0x11: "Raspberry Pi 4 Model B", 0x13: "Raspberry Pi 400", 0x14: "Compute Module 4", 0x15: "Compute Module 4S",
    0x17: "Raspberry Pi 5", 0x18: "Compute Module 5", 0x19: "Raspberry Pi 500", 0x1A: "Compute Module 5 Lite",
}


def check_family(key: str) -> str:
    """``key`` when it names a family (ValueError otherwise)."""
    k = str(key or "").strip().lower()
    if k not in FAMILIES:
        raise ValueError(f"unknown board family {key!r} (expected one of {', '.join(FAMILIES)})")
    return k


def family_of_chip(chip: str) -> Family | None:
    """The family of a SoC name as the page reports it (``BCM2712``, ``BCM2711``), None for any other."""
    return _BY_CHIP.get(str(chip or "").strip().upper())


def family_of(record: dict | None) -> Family:
    """The family of a board record. A record without a chip (seen first as a fastboot gadget, or written before
    the station knew more than one family) is a Raspberry Pi 5; an unknown chip is a ValueError."""
    chip = str((record or {}).get("chip") or "").strip()
    if not chip:
        return PI5
    fam = family_of_chip(chip)
    if fam is None:
        raise ValueError(f"the station provisions {supported_text()} only, this board is a {chip}")
    return fam


def supported_text() -> str:
    """``Raspberry Pi 5 / CM5 / Pi 500 (BCM2712) and Compute Module 4 (BCM2711)``."""
    return " and ".join(f"{f.title} ({f.chip})" for f in FAMILIES.values())


def board_type(boardrev: Any) -> int | None:
    """The board type of a new-style revision code (``USER_BOARDREV``, hex, with or without ``0x``), None when it
    is not one."""
    s = str(boardrev or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        rev = int(s, 16)
    except ValueError:
        return None
    if not rev & (1 << 23):          # old-style codes (Pi 1-3 era) carry no type field
        return None
    return (rev >> 4) & 0xFF


def board_name(btype: int | None) -> str:
    if btype is None:
        return "unknown board"
    return BOARD_TYPES.get(btype, f"board type 0x{btype:02x}")


def unsupported_reason(record: dict | None) -> str:
    """Why the station refuses this board ("" when it does not): an unknown SoC, or a board of a supported SoC that
    is not one of the family's models (a Pi 4 Model B reports BCM2711 like a CM4)."""
    try:
        fam = family_of(record)
    except ValueError as exc:
        return str(exc)
    rev = str((record or {}).get("boardrev") or (((record or {}).get("metadata") or {}).get("USER_BOARDREV")) or "")
    btype = board_type(rev) if rev else None
    if fam.board_types and btype is not None and btype not in fam.board_types:
        return (f"this {fam.chip} board is a {board_name(btype)} (USER_BOARDREV {rev}); of the {fam.chip} boards the "
                f"station provisions the {fam.title} only")
    return ""


def gadget_target_words(targets: str) -> list[str]:
    """The words of ``builds.gadget.targets`` (spaces or commas between them)."""
    return [w for w in str(targets or "").replace(",", " ").split() if w]


def gadget_covers(targets: str, fam: Family) -> bool:
    """The gadget built for ``targets`` boots boards of ``fam``."""
    return bool(set(gadget_target_words(targets)) & fam.gadget_targets)


__all__ = ["Family", "PI5", "CM4", "FAMILIES", "BOARD_TYPES", "check_family", "family_of", "family_of_chip",
           "supported_text", "board_type", "board_name", "unsupported_reason", "gadget_target_words", "gadget_covers"]
