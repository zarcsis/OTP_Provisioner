"""Compute Module 4 (BCM2711) boards next to the Raspberry Pi 5: the board families (otp_server.boards), stage 1
(firmware-2711, bootcode4.bin, no counter-signed second stage), the stage-1 verdicts (CM4 only, a lock that was only
assumed), stage 2 (the gadget's targets), the OS image of each family and a custom image written to a CM4.

The fakes are test_artifacts' (FakeDocker and its handlers): the CM4 behaviour on hardware is not what this checks,
only that the station plans, builds and serves the right files for it.
"""
from __future__ import annotations

import json

import pytest

from otp_server import boards, imagejson
from otp_server.artifacts import NotReady
from otp_server.artifacts.image import label
from otp_server.config import load_config
from otp_server.modules import ZERO_HASH
from test_artifacts import SERIAL, SERIAL2, build_gadget, build_image, make_env  # noqa: F401 (make_env: fixture)
from test_custom_images import cenv, prepared, small_images  # noqa: F401 (fixtures)

#: USER_BOARDREV of a CM4 (type 0x14) and of a Pi 4 Model B (type 0x11), both 4 GB, BCM2711.
CM4_REV = "c03141"
PI4B_REV = "c03111"


def cm4(env, serial: str = SERIAL, *, mode: str = "", lock: str = "") -> dict:
    """A Compute Module 4 seen in RPIBOOT (the page reports chip BCM2711)."""
    env.modules.hello(serial, {"chip": "BCM2711", "board": "Pi 4 / CM4"})
    if mode:
        env.modules.set_mode(serial, mode)
    if lock:
        rec = env.store.get(serial)
        rec["otp_key_hash"] = rec["customer_key_hash"] if lock == "ours" else "ab" * 32
        env.store.put(rec)
    return env.store.get(serial)


# ---------------------------------------------------------------------- boards
def test_families():
    assert boards.family_of({"chip": "BCM2712"}) is boards.PI5
    assert boards.family_of({"chip": " bcm2711 "}) is boards.CM4
    assert boards.family_of({}) is boards.PI5 and boards.family_of({"chip": ""}) is boards.PI5   # older records
    with pytest.raises(ValueError, match="BCM2837"):
        boards.family_of({"chip": "BCM2837"})
    assert boards.family_of_chip("BCM2835") is None
    assert (boards.CM4.second_stage, boards.CM4.pieeprom_size, boards.CM4.countersigned_recovery) == (
        "bootcode4.bin", 512 * 1024, False)
    assert (boards.PI5.second_stage, boards.PI5.pieeprom_size, boards.PI5.countersigned_recovery) == (
        "bootcode5.bin", 2 * 1024 * 1024, True)
    assert boards.check_family(" CM4 ") == "cm4"
    with pytest.raises(ValueError):
        boards.check_family("pi4")


@pytest.mark.parametrize("rev, btype", [("c03141", 0x14), ("0xC03141", 0x14), ("c03111", 0x11), ("d04170", 0x17),
                                        ("a02082", 0x08), ("0002", None), ("zz", None), ("", None)])
def test_board_type(rev, btype):
    assert boards.board_type(rev) == btype


def test_unsupported_boards():
    assert boards.unsupported_reason({"chip": "BCM2711"}) == ""                          # not reported yet
    assert boards.unsupported_reason({"chip": "BCM2711", "boardrev": CM4_REV}) == ""
    why = boards.unsupported_reason({"chip": "BCM2711", "boardrev": PI4B_REV})
    assert "Raspberry Pi 4 Model B" in why and "Compute Module 4 only" in why
    assert "Raspberry Pi 400" in boards.unsupported_reason({"chip": "BCM2711", "metadata": {"USER_BOARDREV": "c03130"}})
    assert boards.unsupported_reason({"chip": "BCM2712", "boardrev": "d04170"}) == ""     # any BCM2712 board
    assert "BCM2837" in boards.unsupported_reason({"chip": "BCM2837"})


def test_gadget_targets():
    assert boards.gadget_target_words(" pi5-family, cm4 ") == ["pi5-family", "cm4"]
    assert boards.gadget_covers("pi5-family,cm4", boards.CM4) and boards.gadget_covers("pi5-family,cm4", boards.PI5)
    assert boards.gadget_covers("pi4-family", boards.CM4) and not boards.gadget_covers("pi4-family", boards.PI5)
    assert not boards.gadget_covers("pi5-family", boards.CM4)


def test_config_families_and_gadget_targets(tmp_path):
    cfg = load_config(overrides={"paths": {"work": str(tmp_path)}})
    assert cfg.builds.image.families == ["pi5", "cm4"] and cfg.builds.gadget.targets == "pi5-family,cm4"
    cfg = load_config(overrides={"paths": {"work": str(tmp_path)}, "builds": {
        "image": {"families": "cm4\npi5, cm4"}, "gadget": {"targets": "pi5-family  cm4,pi5-family"}}})
    assert cfg.builds.image.families == ["cm4", "pi5"] and cfg.builds.gadget.targets == "pi5-family,cm4"
    with pytest.raises(ValueError, match="builds.image.families"):
        load_config(overrides={"paths": {"work": str(tmp_path)}, "builds": {"image": {"families": ["pi4"]}}})
    with pytest.raises(ValueError, match="at least one board family"):
        load_config(overrides={"paths": {"work": str(tmp_path)}, "builds": {"image": {"families": []}}})
    with pytest.raises(ValueError, match="builds.gadget.targets"):
        load_config(overrides={"paths": {"work": str(tmp_path)}, "builds": {"gadget": {"targets": "pi5;cm4"}}})


def test_settings_read_the_old_gadget_default_as_the_new_one():
    from otp_server import settings
    assert "pi5-family" in settings.REPLACED_DEFAULTS["builds.gadget.targets"]
    assert "builds.image.families" in settings.DESCRIPTIONS


def test_hello_refuses_other_chips(make_env):
    env = make_env()
    with pytest.raises(ValueError, match="Compute Module 4"):
        env.modules.hello(SERIAL, {"chip": "BCM2837"})
    assert env.store.get(SERIAL) is None
    rec = cm4(env)
    view = env.modules.public_view(rec)
    assert (view["chip"], view["family"], view["unsupported"]) == ("BCM2711", "cm4", "")


# ---------------------------------------------------------------------- stage 1
def test_stage1_unsigned_cm4(make_env):
    env = make_env()
    cm4(env)
    m = env.arts.stage_manifest(SERIAL, 1, base_url="http://h")
    assert m["mode"] == "unsigned" and m["chip"] == "BCM2711" and m["recovery"] is None
    assert [f["name"] for f in m["files"]] == ["bootcode4.bin", "pieeprom.bin", "pieeprom.sig", "config.txt"]
    # no set_reboot_order: the nRPIBOOT jumper brings a CM4 back into RPIBOOT
    assert m["config_txt"] == "uart_2ndstage=1\nrecovery_reboot=1\n"
    assert m["files"][0]["origin"] == "rpi-eeprom firmware-2711/latest/recovery.bin"
    assert m["source"] == {"channel": "latest", "pieeprom": "pieeprom-2026-10-23.bin", "firmware": "firmware-2711"}
    assert any("nRPIBOOT jumper" in n for n in m["notes"])
    (run,) = env.docker.runs_of("stage1.sh")
    assert run["env"] == {"MODE": "unsigned", "CHANNEL": "latest", "SIGN_RECOVERY": "0", "CHIP": "2711", "LOCKED": "0"}
    assert env.arts.stage_file(SERIAL, 1, "pieeprom.bin").stat().st_size == 512 * 1024
    # a Raspberry Pi 5 gets its own (shared, unsigned) directory, not the CM4's
    env.modules.hello(SERIAL2, {"chip": "BCM2712"})
    m5 = env.arts.stage_manifest(SERIAL2, 1)
    assert m5["files"][0]["name"] == "bootcode5.bin" and m5["recovery"] == "plain"
    assert len(env.docker.runs_of("stage1.sh")) == 2
    assert env.arts.stage_file(SERIAL, 1, "pieeprom.bin").parent != env.arts.stage_file(SERIAL2, 1, "pieeprom.bin").parent


def test_stage1_secure_cm4_burns_the_key_hash(make_env):
    env = make_env()
    rec = cm4(env, mode="secure")
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and m["config_txt"] == "uart_2ndstage=1\nrecovery_reboot=1\nprogram_pubkey=1\n"
    assert [i["key"] for i in m["irreversible"]] == ["program_pubkey"]
    assert m["expect"] == {"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"],
                           "otp_key_hash": None}
    run = env.docker.runs_of("stage1.sh")[-1]
    assert {k: run["env"][k] for k in ("MODE", "CHIP", "SIGN_RECOVERY", "LOCKED")} == {
        "MODE": "signed", "CHIP": "2711", "SIGN_RECOVERY": "0", "LOCKED": "0"}
    assert run["env"]["EXPECT_CKH"] == rec["customer_key_hash"] and "/keys" in run["mounts"]


def test_stage1_cm4_locked_to_our_key_sends_the_plain_second_stage(make_env):
    env = make_env()
    rec = cm4(env, lock="ours")
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and m["irreversible"] == [] and m["recovery"] is None
    assert m["expect"]["otp_key_hash"] == rec["customer_key_hash"]
    assert "plain recovery" in m["notes"][0] and "counter-signed" not in m["notes"][0]
    run = env.docker.runs_of("stage1.sh")[-1]
    assert (run["env"]["SIGN_RECOVERY"], run["env"]["LOCKED"]) == ("0", "1")


def test_cm4_stage1_report_and_an_assumed_lock_that_was_wrong(make_env):
    """A secure stage 1 that broke off after program_pubkey + the whole EEPROM image: the next run assumes the lock
    (signed EEPROM, no program_pubkey=1). If the board then reports an empty OTP, the run fails, the assumption is
    gone and the run after that burns the key hash."""
    env = make_env()
    cm4(env, mode="secure")
    m0 = env.arts.stage_manifest(SERIAL, 1)
    rec, verdict = env.modules.record_result(SERIAL, 1, {
        "ok": False, "interrupted": True, "metadata": {}, "expect": m0["expect"],
        "files_served": [{"name": "pieeprom.bin", "size": 524288}]})
    assert not verdict["ok"] and env.modules.lock_suspected(rec)
    assert any("signed EEPROM without program_pubkey=1" in n for n in verdict["notes"])
    m1 = env.arts.stage_manifest(SERIAL, 1)
    assert m1["mode"] == "signed" and m1["irreversible"] == [] and m1["recovery"] is None
    assert m1["expect"]["otp_key_hash"] == rec["customer_key_hash"]
    rec, verdict = env.modules.record_result(SERIAL, 1, {
        "ok": True, "expect": m1["expect"], "files_served": [{"name": "pieeprom.bin", "size": 524288}],
        "metadata": {"EEPROM_UPDATE": "success", "CUSTOMER_KEY_HASH": ZERO_HASH, "USER_BOARDREV": CM4_REV}})
    assert not verdict["ok"] and any("holds no key hash after all" in n for n in verdict["notes"])
    assert not env.modules.lock_suspected(rec) and rec["stage"] == "new"
    m2 = env.arts.stage_manifest(SERIAL, 1)
    assert [i["key"] for i in m2["irreversible"]] == ["program_pubkey"]


def test_cm4_refused_second_stage_assumes_nothing(make_env):
    env = make_env()
    cm4(env, mode="secure")
    rec, verdict = env.modules.record_result(SERIAL, 1, {
        "ok": False, "second_stage_rejected": True, "recovery": "plain", "metadata": {}, "files_served": []})
    assert not verdict["ok"] and any("nRPIBOOT" in n for n in verdict["notes"])
    assert not rec["facts"].get("otp_lock") and not env.modules.lock_suspected(rec)
    assert not env.modules.recovery_refused_both(rec)
    assert env.arts.stage_manifest(SERIAL, 1)["irreversible"][0]["key"] == "program_pubkey"


def test_a_pi4_model_b_is_refused_after_its_report(make_env):
    env = make_env()
    cm4(env)
    m = env.arts.stage_manifest(SERIAL, 1)
    rec, verdict = env.modules.record_result(SERIAL, 1, {
        "ok": True, "expect": m["expect"], "files_served": [],
        "metadata": {"EEPROM_UPDATE": "success", "USER_BOARDREV": PI4B_REV, "CUSTOMER_KEY_HASH": ZERO_HASH}})
    assert not verdict["ok"] and any("Raspberry Pi 4 Model B" in n for n in verdict["notes"])
    assert rec["stage"] == "new" and "Raspberry Pi 4 Model B" in env.modules.public_view(rec)["unsupported"]
    for n in (1, 2, 3):
        with pytest.raises(NotReady, match="Compute Module 4 only"):
            env.arts.stage_manifest(SERIAL, n)


def test_a_cm4_report_is_accepted(make_env):
    env = make_env()
    cm4(env)
    m = env.arts.stage_manifest(SERIAL, 1)
    rec, verdict = env.modules.record_result(SERIAL, 1, {
        "ok": True, "expect": m["expect"], "files_served": [{"name": "pieeprom.bin", "size": 524288}],
        "metadata": {"EEPROM_UPDATE": "success", "USER_BOARDREV": CM4_REV, "CUSTOMER_KEY_HASH": ZERO_HASH}})
    assert verdict["ok"], verdict
    assert rec["stage"] == "eeprom" and rec["boardrev"] == CM4_REV


# ---------------------------------------------------------------------- stage 2
def test_stage2_cm4_needs_a_gadget_that_boots_it(make_env):
    env = make_env(builds={"gadget": {"targets": "pi5-family"}})
    cm4(env)
    build_gadget(env)
    with pytest.raises(NotReady, match="builds.gadget.targets"):
        env.arts.stage_manifest(SERIAL, 2)
    env.cfg.builds.gadget.targets = "pi5-family,cm4"
    with pytest.raises(NotReady, match="not built"):                  # another gadget: built for both targets
        env.arts.stage_manifest(SERIAL, 2)
    build_gadget(env)
    m = env.arts.stage_manifest(SERIAL, 2)
    assert [f["name"] for f in m["files"]] == ["bootfiles.bin", "boot.img", "config.txt"]
    assert env.docker.runs_of(env.cfg.builds.gadget.image_tag)[-1]["env"]["PGM_TARGETS"] == "pi5-family,cm4"


def test_stage2_signed_cm4(make_env):
    env = make_env()
    cm4(env, lock="ours")
    build_gadget(env)
    m = env.arts.stage_manifest(SERIAL, 2)
    assert m["mode"] == "signed" and "boot.sig" in [f["name"] for f in m["files"]]
    assert any("2711/pubkey.bin added" in n and "no counter-signature" in n for n in m["notes"])


# ---------------------------------------------------------------------- the OS image of each family
def test_image_for_both_families(make_env):
    env = make_env(builds={"image": {"families": ["pi5", "cm4"]}})
    img = env.arts.image
    assert img.missing_variants() == ["clear", "crypt", "cm4-clear", "cm4-crypt"]
    assert img.current_json("crypt", boards.CM4).name == "current-cm4-crypt.json"
    assert label(boards.PI5, "clear") == "clear" and label(boards.CM4, "clear") == "cm4-clear"
    build_image(env)
    assert img.missing_variants() == []
    runs = env.docker.runs_of(env.cfg.builds.image.builder_tag)
    assert len(runs) == 4
    cm4_runs = [r for r in runs if "  layer: rpi-cm4\n" in r["config"]]
    assert len(cm4_runs) == 2 and all("  kernel: otp-rpios-kernel-v8\n" in r["config"] for r in cm4_runs)
    st = env.arts.status()["image"]
    assert set(st["variants"]) == {"clear", "crypt", "cm4-clear", "cm4-crypt"} and st["ready"] is True
    assert st["families"] == ["pi5", "cm4"] and st["variants"]["cm4-crypt"]["family"] == "cm4"
    for v in ("clear", "crypt"):
        d4, man4 = img.current_set(v, boards.CM4)
        d5, man5 = img.current_set(v, boards.PI5)
        assert d4 != d5 and "-cm4-" in d4.name and "-cm4-" not in d5.name
        assert (man4["family"], man4["device_class"]) == ("cm4", "cm4")
        assert (man5["family"], man5["device_class"]) == ("pi5", "pi5")
        assert man4["config_hash"] == img.config_hash(v, boards.CM4) != img.config_hash(v, boards.PI5)
        # a set of the other family never serves: the family is part of what a set is checked against
        assert "pi5 family" in img.rebuild_reason(man5, v, boards.CM4)


def test_stage3_cm4_gets_its_family_image(make_env):
    env = make_env(builds={"image": {"families": ["pi5", "cm4"]}})
    build_image(env)
    cm4(env, mode="open")
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["image"]["family"] == "cm4" and m["image"]["device_class"] == "cm4"
    assert m["image"]["set"] == env.arts.image.current_set("clear", boards.CM4)[0].name
    slot = env.docker.runs_of("boot-slot.sh")[-1]
    assert (slot["env"]["BOARD"], slot["env"]["PRUNE"], slot["env"]["SIGN"]) == ("cm4", "", "0")
    env.modules.hello(SERIAL2, {"chip": "BCM2712"})
    m5 = env.arts.stage_manifest(SERIAL2, 3)
    assert m5["image"]["family"] == "pi5" and m5["image"]["set"] == env.arts.image.current_set("clear")[0].name
    assert env.docker.runs_of("boot-slot.sh")[-1]["env"]["BOARD"] == "pi5"


def test_stage3_cm4_secure(make_env):
    env = make_env(builds={"image": {"families": ["pi5", "cm4"]}})
    build_image(env)
    cm4(env, mode="secure", lock="ours")
    env.export_key(SERIAL)
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["mode"] == "signed" and m["image"]["family"] == "cm4" and m["image"]["encrypted"] is True
    assert m["verify_key"] == [{"dev": "mmcblk0p2", "label": "OSROOT_CRYPT"}]
    ij = json.loads(env.arts.stage_file(SERIAL, 3, "image.json").read_text(encoding="utf-8"))
    assert ij["IGmeta"]["IGconf_device_class"] == "cm4"            # rpi-fastbootd's idpinit checks it
    slot = env.docker.runs_of("boot-slot.sh")[-1]
    assert (slot["env"]["BOARD"], slot["env"]["SIGN"]) == ("cm4", "1")


def test_stage3_cm4_without_its_image_family(make_env):
    env = make_env()                                       # builds.image.families: pi5 only (conftest)
    build_image(env)
    cm4(env, mode="open")
    with pytest.raises(NotReady, match="builds.image.families"):
        env.arts.stage_manifest(SERIAL, 3)


# ---------------------------------------------------------------------- a custom image on a CM4
def test_custom_image_on_a_cm4(cenv, tmp_path):
    """A custom set serves every family: on a CM4 its image.json says cm4 (a derived copy), the boot slot is built
    for the CM4 (its kernel and firmware checked) even unsigned and without first-boot files, and a signed one is
    pruned for it."""
    build_image(cenv)
    cid = prepared(cenv, tmp_path)
    cenv.cfg.image.custom = cid
    cm4(cenv, mode="open")
    n_slots = len(cenv.docker.runs_of("boot-slot.sh"))
    m = cenv.arts.stage_manifest(SERIAL, 3)
    assert m["image"]["source"] == "custom" and m["image"]["device_class"] == "cm4"
    slots = cenv.docker.runs_of("boot-slot.sh")[n_slots:]
    assert [(s["env"]["BOARD"], s["env"]["SIGN"], s["env"]["PRUNE"]) for s in slots] == [("cm4", "0", "")]
    d, _man = cenv.arts.custom.current_set(cid, "clear")
    ij_path = cenv.arts.stage_file(SERIAL, 3, "image.json")
    assert ij_path != d / "image.json" and ij_path.parent.name == "image-json"
    ij = imagejson.load(ij_path)
    assert ij["IGmeta"]["IGconf_device_class"] == "cm4"
    assert imagejson.load(d / "image.json")["IGmeta"]["IGconf_device_class"] == "pi5"     # the set is untouched
    assert m["image_json"]["sha256"] == cenv.arts.hashes.sha256(ij_path)
    # the same image for a locked CM4 in the secure scenario: signed in place, pruned for the CM4
    cm4(cenv, SERIAL2, mode="secure", lock="ours")
    cenv.export_key(SERIAL2)
    m2 = cenv.arts.stage_manifest(SERIAL2, 3)
    assert m2["image"]["device_class"] == "cm4" and m2["mode"] == "signed"
    slot = cenv.docker.runs_of("boot-slot.sh")[-1]
    assert (slot["env"]["BOARD"], slot["env"]["SIGN"], slot["env"]["INPLACE"], slot["env"]["PRUNE"]) == (
        "cm4", "1", "1", "cm4")
    ij2 = json.loads(cenv.arts.stage_file(SERIAL2, 3, "image.json").read_text(encoding="utf-8"))
    assert ij2["IGmeta"]["IGconf_device_class"] == "cm4"


def test_with_device_class():
    ij = {"IGmeta": {"IGconf_device_class": "pi5", "x": 1}, "layout": {}}
    out = imagejson.with_device_class(ij, "cm4")
    assert out["IGmeta"] == {"IGconf_device_class": "cm4", "x": 1} and ij["IGmeta"]["IGconf_device_class"] == "pi5"
    assert imagejson.with_device_class({"layout": {}}, "cm4")["IGmeta"] == {"IGconf_device_class": "cm4"}


# ---------------------------------------------------------------------- boot-slot.sh's board checks (real bash)
def _bash_functions(*names: str) -> str:
    import re
    from otp_server.config import REPO_ROOT
    text = (REPO_ROOT / "docker" / "scripts" / "boot-slot.sh").read_text(encoding="utf-8").replace("\r\n", "\n")
    out = ['die() { echo "ERROR: $*" >&2; exit 1; }']
    for name in names:
        m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
        assert m, name
        out.append(m.group(0))
    return "\n".join(out)


def _bash(script: str, *args: str, env: dict | None = None):
    import os
    import subprocess
    from test_stage1 import _bash as find_bash
    bash = find_bash()
    if bash is None:
        pytest.skip("no usable bash")
    return subprocess.run([bash, "-c", script, "bash", *args], capture_output=True, text=True, timeout=30,
                          env={**os.environ, **(env or {})})


@pytest.mark.parametrize("board, files, error", [
    ("pi5", ["kernel_2712.img", "config.txt"], ""),
    ("pi5", ["kernel8.img"], ""),
    ("pi5", ["config.txt"], "no Raspberry Pi 5 kernel"),
    ("cm4", ["KERNEL8.IMG", "start4.elf", "fixup4.dat"], ""),
    ("cm4", ["kernel_2712.img", "start4.elf", "fixup4.dat"], "no Compute Module 4 kernel"),
    ("cm4", ["kernel8.img", "fixup4.dat"], "no Compute Module 4 firmware"),
])
def test_boot_slot_checks_the_board_files(tmp_path, board, files, error):
    listing = tmp_path / "root.txt"
    listing.write_text("".join(f"::/{f}\n" for f in files), encoding="ascii")
    cp = _bash(_bash_functions("check_board_files") + '\ncheck_board_files "$1"\necho ok\n', listing.as_posix(),
               env={"BOARD": board})
    if error:
        assert cp.returncode != 0 and error in cp.stderr, cp.stderr
    else:
        assert cp.returncode == 0 and cp.stdout.strip() == "ok", cp.stderr


def test_boot_slot_refuses_cm4_firmware_without_the_key_lock(tmp_path):
    fw = tmp_path / "fw"
    fw.mkdir()
    (fw / "start4.elf").write_bytes(b"\x7fELF...lock_device_private_key\0...")
    (fw / "start4cd.elf").write_bytes(b"\x7fELF...lock_device_private_key\0...")
    script = _bash_functions("check_firmware_lock") + '\ncheck_firmware_lock "$1"\n'
    cp = _bash(script, fw.as_posix())
    assert cp.returncode == 0 and "start4.elf: knows lock_device_private_key" in cp.stdout, cp.stderr
    (fw / "start4cd.elf").write_bytes(b"\x7fELF...an old firmware...")
    cp = _bash(script, fw.as_posix())
    assert cp.returncode != 0 and "start4cd.elf predates lock_device_private_key" in cp.stderr
    empty = tmp_path / "empty"
    empty.mkdir()
    cp = _bash(script, empty.as_posix())
    assert cp.returncode != 0 and "no start4*.elf" in cp.stderr


def test_boot_slot_script_wires_the_board():
    from otp_server.config import REPO_ROOT
    text = (REPO_ROOT / "docker" / "scripts" / "boot-slot.sh").read_text(encoding="utf-8")
    assert 'rpi-make-boot-image -b "${BOARD}" -a 64' in text
    assert 'case "${BOARD}" in pi5|cm4) ;;' in text and 'case "${PRUNE}" in ""|pi5|cm4) ;;' in text
    # the CM4 firmware is checked before boot.img is made from the slot, and inside a prebuilt boot.img
    assert 'check_firmware_lock "${WORK}/slot"' in text and 'check_firmware_lock "${WORK}/inner-fw"' in text


# ---------------------------------------------------------------------- WinUSB
def test_winusb_reports_the_cm4_boot_rom(tmp_path):
    from otp_server import winusb
    from test_cli import RPI_INF, WDI_FASTBOOT_INF, _write
    _write(tmp_path, "oem45.inf", RPI_INF)
    r = winusb.scan(tmp_path)
    assert r["rpiboot_cm4"] is True and "0a5c:2711" in r["detail"]
    d2 = tmp_path / "only-fastboot"
    d2.mkdir()
    _write(d2, "oem7.inf", WDI_FASTBOOT_INF, "utf-16")
    r2 = winusb.scan(d2)
    assert r2["rpiboot_cm4"] is False and "only needed for CM4 boards" in r2["detail"]
