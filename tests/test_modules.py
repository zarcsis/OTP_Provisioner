from __future__ import annotations

import json
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from otp_server.modules import STAGE_LABELS, STAGES, ZERO_HASH, ModuleService, normalize_serial
from otp_server.secrets_gen import customer_key_hash, luks_passphrase, public_key_fingerprint
from otp_server.storage import LocalJsonStore

EC_PEM = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def md_ok(**kw):
    md = {
        "USER_SERIAL_NUM": "a7eb274c",
        "MAC_ADDR": "2C:CF:67:70:76:F3",
        "EEPROM_UPDATE": "success",
        "USER_BOARDREV": "B04170",
        "FACTORY_UUID": "1234567890",
        "CUSTOMER_KEY_HASH": ZERO_HASH,
    }
    md.update(kw)
    return md


def s1(metadata, ok=True, expect=None, **kw):
    r = {"ok": ok, "metadata": metadata, "files_served": [{"name": "bootcode5.bin", "size": 104314}],
         "interrupted": False, "error": None,
         "expect": expect or {"secure_boot_provision": False, "customer_key_hash": None}}
    r.update(kw)
    return r


# --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw, want", [
    ("a7eb274c", "a7eb274c"),
    (" A7EB274C\x00 ", "a7eb274c"),
    ("10000000a7eb274c", "a7eb274c"),
    ("10000000A7EB274C\x00\n", "a7eb274c"),
    (b"a7eb274c", "a7eb274c"),
])
def test_normalize_serial_ok(raw, want):
    assert normalize_serial(raw) == want


@pytest.mark.parametrize("raw", ["", "Broadcom", "a7eb274", "a7eb274cd", "g7eb274c", "0x a7eb274c", None, "1234567890ab"])
def test_normalize_serial_bad(raw):
    with pytest.raises(ValueError, match="no usable USB serial"):
        normalize_serial(raw)


def test_constants():
    assert STAGES == ("new", "eeprom", "gadget", "flashed")
    assert STAGE_LABELS["gadget"] == "Fastboot gadget booted"
    assert ZERO_HASH == "0" * 64


def test_hello_creates_then_reuses(module_service: ModuleService, store):
    info = {"chip": "BCM2712", "board": "Pi 5 / CM5 / Pi 500", "rom_stage": "bootrom",
            "usb": {"vendor_id": 0x0A5C, "product_id": 0x2712, "product_name": "BCM2712 Boot",
                    "manufacturer": "Broadcom", "serial_number": "a7eb274c", "junk": {"x": 1}}}
    rec, created = module_service.hello("A7EB274C", info)
    assert created is True
    assert rec["serial"] == "a7eb274c" and rec["stage"] == "new"
    assert rec["chip"] == "BCM2712" and rec["board"] == "Pi 5 / CM5 / Pi 500"
    assert rec["rsa_private_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    assert rec["customer_key_hash"] == customer_key_hash(rec["rsa_public_pem"])
    assert len(rec["device_secret"]) == 64
    assert rec["facts"]["usb"]["product_id"] == 0x2712 and "junk" not in rec["facts"]["usb"]
    assert rec["facts"]["rom_stage"] == "bootrom"
    assert rec["events"][-1]["kind"] == "hello" and rec["created"] and rec["updated"]
    assert store.get("a7eb274c") == rec

    rec2, created2 = module_service.hello("10000000a7eb274c", {"chip": ""})
    assert created2 is False
    for k in ("rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret", "created"):
        assert rec2[k] == rec[k], k  # secrets are never regenerated
    assert rec2["chip"] == "BCM2712"  # empty info does not wipe
    assert [e["kind"] for e in rec2["events"]] == ["hello", "hello"]


def test_hello_bad_serial(module_service):
    with pytest.raises(ValueError):
        module_service.hello("Broadcom")
    assert module_service.list() == []


def test_hello_repairs_partial_secrets(module_service, store):
    rec, _ = module_service.hello("a7eb274c")
    priv = rec["rsa_private_pem"]
    store.put({**rec, "rsa_public_pem": "", "customer_key_hash": "", "device_secret": ""})
    rec2, _ = module_service.hello("a7eb274c")
    assert rec2["rsa_private_pem"] == priv
    assert rec2["rsa_public_pem"] == rec["rsa_public_pem"]
    assert rec2["customer_key_hash"] == rec["customer_key_hash"]
    assert len(rec2["device_secret"]) == 64


def test_identify_fastboot(module_service):
    module_service.hello("a7eb274c")
    rec, created = module_service.identify_fastboot(
        " 10000000A7EB274C\x00", {"product": "rpi5", "secure": "no", "max-download-size": "0x10000000",
                                  "serialno": "x", "evil": "y"})
    assert created is False
    assert rec["duid"] == "10000000a7eb274c"
    assert rec["stage"] == "gadget"
    assert rec["facts"]["fastboot"] == {"product": "rpi5", "secure": "no", "max-download-size": "0x10000000"}
    assert rec["events"][-1]["kind"] == "fastboot"
    # never moves a flashed board backwards; unknown board gets created with secrets
    rec2, created2 = module_service.identify_fastboot("20000000deadbeef")
    assert created2 is True and rec2["stage"] == "gadget" and rec2["rsa_private_pem"]
    module_service.record_result("a7eb274c", 3, {"ok": True, "error": None, "details": {}})
    rec3, _ = module_service.identify_fastboot("10000000a7eb274c")
    assert rec3["stage"] == "flashed"


def test_get_require_list(module_service):
    assert module_service.get("a7eb274c") is None
    assert module_service.get("Broadcom") is None
    with pytest.raises(KeyError):
        module_service.require("a7eb274c")
    with pytest.raises(KeyError):
        module_service.require("nonsense")
    module_service.hello("a7eb274c")
    module_service.hello("bbbbbbbb")
    assert module_service.require("10000000a7eb274c")["serial"] == "a7eb274c"
    # newest updated first
    lst = module_service.list()
    assert {r["serial"] for r in lst} == {"a7eb274c", "bbbbbbbb"}
    assert lst[0]["updated"] >= lst[1]["updated"]


def test_list_sorted_by_updated(cfg, store):
    svc = ModuleService(cfg, store)
    store.put({"serial": "aaaaaaaa", "updated": "2026-09-30T10:00:00Z"})
    store.put({"serial": "bbbbbbbb", "updated": "2026-09-30T12:00:00Z"})
    store.put({"serial": "cccccccc", "updated": "2026-09-30T11:00:00Z"})
    assert [r["serial"] for r in svc.list()] == ["bbbbbbbb", "cccccccc", "aaaaaaaa"]


def test_add_facts(module_service):
    module_service.hello("a7eb274c")
    rec = module_service.add_facts("a7eb274c", {
        "device_key_pem": EC_PEM.replace("\n", "\r\n"),
        "duid": "10000000A7EB274C\x00",
        "fastboot_vars": {"secure-otp": "yes", "nope": "x"},
        "event": {"kind": "note", "note": "hello from page"},
        "ignored": 1,
    })
    assert rec["device_key_pem"] == EC_PEM
    assert rec["duid"] == "10000000a7eb274c"
    assert rec["facts"]["fastboot"] == {"secure-otp": "yes"}
    kinds = [e["kind"] for e in rec["events"]]
    assert "device_key" in kinds and kinds[-1] == "note"
    for bad in ({"device_key_pem": "garbage"}, {"device_key_pem": "-----BEGIN PRIVATE KEY-----"},
                {"duid": "xyz"}, {"fastboot_vars": [1]}, {"event": {"note": "no kind"}}):
        with pytest.raises(ValueError):
            module_service.add_facts("a7eb274c", bad)
    with pytest.raises(KeyError):
        module_service.add_facts("bbbbbbbb", {"duid": "ab"})


def test_stage1_unsigned_ok(module_service):
    module_service.hello("a7eb274c")
    rec, v = module_service.record_result("a7eb274c", 1, s1(md_ok()))
    assert v == {"ok": True, "notes": []}
    assert rec["stage"] == "eeprom"
    assert rec["mac"] == "2c:cf:67:70:76:f3" and rec["boardrev"] == "b04170"
    assert rec["factory_uuid"] == "1234567890"
    assert rec["otp_key_hash"] == ZERO_HASH and rec["secure_boot_provisioned"] is False
    assert rec["metadata"]["EEPROM_UPDATE"] == "success"
    assert rec["facts"]["stage1"]["ok"] is True
    assert rec["facts"]["stage1"]["files_served"] == [{"name": "bootcode5.bin", "size": 104314}]
    assert rec["events"][-1]["kind"] == "stage1" and rec["events"][-1]["note"] == "ok"
    assert not module_service.is_locked(rec) and not module_service.locked_to_our_key(rec)


def test_stage1_failures(module_service):
    module_service.hello("a7eb274c")
    md = md_ok()
    del md["EEPROM_UPDATE"]
    rec, v = module_service.record_result("a7eb274c", 1, s1(md))
    assert v["ok"] is False and "no EEPROM_UPDATE in metadata" in v["notes"]
    assert rec["stage"] == "new"
    assert rec["events"][-1]["note"].startswith("failed: no EEPROM_UPDATE")
    rec, v = module_service.record_result("a7eb274c", 1, s1(md_ok(EEPROM_UPDATE="failed")))
    assert v["ok"] is False and "EEPROM_UPDATE=failed" in v["notes"]
    rec, v = module_service.record_result("a7eb274c", 1, s1({}, ok=False, error="USB disconnected", interrupted=True))
    assert v["ok"] is False
    assert v["notes"][0] == "page reported failure: USB disconnected"
    assert "run was interrupted" in v["notes"]
    assert rec["stage"] == "new"
    assert rec["events"][-1]["note"].startswith("failed: page reported failure: USB disconnected")


def test_stage1_serial_mismatch_is_a_note(module_service):
    module_service.hello("a7eb274c")
    rec, v = module_service.record_result("a7eb274c", 1, s1(md_ok(USER_SERIAL_NUM="deadbeef")))
    assert v["ok"] is True and any("USER_SERIAL_NUM" in n for n in v["notes"])
    assert rec["events"][-1]["note"] == "ok"


def test_stage1_secure_boot(module_service):
    rec, _ = module_service.hello("a7eb274c")
    ours = rec["customer_key_hash"]
    expect = {"secure_boot_provision": True, "customer_key_hash": ours}
    # recovery did not provision
    rec, v = module_service.record_result("a7eb274c", 1, s1(md_ok(), expect=expect))
    assert v["ok"] is False and any("SECURE_BOOT_PROVISION" in n for n in v["notes"])
    assert rec["stage"] == "new"
    # provisioned to a different key
    other = "ab" * 32
    rec, v = module_service.record_result("a7eb274c", 1, s1(
        md_ok(SECURE_BOOT_PROVISION="success", CUSTOMER_KEY_HASH=other.upper()), expect=expect))
    assert v["ok"] is False and any("does not match" in n for n in v["notes"])
    assert rec["otp_key_hash"] == other and rec["secure_boot_provisioned"] is True
    assert module_service.is_locked(rec) and not module_service.locked_to_our_key(rec)
    # provisioned to our key
    rec, v = module_service.record_result("a7eb274c", 1, s1(
        md_ok(SECURE_BOOT_PROVISION="success", CUSTOMER_KEY_HASH=ours.upper()), expect=expect))
    assert v == {"ok": True, "notes": []}
    assert rec["stage"] == "eeprom" and rec["otp_key_hash"] == ours
    assert module_service.locked_to_our_key(rec)
    # OTP is permanent: a later report without SECURE_BOOT_PROVISION does not downgrade the flag
    rec, v = module_service.record_result("a7eb274c", 1, s1(md_ok(CUSTOMER_KEY_HASH=ours)))
    assert v["ok"] is True and rec["secure_boot_provisioned"] is True


def test_stage1_warns_when_locked_to_foreign_key(module_service):
    module_service.hello("a7eb274c")
    _, v = module_service.record_result("a7eb274c", 1, s1(md_ok(CUSTOMER_KEY_HASH="cd" * 32)))
    assert v["ok"] is True and any("different key" in n for n in v["notes"])


def test_stage2(module_service):
    module_service.hello("a7eb274c")
    rec, v = module_service.record_result("a7eb274c", 2, {"ok": True, "files_served": [{"name": "bootfiles.bin", "size": 1}]})
    assert v["ok"] is False and rec["stage"] == "new"
    rec, v = module_service.record_result("a7eb274c", 2, {
        "ok": True, "files_served": [{"name": "bootfiles.bin", "size": 1}, {"name": "boot.img", "size": 2}]})
    assert v == {"ok": True, "notes": []} and rec["stage"] == "gadget"
    assert rec["events"][-1] == {**rec["events"][-1], "kind": "stage2", "note": "ok"}
    rec, v = module_service.record_result("a7eb274c", 2, {"ok": False, "error": "timeout", "files_served": [{"name": "boot.img"}]})
    assert v["ok"] is False and rec["stage"] == "gadget"  # never moves backwards


def test_stage3(module_service):
    module_service.hello("a7eb274c")
    rec, v = module_service.record_result("a7eb274c", 3, {
        "ok": False, "error": "flash failed",
        "details": {"flashed": ["boot.vfat.sparse"], "crypt": [], "device_key_pem": EC_PEM}})
    assert v["ok"] is False and rec["stage"] == "new"
    assert rec["device_key_pem"] == EC_PEM  # stored even on failure (fwcrypto init is irreversible)
    rec, v = module_service.record_result("a7eb274c", 3, {
        "ok": True, "error": None,
        "details": {"flashed": ["boot.vfat.sparse", "root.ext4.sparse.0"],
                    "crypt": [{"dev": "mmcblk0p2", "mname": "osroot_crypt", "passphrase": "SECRET" * 10}],
                    "device_key_pem": None}})
    assert v["ok"] is True and rec["stage"] == "flashed"
    assert rec["facts"]["stage3"]["crypt"] == [{"dev": "mmcblk0p2", "mname": "osroot_crypt"}]
    assert "SECRET" not in json.dumps(rec["facts"])
    assert rec["events"][-1]["kind"] == "stage3"


def test_record_result_bad_input(module_service):
    module_service.hello("a7eb274c")
    for bad in (0, 4, "x"):
        with pytest.raises(ValueError):
            module_service.record_result("a7eb274c", bad, {"ok": True})
    with pytest.raises(KeyError):
        module_service.record_result("bbbbbbbb", 1, {"ok": True})
    rec, v = module_service.record_result("a7eb274c", "2", {"ok": True, "files_served": [{"name": "boot.img"}]})
    assert v["ok"] is True


def test_public_view(module_service):
    rec, _ = module_service.hello("a7eb274c", {"chip": "BCM2712"})
    rec, _ = module_service.record_result("a7eb274c", 1, s1(md_ok()))
    module_service.add_facts("a7eb274c", {"device_key_pem": EC_PEM})
    rec = module_service.require("a7eb274c")
    view = module_service.public_view(rec)
    text = json.dumps(view)
    assert rec["rsa_private_pem"].splitlines()[1] not in text
    assert rec["device_secret"] not in text
    assert "rsa_private_pem" not in text and "PRIVATE KEY" not in text
    assert "device_secret" not in view and view["secrets"]["device_secret"] is True  # only a flag
    assert set(view) == {"serial", "stage", "stage_label", "created", "updated", "chip", "board", "duid", "mac",
                         "factory_uuid", "boardrev", "secrets", "otp", "metadata", "facts", "events"}
    assert view["stage"] == "eeprom" and view["stage_label"] == "EEPROM flashed"
    assert view["secrets"] == {"rsa_key": True, "customer_key_hash": rec["customer_key_hash"], "device_secret": True,
                               "rsa_key_fingerprint": public_key_fingerprint(rec["rsa_public_pem"])}
    assert view["otp"] == {"customer_key_hash": ZERO_HASH, "locked": False, "locked_to_our_key": False,
                           "secure_boot_provisioned": False, "device_key": True,
                           "device_key_fingerprint": public_key_fingerprint(EC_PEM)}
    assert view["events"][-1]["kind"] == "device_key"
    empty = module_service.public_view({"serial": "cccccccc"})
    assert empty["secrets"]["rsa_key"] is False and empty["secrets"]["rsa_key_fingerprint"] == ""
    assert empty["otp"]["customer_key_hash"] == "" and empty["otp"]["locked"] is False


def test_secrets_for(module_service, store):
    rec, _ = module_service.hello("a7eb274c")
    s = module_service.secrets_for("10000000a7eb274c")
    assert s == {k: rec[k] for k in ("rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret")}
    assert len(luks_passphrase(s["device_secret"], "osroot_crypt", "a7eb274c")) == 64
    with pytest.raises(KeyError):
        module_service.secrets_for("bbbbbbbb")
    store.put({"serial": "cccccccc"})  # a record without secrets gets them on demand
    s2 = module_service.secrets_for("cccccccc")
    assert s2["rsa_private_pem"] and store.get("cccccccc")["device_secret"] == s2["device_secret"]


def test_events_capped(module_service):
    for _ in range(105):
        module_service.hello("a7eb274c")
    assert len(module_service.require("a7eb274c")["events"]) == 100


def test_concurrent_updates_do_not_lose_events(cfg, tmp_path):
    svc = ModuleService(cfg, LocalJsonStore(tmp_path / "reg"))
    svc.hello("a7eb274c")
    errors = []

    def worker(i):
        try:
            svc.add_facts("a7eb274c", {"event": {"kind": f"k{i}", "note": ""}})
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    kinds = {e["kind"] for e in svc.require("a7eb274c")["events"]}
    assert {f"k{i}" for i in range(20)} <= kinds


# --------------------------------------------------------------------------------------------------
# stage 2 hand-off and the operator OTP overrides
# --------------------------------------------------------------------------------------------------


def test_stage2_handoff_after_boot_img_is_not_an_interruption(module_service):
    module_service.hello("a7eb274c")
    # The board drops off USB right after boot.img: that is the gadget ramdisk taking over.
    rec, v = module_service.record_result("a7eb274c", 2, {
        "ok": True, "interrupted": True,
        "files_served": [{"name": "bootfiles.bin", "size": 1}, {"name": "boot.img", "size": 2}]})
    assert v == {"ok": True, "notes": []} and rec["stage"] == "gadget"
    assert rec["events"][-1]["note"] == "ok"
    # Interrupted before boot.img went out: still reported.
    _, v = module_service.record_result("a7eb274c", 2, {
        "ok": False, "interrupted": True, "files_served": [{"name": "bootfiles.bin", "size": 1}]})
    assert "run was interrupted" in v["notes"]
    # Other stages keep the note.
    _, v = module_service.record_result("a7eb274c", 1, s1(md_ok(), interrupted=True))
    assert "run was interrupted" in v["notes"]


def test_mark_locked_and_unlocked(module_service, store):
    rec, _ = module_service.hello("a7eb274c")
    ours = rec["customer_key_hash"]
    assert not module_service.locked_to_our_key(rec)
    rec = module_service.mark_locked("A7EB274C", "CLI")
    assert rec["otp_key_hash"] == ours and rec["secure_boot_provisioned"] is True
    assert module_service.locked_to_our_key(rec) and module_service.locked_to_our_key(store.get("a7eb274c"))
    assert rec["events"][-1]["kind"] == "otp_override" and ours in rec["events"][-1]["note"]
    assert "PRIVATE" not in json.dumps(rec["events"])
    assert rec["customer_key_hash"] == ours  # the key is never replaced

    rec = module_service.mark_unlocked("a7eb274c")
    assert rec["otp_key_hash"] == "" and rec["secure_boot_provisioned"] is False
    assert not module_service.is_locked(store.get("a7eb274c"))
    assert rec["events"][-1]["kind"] == "otp_override" and "unlocked" in rec["events"][-1]["note"]

    with pytest.raises(KeyError):
        module_service.mark_locked("bbbbbbbb")
    with pytest.raises(KeyError):
        module_service.mark_unlocked("bbbbbbbb")


def test_mark_locked_refuses_a_module_without_key(module_service, store):
    from otp_server.storage.base import normalize_record

    store.put(normalize_record({"serial": "deadbeef", "stage": "new", "created": "x", "updated": "x"}))
    with pytest.raises(ValueError, match="no private signing key"):
        module_service.mark_locked("deadbeef")
    rec = store.get("deadbeef")
    assert rec["otp_key_hash"] == "" and not rec["rsa_private_pem"]


def test_mark_locked_never_generates_a_key(module_service, store):
    """A record that lost its private key (only the public PEM / hash left) is refused, never re-keyed."""
    from otp_server.secrets_gen import customer_key_hash, generate_rsa_keypair
    from otp_server.storage.base import normalize_record

    priv, pub = generate_rsa_keypair()
    h = customer_key_hash(pub)
    store.put(normalize_record({"serial": "c0ffee01", "stage": "eeprom", "created": "x", "updated": "x",
                                "rsa_public_pem": pub, "customer_key_hash": h}))
    with pytest.raises(ValueError, match="no private signing key"):
        module_service.mark_locked("c0ffee01")
    rec = store.get("c0ffee01")
    assert rec["rsa_public_pem"] == pub and rec["customer_key_hash"] == h and rec["otp_key_hash"] == ""

    # private key present, public PEM missing: derived from the private key, not regenerated
    store.put(normalize_record({"serial": "c0ffee02", "stage": "eeprom", "created": "x", "updated": "x",
                                "rsa_private_pem": priv}))
    module_service.mark_locked("c0ffee02")
    rec = store.get("c0ffee02")
    assert rec["rsa_private_pem"] == priv and rec["customer_key_hash"] == h and rec["otp_key_hash"] == h

    # a stored hash that does not match the key is refused
    store.put(normalize_record({"serial": "c0ffee03", "stage": "eeprom", "created": "x", "updated": "x",
                                "rsa_private_pem": priv, "rsa_public_pem": pub, "customer_key_hash": "ab" * 32}))
    with pytest.raises(ValueError, match="does not match"):
        module_service.mark_locked("c0ffee03")
