from __future__ import annotations

import json
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from memstore import MemoryStore
from otp_server.modules import MODES, STAGE_LABELS, STAGES, ZERO_HASH, ModuleService, normalize_serial
from otp_server.secrets_gen import customer_key_hash, luks_passphrase, public_key_fingerprint

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
    assert MODES == ("open", "secure")
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


# ---------------------------------------------------------------------- an OTP lock the board has not reported
SECURE_SERVED = [{"name": "config.txt", "size": 72}, {"name": "pieeprom.sig", "size": 80},
                 {"name": "pieeprom.bin", "size": 2097152}]


def _interrupted_secure_run(ms, serial="a7eb274c", served=SECURE_SERVED):
    rec = ms.require(serial)
    expect = {"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"]}
    return ms.record_result(serial, 1, s1({}, ok=False, expect=expect, interrupted=True, files_served=served))


def test_an_interrupted_secure_stage1_after_the_eeprom_assumes_the_lock(module_service):
    ms = module_service
    ms.hello("a7eb274c")
    ms.set_mode("a7eb274c", "secure")
    # ebbdf4fd, 2026-10-06: program_pubkey=1 and the whole EEPROM went out, the report never came back
    rec, v = _interrupted_secure_run(ms)
    assert v["ok"] is False and any("probably holds our key hash" in n for n in v["notes"])
    assert ms.lock_suspected(rec) and not ms.is_locked(rec) and not ms.locked_to_our_key(rec)
    assert ms.lock_assumption(rec)["state"] == "suspected" and "pieeprom.bin" in ms.lock_assumption(rec)["why"]
    assert rec["events"][-2]["kind"] == "otp_lock" and rec["events"][-1]["kind"] == "stage1"
    view = ms.public_view(rec)
    assert view["otp"]["lock_suspected"] is True and view["otp"]["lock_note"] and view["mode_locked"] is True
    assert ms.mode_of(rec) == "secure"
    with pytest.raises(ValueError, match="probably holds"):
        ms.set_mode("a7eb274c", "open")
    # the board reports its OTP at the next stage 1 (counter-signed second stage, no program_pubkey): settled
    rec, v = ms.record_result("a7eb274c", 1, s1(md_ok(CUSTOMER_KEY_HASH=rec["customer_key_hash"])))
    assert v["ok"] is True and ms.locked_to_our_key(rec) and not ms.lock_suspected(rec)
    assert "otp_lock" not in rec["facts"]


@pytest.mark.parametrize("served, mode", [
    (SECURE_SERVED[:1], "secure"),                       # the board never got the EEPROM: nothing was written
    (SECURE_SERVED, "open"),                             # no program_pubkey: OTP untouched
])
def test_other_broken_runs_assume_nothing(module_service, served, mode):
    ms = module_service
    ms.hello("a7eb274c")
    ms.set_mode("a7eb274c", mode)
    rec = ms.require("a7eb274c")
    expect = ({"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"]} if mode == "secure"
              else None)
    rec, v = ms.record_result("a7eb274c", 1, s1({}, ok=False, expect=expect, interrupted=True, files_served=served))
    assert v["ok"] is False and not ms.lock_suspected(rec) and "otp_lock" not in rec["facts"]


def test_a_refused_second_stage_flips_the_assumption(module_service):
    ms = module_service
    ms.hello("a7eb274c")
    ms.set_mode("a7eb274c", "secure")

    def refused(variant):
        return ms.record_result("a7eb274c", 1, s1({}, ok=False, error="refused", files_served=[],
                                                  second_stage_rejected=True, recovery=variant))

    rec, v = refused("plain")                         # the ROM wants a counter-signed second stage: locked
    assert v["ok"] is False and ms.lock_suspected(rec) and any("refused the plain" in n for n in v["notes"])
    assert rec["facts"]["stage1"]["second_stage_rejected"] == "plain"
    rec, v = refused("countersigned")                 # ... but not to our key either: both refused
    assert not ms.lock_suspected(rec) and ms.recovery_refused_both(rec)
    assert any("refused both" in n for n in v["notes"])
    rec = ms.mark_unlocked("a7eb274c")                # the operator checked the board: start over
    assert not ms.recovery_refused_both(rec) and "otp_lock" not in rec["facts"]

    rec, v = _interrupted_secure_run(ms)              # assumed locked ...
    rec, v = refused("countersigned")                 # ... the ROM says no: plain + program_pubkey next time
    assert not ms.lock_suspected(rec) and not ms.recovery_refused_both(rec)
    assert any("holds no key hash" in n for n in v["notes"]) and ms.mode_of(rec) == "secure"
    _, v = refused("bogus")
    assert any("did not say which" in n for n in v["notes"])


def test_a_refused_countersigned_stage_undoes_only_an_operator_mark(module_service):
    ms = module_service
    ms.hello("a7eb274c")
    rec = ms.mark_locked("a7eb274c")                   # the operator's guess, never confirmed by the board
    rec, _ = ms.record_result("a7eb274c", 1, s1({}, ok=False, files_served=[], second_stage_rejected=True,
                                                recovery="countersigned"))
    assert not ms.is_locked(rec) and rec["secure_boot_provisioned"] is False
    # the board itself reported our key hash: a refusal does not overrule that
    ours = rec["customer_key_hash"]
    ms.record_result("a7eb274c", 1, s1(md_ok(CUSTOMER_KEY_HASH=ours, SECURE_BOOT_PROVISION="success")))
    rec, v = ms.record_result("a7eb274c", 1, s1({}, ok=False, files_served=[], second_stage_rejected=True,
                                                recovery="countersigned"))
    assert ms.locked_to_our_key(rec) and any("USB cable" in n for n in v["notes"])


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
        "details": {"flashed": ["boot.vfat.sparse"], "device_key_pem": EC_PEM}})
    assert v["ok"] is False and rec["stage"] == "new"
    assert rec["device_key_pem"] == EC_PEM  # stored even on failure (fwcrypto init is irreversible)
    rec, v = module_service.record_result("a7eb274c", 3, {
        "ok": True, "error": None,
        "details": {"flashed": ["boot.vfat.sparse", "root.ext4.sparse.0"],
                    "crypt": [{"dev": "mmcblk0p2", "mname": "osroot_crypt", "passphrase": "SECRET" * 10}],
                    "device_key_pem": None}})
    assert v["ok"] is True and rec["stage"] == "flashed"
    assert "crypt" not in rec["facts"]["stage3"]          # not something the station asks for: not kept
    assert "SECRET" not in json.dumps(rec)
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
    assert set(view) == {"serial", "stage", "stage_label", "mode", "mode_chosen", "mode_locked", "created", "updated",
                         "chip", "board", "duid", "mac", "factory_uuid", "boardrev", "secrets", "otp", "metadata",
                         "facts", "events"}
    assert view["stage"] == "eeprom" and view["stage_label"] == "EEPROM flashed"
    assert (view["mode"], view["mode_chosen"], view["mode_locked"]) == ("open", "", False)  # cfg default_mode
    assert view["secrets"] == {"rsa_key": True, "customer_key_hash": rec["customer_key_hash"], "device_secret": True,
                               "rsa_key_fingerprint": public_key_fingerprint(rec["rsa_public_pem"])}
    assert view["otp"] == {"customer_key_hash": ZERO_HASH, "locked": False, "locked_to_our_key": False,
                           "secure_boot_provisioned": False, "lock_suspected": False, "lock_note": "", "device_key": True,
                           "device_key_fingerprint": public_key_fingerprint(EC_PEM),
                           "device_key_exported": False}
    assert view["events"][-1]["kind"] == "device_key"
    empty = module_service.public_view({"serial": "cccccccc"})
    assert empty["secrets"]["rsa_key"] is False and empty["secrets"]["rsa_key_fingerprint"] == ""
    assert empty["otp"]["customer_key_hash"] == "" and empty["otp"]["locked"] is False
    assert empty["otp"]["device_key_exported"] is False and empty["mode"] == "open" and empty["mode_chosen"] == ""


def test_secrets_for(module_service, store):
    rec, _ = module_service.hello("a7eb274c")
    s = module_service.secrets_for("10000000a7eb274c")
    assert s == {k: rec[k] for k in ("rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret",
                                     "device_private_pem")}
    assert s["device_private_pem"] == ""  # nothing exported yet
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


def test_concurrent_updates_do_not_lose_events(cfg):
    svc = ModuleService(cfg, MemoryStore())
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


# --------------------------------------------------------------------------------------------------
# scenarios: mode_of / set_mode
# --------------------------------------------------------------------------------------------------


@pytest.fixture
def svc_open(make_cfg, tmp_path, store):
    return ModuleService(make_cfg(tmp_path / "open"), store)


@pytest.fixture
def svc_secure(make_cfg, tmp_path, store):
    return ModuleService(make_cfg(tmp_path / "secure", provisioning={"default_mode": "secure"}), store)


def test_mode_of_default_comes_from_cfg(svc_open, svc_secure):
    assert svc_open.cfg.provisioning.default_mode == "open"
    assert svc_secure.cfg.provisioning.default_mode == "secure"
    for rec in ({"serial": "a7eb274c"}, {"serial": "a7eb274c", "mode": ""},
                {"serial": "a7eb274c", "mode": "bogus"}, {}):
        assert svc_open.mode_of(rec) == "open", rec
        assert svc_secure.mode_of(rec) == "secure", rec
    assert svc_secure.mode_of(None) == "secure"


def test_mode_of_chosen_mode_wins_over_the_default(svc_open, svc_secure):
    assert svc_open.mode_of({"serial": "a7eb274c", "mode": "secure"}) == "secure"
    assert svc_secure.mode_of({"serial": "a7eb274c", "mode": "open"}) == "open"
    assert svc_open.mode_of({"serial": "a7eb274c", "mode": " SECURE "}) == "secure"


def test_mode_of_locked_board_is_always_secure(svc_open, svc_secure):
    for svc in (svc_open, svc_secure):
        assert svc.mode_of({"serial": "a7eb274c", "mode": "open", "otp_key_hash": "ab" * 32}) == "secure"
        assert svc.mode_of({"serial": "a7eb274c", "otp_key_hash": "AB" * 32}) == "secure"
        assert svc.mode_of({"serial": "a7eb274c", "mode": "open", "secure_boot_provisioned": True}) == "secure"
        # an all-zero CUSTOMER_KEY_HASH is an unprogrammed OTP, not a lock
        assert svc.mode_of({"serial": "a7eb274c", "mode": "open", "otp_key_hash": ZERO_HASH}) == "open"


def test_mode_of_after_mark_locked(module_service):
    module_service.hello("a7eb274c")
    module_service.set_mode("a7eb274c", "open")
    rec = module_service.mark_locked("a7eb274c")
    assert rec["mode"] == "open" and module_service.mode_of(rec) == "secure"
    view = module_service.public_view(rec)
    assert (view["mode"], view["mode_chosen"], view["mode_locked"]) == ("secure", "open", True)


def test_set_mode_rejects_unknown_modes(module_service, store):
    module_service.hello("a7eb274c")
    before, puts = store.get("a7eb274c"), store.puts
    for bad in ("bogus", "", None, "signed", "unsigned", "open secure"):
        with pytest.raises(ValueError, match="mode must be one of open, secure"):
            module_service.set_mode("a7eb274c", bad)
    with pytest.raises(ValueError):
        module_service.set_mode("bbbbbbbb", "bogus")  # the mode is checked before the board
    with pytest.raises(KeyError):
        module_service.set_mode("bbbbbbbb", "open")
    assert store.puts == puts and store.get("a7eb274c") == before


def test_set_mode_open_is_refused_on_a_locked_board(module_service, store):
    module_service.hello("a7eb274c")
    module_service.mark_locked("a7eb274c")
    puts = store.puts
    with pytest.raises(ValueError, match="only the secure scenario is possible"):
        module_service.set_mode("a7eb274c", "open")
    assert store.puts == puts and store.get("a7eb274c")["mode"] == ""
    rec = module_service.set_mode("a7eb274c", "secure")
    assert rec["mode"] == "secure" and rec["events"][-1]["kind"] == "mode"

    # secure_boot_provisioned alone (no hash recorded) counts as locked, as does a foreign key hash
    module_service.hello("bbbbbbbb")
    module_service.hello("cccccccc")
    store.put({**store.get("bbbbbbbb"), "secure_boot_provisioned": True})
    store.put({**store.get("cccccccc"), "otp_key_hash": "cd" * 32})
    for serial in ("bbbbbbbb", "cccccccc"):
        with pytest.raises(ValueError, match="OTP holds a key hash"):
            module_service.set_mode(serial, "open")
        assert store.get(serial)["mode"] == ""


def test_set_mode_same_mode_is_a_no_op(module_service, store):
    module_service.hello("a7eb274c")
    rec = module_service.set_mode("a7eb274c", "secure")
    assert rec["mode"] == "secure"
    puts, n_events = store.puts, len(rec["events"])
    again = module_service.set_mode("a7eb274c", " Secure ")
    assert store.puts == puts  # nothing written
    assert len(again["events"]) == n_events  # no event
    assert again == rec == store.get("a7eb274c")


def test_set_mode_switch_resets_the_stage(module_service, store):
    module_service.hello("a7eb274c")
    module_service.set_mode("a7eb274c", "open")
    rec, v = module_service.record_result("a7eb274c", 1, s1(md_ok()))
    assert v["ok"] is True and rec["stage"] == "eeprom"
    rec = module_service.set_mode("a7eb274c", "secure")
    assert rec["mode"] == "secure" and rec["stage"] == "new"
    ev = rec["events"][-1]
    assert ev["kind"] == "mode"
    assert ev["note"].startswith("scenario secure (was open)")
    assert "stage eeprom reset to new" in ev["note"] and "redone" in ev["note"]
    assert store.get("a7eb274c") == rec
    assert module_service.public_view(rec)["mode"] == "secure"
    # switching back while the board is still "new": nothing to reset, no reset clause
    rec = module_service.set_mode("a7eb274c", "open")
    assert rec["stage"] == "new" and rec["events"][-1]["note"] == "scenario open (was secure)"


def test_set_mode_first_choice_keeps_the_progress(module_service, store):
    module_service.hello("a7eb274c")
    module_service.record_result("a7eb274c", 1, s1(md_ok()))
    module_service.identify_fastboot("10000000a7eb274c")
    assert store.get("a7eb274c")["stage"] == "gadget" and store.get("a7eb274c")["mode"] == ""
    # first explicit choice (the cfg default is open, so the stages already ran in this scenario)
    rec = module_service.set_mode("a7eb274c", "open")
    assert rec["stage"] == "gadget" and rec["mode"] == "open"
    assert {k: rec["events"][-1][k] for k in ("kind", "note")} == {"kind": "mode", "note": "scenario open"}
    assert store.get("a7eb274c") == rec


def test_set_mode_first_choice_other_than_the_default_redoes_the_stages(module_service, store):
    # the stages ran in the cfg default scenario (open) without an explicit choice: picking secure must
    # not leave the board "flashed" with an unsigned EEPROM and no device key
    module_service.hello("a7eb274c")
    module_service.record_result("a7eb274c", 1, s1(md_ok()))
    module_service.identify_fastboot("10000000a7eb274c")
    assert store.get("a7eb274c")["stage"] == "gadget" and store.get("a7eb274c")["mode"] == ""
    rec = module_service.set_mode("a7eb274c", "secure")
    assert rec["mode"] == "secure" and rec["stage"] == "new"
    note = rec["events"][-1]["note"]
    assert note.startswith("scenario secure (the stages so far ran as open)")
    assert "stage gadget reset to new" in note
    assert store.get("a7eb274c") == rec


# --------------------------------------------------------------------------------------------------
# OTP device key exported by the fastboot gadget (secure scenario)
# --------------------------------------------------------------------------------------------------


def _p256():
    return ec.generate_private_key(ec.SECP256R1())


def _pub(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _priv_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _der(key, fmt=serialization.PrivateFormat.TraditionalOpenSSL) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, fmt, serialization.NoEncryption())


def _scalar(pem: str) -> int:
    return serialization.load_pem_private_key(pem.encode(), password=None).private_numbers().private_value


@pytest.mark.parametrize("fmt", [serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8],
                         ids=["sec1", "pkcs8"])
def test_store_device_key_from_der(module_service, store, fmt):
    module_service.hello("a7eb274c")
    key = _p256()
    pub = _pub(key)
    rec, info = module_service.store_device_key("A7EB274C", _der(key, fmt), pub.replace("\n", "\r\n"))
    assert info == {"fingerprint": public_key_fingerprint(pub), "already": False, "zero_words": 0}
    assert rec["device_private_pem"].startswith("-----BEGIN PRIVATE KEY-----\n")  # PKCS#8
    assert "\r" not in rec["device_private_pem"]
    assert _scalar(rec["device_private_pem"]) == key.private_numbers().private_value
    assert rec["device_key_pem"] == pub
    ev = rec["events"][-1]
    assert ev["kind"] == "device_key_export" and info["fingerprint"][:16] in ev["note"]
    assert "WARNING" not in ev["note"] and "PRIVATE" not in json.dumps(rec["events"])
    assert store.get("a7eb274c") == rec


def test_store_device_key_raw_scalar(module_service):
    module_service.hello("a7eb274c")
    key = _p256()
    raw = key.private_numbers().private_value.to_bytes(32, "big")
    rec, info = module_service.store_device_key("a7eb274c", raw, _pub(key))
    assert info["already"] is False and info["zero_words"] == 0
    assert _scalar(rec["device_private_pem"]) == key.private_numbers().private_value
    assert rec["device_key_pem"] == _pub(key)


def test_store_device_key_keeps_a_matching_reported_key(module_service):
    """The board reported its public key (add_facts / getvar:public-key) before the export: same key is fine."""
    module_service.hello("a7eb274c")
    key = _p256()
    module_service.add_facts("a7eb274c", {"device_key_pem": _pub(key)})
    rec, info = module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    assert info["already"] is False and rec["device_private_pem"] and rec["device_key_pem"] == _pub(key)


def test_store_device_key_must_match_the_reported_key(module_service, store):
    module_service.hello("a7eb274c")
    puts = store.puts
    with pytest.raises(ValueError, match="does not match the public key the board reports"):
        module_service.store_device_key("a7eb274c", _der(_p256()), _pub(_p256()))
    rec = store.get("a7eb274c")
    assert store.puts == puts and rec["device_private_pem"] == "" and rec["device_key_pem"] == ""


def test_store_device_key_must_match_the_recorded_device_key(module_service, store):
    module_service.hello("a7eb274c")
    recorded = _p256()
    module_service.add_facts("a7eb274c", {"device_key_pem": _pub(recorded)})
    puts = store.puts
    other = _p256()
    with pytest.raises(ValueError, match="differs from the one recorded"):
        module_service.store_device_key("a7eb274c", _der(other), _pub(other))
    rec = store.get("a7eb274c")
    assert store.puts == puts and rec["device_private_pem"] == "" and rec["device_key_pem"] == _pub(recorded)


def test_store_device_key_second_export(module_service, store):
    module_service.hello("a7eb274c")
    key = _p256()
    first, info1 = module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    puts = store.puts
    # the same key again (also as the other DER flavour / raw scalar): already=True, nothing written
    for data in (_der(key), _der(key, serialization.PrivateFormat.PKCS8),
                 key.private_numbers().private_value.to_bytes(32, "big")):
        again, info2 = module_service.store_device_key("a7eb274c", data, _pub(key))
        assert info2 == {**info1, "already": True}
        assert again == first
    assert store.puts == puts and store.get("a7eb274c") == first

    # a different key afterwards is refused (an OTP key cannot change)
    other = _p256()
    with pytest.raises(ValueError, match="an OTP key cannot change"):
        module_service.store_device_key("a7eb274c", _der(other), _pub(other))
    # ... also when the public PEM went missing from the record: the stored private key still decides
    store.put({**store.get("a7eb274c"), "device_key_pem": ""})
    puts = store.puts
    with pytest.raises(ValueError, match="different device private key is already stored"):
        module_service.store_device_key("a7eb274c", _der(other), _pub(other))
    assert store.puts == puts and store.get("a7eb274c")["device_private_pem"] == first["device_private_pem"]


@pytest.mark.parametrize("reported", ["", None, "garbage",
                                      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "private"],
                         ids=["empty", "none", "garbage", "private-header", "private-pem"])
def test_store_device_key_needs_a_public_pem(module_service, store, reported):
    module_service.hello("a7eb274c")
    key = _p256()
    if reported == "private":
        reported = _priv_pem(key)
    puts = store.puts
    with pytest.raises(ValueError, match="PEM public key"):
        module_service.store_device_key("a7eb274c", _der(key), reported)
    assert store.puts == puts and store.get("a7eb274c")["device_private_pem"] == ""


@pytest.mark.parametrize("data", [b"", None, b"\x30" * 1025, b"\x01" * 4096], ids=["empty", "none", "1025", "4096"])
def test_store_device_key_size_limits(module_service, store, data):
    module_service.hello("a7eb274c")
    puts = store.puts
    with pytest.raises(ValueError, match="must be 1..1024 bytes"):
        module_service.store_device_key("a7eb274c", data, _pub(_p256()))
    assert store.puts == puts


@pytest.mark.parametrize("data", [b"not a key", b"\x00" * 32, b"\xff" * 32, b"\x01" * 31],
                         ids=["text", "zero-scalar", "scalar>=n", "31-bytes"])
def test_store_device_key_rejects_unusable_keys(module_service, store, data):
    module_service.hello("a7eb274c")
    puts = store.puts
    with pytest.raises(ValueError):
        module_service.store_device_key("a7eb274c", data, _pub(_p256()))
    assert store.puts == puts


def test_store_device_key_rejects_a_p384_key(module_service, store):
    module_service.hello("a7eb274c")
    key = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ValueError, match="not an ECDSA P-256 key"):
        module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    assert store.get("a7eb274c")["device_private_pem"] == ""


def test_store_device_key_unknown_module(module_service):
    key = _p256()
    with pytest.raises(KeyError):
        module_service.store_device_key("a7eb274c", _der(key), _pub(key))


def test_store_device_key_reports_zero_otp_words(module_service):
    module_service.hello("a7eb274c")
    raw = bytearray(range(1, 33))
    raw[8:12] = b"\0\0\0\0"  # one 32-bit OTP row left blank
    d = int.from_bytes(raw, "big")
    key = ec.derive_private_key(d, ec.SECP256R1())
    rec, info = module_service.store_device_key("a7eb274c", bytes(raw), _pub(key))
    assert info["zero_words"] == 1 and info["already"] is False
    ev = rec["events"][-1]
    assert ev["kind"] == "device_key_export"
    assert "WARNING: 1 of its 8 OTP words are zero" in ev["note"]
    assert raw.hex() not in json.dumps(rec["events"])
    # the key is stored anyway (it is the board's key, weak or not)
    assert _scalar(rec["device_private_pem"]) == d
    _again, info2 = module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    assert info2 == {**info, "already": True}


def test_device_private_key_never_in_public_view(module_service):
    module_service.hello("a7eb274c")
    key = _p256()
    rec, _ = module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    view = module_service.public_view(rec)
    text = json.dumps(view)
    assert "PRIVATE KEY" not in text and "device_private_pem" not in text
    for line in rec["device_private_pem"].splitlines()[1:-1]:
        assert line not in text
    assert format(key.private_numbers().private_value, "064x") not in text
    assert view["otp"]["device_key_exported"] is True and view["otp"]["device_key"] is True
    assert view["otp"]["device_key_fingerprint"] == public_key_fingerprint(_pub(key))


def test_add_facts_refuses_a_device_key_other_than_the_exported_one(module_service, store):
    module_service.hello("a7eb274c")
    key = _p256()
    stored, _ = module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    puts = store.puts
    with pytest.raises(ValueError, match="differs from the exported one"):
        module_service.add_facts("a7eb274c", {"device_key_pem": _pub(_p256()), "duid": "10000000a7eb274c"})
    assert store.puts == puts and store.get("a7eb274c") == stored  # nothing of the request applied
    # the same key (other line endings) is accepted and does not add a device_key event
    rec = module_service.add_facts("a7eb274c", {"device_key_pem": _pub(key).replace("\n", "\r\n")})
    assert rec["device_key_pem"] == _pub(key)
    assert [e["kind"] for e in rec["events"]].count("device_key") == 0


def test_stage3_secure_needs_the_exported_device_key(module_service):
    module_service.hello("a7eb274c")
    module_service.set_mode("a7eb274c", "secure")
    module_service.record_result("a7eb274c", 2, {"ok": True, "files_served": [{"name": "boot.img"}]})
    key = _p256()
    ok_run = {"ok": True, "error": None, "details": {"flashed": ["boot.vfat.sparse"], "device_key_pem": _pub(key)}}
    rec, v = module_service.record_result("a7eb274c", 3, ok_run)
    assert v["ok"] is False
    assert "the OTP device key was not exported to the server (secure mode needs it)" in v["notes"]
    assert rec["stage"] == "gadget" and rec["facts"]["stage3"]["ok"] is False
    assert rec["events"][-1]["note"].startswith("failed: the OTP device key was not exported")
    assert rec["device_key_pem"] == _pub(key)  # the reported key is still kept

    module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    # the key is there, but the page did not prove that the board's key opens its encrypted root
    rec, v = module_service.record_result("a7eb274c", 3, ok_run)
    assert v["ok"] is False and any("oem cryptcheck" in n for n in v["notes"]) and rec["stage"] == "gadget"
    # the board's key must open keyslot 0 (its own); keyslot 1 is the recovery passphrase, a bool is not a slot
    for bad in ([{"dev": "mmcblk0p2", "keyslot": 1}], [{"dev": "mmcblk0p2", "keyslot": False}],
                [{"dev": "mmcblk0p2"}], [{"dev": "mmcblk0p2", "keyslot": 0}, {"dev": "mmcblk0p3", "keyslot": 1}]):
        ok_run["details"]["verified"] = bad
        rec, v = module_service.record_result("a7eb274c", 3, ok_run)
        assert v["ok"] is False and any("keyslot 0" in n for n in v["notes"]) and rec["stage"] == "gadget", bad
    ok_run["details"]["verified"] = [{"dev": "mmcblk0p2", "keyslot": 0, "passphrase": "x" * 64}]
    rec, v = module_service.record_result("a7eb274c", 3, ok_run)
    assert v == {"ok": True, "notes": []} and rec["stage"] == "flashed"
    assert rec["facts"]["stage3"]["verified"] == [{"dev": "mmcblk0p2", "keyslot": 0}]   # nothing else kept
    assert rec["events"][-1] == {**rec["events"][-1], "kind": "stage3", "note": "ok"}


def test_stage3_secure_by_default_mode_needs_the_key(svc_secure):
    svc_secure.hello("a7eb274c")
    _, v = svc_secure.record_result("a7eb274c", 3, {"ok": True, "details": {}})
    assert v["ok"] is False and any("not exported" in n for n in v["notes"])


def test_stage3_open_needs_no_device_key(module_service):
    module_service.hello("a7eb274c")
    module_service.set_mode("a7eb274c", "open")
    rec, v = module_service.record_result("a7eb274c", 3, {"ok": True, "details": {}})
    assert v == {"ok": True, "notes": []} and rec["stage"] == "flashed"


def test_stage3_fails_when_the_reported_key_differs_from_the_exported_one(module_service):
    module_service.hello("a7eb274c")
    module_service.set_mode("a7eb274c", "secure")
    key = _p256()
    module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    rec, v = module_service.record_result("a7eb274c", 3, {
        "ok": True, "details": {"flashed": ["boot.vfat.sparse"], "device_key_pem": _pub(_p256())}})
    assert v["ok"] is False and "the board reports a device key that differs from the exported one" in v["notes"]
    assert rec["stage"] == "new" and rec["device_key_pem"] == _pub(key)  # the recorded key is not replaced
    # with the matching key (CRLF from the page) the run counts
    rec, v = module_service.record_result("a7eb274c", 3, {
        "ok": True, "details": {"device_key_pem": _pub(key).replace("\n", "\r\n"), "verified": [{"dev": "mmcblk0p2", "keyslot": 0}]}})
    assert v["ok"] is True and rec["stage"] == "flashed" and rec["device_key_pem"] == _pub(key)


def test_secrets_for_returns_the_exported_device_key(module_service):
    module_service.hello("a7eb274c")
    assert module_service.secrets_for("a7eb274c")["device_private_pem"] == ""
    key = _p256()
    rec, _ = module_service.store_device_key("a7eb274c", _der(key), _pub(key))
    s = module_service.secrets_for("10000000a7eb274c")
    assert s["device_private_pem"] == rec["device_private_pem"]
    assert _scalar(s["device_private_pem"]) == key.private_numbers().private_value
    assert set(s) == {"rsa_private_pem", "rsa_public_pem", "customer_key_hash", "device_secret", "device_private_pem"}
