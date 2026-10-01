"""Stage 1 (EEPROM & OTP): key-hash checks, boot.conf rules per mode, fingerprint inputs, stage1.sh guards.

Self-contained: a fake repo checkout (firmware-2712 + docker/scripts) and a fake docker runner that
simulates stage1.sh by writing its outputs into the /out mount. The last tests run the real
``docker/scripts/stage1.sh`` with bash for the argument/guard checks that fail before any tool runs.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from otp_server.artifacts import Artifacts, NotReady
from otp_server.artifacts.stage1 import signed_boot_conf, unsigned_boot_conf
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.secrets_gen import customer_key_hash
from otp_server.storage.local import LocalJsonStore

SERIAL = "a7eb274c"
TOOLS_TAG = "otp-tools:latest"
REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------- fakes
def make_repo(base: Path) -> Path:
    repo = base / "repo"
    (repo / "docker" / "scripts").mkdir(parents=True)
    for name in ("tools.Dockerfile", "tools-entrypoint.sh", "gadget.Dockerfile", "gadget-entrypoint.sh"):
        (repo / "docker" / name).write_text(f"# {name}\n", encoding="utf-8")
    (repo / "docker" / "scripts" / "stage1.sh").write_text("#!/bin/bash\n# stage1.sh\n", encoding="utf-8")
    d = repo / "external" / "usbboot" / "rpi-eeprom" / "firmware-2712" / "default"
    d.mkdir(parents=True)
    (d / "pieeprom-2026-09-25.bin").write_bytes(b"\2" * 2097152)
    (d / "recovery.bin").write_bytes(b"\4" * 104314)
    (repo / "external" / "usbboot" / "tools").mkdir(parents=True)
    (repo / "external" / "usbboot" / "tools" / "update-pieeprom.sh").write_text("#!/bin/sh\n# v1\n", encoding="utf-8")
    return repo


class FakeDocker:
    """Just enough of DockerRunner for the tools image and stage1.sh."""

    def __init__(self):
        self.labels: dict[str, dict] = {}
        self.runs: list[dict] = []
        self.stage1 = self.h_stage1

    def status(self, max_age: float = 5.0) -> dict:
        return {"ok": True, "version": "29.6.0", "detail": "", "arm64": True}

    def ensure_daemon(self, log=None, timeout: float = 180.0) -> None:
        pass

    def ensure_arm64(self, log=None) -> None:
        pass

    def image_exists(self, tag: str) -> bool:
        return tag in self.labels

    def image_label(self, tag: str, label: str):
        return self.labels[tag].get(label, "") if tag in self.labels else None

    def image_info(self, tag: str):
        return {"id": "sha256:1", "created": "2026-09-30T10:00:00Z", "size": 1} if tag in self.labels else None

    def build_image(self, tag, dockerfile, context, *, platform=None, pull=False, labels=None, build_args=None,
                    log=None, **_kw) -> None:
        self.labels[tag] = dict(labels or {})

    def volume_exists(self, name: str) -> bool:
        return True

    def run(self, image, args=(), *, mounts=(), env=None, log=None, check=True, **_kw) -> int:
        call = {"image": image, "args": list(args), "mounts": {m.target: m for m in mounts}, "env": dict(env or {})}
        if "/keys" in call["mounts"]:
            kdir = Path(call["mounts"]["/keys"].source)
            call["public_pem"] = (kdir / "public.pem").read_text(encoding="ascii")
        self.runs.append(call)
        assert image == TOOLS_TAG and args[:1] == ["stage1.sh"], (image, args)
        self.stage1(call)
        return 0

    @staticmethod
    def h_stage1(call):
        """What the real script does when its checks pass (build-info records the key it used)."""
        out = Path(call["mounts"]["/out"].source)
        env = call["env"]
        ckh = customer_key_hash(call["public_pem"]) if "public_pem" in call else None
        (out / "bootcode5.bin").write_bytes(b"recovery" + env["SIGN_RECOVERY"].encode())
        (out / "pieeprom.bin").write_bytes(b"\2" * 2097152)
        sig = hashlib.sha256((out / "pieeprom.bin").read_bytes()).hexdigest() + "\nts: 1\n"
        (out / "pieeprom.sig").write_text(sig, encoding="ascii")
        (out / "build-info.json").write_text(json.dumps({"mode": env["MODE"], "customer_key_hash": ckh}),
                                             encoding="utf-8")


class Env:
    def __init__(self, cfg, docker, jobs, modules, store, arts):
        self.cfg, self.docker, self.jobs, self.modules, self.store, self.arts = cfg, docker, jobs, modules, store, arts

    def board(self, **fields) -> dict:
        self.modules.hello(SERIAL, {"chip": "BCM2712"})
        rec = self.store.get(SERIAL)
        if fields:
            rec.update(fields)
            self.store.put(rec)
        return self.store.get(SERIAL)

    def out_dirs(self) -> list[Path]:
        d = [Path(r["mounts"]["/out"].source) for r in self.docker.runs]
        return [p.with_name(p.name[:-len(".partial")]) for p in d]


@pytest.fixture
def make_env(make_cfg, tmp_path):
    def _make(**overrides) -> Env:
        repo = make_repo(tmp_path)
        cfg = make_cfg(tmp_path, repo_root=repo, **overrides)
        docker = FakeDocker()
        jobs = JobManager(cfg.work_dir)
        store = LocalJsonStore(cfg.storage.local_dir)
        modules = ModuleService(cfg, store)
        arts = Artifacts(cfg, docker, jobs, modules)
        docker.labels[TOOLS_TAG] = {"otp.tools.hash": arts.tools.hash()}
        return Env(cfg, docker, jobs, modules, store, arts)
    return _make


# ---------------------------------------------------------------------- #9 key hash
def test_signed_passes_expect_ckh_from_the_key(make_env):
    env = make_env(provisioning={"secure_boot": True})
    rec = env.board()
    m = env.arts.stage_manifest(SERIAL, 1)
    ckh = customer_key_hash(rec["rsa_public_pem"])
    assert m["expect"] == {"secure_boot_provision": True, "customer_key_hash": ckh}
    (run,) = env.docker.runs
    assert run["env"]["EXPECT_CKH"] == ckh and customer_key_hash(run["public_pem"]) == ckh
    assert not any("PRIVATE KEY" in ln for j in env.jobs.list() for ln in j.lines)


def test_unsigned_passes_no_expect_ckh(make_env):
    env = make_env()
    env.board()
    env.arts.stage_manifest(SERIAL, 1)
    assert "EXPECT_CKH" not in env.docker.runs[0]["env"]


def test_record_hash_not_matching_its_key_is_refused_before_building(make_env):
    env = make_env(provisioning={"secure_boot": True})
    env.board(customer_key_hash="ab" * 32)
    with pytest.raises(NotReady, match="does not match its RSA key"):
        env.arts.stage_manifest(SERIAL, 1)
    with pytest.raises(NotReady, match="does not match its RSA key"):
        env.arts.stage_file(SERIAL, 1, "pieeprom.bin")
    assert env.docker.runs == []


def test_record_hash_mismatch_refused_even_with_a_complete_dir(make_env):
    env = make_env(provisioning={"secure_boot": True})
    env.board()
    env.arts.stage_manifest(SERIAL, 1)
    assert len(env.docker.runs) == 1
    env.board(customer_key_hash="cd" * 32)          # storage edited after the build
    with pytest.raises(NotReady, match="does not match its RSA key"):
        env.arts.stage_manifest(SERIAL, 1)
    assert len(env.docker.runs) == 1


def test_record_without_key_but_with_hash_is_refused(make_env):
    """A record that lost its PEMs keeps a stale hash; secrets_for mints a new key: never sign with it."""
    env = make_env(provisioning={"secure_boot": True})
    old = env.board()["customer_key_hash"]
    env.board(rsa_private_pem="", rsa_public_pem="", customer_key_hash=old)
    with pytest.raises(NotReady, match="does not match its RSA key"):
        env.arts.stage_manifest(SERIAL, 1)
    assert env.docker.runs == []


def test_build_info_must_name_the_expected_key(make_env):
    env = make_env(provisioning={"secure_boot": True})
    env.board()

    def wrong_key(call):
        FakeDocker.h_stage1(call)
        p = Path(call["mounts"]["/out"].source) / "build-info.json"
        p.write_text(json.dumps({"mode": "signed", "customer_key_hash": "ef" * 32}), encoding="utf-8")

    env.docker.stage1 = wrong_key
    with pytest.raises(NotReady, match="not built with the board's key"):
        env.arts.stage_manifest(SERIAL, 1)


def test_complete_dir_with_other_key_in_build_info_is_rebuilt(make_env):
    env = make_env(provisioning={"secure_boot": True})
    env.board()
    env.arts.stage_manifest(SERIAL, 1)
    final = env.out_dirs()[0]
    info = json.loads((final / "build-info.json").read_text(encoding="utf-8"))
    info["customer_key_hash"] = "ef" * 32
    (final / "build-info.json").write_text(json.dumps(info), encoding="utf-8")
    env.arts.stage_manifest(SERIAL, 1)
    assert len(env.docker.runs) == 2


# ---------------------------------------------------------------------- #11 signed boot.conf
def test_signed_boot_conf_ignores_keys_under_a_model_filter():
    conf = "[all]\nBOOT_UART=1\n[cm5]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n"
    out = signed_boot_conf(conf)
    assert out == "[all]\nBOOT_UART=1\n[cm5]\n[all]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n"


def test_signed_boot_conf_removes_conflicting_filtered_override():
    conf = "[all]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n[pi5]\nENABLE_SELF_UPDATE=1\n"
    out = signed_boot_conf(conf)
    assert "ENABLE_SELF_UPDATE=1" not in out
    assert out == "[all]\nSIGNED_BOOT=1\n[pi5]\n[all]\nENABLE_SELF_UPDATE=0\n"


def test_signed_boot_conf_keeps_a_correct_all_section():
    for conf in ("[all]\nSIGNED_BOOT=1\nENABLE_SELF_UPDATE=0\n",
                 "SIGNED_BOOT=1\nENABLE_SELF_UPDATE=0\n[cm5]\nBOOT_UART=1\n",        # implicit [all]
                 "[cm5]\nBOOT_UART=1\n[ALL]\nSIGNED_BOOT = 1\nENABLE_SELF_UPDATE=0\n"):
        assert signed_boot_conf(conf) == conf


def test_signed_boot_conf_normalises_odd_spellings():
    out = signed_boot_conf("[all]\nsigned_boot=1\nENABLE_SELF_UPDATE=0 # off\nBOOT_UART=1\n")
    assert out == "[all]\nBOOT_UART=1\n[all]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n"


def test_signed_manifest_uses_section_aware_boot_conf(make_env):
    env = make_env(provisioning={"secure_boot": True,
                                 "boot_conf": "[all]\nBOOT_UART=1\n[cm5]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n"})
    env.board()
    env.arts.stage_manifest(SERIAL, 1)
    conf = (env.out_dirs()[0] / "boot.conf").read_text(encoding="utf-8")
    assert conf.endswith("[all]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n")


# ---------------------------------------------------------------------- #12 unsigned boot.conf
def test_unsigned_boot_conf_strips_signed_boot():
    text, removed = unsigned_boot_conf("[all]\nBOOT_UART=1\nSIGNED_BOOT=1\n[cm5]\nsigned_boot=2\nSIGNED_BOOT=0\n")
    assert text == "[all]\nBOOT_UART=1\n[cm5]\nSIGNED_BOOT=0\n"
    assert removed == ["SIGNED_BOOT=1", "signed_boot=2"]
    plain = "[all]\nBOOT_UART=1\n"
    assert unsigned_boot_conf(plain) == (plain, [])


def test_unsigned_manifest_warns_and_strips(make_env):
    env = make_env(provisioning={"boot_conf": "[all]\nBOOT_UART=1\nSIGNED_BOOT=1\nENABLE_SELF_UPDATE=0\n"})
    env.board()
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "unsigned"
    assert any("SIGNED_BOOT=1" in n and "removed" in n for n in m["notes"])
    conf = (env.out_dirs()[0] / "boot.conf").read_text(encoding="utf-8")
    assert conf == "[all]\nBOOT_UART=1\nENABLE_SELF_UPDATE=0\n"
    assert any("WARNING" in ln and "SIGNED_BOOT=1" in ln for ln in env.jobs.last("stage1").lines)


def test_unsigned_default_boot_conf_has_no_warning(make_env):
    env = make_env()
    env.board()
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["notes"] == ["unsigned EEPROM update; OTP is not changed in this stage"]


# ---------------------------------------------------------------------- #7 fingerprint inputs
@pytest.mark.parametrize("which", ["recovery.bin", "pieeprom-2026-09-25.bin", "update-pieeprom.sh"])
def test_same_size_firmware_change_rebuilds(make_env, which):
    env = make_env()
    env.board()
    env.arts.stage_manifest(SERIAL, 1)
    fw = env.cfg.repo_root / "external" / "usbboot" / "rpi-eeprom" / "firmware-2712" / "default"
    path = (env.cfg.repo_root / "external" / "usbboot" / "tools" / which) if which.endswith(".sh") else fw / which
    data = bytearray(path.read_bytes())
    data[-2] ^= 0x01                                            # same name, same size, other content
    path.write_bytes(bytes(data))
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 10_000_000_000))
    env.arts.stage_manifest(SERIAL, 1)
    assert len(env.docker.runs) == 2
    assert env.out_dirs()[0] != env.out_dirs()[1]


# ---------------------------------------------------------------------- stage1.sh guards (real script)
def _bash() -> str | None:
    cands = []
    if sys.platform == "win32":
        for root in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramW6432", "")):
            if root:
                cands.append(str(Path(root) / "Git" / "bin" / "bash.exe"))
    found = shutil.which("bash")
    if found and not found.lower().endswith(r"system32\bash.exe"):      # WSL's bash cannot see C:\ paths
        cands.append(found)
    for c in cands:
        if Path(c).is_file():
            return c
    return None


def _run_script(tmp_path: Path, env_extra: dict, boot_conf: str, config_txt: str):
    bash = _bash()
    if bash is None:
        pytest.skip("no usable bash")
    out = tmp_path / "out"
    out.mkdir()
    (out / "boot.conf").write_bytes(boot_conf.encode())
    (out / "config.txt").write_bytes(config_txt.encode())
    ext = tmp_path / "ext"
    (ext / "usbboot" / "rpi-eeprom").mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if k != "EXPECT_CKH"}
    env.update({"EXT": ext.as_posix(), "OUT": out.as_posix(), "KEYS": (tmp_path / "keys").as_posix(),
                "CHANNEL": "default", **env_extra})
    script = (REPO_ROOT / "docker" / "scripts" / "stage1.sh").as_posix()
    probe = subprocess.run([bash, "-c", f'[ -f "{script}" ]'], capture_output=True)
    if probe.returncode != 0:
        pytest.skip("bash cannot see Windows paths")
    return subprocess.run([bash, script], env=env, capture_output=True, text=True, timeout=60)


CFG_PLAIN = "uart_2ndstage=1\nset_reboot_order=0x3\nrecovery_reboot=1\n"


def test_script_refuses_unsigned_with_signed_boot(tmp_path):
    cp = _run_script(tmp_path, {"MODE": "unsigned", "SIGN_RECOVERY": "0"},
                     "[all]\r\nBOOT_UART=1\r\n[cm5]\r\nSIGNED_BOOT=1\r\n", CFG_PLAIN)
    assert cp.returncode != 0
    assert "SIGNED_BOOT=1 but MODE=unsigned" in cp.stderr


def test_script_unsigned_signed_boot_0_passes_the_guard(tmp_path):
    cp = _run_script(tmp_path, {"MODE": "unsigned", "SIGN_RECOVERY": "0"}, "[all]\nSIGNED_BOOT=0\n", CFG_PLAIN)
    assert "SIGNED_BOOT" not in cp.stderr
    assert "firmware directory not found" in cp.stderr          # got past the guard, stopped at the fake ext


@pytest.mark.parametrize("ckh, msg", [(None, "needs EXPECT_CKH"), ("xyz", "64 hex"), ("ab" * 31, "64 hex")])
def test_script_signed_needs_valid_expect_ckh(tmp_path, ckh, msg):
    extra = {"MODE": "signed", "SIGN_RECOVERY": "0"}
    if ckh is not None:
        extra["EXPECT_CKH"] = ckh
    cp = _run_script(tmp_path, extra, "[all]\nSIGNED_BOOT=1\n", CFG_PLAIN + "program_pubkey=1\n")
    assert cp.returncode != 0 and msg in cp.stderr


def test_script_compares_key_hash_with_expect_ckh():
    text = (REPO_ROOT / "docker" / "scripts" / "stage1.sh").read_text(encoding="utf-8")
    assert '[ "${CKH}" = "${EXPECT_CKH}" ] || die' in text
    assert '[ "${pub_hash}" = "${EXPECT_CKH}" ] || die' in text
