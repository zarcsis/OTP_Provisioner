"""Artifacts facade with a FakeDockerRunner: stage 1/2/3 manifests, gadget + image builds, signing modes.

The fake records every docker call and simulates the docker/scripts contract (SPEC §11) by writing
files into the directory mounted at /out.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

from otp_server.artifacts import Artifacts, NotReady
from otp_server.artifacts.stage1 import config_txt, signed_boot_conf
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.secrets_gen import luks_passphrase
from otp_server.storage.local import LocalJsonStore

SERIAL = "a7eb274c"
SERIAL2 = "0badc0de"
BLK = 4096
TOOLS_TAG = "otp-tools:latest"


# ---------------------------------------------------------------------- fixtures: files
def make_sparse(path: Path, chunks, blk: int = BLK) -> Path:
    body = b""
    blocks = 0
    for kind, n in chunks:
        if kind == "raw":
            data = bytes([0x11]) * (n * blk)
            body += struct.pack("<HHII", 0xCAC1, 0, n, 12 + len(data)) + data
        elif kind == "dc":
            body += struct.pack("<HHII", 0xCAC3, 0, n, 12)
        blocks += n
    path.write_bytes(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, blocks, len(chunks), 0) + body)
    return path


CRYPT_PMAP = [
    {"attributes": {"PMAPversion": "1.3.0", "system_type": "flat"}},
    {"partitions": [{"comment": "kernel + device tree + initramfs", "image": "boot"}]},
    {"encrypted": {"expand-to-fit": True,
                   "luks2": {"key_size": 512, "cipher": "aes-xts-plain64", "label": "OSROOT_CRYPT",
                             "uuid": "0b7f3c1e-5d9a-4c7e-9f59-1f6c2a8d9e11", "hash": "sha256",
                             "mname": "osroot_crypt", "etype": "raw"},
                   "partitions": [{"comment": "Encrypted root filesystem", "image": "root", "expand-to-fit": True}]}},
]


def image_json_doc(storage: str = "sd") -> dict:
    return {
        "IGversion": "2.2.0",
        "IGmeta": {"IGconf_device_class": "pi5", "IGconf_device_storage_type": storage,
                   "IGconf_device_sector_size": 512, "IGconf_image_version": "v1.2",
                   "IGconf_image_outputdir": "/work/image-deb13-arm64-min"},
        "attributes": {"image-name": "deb13-arm64-min.img", "image-size": 1 << 30, "image-palign-bytes": "8M"},
        "layout": {"partitiontable": {"label": "dos"},
                   "partitionimages": {
                       "boot": {"name": "boot", "image": "boot.vfat", "simage": "boot.vfat.sparse",
                                "bootable": "true", "type": "vfat", "size": 64 * BLK},
                       "root": {"name": "root", "image": "root.ext4", "simage": "root.ext4.sparse",
                                "type": "ext4", "size": 64 * BLK}},
                   "provisionmap": CRYPT_PMAP},
    }


def make_repo(base: Path) -> tuple[Path, Path]:
    repo = base / "repo"
    (repo / "docker" / "scripts").mkdir(parents=True)
    for name in ("tools.Dockerfile", "tools-entrypoint.sh", "gadget.Dockerfile", "gadget-entrypoint.sh"):
        (repo / "docker" / name).write_text(f"# {name}\n", encoding="utf-8")
    for name in ("stage1.sh", "stage2-sign.sh", "boot-resign.sh", "image-collect.sh"):
        (repo / "docker" / "scripts" / name).write_text(f"#!/bin/bash\n# {name}\n", encoding="utf-8")
    fw = repo / "external" / "usbboot" / "rpi-eeprom" / "firmware-2712"
    for ch in ("default", "latest"):
        d = fw / ch
        d.mkdir(parents=True)
        (d / "pieeprom-2026-05-26.bin").write_bytes(b"\1" * 2097152)
        (d / "pieeprom-2026-09-25.bin").write_bytes(b"\2" * 2097152)
        (d / "pieeprom-2026-12-31.bin").write_bytes(b"\3" * 100)          # wrong size: ignored
        (d / "recovery.bin").write_bytes(b"\4" * 104314)
    (repo / "external" / "usbboot" / "firmware").mkdir(parents=True)
    (repo / "external" / "usbboot" / "firmware" / "bootfiles.bin").write_bytes(b"bootfiles-tar" * 100)
    hs = repo / "external" / "rpi-sb-provisioner" / "host-support"
    hs.mkdir(parents=True)
    (hs / "fastboot-gadget-pi5-family.img").write_bytes(b"prebuilt-gadget" * 1000)
    (repo / "external" / "pi-gen-micro").mkdir(parents=True)
    (repo / "external" / "pi-gen-micro" / "pi-gen-micro").write_text("#!/bin/bash\n", encoding="utf-8")
    droneos = base / "droneos"
    (droneos / "docker").mkdir(parents=True)
    (droneos / "build.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (droneos / "docker" / "Dockerfile").write_text("FROM debian:trixie-slim\n", encoding="utf-8")
    (droneos / "droneos.yaml").write_text("device:\n  layer: rpi5\n", encoding="utf-8")
    return repo, droneos


# ---------------------------------------------------------------------- fake docker
class FakeDocker:
    """Records calls; simulates scripts/builders by writing into the /out mount."""

    def __init__(self, tools_ready_hash: str | None = None):
        self.labels: dict[str, dict] = {}
        self.builds: list[dict] = []
        self.runs: list[dict] = []
        self.calls: list[str] = []
        self.handlers: dict[str, object] = {}     # script name or image tag -> fn(call)
        self.fail: set[str] = set()

    # daemon
    def status(self, max_age: float = 5.0) -> dict:
        return {"ok": True, "version": "29.6.0", "detail": "", "arm64": True}

    def ensure_daemon(self, log=None, timeout: float = 180.0) -> None:
        self.calls.append("ensure_daemon")

    def ensure_arm64(self, log=None) -> None:
        self.calls.append("ensure_arm64")

    # images
    def image_exists(self, tag: str) -> bool:
        return tag in self.labels

    def image_label(self, tag: str, label: str):
        return self.labels[tag].get(label, "") if tag in self.labels else None

    def image_info(self, tag: str):
        return {"id": "sha256:1", "created": "2026-09-30T10:00:00Z", "size": 123456} if tag in self.labels else None

    def build_image(self, tag, dockerfile, context, *, platform=None, pull=False, labels=None, build_args=None,
                    log=None) -> None:
        self.builds.append({"tag": tag, "dockerfile": Path(dockerfile), "context": Path(context),
                            "platform": platform, "labels": dict(labels or {})})
        self.labels[tag] = dict(labels or {})

    def volume_exists(self, name: str) -> bool:
        return True

    def run(self, image, args=(), *, mounts=(), env=None, privileged=False, platform=None, entrypoint=None,
            hostname=None, log=None, check=True, interactive=False) -> int:
        call = {"image": image, "args": list(args), "mounts": {m.target: m for m in mounts},
                "env": dict(env or {}), "privileged": privileged, "platform": platform, "hostname": hostname,
                "interactive": interactive}
        if "/keys" in call["mounts"]:
            kdir = Path(call["mounts"]["/keys"].source)
            call["keys_dir"] = kdir
            call["keys_files"] = sorted(os.listdir(kdir))
        if "/in" in call["mounts"]:
            call["in_files"] = sorted(os.listdir(call["mounts"]["/in"].source))
        self.runs.append(call)
        name = args[0] if image == TOOLS_TAG and args else image
        if name in self.fail:
            from otp_server.docker import DockerError
            raise DockerError(f"docker run {image} exited with 1", 1)
        fn = self.handlers.get(name)
        if fn:
            fn(call)
        if log:
            log(f"fake run {name}")
        return 0

    def runs_of(self, name: str) -> list[dict]:
        return [r for r in self.runs if (r["args"][:1] == [name] if r["image"] == TOOLS_TAG else r["image"] == name)]


def base_env(call) -> dict:
    """MODE / CHANNEL / SIGN_RECOVERY of a stage1.sh run (signed runs also carry EXPECT_CKH)."""
    return {k: call["env"][k] for k in ("MODE", "CHANNEL", "SIGN_RECOVERY")}


def out_dir(call) -> Path:
    return Path(call["mounts"]["/out"].source)


def h_stage1(call):
    out = out_dir(call)
    assert (out / "boot.conf").is_file() and (out / "config.txt").is_file()
    (out / "bootcode5.bin").write_bytes(b"recovery" + call["env"]["SIGN_RECOVERY"].encode())
    (out / "pieeprom.bin").write_bytes(b"\2" * 2097152)
    # pieeprom.sig = sha256 + ts in both modes (a signed EEPROM embeds bootconf.sig instead)
    sig = hashlib.sha256((out / "pieeprom.bin").read_bytes()).hexdigest() + "\nts: 1\n"
    (out / "pieeprom.sig").write_text(sig, encoding="ascii")
    # stage1.sh reports the key hash it built with (EXPECT_CKH, signed mode only)
    (out / "build-info.json").write_text(json.dumps({"mode": call["env"]["MODE"],
                                                     "customer_key_hash": call["env"].get("EXPECT_CKH")}),
                                         encoding="utf-8")


def h_stage2(call):
    out = out_dir(call)
    (out / "boot.sig").write_text(hashlib.sha256(b"b").hexdigest() + "\nrsa2048: " + "cd" * 256 + "\n",
                                  encoding="ascii")
    (out / "bootfiles.bin").write_bytes(b"signed-bootfiles")


def h_gadget(call):
    out = out_dir(call)
    t = call["env"]["PGM_TARGETS"]
    (out / f"fastboot-gadget-{t}.img").write_bytes(b"built-gadget" * 500)
    (out / "build-info.json").write_text(json.dumps({"targets": t, "built": "2026-09-30T11:00:00Z",
                                                     "pi_gen_micro_commit": call["env"]["PGM_COMMIT"]}),
                                         encoding="utf-8")


def h_builder(call):
    (out_dir(call) / "deb13-arm64-min.img").write_bytes(b"raw image")


def h_collect(call, *, corrupt: str = ""):
    out = out_dir(call)
    (out / "image.json").write_text(json.dumps(image_json_doc()), encoding="utf-8")
    make_sparse(out / "boot.vfat.sparse", [("raw", 2), ("dc", 30)])
    make_sparse(out / "root.ext4.sparse.0", [("raw", 3), ("dc", 37)])
    make_sparse(out / "root.ext4.sparse.1", [("dc", 3), ("raw", 1), ("dc", 36)] if corrupt != "mixed"
                else [("dc", 3), ("raw", 1)])

    def piece(n):
        p = out / n
        return {"file": n, "size": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}

    pieces_root = [piece("root.ext4.sparse.0"), piece("root.ext4.sparse.1")]
    if corrupt == "sha":
        pieces_root[1]["sha256"] = "0" * 64
    collect = {"image_name": "deb13-arm64-min", "outputdir": "/work/image-deb13-arm64-min",
               "image_version": "v1.2", "device_class": "pi5", "storage_type": "sd",
               "simages": {"boot.vfat.sparse": {"size": (out / "boot.vfat.sparse").stat().st_size,
                                                "pieces": [piece("boot.vfat.sparse")]},
                           "root.ext4.sparse": {"size": 999, "pieces": pieces_root}}}
    if corrupt == "missing":
        (out / "root.ext4.sparse.1").unlink()
    (out / "collect.json").write_text(json.dumps(collect), encoding="utf-8")


def h_resign(call):
    out = out_dir(call)
    s = call["env"]["SIMAGE"]
    assert (Path(call["mounts"]["/in"].source) / s).is_file()
    make_sparse(out / s, [("raw", 1), ("dc", 31)])
    (out / "resign.json").write_text(json.dumps({"simage": s, "pieces": [{"file": s, "size": (out / s).stat().st_size}]}),
                                     encoding="utf-8")


# ---------------------------------------------------------------------- environment
class Env:
    def __init__(self, cfg, docker, jobs, modules, store, arts):
        self.cfg, self.docker, self.jobs, self.modules, self.store, self.arts = cfg, docker, jobs, modules, store, arts

    def board(self, serial=SERIAL, lock: str = "") -> dict:
        rec, _ = self.modules.hello(serial, {"chip": "BCM2712"})
        if lock:
            rec = self.store.get(serial)
            rec["otp_key_hash"] = rec["customer_key_hash"] if lock == "ours" else "ab" * 32
            self.store.put(rec)
        return self.store.get(serial)

    def wait_all(self):
        for j in self.jobs.list():
            assert j.wait(20), j


@pytest.fixture
def make_env(make_cfg, tmp_path):
    def _make(tools_ready: bool = True, **overrides) -> Env:
        repo, droneos = make_repo(tmp_path)
        paths = overrides.pop("paths", {})
        paths.setdefault("droneos", str(droneos))
        cfg = make_cfg(tmp_path, repo_root=repo, paths=paths, **overrides)
        docker = FakeDocker()
        docker.handlers.update({"stage1.sh": h_stage1, "stage2-sign.sh": h_stage2, "image-collect.sh": h_collect,
                                "boot-resign.sh": h_resign, cfg.builds.gadget.image_tag: h_gadget,
                                cfg.builds.image.builder_tag: h_builder})
        jobs = JobManager(cfg.work_dir)
        store = LocalJsonStore(cfg.storage.local_dir)
        modules = ModuleService(cfg, store)
        arts = Artifacts(cfg, docker, jobs, modules)
        if tools_ready:
            docker.labels[TOOLS_TAG] = {"otp.tools.hash": arts.tools.hash()}
        return Env(cfg, docker, jobs, modules, store, arts)
    return _make


def sha(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# ---------------------------------------------------------------------- stage 1
def test_stage1_unsigned_shared_dir(make_env):
    env = make_env()
    env.board()
    m = env.arts.stage_manifest(SERIAL, 1, base_url="http://127.0.0.1:8765")
    assert m["stage"] == 1 and m["kind"] == "rpiboot" and m["ready"] is True and m["mode"] == "unsigned"
    assert [f["name"] for f in m["files"]] == ["bootcode5.bin", "pieeprom.bin", "pieeprom.sig", "config.txt"]
    assert m["config_txt"] == "uart_2ndstage=1\nset_reboot_order=0x3\nrecovery_reboot=1\n"
    assert m["irreversible"] == [] and m["expect"] == {"secure_boot_provision": False, "customer_key_hash": None}
    assert m["source"]["pieeprom"] == "pieeprom-2026-09-25.bin"
    f0 = m["files"][0]
    assert f0["url"] == f"http://127.0.0.1:8765/api/modules/{SERIAL}/stage/1/files/bootcode5.bin"
    assert f0["origin"] == "rpi-eeprom firmware-2712/default/recovery.bin"
    runs = env.docker.runs_of("stage1.sh")
    assert len(runs) == 1
    r = runs[0]
    assert r["image"] == TOOLS_TAG and r["args"] == ["stage1.sh"]
    assert r["env"] == {"MODE": "unsigned", "CHANNEL": "default", "SIGN_RECOVERY": "0"}
    assert r["mounts"]["/scripts"].readonly and r["mounts"]["/ext"].readonly
    assert Path(r["mounts"]["/ext"].source) == env.cfg.repo_root / "external"
    assert not r["mounts"]["/out"].readonly and "/keys" not in r["mounts"]
    d = Path(r["mounts"]["/out"].source)
    assert d.name.endswith(".partial") and d.parent == env.cfg.work_dir / "artifacts" / "stage1"
    final = d.with_name(d.name[:-len(".partial")])
    assert (final / ".complete").is_file()
    assert (final / "boot.conf").read_text(encoding="utf-8") == env.cfg.provisioning.boot_conf.replace("\r\n", "\n")
    for f in m["files"]:
        p = env.arts.stage_file(SERIAL, 1, f["name"])
        assert p.parent == final and f["sha256"] == sha(p) and f["size"] == p.stat().st_size
    # another board shares the unsigned dir: no second docker run
    env.board(SERIAL2)
    m2 = env.arts.stage_manifest(SERIAL2, 1)
    assert len(env.docker.runs_of("stage1.sh")) == 1
    assert m2["files"][0]["url"] == f"/api/modules/{SERIAL2}/stage/1/files/bootcode5.bin"
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 1, "boot.conf")
    job = env.jobs.last("stage1")
    assert job.status == "succeeded" and job.title == "Stage 1 files (unsigned)"


def test_stage1_signed_secure_boot(make_env):
    env = make_env(provisioning={"secure_boot": True, "jtag_lock": True})
    rec = env.board()
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed"
    assert m["config_txt"] == ("uart_2ndstage=1\nset_reboot_order=0x3\nrecovery_reboot=1\n"
                               "program_pubkey=1\nprogram_jtag_lock=1\n")
    assert [i["key"] for i in m["irreversible"]] == ["program_pubkey", "program_jtag_lock"]
    assert "OTP" in m["irreversible"][0]["why"]
    assert m["expect"] == {"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"]}
    r = env.docker.runs_of("stage1.sh")[0]
    assert base_env(r) == {"MODE": "signed", "CHANNEL": "default", "SIGN_RECOVERY": "0"}
    assert r["mounts"]["/keys"].readonly and r["keys_files"] == ["private.pem", "public.pem"]
    assert not r["keys_dir"].exists()                       # temp key dir removed after the run
    d = Path(r["mounts"]["/out"].source)
    assert d.parent == env.cfg.work_dir / "modules" / SERIAL / "stage1"
    conf = (d.with_name(d.name[:-8]) / "boot.conf").read_text(encoding="utf-8")
    assert "ENABLE_SELF_UPDATE=0" in conf and "SIGNED_BOOT=1" in conf and "BOOT_ORDER=0xf2461" in conf
    assert env.jobs.last(f"stage1:{SERIAL}").status == "succeeded"
    # the private key never lands in the job log
    assert not any("PRIVATE KEY" in ln for j in env.jobs.list() for ln in j.lines)


def test_stage1_locked_to_our_key(make_env):
    env = make_env(provisioning={"secure_boot": True})
    env.board(lock="ours")
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and "program_pubkey=1" not in m["config_txt"] and m["irreversible"] == []
    assert m["expect"]["secure_boot_provision"] is False
    assert env.docker.runs_of("stage1.sh")[0]["env"]["SIGN_RECOVERY"] == "1"
    assert "counter-signed" in m["files"][0]["origin"]


def test_stage1_locked_without_secure_boot_still_signed(make_env):
    env = make_env(provisioning={"secure_boot": False, "jtag_lock": True})
    env.board(lock="ours")
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and m["irreversible"] == []
    assert m["config_txt"] == config_txt(False, False)
    assert base_env(env.docker.runs_of("stage1.sh")[0]) == {"MODE": "signed", "CHANNEL": "default",
                                                             "SIGN_RECOVERY": "1"}


def test_stage1_latest_channel(make_env):
    env = make_env(provisioning={"firmware_channel": "latest"})
    env.board()
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["source"]["channel"] == "latest"
    assert env.docker.runs_of("stage1.sh")[0]["env"]["CHANNEL"] == "latest"


def test_locked_to_other_key_is_refused(make_env):
    env = make_env()
    env.board(lock="other")
    for stage in (1, 2, 3):
        with pytest.raises(NotReady, match="different key"):
            env.arts.stage_manifest(SERIAL, stage)
    assert env.docker.runs == []


def test_unknown_board_and_bad_stage(make_env):
    env = make_env()
    with pytest.raises(KeyError):
        env.arts.stage_manifest("12345678", 1)
    env.board()
    with pytest.raises(ValueError):
        env.arts.stage_manifest(SERIAL, 4)


def test_stage1_needs_tools_image(make_env):
    env = make_env(tools_ready=False)
    env.board()
    with pytest.raises(NotReady) as ei:
        env.arts.stage_manifest(SERIAL, 1)
    job = ei.value.job
    assert job is not None and job.target == "tools"
    assert ei.value.to_dict()["job"]["target"] == "tools"
    assert job.wait(10) and job.status == "succeeded"
    b = env.docker.builds[-1]
    assert b["tag"] == TOOLS_TAG and b["dockerfile"].name == "tools.Dockerfile"
    assert b["context"] == env.cfg.repo_root / "docker" and b["labels"] == {"otp.tools.hash": env.arts.tools.hash()}
    assert env.arts.stage_manifest(SERIAL, 1)["ready"] is True


def test_stage1_script_failure_is_not_ready(make_env):
    env = make_env()
    env.board()
    env.docker.fail.add("stage1.sh")
    with pytest.raises(NotReady, match="stage 1 files failed"):
        env.arts.stage_manifest(SERIAL, 1)


def test_stage1_rejects_sig_not_matching_image(make_env):
    env = make_env()
    env.board()

    def bad(call):
        h_stage1(call)
        (out_dir(call) / "pieeprom.sig").write_text("0" * 64 + "\nts: 1\n", encoding="ascii")

    env.docker.handlers["stage1.sh"] = bad
    with pytest.raises(NotReady, match="does not match pieeprom.bin"):
        env.arts.stage_manifest(SERIAL, 1)


def test_signed_boot_conf():
    base = "[all]\nBOOT_UART=1\nBOOT_ORDER=0xf2461\n"
    out = signed_boot_conf(base)
    assert out == base + "[all]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n"
    already = "[all]\nSIGNED_BOOT=1\nENABLE_SELF_UPDATE=0\n"
    assert signed_boot_conf(already) == already
    wrong = "[all]\nSIGNED_BOOT=0\nBOOT_UART=1\n"
    fixed = signed_boot_conf(wrong)
    assert "SIGNED_BOOT=0" not in fixed and fixed.endswith("[all]\nENABLE_SELF_UPDATE=0\nSIGNED_BOOT=1\n")


# ---------------------------------------------------------------------- gadget / stage 2
def test_gadget_source_selection(make_env):
    env = make_env(builds={"gadget": {"source": "auto"}})
    g = env.arts.gadget
    path, source, _v = g.current()
    assert source == "prebuilt" and path.name == "fastboot-gadget-pi5-family.img"
    st = env.arts.status()["gadget"]
    assert st["ready"] and st["source"] == "prebuilt" and st["size"] == path.stat().st_size

    g.gcfg.source = "build"
    with pytest.raises(NotReady, match="not built"):
        g.current()
    g.gcfg.source = "prebuilt"
    assert g.current()[1] == "prebuilt"
    g.gcfg.targets = "pi4-family"
    with pytest.raises(NotReady, match="no prebuilt"):
        g.current()
    g.gcfg.source = "auto"
    with pytest.raises(NotReady):
        g.current()
    assert env.arts.status()["gadget"]["ready"] is False


def test_gadget_build_job(make_env):
    env = make_env(builds={"gadget": {"source": "build"}})
    job = env.arts.start_build("gadget")
    assert job.target == "gadget" and job.title == "Build fastboot gadget"
    assert job.wait(10) and job.status == "succeeded", (job.error, list(job.lines)[-6:])
    assert env.docker.calls[:2] == ["ensure_daemon", "ensure_arm64"]
    b = env.docker.builds[-1]
    assert b["tag"] == "otp-gadget-builder:trixie" and b["platform"] == "linux/arm64"
    assert b["dockerfile"] == env.cfg.repo_root / "docker" / "gadget.Dockerfile"
    r = env.docker.runs_of("otp-gadget-builder:trixie")[0]
    assert r["platform"] == "linux/arm64" and r["args"] == []
    assert r["env"] == {"PGM_TARGETS": "pi5-family", "PGM_COMMIT": env.arts.gadget.commit()}
    assert Path(r["mounts"]["/src"].source) == env.cfg.repo_root / "external" / "pi-gen-micro"
    assert r["mounts"]["/src"].readonly
    assert r["mounts"]["/work"].type == "volume" and r["mounts"]["/work"].source == "otp-pgm-work"
    key = env.arts.gadget.key()
    assert key.endswith("-pi5-family")
    assert Path(r["mounts"]["/out"].source) == env.cfg.work_dir / "artifacts" / "gadget" / f"{key}.partial"
    path, source, version = env.arts.gadget.current()
    assert source == "built" and version == key and path.parent.name == key
    st = env.arts.status()["gadget"]
    assert st["source"] == "built" and st["built"] == "2026-09-30T11:00:00Z" and st["job"]["status"] == "succeeded"
    # already built: a non-forced build does not run docker again
    n = len(env.docker.runs)
    env.arts.start_build("gadget").wait(10)
    assert len(env.docker.runs) == n
    env.arts.start_build("gadget", force=True).wait(10)
    assert len(env.docker.runs) == n + 1


def test_stage2_unsigned(make_env):
    env = make_env()
    env.board()
    m = env.arts.stage_manifest(SERIAL, 2, base_url="")
    assert m["stage"] == 2 and m["kind"] == "rpiboot" and m["mode"] == "unsigned"
    assert [f["name"] for f in m["files"]] == ["bootfiles.bin", "boot.img", "config.txt"]
    assert m["config_txt"] == "boot_ramdisk=1\nuart_2ndstage=1\n"
    assert m["source"]["gadget"] == "prebuilt"
    assert env.arts.stage_file(SERIAL, 2, "bootfiles.bin") == env.cfg.repo_root / "external/usbboot/firmware/bootfiles.bin"
    cfgp = env.arts.stage_file(SERIAL, 2, "config.txt")
    assert cfgp == env.cfg.work_dir / "artifacts" / "stage2" / "config.txt"
    assert cfgp.read_bytes() == b"boot_ramdisk=1\nuart_2ndstage=1\n"
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 2, "boot.sig")
    assert env.docker.runs == []
    # no sidecar files are written into the repository
    assert not list((env.cfg.repo_root / "external").rglob("*.sha256"))


def test_stage2_signed_when_locked_to_our_key(make_env):
    env = make_env()
    env.board(lock="ours")
    m = env.arts.stage_manifest(SERIAL, 2)
    assert m["mode"] == "signed"
    assert [f["name"] for f in m["files"]] == ["bootfiles.bin", "boot.img", "boot.sig", "config.txt"]
    r = env.docker.runs_of("stage2-sign.sh")[0]
    assert r["in_files"] == ["boot.img", "bootfiles.bin"] and r["mounts"]["/in"].readonly
    assert r["keys_files"] == ["private.pem", "public.pem"] and not r["keys_dir"].exists()
    signed_bf = env.arts.stage_file(SERIAL, 2, "bootfiles.bin")
    assert signed_bf.read_bytes() == b"signed-bootfiles"
    assert signed_bf.parent.parent == env.cfg.work_dir / "modules" / SERIAL / "stage2"
    assert env.arts.stage_file(SERIAL, 2, "boot.sig").parent == signed_bf.parent
    env.arts.stage_manifest(SERIAL, 2)
    assert len(env.docker.runs_of("stage2-sign.sh")) == 1          # cached per board


# ---------------------------------------------------------------------- image / stage 3
def build_image(env) -> None:
    job = env.arts.start_build("image")
    assert job.title == "Build droneos image"
    assert job.wait(20), "image job hangs"
    assert job.status == "succeeded", "\n".join(job.lines)


def test_image_build_argv_and_collect(make_env):
    env = make_env()
    build_image(env)
    r = env.docker.runs_of("droneos-builder:trixie")[0]
    assert r["args"] == ["--in-container", "-B", "/work", "-o", "/out", "-c", "/src/droneos.yaml",
                         "--", "IGconf_image_pmap=crypt"]
    assert r["privileged"] and r["interactive"] and r["hostname"] == "droneos-builder"
    assert r["env"] == {"DRONEOS_IN_CONTAINER": "1", "DRONEOS_ROOT": "/src", "DRONEOS_VERSION": "unknown"}
    assert Path(r["mounts"]["/src"].source) == env.cfg.droneos_dir and r["mounts"]["/src"].readonly
    assert r["mounts"]["/work"].type == "volume" and r["mounts"]["/work"].source == "otp-droneos-work"
    staging = env.cfg.work_dir / "artifacts" / "image" / "staging"
    assert Path(r["mounts"]["/out"].source) == staging and "/cfg" not in r["mounts"]
    b = [x for x in env.docker.builds if x["tag"] == "droneos-builder:trixie"][0]
    assert b["context"] == env.cfg.droneos_dir / "docker"
    c = env.docker.runs_of("image-collect.sh")[0]
    assert c["env"] == {"MAX_PIECE": "268435456"}
    assert c["mounts"]["/work"].type == "volume" and c["mounts"]["/work"].readonly
    assert Path(c["mounts"]["/out"].source).name.endswith(".partial")

    cur = json.loads((env.cfg.work_dir / "artifacts" / "image" / "current.json").read_text(encoding="utf-8"))
    set_dir = env.cfg.work_dir / "artifacts" / "image" / cur["set"]
    assert cur["set"].startswith("deb13-arm64-min-unknown-") and (set_dir / ".complete").is_file()
    man = json.loads((set_dir / "manifest.json").read_text(encoding="utf-8"))
    assert man["name"] == "deb13-arm64-min" and man["version"] == "unknown" and man["set"] == cur["set"]
    assert man["device_class"] == "pi5" and man["storage_type"] == "sd" and man["encrypted"] is True
    assert man["overrides"] == ["IGconf_image_pmap=crypt"]
    assert [p["name"] for p in man["simages"]["root.ext4.sparse"]] == ["root.ext4.sparse.0", "root.ext4.sparse.1"]
    assert man["simages"]["root.ext4.sparse"][1]["sha256"] == sha(set_dir / "root.ext4.sparse.1")
    assert not list(staging.glob("*.img"))                      # raw image dropped (keep_raw_image false)
    st = env.arts.status()["image"]
    assert st["ready"] and st["source"] == "built" and st["version"] == "unknown" and st["size"] > 0


def test_image_config_outside_checkout_and_keep_raw(make_env, tmp_path):
    ext = tmp_path / "cfgs" / "other.yaml"
    ext.parent.mkdir()
    ext.write_text("image: {}\n", encoding="utf-8")
    env = make_env(builds={"image": {"config": str(ext), "keep_raw_image": True, "overrides": []}})
    build_image(env)
    r = env.docker.runs_of("droneos-builder:trixie")[0]
    assert r["args"] == ["--in-container", "-B", "/work", "-o", "/out", "-c", "/cfg/other.yaml"]
    assert Path(r["mounts"]["/cfg"].source) == ext.parent and r["mounts"]["/cfg"].readonly
    assert list((env.cfg.work_dir / "artifacts" / "image" / "staging").glob("*.img"))


@pytest.mark.parametrize("corrupt,msg", [("sha", "sha256 mismatch"), ("missing", "missing"),
                                         ("mixed", "different images")])
def test_image_collect_validation_failures(make_env, corrupt, msg):
    env = make_env()
    env.docker.handlers["image-collect.sh"] = lambda call: h_collect(call, corrupt=corrupt)
    job = env.arts.start_build("image")
    job.wait(20)
    assert job.status == "failed" and msg in job.error
    assert not (env.cfg.work_dir / "artifacts" / "image" / "current.json").exists()
    with pytest.raises(NotReady, match="not built"):
        env.board()
        env.arts.stage_manifest(SERIAL, 3)


def test_stage3_not_ready_before_build(make_env):
    env = make_env()
    env.board()
    with pytest.raises(NotReady) as ei:
        env.arts.stage_manifest(SERIAL, 3)
    assert ei.value.job is None
    assert env.arts.status()["image"]["ready"] is False


def test_stage3_unsigned_manifest(make_env):
    env = make_env()
    build_image(env)
    rec = env.board()
    n_runs = len(env.docker.runs)
    m = env.arts.stage_manifest(SERIAL, 3, base_url="http://h")
    assert m["stage"] == 3 and m["kind"] == "fastboot-idp" and m["title"] == "Image" and m["mode"] == "unsigned"
    assert m["storage_device"] == "mmcblk0" and m["fwcrypto_init"] is True and m["erase"] is True
    assert list(m["parts"]) == ["boot.vfat.sparse", "root.ext4.sparse"]
    assert [p["name"] for p in m["parts"]["root.ext4.sparse"]] == ["root.ext4.sparse.0", "root.ext4.sparse.1"]
    p1 = m["parts"]["root.ext4.sparse"][1]
    assert set(p1) == {"name", "size", "sha256", "url"}
    assert p1["url"] == f"http://h/api/modules/{SERIAL}/stage/3/files/root.ext4.sparse.1"
    assert m["image_json"]["name"] == "image.json" and m["image_json"]["url"].endswith("/stage/3/files/image.json")
    assert m["image"]["name"] == "deb13-arm64-min" and m["image"]["encrypted"] is True
    assert m["image"]["storage_type"] == "sd" and m["image"]["device_class"] == "pi5"
    assert m["crypt"] == [{"dev": "mmcblk0p2", "mname": "osroot_crypt", "label": "OSROOT_CRYPT",
                           "passphrase": luks_passphrase(rec["device_secret"], "osroot_crypt", SERIAL)}]
    assert [i["key"] for i in m["irreversible"]] == ["oem fwcrypto init", "erase"]
    assert m["irreversible"][1]["value"] == "mmcblk0"
    total = m["image_json"]["size"] + sum(p["size"] for ps in m["parts"].values() for p in ps)
    assert m["total_bytes"] == total and m["max_piece_size"] == 268435456
    path = env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.1")
    assert sha(path) == p1["sha256"]
    assert env.arts.stage_file(SERIAL, 3, "image.json").name == "image.json"
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 3, "manifest.json")
    assert len(env.docker.runs) == n_runs                        # unsigned stage 3 needs no docker


def test_stage3_no_passphrase_no_erase(make_env):
    env = make_env(provisioning={"recovery_passphrase": False, "erase_storage": False})
    build_image(env)
    env.board()
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["crypt"] == [] and m["erase"] is False
    assert [i["key"] for i in m["irreversible"]] == ["oem fwcrypto init"]
    assert any("recovery_passphrase" in n for n in m["notes"])


def test_stage3_signed_resigns_boot_slot(make_env):
    env = make_env()
    build_image(env)
    env.board(lock="ours")
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["mode"] == "signed"
    r = env.docker.runs_of("boot-resign.sh")[0]
    assert r["env"] == {"SIMAGE": "boot.vfat.sparse", "MAX_PIECE": "268435456"}
    cur = json.loads((env.cfg.work_dir / "artifacts" / "image" / "current.json").read_text(encoding="utf-8"))
    assert Path(r["mounts"]["/in"].source) == env.cfg.work_dir / "artifacts" / "image" / cur["set"]
    assert r["mounts"]["/in"].readonly and r["keys_files"] == ["private.pem", "public.pem"]
    assert [p["name"] for p in m["parts"]["boot.vfat.sparse"]] == ["boot.vfat.sparse"]
    p = env.arts.stage_file(SERIAL, 3, "boot.vfat.sparse")
    assert p.parent.parent == env.cfg.work_dir / "modules" / SERIAL / "stage3"
    assert m["parts"]["boot.vfat.sparse"][0]["sha256"] == sha(p)
    # root pieces still come from the shared set
    assert env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0").parent.name == cur["set"]
    env.arts.stage_manifest(SERIAL, 3)
    assert len(env.docker.runs_of("boot-resign.sh")) == 1


# ---------------------------------------------------------------------- facade
def test_status_shape_and_start_build_validation(make_env):
    env = make_env()
    st = env.arts.status()
    assert set(st) == {"tools", "gadget", "image"}
    for target, s in st.items():
        assert s["target"] == target
        assert set(s) >= {"target", "ready", "source", "version", "path", "size", "built", "detail", "job"}
    assert st["tools"]["ready"] is True and st["tools"]["path"] == TOOLS_TAG
    with pytest.raises(ValueError):
        env.arts.start_build("everything")


def test_tools_outdated_label(make_env):
    env = make_env()
    env.docker.labels[TOOLS_TAG] = {"otp.tools.hash": "old"}
    st = env.arts.status()["tools"]
    assert st["ready"] is False and "out of date" in st["detail"]


def test_auto_build(make_env):
    env = make_env(tools_ready=False)
    jobs = env.arts.auto_build()
    assert [j.target for j in jobs] == ["tools", "gadget", "image"]
    env.wait_all()
    assert all(j.status == "succeeded" for j in jobs), [(j.target, j.error) for j in jobs]
    assert env.arts.auto_build() == []                  # everything present now


def test_auto_build_prebuilt_gadget(make_env):
    env = make_env(builds={"gadget": {"source": "prebuilt"}})
    jobs = env.arts.auto_build()
    assert [j.target for j in jobs] == ["image"]
    env.wait_all()


# ---------------------------------------------------------------------- review fixes
# #3 downloads are pinned to the manifest the page fetched
def test_stage_file_serves_the_issued_manifest_not_a_newer_artifact(make_env):
    env = make_env(builds={"gadget": {"source": "auto"}})
    env.board()
    m = env.arts.stage_manifest(SERIAL, 2)
    assert m["source"]["gadget"] == "prebuilt"
    boot = {f["name"]: f for f in m["files"]}["boot.img"]
    # a gadget build commits while the page still holds the prebuilt manifest
    job = env.arts.start_build("gadget")
    assert job.wait(10) and job.status == "succeeded", job.error
    assert env.arts.gadget.current()[1] == "built"
    p = env.arts.stage_file(SERIAL, 2, "boot.img")
    assert p == env.arts.gadget.prebuilt_path and sha(p) == boot["sha256"]
    # a new manifest switches the downloads to the built gadget
    m2 = env.arts.stage_manifest(SERIAL, 2)
    assert m2["source"]["gadget"] == "built"
    p2 = env.arts.stage_file(SERIAL, 2, "boot.img")
    assert p2 == env.arts.gadget.built_image() and sha(p2) == {f["name"]: f for f in m2["files"]}["boot.img"]["sha256"]
    # the pinned file itself changed: refused, the page must restart the stage
    p2.write_bytes(b"tampered")
    with pytest.raises(NotReady, match="changed after its manifest was issued"):
        env.arts.stage_file(SERIAL, 2, "boot.img")
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 2, "boot.sig")


def test_stage3_download_survives_an_image_rebuild(make_env):
    env = make_env()
    build_image(env)
    env.board()
    m = env.arts.stage_manifest(SERIAL, 3)
    old = env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0")
    job = env.arts.start_build("image", force=True)
    assert job.wait(20) and job.status == "succeeded", job.error
    assert env.arts.image.current_set()[0] != old.parent          # a new set is current
    p = env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0")
    assert p == old and p.is_file() and sha(p) == m["parts"]["root.ext4.sparse"][0]["sha256"]


# #4 write_text retries os.replace on Windows sharing violations
def test_write_text_retries_permission_error(tmp_path, monkeypatch):
    from otp_server.artifacts import common

    real = os.replace
    calls = []

    def flaky(src, dst):
        calls.append(dst)
        if len(calls) < 3:
            raise PermissionError(13, "file is open")
        real(src, dst)

    monkeypatch.setattr(common.os, "replace", flaky)
    target = tmp_path / "current.json"
    common.write_json(target, {"set": "a"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"set": "a"} and len(calls) == 3
    monkeypatch.setattr(common.os, "replace", lambda s, d: (_ for _ in ()).throw(PermissionError(13, "held")))
    monkeypatch.setattr(common.time, "sleep", lambda _s: None)
    with pytest.raises(PermissionError):
        common.write_json(target, {"set": "b"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"set": "a"}
    assert [p.name for p in tmp_path.iterdir()] == ["current.json"]       # no .tmp left behind


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing semantics")
def test_write_json_while_a_reader_holds_the_file(tmp_path):
    import threading

    from otp_server.artifacts import common

    target = tmp_path / "current.json"
    common.write_json(target, {"set": "a"})
    f = open(target, "r", encoding="utf-8")
    threading.Timer(0.3, f.close).start()
    common.write_json(target, {"set": "b"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"set": "b"}


# #5 a forced rebuild never replaces a directory in place
def test_forced_gadget_rebuild_keeps_the_served_dir(make_env):
    env = make_env(builds={"gadget": {"source": "build"}})
    assert env.arts.start_build("gadget").wait(10)
    p1, _src, v1 = env.arts.gadget.current()
    content = p1.read_bytes()
    with open(p1, "rb"):                      # being served (on Windows this blocks deleting it)
        job = env.arts.start_build("gadget", force=True)
        assert job.wait(10) and job.status == "succeeded", job.error
    p2, src, v2 = env.arts.gadget.current()
    key = env.arts.gadget.key()
    assert src == "built" and v1 == key and v2 == f"{key}-r2" and p2.parent.name == v2
    assert p1.read_bytes() == content and (p1.parent / ".complete").is_file()
    job = env.arts.start_build("gadget", force=True)
    assert job.wait(10) and job.status == "succeeded"
    assert env.arts.gadget.current()[2] == f"{key}-r3"


def test_commit_partial_moves_the_old_dir_aside(tmp_path, monkeypatch):
    from otp_server.artifacts import common

    final = tmp_path / "set"
    final.mkdir()
    (final / "a.bin").write_bytes(b"old")
    part = common.fresh_partial(final)
    (part / "a.bin").write_bytes(b"new")
    common.commit_partial(part, final)
    assert (final / "a.bin").read_bytes() == b"new" and common.is_complete(final)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["set"]           # aside copy removed
    # moving the old dir aside fails: the old dir is left complete, the error is raised
    part = common.fresh_partial(final)
    (part / "a.bin").write_bytes(b"newer")
    real = common.replace_retry

    def refuse(src, dst, *a, **kw):
        if Path(src) == final:
            raise PermissionError(13, "in use")
        return real(src, dst, *a, **kw)

    monkeypatch.setattr(common, "replace_retry", refuse)
    with pytest.raises(RuntimeError, match="left as it was"):
        common.commit_partial(part, final)
    assert (final / "a.bin").read_bytes() == b"new" and common.is_complete(final)


@pytest.mark.skipif(os.name != "nt", reason="an open file blocks deletion only on Windows")
def test_rmtree_reports_what_it_could_not_remove(tmp_path, caplog):
    from otp_server.artifacts import common

    d = tmp_path / "d"
    d.mkdir()
    (d / "held.bin").write_bytes(b"x")
    with open(d / "held.bin", "rb"), caplog.at_level("WARNING"):
        assert common.rmtree(d) is False
    assert "could not remove" in caplog.text and str(d) in caplog.text
    assert common.rmtree(d) is True and not d.exists()


# #6 heavy builds exclude each other across processes
def test_heavy_lock_waits_for_another_process(tmp_path):
    import subprocess
    import sys
    import threading

    from otp_server.artifacts import common

    work = tmp_path / "work"
    holder = ("import sys; from pathlib import Path; from otp_server.artifacts.common import FileLock, HEAVY_LOCK_FILE; "
              "l = FileLock(Path(sys.argv[1]) / 'tmp' / HEAVY_LOCK_FILE); assert l.acquire(blocking=False); "
              "print('locked', flush=True); sys.stdin.readline(); l.release()")
    proc = subprocess.Popen([sys.executable, "-B", "-c", holder, str(work)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, cwd=str(Path(__file__).resolve().parent.parent), text=True)
    try:
        assert proc.stdout.readline().strip() == "locked"
        lines: list[str] = []
        entered = threading.Event()

        def build():
            with common.heavy_lock(work, lines.append, poll=0.05):
                entered.set()

        t = threading.Thread(target=build, daemon=True)
        t.start()
        assert not entered.wait(0.6), "entered while another process holds the heavy lock"
        assert any("another OTP_Provisioner process" in ln for ln in lines)
        proc.stdin.write("go\n")
        proc.stdin.flush()
        assert entered.wait(10)
        t.join(5)
    finally:
        proc.kill()
        proc.wait(10)
    assert common.HEAVY_LOCK.acquire(blocking=False)
    common.HEAVY_LOCK.release()


# #7 build identities cover every input that changes the output
def test_gadget_key_covers_the_builder_files(make_env):
    env = make_env(builds={"gadget": {"source": "build"}})
    g = env.arts.gadget
    assert env.arts.start_build("gadget").wait(10)
    k1 = g.key()
    assert g.built_image() is not None
    (env.cfg.repo_root / "docker" / "gadget-entrypoint.sh").write_text("# changed\n", encoding="utf-8")
    assert g.key() != k1 and g.key().endswith("-pi5-family")
    assert g.built_image() is None
    with pytest.raises(NotReady, match="not built"):
        g.current()
    (env.cfg.repo_root / "docker" / "gadget-entrypoint.sh").write_bytes(b"# gadget-entrypoint.sh\r\n")
    assert g.key() == k1                       # CRLF-normalised: a Windows checkout hashes the same


def test_image_set_split_larger_than_max_piece_needs_rebuild(make_env):
    env = make_env()
    build_image(env)
    env.board()
    assert env.arts.image.current_set() is not None
    env.cfg.provisioning.max_piece_size = 1 << 20      # smaller than the 256 MiB the set was split with
    assert env.arts.image.current_set() is None
    with pytest.raises(NotReady, match="rebuild needed"):
        env.arts.stage_manifest(SERIAL, 3)
    st = env.arts.status()["image"]
    assert st["ready"] is False and "rebuild needed" in st["detail"]
    assert "image" in [j.target for j in env.arts.auto_build()]
    env.wait_all()
    man = env.arts.image.current_set()[1]
    assert man["max_piece_size"] == 1 << 20
    assert env.arts.stage_manifest(SERIAL, 3)["max_piece_size"] == 1 << 20


# #15 temporary key directories never linger silently
def test_tempkeys_cleans_up_when_enter_fails(tmp_path):
    from otp_server.artifacts.common import TempKeys

    tk = TempKeys(tmp_path, "-----BEGIN PRIVATE KEY-----\nx\n", None)   # public.pem write fails
    with pytest.raises(AttributeError):
        with tk:
            pass
    assert not tk.dir.exists() and list((tmp_path / "tmp").iterdir()) == []


def test_tempkeys_normal_use_leaves_nothing(tmp_path):
    from otp_server.artifacts.common import TempKeys

    with TempKeys(tmp_path, "priv", "pub") as kdir:
        assert sorted(os.listdir(kdir)) == ["private.pem", "public.pem"]
    assert list((tmp_path / "tmp").iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="an open file blocks deletion only on Windows")
def test_tempkeys_warns_when_it_cannot_remove(tmp_path, caplog, monkeypatch):
    from otp_server.artifacts import common

    monkeypatch.setattr(common.time, "sleep", lambda _s: None)
    with caplog.at_level("WARNING"):
        with common.TempKeys(tmp_path, "SECRET-PEM", "pub") as kdir:
            held = open(kdir / "private.pem", "rb")
    try:
        assert kdir.exists() and "could not be removed" in caplog.text and str(kdir) in caplog.text
        assert "SECRET-PEM" not in caplog.text
    finally:
        held.close()
    assert kdir in common.sweep_stale_temp(tmp_path) and not kdir.exists()


def test_sweep_stale_temp(tmp_path):
    from otp_server.artifacts import common

    tmp = tmp_path / "tmp"
    tmp.mkdir()
    stale = tmp / "keys-aaaa"                         # lock file present but not held: dead owner
    stale.mkdir()
    (stale / "private.pem").write_text("x")
    (tmp / "keys-aaaa.lock").write_text("")
    fresh = tmp / "keys-bbbb"                         # no lock file, just created: maybe being set up
    fresh.mkdir()
    old = tmp / "keys-cccc"                           # no lock file, old
    old.mkdir()
    os.utime(old, (1, 1))
    (tmp / "keys-dddd.lock").write_text("")           # orphaned lock file
    (tmp / common.HEAVY_LOCK_FILE).write_text("")     # never swept
    aside = tmp_path / "artifacts" / "gadget" / "k.old-1234"
    aside.mkdir(parents=True)
    with common.TempKeys(tmp_path, "priv", "pub") as live:
        removed = common.sweep_stale_temp(tmp_path)
        assert live.exists() and (live / "private.pem").is_file()      # held by a live owner
    assert set(removed) == {stale, old, tmp / "keys-dddd.lock", aside}
    assert fresh.exists() and (tmp / common.HEAVY_LOCK_FILE).exists()
    assert sorted(p.name for p in tmp.iterdir()) == [common.HEAVY_LOCK_FILE, "keys-bbbb"]


def test_artifacts_init_sweeps_stale_keys(make_env, tmp_path):
    env = make_env()
    stale = env.cfg.work_dir / "tmp" / "keys-0123abcd"
    stale.mkdir(parents=True)
    (stale / "private.pem").write_text("x")
    os.utime(stale, (1, 1))
    Artifacts(env.cfg, env.docker, env.jobs, env.modules)
    assert not stale.exists()
