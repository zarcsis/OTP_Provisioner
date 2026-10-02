"""Artifacts facade with a FakeDockerRunner: stage 1/2/3 manifests, gadget + image builds, scenarios.

The fake records every docker call and simulates the docker/scripts contract (SPEC §11) by writing
files into the directory mounted at /out. The image builder honours ``IGconf_image_pmap`` the way
rpi-image-gen does: it leaves a ``clear`` or ``crypt`` build in the work volume, and the fake
image-collect.sh copies an image.json with (crypt) or without (clear) the encrypted provisionmap
section out of it.

Scenarios are chosen per board (``ModuleService.mode_of``): ``open`` = unsigned EEPROM + clear image,
``secure`` = signed EEPROM with program_pubkey + crypt image + OTP device key export; a board whose OTP
holds a key hash is always ``secure``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from memstore import MemoryStore
from otp_server import imagejson
from otp_server.artifacts import Artifacts, NotReady
from otp_server.artifacts.image import KEY_EXPORT, VARIANTS
from otp_server.artifacts.stage1 import config_txt, signed_boot_conf
from otp_server.jobs import JobManager
from otp_server.modules import ModuleService
from otp_server.secrets_gen import luks_passphrase

SERIAL = "a7eb274c"
SERIAL2 = "0badc0de"
BLK = 4096
TOOLS_TAG = "otp-tools:latest"
BUILDER_TAG = "otp-image-builder:trixie"
GADGET_TAG = "otp-gadget-builder:trixie"
REAL_REPO = Path(__file__).resolve().parent.parent


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

CLEAR_PMAP = [
    {"attributes": {"PMAPversion": "1.3.0", "system_type": "flat"}},
    {"partitions": [{"comment": "kernel + device tree + initramfs", "image": "boot"},
                    {"comment": "Root filesystem", "image": "root", "expand-to-fit": True}]},
]


def image_json_doc(storage: str = "sd", *, encrypted: bool = True) -> dict:
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
                   "provisionmap": CRYPT_PMAP if encrypted else CLEAR_PMAP},
    }


def test_fake_image_json_variants_are_what_the_product_checks():
    # the fixture itself: a clear doc has no encrypted section anywhere, a crypt doc has one container
    assert imagejson.is_encrypted(image_json_doc(encrypted=True)) is True
    assert imagejson.is_encrypted(image_json_doc(encrypted=False)) is False
    assert imagejson.crypt_containers(image_json_doc(encrypted=False)) == []
    assert [c["mname"] for c in imagejson.crypt_containers(image_json_doc())] == ["osroot_crypt"]


HELPER_FILES = {
    "control": "Package: otp-keyexport\nArchitecture: arm64\nDepends: rpifwcrypto\n",
    "install": "otp-keyexport /usr/local/bin 0755\notp-keyexport-boot.service /etc/systemd/system 0644\n",
    "otp-keyexport": "#!/bin/sh\nset -u\necho fake helper\n",
    "otp-keyexport-boot.service": "[Service]\nExecStart=/usr/local/bin/otp-keyexport boot\n",
}


def make_repo(base: Path) -> tuple[Path, Path]:
    repo = base / "repo"
    (repo / "docker" / "scripts").mkdir(parents=True)
    for name in ("tools.Dockerfile", "tools-entrypoint.sh", "gadget.Dockerfile", "gadget-entrypoint.sh"):
        (repo / "docker" / name).write_text(f"# {name}\n", encoding="utf-8")
    for name in ("stage1.sh", "stage2-sign.sh", "boot-resign.sh", "image-collect.sh"):
        (repo / "docker" / "scripts" / name).write_text(f"#!/bin/bash\n# {name}\n", encoding="utf-8")
    helpers = repo / "docker" / "gadget-helpers" / "otp-keyexport"
    helpers.mkdir(parents=True)
    for name, text in HELPER_FILES.items():
        (helpers / name).write_bytes(text.encode("utf-8"))
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
    (repo / "external" / "pi-gen-micro").mkdir(parents=True)
    (repo / "external" / "pi-gen-micro" / "pi-gen-micro").write_text("#!/bin/bash\n", encoding="utf-8")
    image = repo / "image"
    for d in ("docker", "layer", "rpi-image-gen"):
        (image / d).mkdir(parents=True)
    (image / "build.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (image / "docker" / "Dockerfile").write_text("FROM debian:trixie-slim\n", encoding="utf-8")
    (image / "docker" / "entrypoint.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (image / "layer" / "otp-minbase.yaml").write_text("# otp-minbase\n", encoding="utf-8")
    (image / "layer" / "otp-image.yaml").write_text("# otp-image\n", encoding="utf-8")
    (image / "rpi-image-gen" / "rpi-image-gen").write_text("#!/bin/bash\n", encoding="utf-8")
    return repo, image


# ---------------------------------------------------------------------- fake docker
class FakeDocker:
    """Records calls; simulates scripts/builders by writing into the /out mount.

    ``volumes`` stands for the named volumes: the image builder leaves ``{"pmap": <variant>}`` in its
    work volume, the fake image-collect.sh reads it back.
    """

    def __init__(self):
        self.labels: dict[str, dict] = {}
        self.builds: list[dict] = []
        self.runs: list[dict] = []
        self.calls: list[str] = []
        self.handlers: dict[str, object] = {}     # script name or image tag -> fn(call)
        self.fail: set[str] = set()
        self.volumes: dict[str, dict] = {}

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
                "interactive": interactive, "docker": self}
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
    # every build yields different bytes (the out dir names the revision), like a real rebuild
    (out / f"fastboot-gadget-{t}.img").write_bytes(b"built-gadget " + out.name.encode() + b"\n" + b"g" * 6000)
    (out / "build-info.json").write_text(json.dumps({"targets": t, "built": "2026-09-30T11:00:00Z",
                                                     "pi_gen_micro_commit": call["env"]["PGM_COMMIT"],
                                                     "helpers": ["otp-keyexport"]}),
                                         encoding="utf-8")


def pmap_of(args: list[str]) -> str:
    """The ``IGconf_image_pmap`` an image build was asked for (exactly one, the last override)."""
    pmaps = [a.split("=", 1)[1] for a in args if a.startswith("IGconf_image_pmap=")]
    assert len(pmaps) == 1 and args[-1] == f"IGconf_image_pmap={pmaps[0]}", args
    return pmaps[0]


def h_builder(call, *, forced_pmap: str | None = None):
    pmap = pmap_of(call["args"])
    cfg_dir = Path(call["mounts"]["/cfg"].source)          # the config the station wrote, read while it exists
    call["config"] = (cfg_dir / "otp-image.yaml").read_text(encoding="utf-8")
    call["secret_files"] = {f.relative_to(cfg_dir).as_posix(): f.read_bytes()
                            for f in sorted(cfg_dir.rglob("*")) if f.is_file() and f.name != "otp-image.yaml"}
    call["docker"].volumes[call["mounts"]["/work"].source] = {"pmap": forced_pmap or pmap}
    (out_dir(call) / "deb13-arm64-min.img").write_bytes(b"raw image " + pmap.encode())


def h_collect(call, *, corrupt: str = ""):
    out = out_dir(call)
    built = call["docker"].volumes.get(call["mounts"]["/work"].source) or {}
    assert built.get("pmap") in VARIANTS, "image-collect.sh ran without an image build in the work volume"
    (out / "image.json").write_text(json.dumps(image_json_doc(encrypted=built["pmap"] == "crypt")),
                                    encoding="utf-8")
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

    def board(self, serial=SERIAL, lock: str = "", mode: str = "") -> dict:
        """A board seen in RPIBOOT; ``mode`` = the scenario chosen for it, ``lock`` = ours | other (OTP)."""
        self.modules.hello(serial, {"chip": "BCM2712"})
        if mode:
            self.modules.set_mode(serial, mode)
        if lock:
            rec = self.store.get(serial)
            rec["otp_key_hash"] = rec["customer_key_hash"] if lock == "ours" else "ab" * 32
            self.store.put(rec)
        return self.store.get(serial)

    def wait_all(self):
        for j in self.jobs.list():
            assert j.wait(20), j

    def report_stage1_locked(self, serial=SERIAL) -> dict:
        """The page's stage-1 report of a secure board: program_pubkey done, OTP holds the key hash."""
        h = self.store.get(serial)["customer_key_hash"]
        rec, verdict = self.modules.record_result(serial, 1, {
            "ok": True,
            "metadata": {"EEPROM_UPDATE": "success", "SECURE_BOOT_PROVISION": "success", "CUSTOMER_KEY_HASH": h},
            "expect": {"secure_boot_provision": True, "customer_key_hash": h}})
        assert verdict["ok"] and self.modules.locked_to_our_key(rec), verdict
        return rec

    @property
    def image_root(self) -> Path:
        return self.cfg.work_dir / "artifacts" / "image"

    def current(self, variant: str) -> dict:
        return json.loads((self.image_root / f"current-{variant}.json").read_text(encoding="utf-8"))


@pytest.fixture
def make_env(make_cfg, tmp_path):
    def _make(tools_ready: bool = True, **overrides) -> Env:
        repo, _image = make_repo(tmp_path)
        paths = overrides.pop("paths", {})
        cfg = make_cfg(tmp_path, repo_root=repo, paths=paths, **overrides)
        docker = FakeDocker()
        docker.handlers.update({"stage1.sh": h_stage1, "stage2-sign.sh": h_stage2, "image-collect.sh": h_collect,
                                "boot-resign.sh": h_resign, cfg.builds.gadget.image_tag: h_gadget,
                                cfg.builds.image.builder_tag: h_builder})
        jobs = JobManager(cfg.work_dir)
        store = MemoryStore()
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
    rec = env.board()
    assert env.modules.mode_of(rec) == "open"                 # provisioning.default_mode
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


def test_stage1_signed_secure_scenario(make_env):
    env = make_env(provisioning={"jtag_lock": True})
    rec = env.board(mode="secure")
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed"
    assert m["config_txt"] == ("uart_2ndstage=1\nset_reboot_order=0x3\nrecovery_reboot=1\n"
                               "program_pubkey=1\nprogram_jtag_lock=1\n")
    assert [i["key"] for i in m["irreversible"]] == ["program_pubkey", "program_jtag_lock"]
    assert "OTP" in m["irreversible"][0]["why"]
    assert m["expect"] == {"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"]}
    r = env.docker.runs_of("stage1.sh")[0]
    assert base_env(r) == {"MODE": "signed", "CHANNEL": "default", "SIGN_RECOVERY": "0"}
    assert r["env"]["EXPECT_CKH"] == rec["customer_key_hash"]
    assert r["mounts"]["/keys"].readonly and r["keys_files"] == ["private.pem", "public.pem"]
    assert not r["keys_dir"].exists()                       # temp key dir removed after the run
    d = Path(r["mounts"]["/out"].source)
    assert d.parent == env.cfg.work_dir / "modules" / SERIAL / "stage1"
    conf = (d.with_name(d.name[:-8]) / "boot.conf").read_text(encoding="utf-8")
    assert "ENABLE_SELF_UPDATE=0" in conf and "SIGNED_BOOT=1" in conf and "BOOT_ORDER=0xf2461" in conf
    assert env.jobs.last(f"stage1:{SERIAL}").status == "succeeded"
    # the private key never lands in the job log
    assert not any("PRIVATE KEY" in ln for j in env.jobs.list() for ln in j.lines)


def test_stage1_default_mode_and_per_board_choice(make_env):
    env = make_env(provisioning={"default_mode": "secure"})
    rec = env.board()                                     # no choice made: provisioning.default_mode
    assert env.modules.mode_of(rec) == "secure"
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and "program_pubkey=1" in m["config_txt"]
    assert m["expect"] == {"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"]}
    env.board(SERIAL2, mode="open")                       # the operator's choice wins over the default
    m2 = env.arts.stage_manifest(SERIAL2, 1)
    assert m2["mode"] == "unsigned" and m2["irreversible"] == [] and "program_pubkey=1" not in m2["config_txt"]
    assert [base_env(r)["MODE"] for r in env.docker.runs_of("stage1.sh")] == ["signed", "unsigned"]


def test_stage1_follows_a_scenario_switch(make_env):
    env = make_env()
    env.board()
    assert env.arts.stage_manifest(SERIAL, 1)["mode"] == "unsigned"
    unsigned_dir = env.arts.stage_file(SERIAL, 1, "pieeprom.bin").parent
    assert unsigned_dir.parent == env.cfg.work_dir / "artifacts" / "stage1"
    env.modules.set_mode(SERIAL, "secure")
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and [i["key"] for i in m["irreversible"]] == ["program_pubkey"]
    assert env.arts.stage_file(SERIAL, 1, "pieeprom.bin").parent.parent == env.cfg.work_dir / "modules" / SERIAL / "stage1"
    env.modules.set_mode(SERIAL, "open")                  # back: the shared unsigned dir is reused
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "unsigned" and env.arts.stage_file(SERIAL, 1, "pieeprom.bin").parent == unsigned_dir
    assert [base_env(r)["MODE"] for r in env.docker.runs_of("stage1.sh")] == ["unsigned", "signed"]


@pytest.mark.parametrize("chosen", ["", "open", "secure"])
def test_stage1_locked_to_our_key(make_env, chosen):
    env = make_env()
    rec = env.board(mode=chosen, lock="ours")
    assert env.modules.mode_of(rec) == "secure"           # a locked board is secure whatever was chosen
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "signed" and m["config_txt"] == config_txt(False, False) and m["irreversible"] == []
    assert m["expect"] == {"secure_boot_provision": False, "customer_key_hash": None}
    assert base_env(env.docker.runs_of("stage1.sh")[0]) == {"MODE": "signed", "CHANNEL": "default",
                                                             "SIGN_RECOVERY": "1"}
    assert "counter-signed" in m["files"][0]["origin"]


def test_stage1_jtag_lock_follows_the_scenario(make_env):
    env = make_env(provisioning={"jtag_lock": True})
    env.board()                                           # open: jtag_lock does not apply
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["mode"] == "unsigned" and m["config_txt"] == config_txt(False, False) and m["irreversible"] == []
    assert "provisioning.jtag_lock only applies to the secure scenario" in m["notes"]
    env.board(SERIAL2, mode="open", lock="ours")          # locked -> secure: jtag_lock applies, no pubkey
    m2 = env.arts.stage_manifest(SERIAL2, 1)
    assert m2["mode"] == "signed" and m2["config_txt"] == config_txt(False, True)
    assert [i["key"] for i in m2["irreversible"]] == ["program_jtag_lock"]
    assert m2["expect"]["secure_boot_provision"] is False
    assert not any("jtag_lock only applies" in n for n in m2["notes"])


def test_stage1_latest_channel(make_env):
    env = make_env(provisioning={"firmware_channel": "latest"})
    env.board()
    m = env.arts.stage_manifest(SERIAL, 1)
    assert m["source"]["channel"] == "latest"
    assert env.docker.runs_of("stage1.sh")[0]["env"]["CHANNEL"] == "latest"


@pytest.mark.parametrize("chosen", ["", "secure"])
def test_locked_to_other_key_is_refused(make_env, chosen):
    env = make_env()
    env.board(mode=chosen, lock="other")
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
def build_gadget(env) -> None:
    job = env.arts.start_build("gadget")
    assert job.title == "Build fastboot gadget"
    assert job.wait(10), "gadget job hangs"
    assert job.status == "succeeded", "\n".join(job.lines)


def test_gadget_is_always_built_here(make_env):
    env = make_env()
    env.board()
    g = env.arts.gadget
    with pytest.raises(NotReady, match="not built") as ei:
        g.current()
    assert ei.value.job is None
    st = env.arts.status()["gadget"]
    assert st["ready"] is False and st["source"] is None and "not built" in st["detail"]
    with pytest.raises(NotReady, match="not built") as ei:
        env.arts.stage_manifest(SERIAL, 2)
    assert ei.value.job is None                          # nothing is building it yet
    assert env.docker.runs == []
    build_gadget(env)
    path, source, version = g.current()
    assert source == "built" and version == g.key() and path == g.built_image()
    assert path.read_bytes().startswith(b"built-gadget")
    st = env.arts.status()["gadget"]
    assert st["ready"] and st["source"] == "built" and st["size"] == path.stat().st_size
    assert "otp-keyexport" in st["detail"]
    m = env.arts.stage_manifest(SERIAL, 2)
    assert m["source"] == {"gadget": "built", "version": version}
    assert env.arts.stage_file(SERIAL, 2, "boot.img") == path


def test_stage2_waits_for_a_running_gadget_build(make_env):
    env = make_env()
    env.board()
    gate = threading.Event()

    def slow(call):
        assert gate.wait(10)
        h_gadget(call)

    env.docker.handlers[GADGET_TAG] = slow
    job = env.arts.start_build("gadget")
    try:
        with pytest.raises(NotReady, match="not built") as ei:
            env.arts.stage_manifest(SERIAL, 2)
        assert ei.value.job is job and ei.value.to_dict()["job"]["target"] == "gadget"
        assert env.arts.status()["gadget"]["job"]["id"] == job.id
    finally:
        gate.set()
    assert job.wait(10) and job.status == "succeeded", job.error
    assert env.arts.stage_manifest(SERIAL, 2)["source"]["gadget"] == "built"


def test_gadget_build_job(make_env):
    env = make_env()
    job = env.arts.start_build("gadget")
    assert job.target == "gadget" and job.title == "Build fastboot gadget"
    assert job.wait(10) and job.status == "succeeded", (job.error, list(job.lines)[-6:])
    assert env.docker.calls[:2] == ["ensure_daemon", "ensure_arm64"]
    b = env.docker.builds[-1]
    assert b["tag"] == GADGET_TAG and b["platform"] == "linux/arm64"
    assert b["dockerfile"] == env.cfg.repo_root / "docker" / "gadget.Dockerfile"
    assert b["context"] == env.cfg.repo_root / "docker"         # the context carries gadget-helpers/
    r = env.docker.runs_of(GADGET_TAG)[0]
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
    # every helper package file is part of the builder identity
    helpers = env.cfg.repo_root / "docker" / "gadget-helpers" / "otp-keyexport"
    assert {helpers / n for n in HELPER_FILES} <= set(env.arts.gadget.builder_files)
    # already built: a non-forced build does not run docker again
    n = len(env.docker.runs)
    env.arts.start_build("gadget").wait(10)
    assert len(env.docker.runs) == n
    env.arts.start_build("gadget", force=True).wait(10)
    assert len(env.docker.runs) == n + 1


def test_stage2_unsigned(make_env):
    env = make_env()
    env.board()
    build_gadget(env)
    n_runs = len(env.docker.runs)
    m = env.arts.stage_manifest(SERIAL, 2, base_url="")
    assert m["stage"] == 2 and m["kind"] == "rpiboot" and m["mode"] == "unsigned"
    assert [f["name"] for f in m["files"]] == ["bootfiles.bin", "boot.img", "config.txt"]
    assert m["config_txt"] == "boot_ramdisk=1\nuart_2ndstage=1\n"
    assert m["source"] == {"gadget": "built", "version": env.arts.gadget.key()}
    assert m["irreversible"] == [] and m["expect"] == {"secure_boot_provision": False, "customer_key_hash": None}
    assert not any("OTP device key" in n for n in m["notes"])      # open scenario: no key export
    assert env.arts.stage_file(SERIAL, 2, "bootfiles.bin") == env.cfg.repo_root / "external/usbboot/firmware/bootfiles.bin"
    assert env.arts.stage_file(SERIAL, 2, "boot.img") == env.arts.gadget.built_image()
    cfgp = env.arts.stage_file(SERIAL, 2, "config.txt")
    assert cfgp == env.cfg.work_dir / "artifacts" / "stage2" / "config.txt"
    assert cfgp.read_bytes() == b"boot_ramdisk=1\nuart_2ndstage=1\n"
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 2, "boot.sig")
    assert len(env.docker.runs) == n_runs                          # unsigned stage 2 needs no docker
    # no sidecar files are written into the repository
    assert not list((env.cfg.repo_root / "external").rglob("*.sha256"))


def test_stage2_secure_scenario_uses_the_same_gadget(make_env):
    env = make_env()
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")      # secure stage 2 needs stage 1 done (OTP locked)
    build_gadget(env)
    m_open = env.arts.stage_manifest(SERIAL, 2)
    m_sec = env.arts.stage_manifest(SERIAL2, 2)
    assert m_open["mode"] == "unsigned" and not any("OTP device key" in n for n in m_open["notes"])
    assert m_sec["mode"] == "signed"
    assert [f["name"] for f in m_sec["files"]] == ["bootfiles.bin", "boot.img", "boot.sig", "config.txt"]
    assert any("exports the OTP device key" in n for n in m_sec["notes"])
    # one gadget for both scenarios: only the signature differs
    boot = {f["name"]: f for f in m_open["files"]}["boot.img"]
    assert {f["name"]: f for f in m_sec["files"]}["boot.img"]["sha256"] == boot["sha256"]
    assert env.arts.stage_file(SERIAL2, 2, "boot.img") == env.arts.stage_file(SERIAL, 2, "boot.img")
    assert env.arts.stage_file(SERIAL, 2, "boot.img") == env.arts.gadget.built_image()
    assert len(env.docker.runs_of("stage2-sign.sh")) == 1          # only the locked board is signed for


@pytest.mark.parametrize("chosen", ["", "open"])
def test_stage2_signed_when_locked_to_our_key(make_env, chosen):
    env = make_env()
    env.board(mode=chosen, lock="ours")
    build_gadget(env)
    m = env.arts.stage_manifest(SERIAL, 2)
    assert m["mode"] == "signed"
    assert [f["name"] for f in m["files"]] == ["bootfiles.bin", "boot.img", "boot.sig", "config.txt"]
    assert any("exports the OTP device key" in n for n in m["notes"])     # locked = secure scenario
    r = env.docker.runs_of("stage2-sign.sh")[0]
    assert r["in_files"] == ["boot.img", "bootfiles.bin"] and r["mounts"]["/in"].readonly
    assert r["keys_files"] == ["private.pem", "public.pem"] and not r["keys_dir"].exists()
    signed_bf = env.arts.stage_file(SERIAL, 2, "bootfiles.bin")
    assert signed_bf.read_bytes() == b"signed-bootfiles"
    assert signed_bf.parent.parent == env.cfg.work_dir / "modules" / SERIAL / "stage2"
    assert env.arts.stage_file(SERIAL, 2, "boot.sig").parent == signed_bf.parent
    env.arts.stage_manifest(SERIAL, 2)
    assert len(env.docker.runs_of("stage2-sign.sh")) == 1          # cached per board


SECURE_NEEDS_STAGE1 = ("is in the secure scenario but its OTP does not hold this board's key hash yet: "
                       "run stage 1 first (signed EEPROM + program_pubkey)")


def test_scenario_switch_drops_the_boards_pinned_downloads(make_env):
    env = make_env()
    build_gadget(env)
    build_image(env)
    env.board(mode="open")
    m3 = env.arts.stage_manifest(SERIAL, 3)                     # open: the clear image, pinned
    piece = m3["parts"]["root.ext4.sparse"][0]["name"]
    assert env.arts.stage_file(SERIAL, 3, piece).is_file()
    env.modules.set_mode(SERIAL, "secure")                      # what POST /api/modules/{serial}/mode does ...
    env.arts.forget_board(SERIAL)                               # ... together with this
    with pytest.raises(NotReady, match="run stage 1 first"):   # the old pins no longer serve the clear image
        env.arts.stage_file(SERIAL, 3, piece)
    other = env.board(serial=SERIAL2, mode="open")             # other boards keep their pins
    m3b = env.arts.stage_manifest(SERIAL2, 3)
    env.arts.forget_board(SERIAL)
    assert env.arts.stage_file(SERIAL2, 3, m3b["image_json"]["name"]).is_file() and other


@pytest.mark.parametrize("how", ["chosen", "default_mode"])
def test_secure_board_needs_stage1_before_stages_2_and_3(make_env, how):
    env = make_env(**({"provisioning": {"default_mode": "secure"}} if how == "default_mode" else {}))
    build_gadget(env)
    build_image(env)
    rec = env.board(mode="secure" if how == "chosen" else "")
    assert env.modules.mode_of(rec) == "secure" and not env.modules.is_locked(rec)
    n_jobs, n_runs = len(env.jobs.list()), len(env.docker.runs)
    for stage, name in ((2, "boot.img"), (3, "image.json")):
        with pytest.raises(NotReady) as ei:
            env.arts.stage_manifest(SERIAL, stage)
        assert ei.value.reason == f"board {SERIAL} {SECURE_NEEDS_STAGE1}"
        assert ei.value.job is None and ei.value.to_dict()["job"] is None
        with pytest.raises(NotReady, match="run stage 1 first"):          # no manifest, no download
            env.arts.stage_file(SERIAL, stage, name)
    assert len(env.jobs.list()) == n_jobs and len(env.docker.runs) == n_runs   # nothing was started
    # stage 1 is served: the signed EEPROM that burns the board's key hash into OTP
    m1 = env.arts.stage_manifest(SERIAL, 1)
    assert m1["mode"] == "signed" and [i["key"] for i in m1["irreversible"]] == ["program_pubkey"]
    assert m1["expect"] == {"secure_boot_provision": True, "customer_key_hash": rec["customer_key_hash"]}
    # the page reports stage 1 done (OTP locked to our key): stages 2 and 3 are served, signed
    env.report_stage1_locked(SERIAL)
    m2 = env.arts.stage_manifest(SERIAL, 2)
    assert m2["mode"] == "signed" and "boot.sig" in [f["name"] for f in m2["files"]]
    assert len(env.docker.runs_of("stage2-sign.sh")) == 1
    m3 = env.arts.stage_manifest(SERIAL, 3)
    assert m3["mode"] == "signed" and m3["scenario"] == "secure" and m3["image"]["variant"] == "crypt"
    assert m3["fwcrypto_init"] is True and m3["key_export"] == KEY_EXPORT
    assert len(env.docker.runs_of("boot-resign.sh")) == 1
    # an open board is not held back by the rule
    env.board(SERIAL2, mode="open")
    assert env.arts.stage_manifest(SERIAL2, 2)["mode"] == "unsigned"
    assert env.arts.stage_manifest(SERIAL2, 3)["scenario"] == "open"


# ---------------------------------------------------------------------- image / stage 3
def build_image(env) -> None:
    job = env.arts.start_build("image")
    assert job.title == "Build OS images (clear + crypt)"
    assert job.wait(20), "image job hangs"
    assert job.status == "succeeded", "\n".join(job.lines)


def test_image_variant_helpers(make_env):
    env = make_env(builds={"image": {"overrides": ["IGconf_extra=1"]}})
    img = env.arts.image
    assert VARIANTS == ("clear", "crypt")
    assert img.overrides("clear") == ["IGconf_extra=1", "IGconf_image_pmap=clear"]
    assert img.overrides("crypt") == ["IGconf_extra=1", "IGconf_image_pmap=crypt"]
    assert img.config_hash("clear") != img.config_hash("crypt")
    assert img.build_args("crypt") == ["--in-container", "-B", "/work", "-o", "/out", "-c", "/cfg/otp-image.yaml",
                                       "--", "IGconf_extra=1", "IGconf_image_pmap=crypt"]
    assert img.current_json("clear") == env.image_root / "current-clear.json"
    for bad in ("open", "secure", "", "CRYPT"):
        with pytest.raises(ValueError):
            img.overrides(bad)
        with pytest.raises(ValueError):
            img.current_json(bad)
    assert img.missing_variants() == ["clear", "crypt"]


def test_image_build_argv_and_collect(make_env):
    env = make_env()
    assert env.arts.image.missing_variants() == list(VARIANTS)
    build_image(env)
    runs = env.docker.runs_of(BUILDER_TAG)
    assert len(runs) == 2                                  # one build per variant, clear first
    for r, v in zip(runs, VARIANTS):
        assert r["args"] == ["--in-container", "-B", "/work", "-o", "/out", "-c", "/cfg/otp-image.yaml",
                             "--", f"IGconf_image_pmap={v}"]
        assert r["privileged"] and r["interactive"] and r["hostname"] == "otp-image-builder"
        assert r["env"] == {"OTP_IMAGE_IN_CONTAINER": "1", "OTP_IMAGE_ROOT": "/src", "OTP_IMAGE_VERSION": "unknown",
                            "OTP_IMAGE_CONFIG_ID": "otp-image.yaml"}
        assert Path(r["mounts"]["/src"].source) == env.cfg.image_dir and r["mounts"]["/src"].readonly
        assert r["mounts"]["/work"].type == "volume" and r["mounts"]["/work"].source == "otp-image-work"
        assert Path(r["mounts"]["/out"].source) == env.image_root / "staging"
        cfg_dir = Path(r["mounts"]["/cfg"].source)
        assert r["mounts"]["/cfg"].readonly and cfg_dir.parent == env.image_root / "cfg"
        assert not cfg_dir.exists()                          # the config dir (secrets) is gone after the build
        assert "  base: otp-minbase\n  station: otp-image\n" in r["config"] and "openssh-server" not in r["config"]
        assert r["secret_files"] == {}                       # defaults: no password, no Wi-Fi, no SSH
    b = [x for x in env.docker.builds if x["tag"] == BUILDER_TAG]
    assert b and all(x["context"] == env.cfg.image_dir / "docker" for x in b)
    assert all(x["dockerfile"] == env.cfg.image_dir / "docker" / "Dockerfile" for x in b)
    collects = env.docker.runs_of("image-collect.sh")
    assert len(collects) == 2
    for c in collects:
        assert c["env"] == {"MAX_PIECE": "268435456"}
        assert c["mounts"]["/work"].type == "volume" and c["mounts"]["/work"].readonly
        assert Path(c["mounts"]["/out"].source).name.endswith(".partial")

    assert not (env.image_root / "current.json").exists()          # one current file per variant
    sets = {}
    for v in VARIANTS:
        cur = env.current(v)
        set_dir = env.image_root / cur["set"]
        assert cur["set"].startswith(f"deb13-arm64-min-{v}-unknown-") and (set_dir / ".complete").is_file()
        man = json.loads((set_dir / "manifest.json").read_text(encoding="utf-8"))
        assert man["name"] == "deb13-arm64-min" and man["version"] == "unknown" and man["set"] == cur["set"]
        assert man["variant"] == v and man["encrypted"] is (v == "crypt")
        assert imagejson.is_encrypted(imagejson.load(set_dir / "image.json")) is (v == "crypt")
        assert man["device_class"] == "pi5" and man["storage_type"] == "sd"
        assert man["overrides"] == [f"IGconf_image_pmap={v}"]
        assert man["config_hash"] == env.arts.image.config_hash(v)
        assert man["sources_hash"] == env.arts.image.sources_hash() and "rpi_image_gen_commit" in man
        assert man["image_settings"]["hostname"] == "pi5" and man["image_settings"]["password_set"] is False
        assert "droneos_commit" not in man and "config" not in man
        assert [p["name"] for p in man["simages"]["root.ext4.sparse"]] == ["root.ext4.sparse.0", "root.ext4.sparse.1"]
        assert man["simages"]["root.ext4.sparse"][1]["sha256"] == sha(set_dir / "root.ext4.sparse.1")
        assert env.arts.image.current_set(v) == (set_dir, man)
        sets[v] = set_dir
    assert sets["clear"] != sets["crypt"]
    assert not list((env.image_root / "staging").glob("*.img"))   # raw images dropped (keep_raw_image false)
    assert env.arts.image.missing_variants() == []
    st = env.arts.status()["image"]
    assert st["ready"] and st["source"] == "built" and st["version"] == "unknown" and st["size"] > 0
    assert st["path"] == str(sets["crypt"])                       # top level describes the crypt set
    assert set(st["variants"]) == set(VARIANTS)
    for v in VARIANTS:
        vs = st["variants"][v]
        assert vs["ready"] is True and vs["path"] == str(sets[v]) and vs["set"] == sets[v].name
        assert vs["size"] > 0 and vs["version"] == "unknown"
    assert "encrypted" in st["variants"]["crypt"]["detail"]
    assert "encrypted" not in st["variants"]["clear"]["detail"]
    # both present: a non-forced build runs nothing
    n = len(env.docker.runs)
    build_image(env)
    assert len(env.docker.runs) == n


def test_image_keep_raw_and_overrides(make_env):
    env = make_env(builds={"image": {"keep_raw_image": True, "overrides": ["IGconf_x=1"]}})
    build_image(env)
    runs = env.docker.runs_of(BUILDER_TAG)
    assert [r["args"] for r in runs] == [["--in-container", "-B", "/work", "-o", "/out", "-c", "/cfg/otp-image.yaml",
                                          "--", "IGconf_x=1", f"IGconf_image_pmap={v}"] for v in VARIANTS]
    assert list((env.image_root / "staging").glob("*.img"))
    for v in VARIANTS:
        assert env.arts.image.current_set(v)[1]["overrides"] == ["IGconf_x=1", f"IGconf_image_pmap={v}"]


@pytest.mark.parametrize("corrupt,msg", [("sha", "sha256 mismatch"), ("missing", "missing"),
                                         ("mixed", "different images")])
def test_image_collect_validation_failures(make_env, corrupt, msg):
    env = make_env()
    env.docker.handlers["image-collect.sh"] = lambda call: h_collect(call, corrupt=corrupt)
    job = env.arts.start_build("image")
    job.wait(20)
    assert job.status == "failed" and msg in job.error
    for v in VARIANTS:
        assert not (env.image_root / f"current-{v}.json").exists()
    assert env.arts.image.missing_variants() == list(VARIANTS)
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")
    for serial in (SERIAL, SERIAL2):
        with pytest.raises(NotReady, match="not built"):
            env.arts.stage_manifest(serial, 3)


@pytest.mark.parametrize("forced", VARIANTS)
def test_image_collect_refuses_a_build_of_the_wrong_kind(make_env, forced):
    """A builder that ignores IGconf_image_pmap must not publish its image under the other variant."""
    env = make_env()
    env.docker.handlers[BUILDER_TAG] = lambda call: h_builder(call, forced_pmap=forced)
    job = env.arts.start_build("image")
    assert job.wait(20) and job.status == "failed"
    wrong = "clear" if forced == "crypt" else "crypt"
    kind = "encrypted" if forced == "crypt" else "not encrypted"
    assert f"the {wrong} build produced an image that is {kind}" in job.error
    assert "IGconf_image_pmap ignored" in job.error
    assert not (env.image_root / f"current-{wrong}.json").exists()
    assert wrong in env.arts.image.missing_variants()
    st = env.arts.status()["image"]
    assert st["ready"] is False and st["variants"][wrong]["ready"] is False
    if forced == "clear":       # clear is built first and is right; the crypt build is refused
        assert env.arts.image.missing_variants() == ["crypt"] and st["variants"]["clear"]["ready"] is True
    else:                       # the clear build fails first and the job stops there
        assert env.arts.image.missing_variants() == ["clear", "crypt"]
    # nothing published under the wrong variant can be served to a board of that scenario
    if wrong == "clear":
        env.board(mode="open")
    else:
        env.board(mode="secure", lock="ours")
    with pytest.raises(NotReady, match="not built"):
        env.arts.stage_manifest(SERIAL, 3)


def test_image_build_only_the_missing_variant(make_env):
    env = make_env()
    build_gadget(env)
    build_image(env)
    crypt_set = env.arts.image.current_set("crypt")[1]["set"]
    clear_set = env.arts.image.current_set("clear")[1]["set"]
    (env.image_root / "current-clear.json").unlink()
    assert env.arts.image.missing_variants() == ["clear"]
    st = env.arts.status()["image"]
    assert st["ready"] is False and st["variants"]["crypt"]["ready"] is True
    assert st["variants"]["clear"]["ready"] is False and "clear: the clear image is not built yet" in st["detail"]
    n = len(env.docker.runs_of(BUILDER_TAG))
    jobs = env.arts.auto_build()
    assert [j.target for j in jobs] == ["image"]
    env.wait_all()
    assert all(j.status == "succeeded" for j in jobs), [j.error for j in jobs]
    assert [r["args"][-1] for r in env.docker.runs_of(BUILDER_TAG)[n:]] == ["IGconf_image_pmap=clear"]
    assert env.arts.image.current_set("crypt")[1]["set"] == crypt_set              # untouched
    new_clear = env.arts.image.current_set("clear")[1]["set"]
    assert new_clear == f"{clear_set}-r2"                 # the old dir is still there: never replaced
    assert env.arts.image.missing_variants() == [] and env.arts.auto_build() == []
    # an explicit forced build of one variant rebuilds just that one
    n = len(env.docker.runs_of(BUILDER_TAG))
    job = env.jobs.submit("image", "crypt only", lambda j: env.arts.image.build(j, force=True, variants=["crypt"]))
    assert job.wait(20) and job.status == "succeeded", job.error
    assert [r["args"][-1] for r in env.docker.runs_of(BUILDER_TAG)[n:]] == ["IGconf_image_pmap=crypt"]
    assert env.arts.image.current_set("crypt")[1]["set"] == f"{crypt_set}-r2"
    assert env.arts.image.current_set("clear")[1]["set"] == new_clear
    job = env.jobs.submit("image", "bad", lambda j: env.arts.image.build(j, variants=["secure"]))
    assert job.wait(20) and job.status == "failed" and "variant" in job.error


def test_stage3_not_ready_before_build(make_env):
    env = make_env()
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")
    for serial, v in ((SERIAL, "clear"), (SERIAL2, "crypt")):
        with pytest.raises(NotReady, match=rf"\({v}\) is not built yet") as ei:
            env.arts.stage_manifest(serial, 3)
        assert ei.value.job is None
    st = env.arts.status()["image"]
    assert st["ready"] is False and st["source"] is None
    assert all(st["variants"][v]["ready"] is False and "not built" in st["variants"][v]["detail"] for v in VARIANTS)


def test_stage3_open_manifest(make_env):
    env = make_env()
    build_image(env)
    env.board()
    clear_dir, clear_man = env.arts.image.current_set("clear")
    n_runs = len(env.docker.runs)
    m = env.arts.stage_manifest(SERIAL, 3, base_url="http://h")
    assert m["stage"] == 3 and m["kind"] == "fastboot-idp" and m["title"] == "Image" and m["mode"] == "unsigned"
    assert m["scenario"] == "open"
    assert m["image"]["variant"] == "clear" and m["image"]["encrypted"] is False
    assert m["image"]["set"] == clear_man["set"] and m["image"]["name"] == "deb13-arm64-min"
    assert m["image"]["storage_type"] == "sd" and m["image"]["device_class"] == "pi5"
    # nothing touches OTP: no fwcrypto init, no key export, no LUKS passphrase
    assert m["fwcrypto_init"] is False and m["key_export"] is None and m["crypt"] == []
    assert m["storage_device"] == "mmcblk0" and m["erase"] is True
    assert [i["key"] for i in m["irreversible"]] == ["erase"] and m["irreversible"][0]["value"] == "mmcblk0"
    assert any("open scenario" in n for n in m["notes"])
    assert list(m["parts"]) == ["boot.vfat.sparse", "root.ext4.sparse"]
    assert [p["name"] for p in m["parts"]["root.ext4.sparse"]] == ["root.ext4.sparse.0", "root.ext4.sparse.1"]
    p1 = m["parts"]["root.ext4.sparse"][1]
    assert set(p1) == {"name", "size", "sha256", "url"}
    assert p1["url"] == f"http://h/api/modules/{SERIAL}/stage/3/files/root.ext4.sparse.1"
    assert m["image_json"]["name"] == "image.json" and m["image_json"]["url"].endswith("/stage/3/files/image.json")
    total = m["image_json"]["size"] + sum(p["size"] for ps in m["parts"].values() for p in ps)
    assert m["total_bytes"] == total and m["max_piece_size"] == 268435456
    path = env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.1")
    assert path.parent == clear_dir and sha(path) == p1["sha256"]
    ij = env.arts.stage_file(SERIAL, 3, "image.json")
    assert ij.parent == clear_dir and imagejson.is_encrypted(imagejson.load(ij)) is False
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 3, "manifest.json")
    assert len(env.docker.runs) == n_runs                        # unsigned stage 3 needs no docker


def test_stage3_open_scenario_ignores_recovery_passphrase(make_env):
    env = make_env(provisioning={"recovery_passphrase": True, "erase_storage": False})
    build_image(env)
    env.board()
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["scenario"] == "open" and m["crypt"] == [] and m["erase"] is False
    assert m["irreversible"] == [] and m["fwcrypto_init"] is False and m["key_export"] is None


def test_stage3_secure_manifest(make_env):
    env = make_env()
    build_image(env)
    env.board(mode="secure")
    env.report_stage1_locked(SERIAL)                          # stage 3 of a secure board follows stage 1
    crypt_dir, crypt_man = env.arts.image.current_set("crypt")
    n_runs = len(env.docker.runs)
    m = env.arts.stage_manifest(SERIAL, 3, base_url="http://h")
    assert m["scenario"] == "secure" and m["mode"] == "signed"           # locked to our key: boot slot re-signed
    assert m["image"]["variant"] == "crypt" and m["image"]["encrypted"] is True
    assert m["image"]["set"] == crypt_man["set"]
    assert m["fwcrypto_init"] is True and m["erase"] is True
    assert m["key_export"] == KEY_EXPORT and m["key_export"] is not KEY_EXPORT     # a copy, not the constant
    assert set(m["key_export"]) == {"dir", "key", "status", "request"}
    assert all(m["key_export"][k].startswith(m["key_export"]["dir"] + "/") for k in ("key", "status", "request"))
    assert [i["key"] for i in m["irreversible"]] == ["oem fwcrypto init", "erase"]
    assert "OTP" in m["irreversible"][0]["why"] and m["irreversible"][1]["value"] == "mmcblk0"
    assert m["crypt"] == []                                   # provisioning.recovery_passphrase is off by default
    assert any("exported to the station" in n for n in m["notes"])
    for simage, pieces in m["parts"].items():
        for p in pieces:
            path = env.arts.stage_file(SERIAL, 3, p["name"])
            if simage == "boot.vfat.sparse":                  # per-board re-signed boot slot
                assert path.parent.parent == env.cfg.work_dir / "modules" / SERIAL / "stage3"
            else:                                             # everything else from the shared crypt set
                assert path.parent == crypt_dir
            assert sha(path) == p["sha256"]
    ij = env.arts.stage_file(SERIAL, 3, "image.json")
    assert ij.parent == crypt_dir and imagejson.is_encrypted(imagejson.load(ij)) is True
    assert [r["args"][:1] for r in env.docker.runs[n_runs:]] == [["boot-resign.sh"]]   # the only docker run


def test_stage3_secure_with_recovery_passphrase(make_env):
    env = make_env(provisioning={"recovery_passphrase": True, "erase_storage": False})
    build_image(env)
    rec = env.board(mode="secure", lock="ours")
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["mode"] == "signed" and m["scenario"] == "secure"
    assert m["crypt"] == [{"dev": "mmcblk0p2", "mname": "osroot_crypt", "label": "OSROOT_CRYPT",
                           "passphrase": luks_passphrase(rec["device_secret"], "osroot_crypt", SERIAL)}]
    assert m["erase"] is False and [i["key"] for i in m["irreversible"]] == ["oem fwcrypto init"]


@pytest.mark.parametrize("chosen", ["", "open", "secure"])
def test_stage3_signed_resigns_boot_slot(make_env, chosen):
    env = make_env()
    build_image(env)
    env.board(mode=chosen, lock="ours")                       # locked to our key: always the secure scenario
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["mode"] == "signed" and m["scenario"] == "secure" and m["image"]["variant"] == "crypt"
    assert m["fwcrypto_init"] is True and m["key_export"] == KEY_EXPORT
    r = env.docker.runs_of("boot-resign.sh")[0]
    assert r["env"] == {"SIMAGE": "boot.vfat.sparse", "MAX_PIECE": "268435456"}
    crypt_set = env.current("crypt")["set"]
    assert Path(r["mounts"]["/in"].source) == env.image_root / crypt_set
    assert r["mounts"]["/in"].readonly and r["keys_files"] == ["private.pem", "public.pem"]
    assert not r["keys_dir"].exists()
    assert [p["name"] for p in m["parts"]["boot.vfat.sparse"]] == ["boot.vfat.sparse"]
    p = env.arts.stage_file(SERIAL, 3, "boot.vfat.sparse")
    assert p.parent.parent == env.cfg.work_dir / "modules" / SERIAL / "stage3"
    assert m["parts"]["boot.vfat.sparse"][0]["sha256"] == sha(p)
    # root pieces still come from the shared crypt set
    assert env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0").parent.name == crypt_set
    env.arts.stage_manifest(SERIAL, 3)
    assert len(env.docker.runs_of("boot-resign.sh")) == 1


def test_stage3_follows_the_board_scenario(make_env):
    env = make_env()
    build_image(env)
    env.board()
    clear_dir = env.arts.image.current_set("clear")[0]
    crypt_dir = env.arts.image.current_set("crypt")[0]
    assert env.arts.stage_manifest(SERIAL, 3)["image"]["variant"] == "clear"
    assert env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0").parent == clear_dir
    # switched to secure after the open stages: stages 2 and 3 wait until stage 1 has locked the OTP
    env.modules.set_mode(SERIAL, "secure")
    for stage in (2, 3):
        with pytest.raises(NotReady, match="run stage 1 first"):
            env.arts.stage_manifest(SERIAL, stage)
    assert env.arts.stage_manifest(SERIAL, 1)["mode"] == "signed"
    env.report_stage1_locked(SERIAL)
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["scenario"] == "secure" and m["mode"] == "signed" and m["image"]["variant"] == "crypt"
    assert env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0").parent == crypt_dir
    assert env.arts.stage_file(SERIAL, 3, "image.json").parent == crypt_dir


@pytest.mark.parametrize("variant", VARIANTS)
def test_stage3_refuses_an_image_whose_encryption_does_not_match(make_env, variant):
    """Defence in depth: the set's image.json is checked against the scenario, not just the manifest."""
    env = make_env()
    build_image(env)
    if variant == "clear":
        env.board(mode="open")
    else:
        env.board(mode="secure", lock="ours")
    set_dir = env.arts.image.current_set(variant)[0]
    (set_dir / "image.json").write_text(json.dumps(image_json_doc(encrypted=variant == "clear")), encoding="utf-8")
    scenario = "open" if variant == "clear" else "secure"
    with pytest.raises(NotReady, match=f"the {scenario} scenario needs"):
        env.arts.stage_manifest(SERIAL, 3)


def test_key_export_paths_match_the_gadget_helper():
    """The stage-3 key_export paths are where docker/gadget-helpers/otp-keyexport works."""
    pkg = REAL_REPO / "docker" / "gadget-helpers" / "otp-keyexport"
    script = (pkg / "otp-keyexport").read_text(encoding="utf-8")
    m = re.search(r'^DIR="\$\{OTP_KEYEXPORT_DIR:-([^}]+)\}"', script, re.MULTILINE)
    assert m and m.group(1) == KEY_EXPORT["dir"]
    assert KEY_EXPORT["key"] == KEY_EXPORT["dir"] + "/key.der" and '"$DIR/key.der"' in script
    assert KEY_EXPORT["status"] == KEY_EXPORT["dir"] + "/status" and '"$DIR/status"' in script
    assert KEY_EXPORT["request"] == KEY_EXPORT["dir"] + "/request" and '"$DIR/request"' in script
    path_unit = (pkg / "otp-keyexport-request.path").read_text(encoding="utf-8")
    assert f"PathExists={KEY_EXPORT['request']}" in path_unit.splitlines()
    install = {ln.split()[0]: ln.split()[1:] for ln in (pkg / "install").read_text(encoding="utf-8").splitlines()
               if ln.strip()}
    assert install["otp-keyexport"][0] == "/usr/local/bin"
    for unit, mode in (("otp-keyexport-boot.service", "boot"), ("otp-keyexport-request.service", "request")):
        assert f"ExecStart=/usr/local/bin/otp-keyexport {mode}" in (pkg / unit).read_text(encoding="utf-8").splitlines()
        assert unit in install
    # the boot export must run before rpi-fastbootd READ-locks the key
    assert "Before=fastbootd.service" in (pkg / "otp-keyexport-boot.service").read_text(encoding="utf-8").splitlines()
    assert "Package: otp-keyexport" in (pkg / "control").read_text(encoding="utf-8").splitlines()


# ---------------------------------------------------------------------- facade
def test_status_shape_and_start_build_validation(make_env):
    env = make_env()
    st = env.arts.status()
    assert set(st) == {"tools", "gadget", "image"}
    for target, s in st.items():
        assert s["target"] == target
        assert set(s) >= {"target", "ready", "source", "version", "path", "size", "built", "detail", "job"}
    assert st["tools"]["ready"] is True and st["tools"]["path"] == TOOLS_TAG
    assert set(st["image"]["variants"]) == set(VARIANTS)
    for vs in st["image"]["variants"].values():
        assert set(vs) == {"ready", "set", "version", "path", "size", "built", "detail"}
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
    assert env.arts.gadget.built_image() is not None and env.arts.image.missing_variants() == []
    assert [pmap_of(r["args"]) for r in env.docker.runs_of(BUILDER_TAG)] == list(VARIANTS)
    assert env.arts.auto_build() == []                  # everything present now


def test_auto_build_skips_what_is_built(make_env):
    env = make_env()
    build_gadget(env)
    jobs = env.arts.auto_build()
    assert [j.target for j in jobs] == ["image"]        # tools ready, gadget built
    env.wait_all()
    assert env.arts.auto_build() == []


# ---------------------------------------------------------------------- review fixes
# #3 downloads are pinned to the manifest the page fetched
def test_stage_file_serves_the_issued_manifest_not_a_newer_artifact(make_env):
    env = make_env()
    env.board()
    build_gadget(env)
    m = env.arts.stage_manifest(SERIAL, 2)
    key = env.arts.gadget.key()
    assert m["source"] == {"gadget": "built", "version": key}
    boot = {f["name"]: f for f in m["files"]}["boot.img"]
    p1 = env.arts.gadget.built_image()
    # a gadget rebuild commits while the page still holds the first manifest
    job = env.arts.start_build("gadget", force=True)
    assert job.wait(10) and job.status == "succeeded", job.error
    assert env.arts.gadget.current()[2] == f"{key}-r2"
    p = env.arts.stage_file(SERIAL, 2, "boot.img")
    assert p == p1 and sha(p) == boot["sha256"]
    # a new manifest switches the downloads to the new build
    m2 = env.arts.stage_manifest(SERIAL, 2)
    assert m2["source"] == {"gadget": "built", "version": f"{key}-r2"}
    p2 = env.arts.stage_file(SERIAL, 2, "boot.img")
    assert p2 == env.arts.gadget.built_image() and p2 != p1
    assert sha(p2) == {f["name"]: f for f in m2["files"]}["boot.img"]["sha256"] != boot["sha256"]
    # the pinned file itself changed: refused, the page must restart the stage
    p2.write_bytes(b"tampered")
    with pytest.raises(NotReady, match="changed after its manifest was issued"):
        env.arts.stage_file(SERIAL, 2, "boot.img")
    with pytest.raises(FileNotFoundError):
        env.arts.stage_file(SERIAL, 2, "boot.sig")


@pytest.mark.parametrize("mode,lock,variant", [("open", "", "clear"), ("secure", "ours", "crypt")])
def test_stage3_download_survives_an_image_rebuild(make_env, mode, lock, variant):
    env = make_env()
    build_image(env)
    env.board(mode=mode, lock=lock)
    m = env.arts.stage_manifest(SERIAL, 3)
    assert m["image"]["variant"] == variant and m["mode"] == ("signed" if lock else "unsigned")
    boot = env.arts.stage_file(SERIAL, 3, "boot.vfat.sparse")
    old = env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0")
    assert old.parent == env.arts.image.current_set(variant)[0]
    job = env.arts.start_build("image", force=True)
    assert job.wait(20) and job.status == "succeeded", job.error
    for v in VARIANTS:                                        # a forced build rebuilds both variants
        assert env.arts.image.current_set(v)[1]["set"].endswith("-r2")
    assert env.arts.image.current_set(variant)[0] != old.parent          # a new set is current
    p = env.arts.stage_file(SERIAL, 3, "root.ext4.sparse.0")
    assert p == old and p.is_file() and sha(p) == m["parts"]["root.ext4.sparse"][0]["sha256"]
    pb = env.arts.stage_file(SERIAL, 3, "boot.vfat.sparse")        # re-signed per board when locked
    assert pb == boot and sha(pb) == m["parts"]["boot.vfat.sparse"][0]["sha256"]


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
    from otp_server.artifacts import common

    target = tmp_path / "current.json"
    common.write_json(target, {"set": "a"})
    f = open(target, "r", encoding="utf-8")
    threading.Timer(0.3, f.close).start()
    common.write_json(target, {"set": "b"})
    assert json.loads(target.read_text(encoding="utf-8")) == {"set": "b"}


# #5 a forced rebuild never replaces a directory in place
def test_forced_gadget_rebuild_keeps_the_served_dir(make_env):
    env = make_env()
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
    env = make_env()
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


def test_gadget_key_covers_the_helper_packages(make_env):
    env = make_env()
    env.board()
    g = env.arts.gadget
    build_gadget(env)
    k1, h1 = g.key(), g.builder_hash()
    assert env.arts.stage_manifest(SERIAL, 2)["ready"] is True
    pkg = env.cfg.repo_root / "docker" / "gadget-helpers" / "otp-keyexport"
    script = pkg / "otp-keyexport"
    original = script.read_bytes()
    script.write_bytes(original + b"echo changed\n")             # a helper changed: the gadget is stale
    assert g.builder_hash() != h1 and g.key() != k1 and g.key().endswith("-pi5-family")
    assert g.built_image() is None
    with pytest.raises(NotReady, match="not built"):
        g.current()
    with pytest.raises(NotReady, match="not built"):
        env.arts.stage_manifest(SERIAL, 2)
    assert env.arts.status()["gadget"]["ready"] is False
    assert [j.target for j in env.arts.auto_build()] == ["gadget", "image"]
    env.wait_all()
    assert g.built_image() is not None and g.key() != k1
    script.write_bytes(original.replace(b"\n", b"\r\n"))          # back, CRLF: the first build is current again
    assert g.key() == k1 and g.built_image().parent.name == k1
    # a new file anywhere under docker/gadget-helpers/ (a new package, a nested file) counts too
    extra = env.cfg.repo_root / "docker" / "gadget-helpers" / "other-helper" / "debian" / "rules"
    extra.parent.mkdir(parents=True)
    extra.write_bytes(b"#!/usr/bin/make -f\n")
    assert extra in g.builder_files and g.key() != k1
    extra.unlink()
    assert g.key() == k1
    (pkg / "control").unlink()                                    # a removed file counts as well
    assert g.key() != k1


def test_image_set_split_larger_than_max_piece_needs_rebuild(make_env):
    env = make_env()
    build_image(env)
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")
    assert env.arts.image.missing_variants() == []
    env.cfg.provisioning.max_piece_size = 1 << 20      # smaller than the 256 MiB the sets were split with
    assert env.arts.image.missing_variants() == list(VARIANTS)
    for v in VARIANTS:
        assert env.arts.image.current_set(v) is None
        assert "rebuild needed" in env.arts.image.rebuild_reason(env.arts.image.published_set(v)[1], v)
    for serial in (SERIAL, SERIAL2):
        with pytest.raises(NotReady, match="rebuild needed"):
            env.arts.stage_manifest(serial, 3)
    st = env.arts.status()["image"]
    assert st["ready"] is False and "rebuild needed" in st["detail"]
    assert all("rebuild needed" in st["variants"][v]["detail"] for v in VARIANTS)
    assert "image" in [j.target for j in env.arts.auto_build()]
    env.wait_all()
    for v in VARIANTS:
        assert env.arts.image.current_set(v)[1]["max_piece_size"] == 1 << 20
    for serial in (SERIAL, SERIAL2):
        assert env.arts.stage_manifest(serial, 3)["max_piece_size"] == 1 << 20


@pytest.fixture
def rig_git(monkeypatch):
    """Fake ``git describe`` / ``rev-parse`` of the rpi-image-gen submodule; mutate ``["describe"]`` to move it."""
    from otp_server.artifacts import image as image_mod

    state = {"describe": "368e8f0", "rev-parse": "368e8f0" + "0" * 33, "calls": 0}

    def fake(repo, *args, **kw):
        state["calls"] += 1
        return state.get(args[0])

    monkeypatch.setattr(image_mod, "git_output", fake)
    monkeypatch.setattr(image_mod.ImageBuilder, "VERSION_TTL", 0.0)
    return state


def test_image_new_rpi_image_gen_commit_needs_rebuild(make_env, rig_git):
    env = make_env()
    build_image(env)
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")
    old = {}
    for v in VARIANTS:
        cur = env.arts.image.current_set(v)
        assert cur is not None and cur[1]["version"] == "368e8f0" and f"-{v}-368e8f0-" in cur[1]["set"]
        assert cur[1]["rpi_image_gen_commit"].startswith("368e8f0")
        old[v] = cur[0]
    assert env.arts.status()["image"]["ready"] is True

    rig_git["describe"] = "v1.2-3-gabcdef1"              # the submodule pointer moved
    assert env.arts.image.missing_variants() == list(VARIANTS)
    for serial in (SERIAL, SERIAL2):
        with pytest.raises(NotReady, match="rpi-image-gen is at v1.2-3-gabcdef1, image set .* was built from 368e8f0"):
            env.arts.stage_manifest(serial, 3)
    st = env.arts.status()["image"]
    assert st["ready"] is False and "rebuild needed" in st["detail"]
    assert "image" in [j.target for j in env.arts.auto_build()]
    env.wait_all()
    for v in VARIANTS:
        cur = env.arts.image.current_set(v)
        assert cur is not None and cur[1]["version"] == "v1.2-3-gabcdef1" and cur[0] != old[v]
        assert f"-{v}-v1.2-3-gabcdef1-" in cur[1]["set"]
    for serial in (SERIAL, SERIAL2):
        assert env.arts.stage_manifest(serial, 3)["image"]["version"] == "v1.2-3-gabcdef1"


def test_image_unknown_rpi_image_gen_version_keeps_serving(make_env, rig_git):
    env = make_env()
    build_image(env)
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")
    rig_git["describe"] = None                           # git failed: no reason to block stage 3
    assert env.arts.image.version() == "unknown"
    assert env.arts.image.missing_variants() == []
    for serial in (SERIAL, SERIAL2):
        assert env.arts.stage_manifest(serial, 3)["image"]["version"] == "368e8f0"


def test_image_config_change_needs_rebuild(make_env):
    env = make_env()
    build_image(env)
    env.board()
    env.board(SERIAL2, mode="secure", lock="ours")
    assert env.arts.image.missing_variants() == []
    original = env.cfg.image
    changed = "the image settings, builds.image.overrides or the station's image sources changed"
    for edit in ({"hostname": "drone7"}, {"wifi_ssid": "Field", "wifi_password": "secret-pass"},
                 {"password_hash": "$6$salt$" + "x" * 86}, {"ssh": True}):
        env.cfg.image = replace(original, **edit)
        assert env.arts.image.missing_variants() == list(VARIANTS), edit
        for serial in (SERIAL, SERIAL2):
            with pytest.raises(NotReady, match=re.escape(changed)):
                env.arts.stage_manifest(serial, 3)
        env.cfg.image = original
        assert env.arts.image.missing_variants() == []
    # a changed Wi-Fi password alone (same SSID) is a different image too: the secret files count
    env.cfg.image = replace(original, wifi_ssid="Field", wifi_password="secret-pass")
    h1 = env.arts.image.config_hash("clear")
    env.cfg.image = replace(original, wifi_ssid="Field", wifi_password="other-pass")
    assert env.arts.image.config_hash("clear") != h1
    env.cfg.image = original
    env.cfg.builds.image.overrides = ["IGconf_x=1"]
    assert env.arts.image.missing_variants() == list(VARIANTS)
    for serial in (SERIAL, SERIAL2):
        with pytest.raises(NotReady, match=re.escape(changed)):
            env.arts.stage_manifest(serial, 3)
    env.cfg.builds.image.overrides = []
    assert env.arts.image.missing_variants() == []


def test_image_sources_change_needs_rebuild(make_env, monkeypatch):
    from otp_server.artifacts import image as image_mod

    monkeypatch.setattr(image_mod.ImageBuilder, "SOURCES_TTL", 0.0)
    env = make_env()
    build_image(env)
    assert env.arts.image.missing_variants() == []
    layer = env.cfg.image_dir / "layer" / "otp-image.yaml"
    layer.write_text("# otp-image v2\n", encoding="utf-8")
    assert env.arts.image.missing_variants() == list(VARIANTS)
    layer.write_bytes(b"# otp-image\r\n")                   # back, with CRLF (a Windows checkout): same
    assert env.arts.image.missing_variants() == []
    (env.cfg.image_dir / "layer" / "extra.yaml").write_text("# new layer\n", encoding="utf-8")
    assert env.arts.image.missing_variants() == list(VARIANTS)
    (env.cfg.image_dir / "layer" / "extra.yaml").unlink()
    (env.cfg.image_dir / "rpi-image-gen" / "README").write_text("not hashed: versioned by its commit\n",
                                                               encoding="utf-8")
    assert env.arts.image.missing_variants() == []


def test_image_build_writes_the_settings_as_files(make_env):
    from otp_server.passhash import sha512_crypt

    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGabcdefghijklmnopqrstuvwxyz0123456789ABCD op@station"
    env = make_env(image={"hostname": "drone7", "password_hash": sha512_crypt("pw", "salt"), "ssh": True,
                          "ssh_password_login": False, "ssh_authorized_keys": [key],
                          "wifi_ssid": "Field Net", "wifi_password": "p$ss \\w0rd", "wifi_country": "pl"})
    build_image(env)
    for r in env.docker.runs_of(BUILDER_TAG):
        text = r["config"]
        assert '  hostname: "drone7"' in text and '  regdom: "PL"' in text and "  ssh: openssh-server" in text
        assert '  secrets: "/cfg/secrets"' in text and '  pubkey_only: "y"' in text
        assert '  pubkey_user1: "/cfg/secrets/authorized_keys"' in text
        assert "$" not in text.replace("rpi-image-gen expands $ in values", "")   # no secret is a config value
        files = r["secret_files"]
        assert files["secrets/user1.passhash"] == (sha512_crypt("pw", "salt") + "\n").encode()
        assert files["secrets/authorized_keys"] == (key + "\n").encode()
        profile = files["secrets/iwd/Field Net.psk"].decode()
        assert "Passphrase=p$ss\\s\\\\w0rd\n" in profile and "PreSharedKey=" in profile
    for v in VARIANTS:
        man = env.arts.image.current_set(v)[1]
        assert man["image_settings"]["wifi_ssid"] == "Field Net" and man["image_settings"]["password_set"] is True
        assert "p$ss" not in json.dumps(man) and "$6$" not in json.dumps(man)   # no secret in the manifest
    assert not list((env.image_root / "cfg").iterdir())


def test_image_build_follows_settings_changed_meanwhile(make_env):
    env = make_env()
    seen = []

    def builder(call):
        h_builder(call)
        seen.append(call["config"])
        if len(seen) == 1:                       # the operator saves new settings while clear builds
            env.cfg.image = replace(env.cfg.image, hostname="drone8")

    env.docker.handlers[BUILDER_TAG] = builder
    build_image(env)
    assert [c.count('hostname: "drone8"') for c in seen] == [0, 1, 1]   # clear, crypt, clear again
    assert env.arts.image.missing_variants() == []
    job = env.jobs.list()[0]
    assert any("the image settings changed during the build" in ln for ln in job.lines)


def test_image_variant_mismatch_needs_rebuild(make_env):
    env = make_env()
    build_image(env)
    env.board()
    crypt_dir, crypt_man = env.arts.image.current_set("crypt")
    assert env.arts.image.rebuild_reason(crypt_man, "crypt") is None
    why = env.arts.image.rebuild_reason(crypt_man, "clear")
    assert why == f"rebuild needed: image set {crypt_man['set']} is a crypt image, not clear"
    # current-clear.json pointing at the crypt set (a hand edit, a bug): never served as clear
    (env.image_root / "current-clear.json").write_text(json.dumps({"set": crypt_man["set"]}), encoding="utf-8")
    assert env.arts.image.published_set("clear") == (crypt_dir, crypt_man)
    assert env.arts.image.current_set("clear") is None
    assert env.arts.image.missing_variants() == ["clear"]
    assert env.arts.image.variant_status("clear")["detail"] == why
    with pytest.raises(NotReady, match="is a crypt image, not clear"):
        env.arts.stage_manifest(SERIAL, 3)
    assert env.arts.status()["image"]["ready"] is False


def test_image_version_is_cached_briefly(make_env, rig_git, monkeypatch):
    from otp_server.artifacts import image as image_mod

    env = make_env()
    monkeypatch.setattr(image_mod.ImageBuilder, "VERSION_TTL", 3600.0)
    n = rig_git["calls"]
    assert env.arts.image.version() == "368e8f0"
    rig_git["describe"] = "abcdef1"
    assert env.arts.image.version() == "368e8f0" and rig_git["calls"] == n + 1
    assert env.arts.image.version(max_age=0) == "abcdef1"


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


def test_image_build_sweeps_config_dirs_of_interrupted_builds(make_env):
    env = make_env()
    left = env.image_root / "cfg" / "deadbeef-clear" / "secrets"
    left.mkdir(parents=True)
    (left / "user1.passhash").write_text("$6$old$hash\n", encoding="utf-8")
    build_image(env)
    assert not (env.image_root / "cfg" / "deadbeef-clear").exists()
    job = env.jobs.list()[0]
    assert any("removed the config dir of an interrupted build: deadbeef-clear" in ln for ln in job.lines)
    assert list((env.image_root / "cfg").iterdir()) == []
