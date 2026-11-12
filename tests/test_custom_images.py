"""Custom OS images and the image file for Raspberry Pi Imager.

* :mod:`otp_server.diskimage`: the checks of an uploaded ``.img`` and the disk image assembled from sparse
  pieces (MBR, alignment, every byte where it belongs);
* :func:`otp_server.sparse.expand` and ``docker/scripts/ext4_sparse.py`` (the allocation bitmap decides
  what is written);
* :func:`otp_server.imagejson.custom_image_json` for both variants;
* :class:`otp_server.artifacts.custom.CustomImages` with the fake Docker of test_artifacts: upload, the
  preparation job, status, delete, stage 3 with ``image.custom``, the image file of a locked board;
* the station image's crypt layer carries the same otp-growroot as docker/scripts/custom-crypt.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from otp_server import diskimage, imagejson, sparse
from otp_server.artifacts import NotReady
from otp_server.artifacts.custom import SCRIPT_FILES
from test_artifacts import CID, SERIAL, TOOLS_TAG, build_image, make_env, make_sparse  # noqa: F401 (make_env: fixture)

REPO = Path(__file__).resolve().parent.parent
MiB = 1024 * 1024
BLK = 4096


# ---------------------------------------------------------------------- a small disk image
def make_disk(path: Path, *, boot_type: int = 0x0C, root_type: int = 0x83, extra: bool = False, gpt: bool = False,
              fat: bool = True, ext4: bool = True, extents: bool = True, size: int = 4 * MiB,
              disk_id: int = 0x8A438930, lead: bytes = b"") -> Path:
    """MBR, p1 = 1 MiB FAT at 1 MiB, p2 = 2 MiB ext4 at 2 MiB (sectors), in a ``size``-byte file."""
    b = bytearray(size)
    struct.pack_into("<I", b, 440, disk_id)
    entries = [(boot_type, 2048, 2048), (root_type, 4096, 4096)]
    if extra:
        entries.append((0x83, 8192, 8))
    if gpt:
        entries = [(0xEE, 1, size // 512 - 1)]
    for i, (t, start, n) in enumerate(entries):
        struct.pack_into("<B3sB3sII", b, 446 + 16 * i, 0, b"\0\0\0", t, b"\0\0\0", start, n)
    b[510:512] = b"\x55\xaa"
    if fat:
        o = 2048 * 512
        b[o + 0x52:o + 0x55] = b"FAT"
        b[o + 510:o + 512] = b"\x55\xaa"
    if ext4:
        o = 4096 * 512 + 1024
        struct.pack_into("<H", b, o + 56, 0xEF53)
        struct.pack_into("<I", b, o + 96, 0x2C2 if extents else 0x2)
    if lead:
        b[:len(lead)] = lead
    path.write_bytes(bytes(b))
    return path


@pytest.fixture
def small_images(monkeypatch):
    monkeypatch.setattr(diskimage, "MIN_IMAGE_BYTES", 1 * MiB)


def test_read_layout_of_a_raspberry_pi_os_like_image(tmp_path, small_images):
    lay = diskimage.read_layout(make_disk(tmp_path / "a.img"))
    assert lay == {"label": "dos", "id": "0x8a438930", "bytes": 4 * MiB,
                   "partitions": [{"n": 1, "start": 2048, "sectors": 2048, "type": "c"},
                                  {"n": 2, "start": 4096, "sectors": 4096, "type": "83"}]}


@pytest.mark.parametrize("kw,msg", [
    ({"lead": b"\xfd7zXZ\x00"}, "xz-compressed: unpack it"),
    ({"lead": b"PK\x03\x04"}, "zip-compressed"),
    ({"gpt": True}, "GPT partition table"),
    ({"extra": True}, "3 partitions; expected exactly two"),
    ({"boot_type": 0x83}, "partition 1 has type 0x83, expected a FAT boot partition"),
    ({"root_type": 0x0C}, "partition 2 has type 0xc, expected a Linux root partition"),
    ({"fat": False}, "partition 1 does not hold a FAT file system"),
    ({"ext4": False}, "partition 2 does not hold an ext2/3/4 file system"),
    ({"extents": False}, "holds ext2 or ext3"),
    ({"size": 3 * MiB}, "ends past the end of the file: the upload is truncated"),
])
def test_read_layout_refuses_what_the_station_cannot_take(tmp_path, small_images, kw, msg):
    with pytest.raises(ValueError, match=msg):
        diskimage.read_layout(make_disk(tmp_path / "x.img", **kw))


def test_read_layout_no_partition_table_and_too_small(tmp_path, small_images):
    p = tmp_path / "raw.img"
    p.write_bytes(bytes(2 * MiB))
    with pytest.raises(ValueError, match="no MBR partition table"):
        diskimage.read_layout(p)
    p.write_bytes(bytes(1000))
    with pytest.raises(ValueError, match="too small"):
        diskimage.read_layout(p)


# ---------------------------------------------------------------------- sparse expansion and the disk plan
def sparse_file(path: Path, chunks, total: int | None = None) -> Path:
    """chunks: ("raw", bytes) | ("fill", blocks, word) | ("dc", blocks)."""
    body, blocks = b"", 0
    for c in chunks:
        if c[0] == "raw":
            assert len(c[1]) % BLK == 0
            body += struct.pack("<HHII", 0xCAC1, 0, len(c[1]) // BLK, 12 + len(c[1])) + c[1]
            blocks += len(c[1]) // BLK
        elif c[0] == "fill":
            body += struct.pack("<HHII", 0xCAC2, 0, c[1], 16) + c[2]
            blocks += c[1]
        else:
            body += struct.pack("<HHII", 0xCAC3, 0, c[1], 12)
            blocks += c[1]
    assert total is None or total == blocks
    path.write_bytes(struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, BLK, blocks, len(chunks), 0) + body)
    return path


def test_expand_joins_pieces_and_zero_fills_dont_care(tmp_path):
    a = bytes(range(256)) * 16
    p0 = sparse_file(tmp_path / "s.0", [("raw", a), ("fill", 2, b"\xab\xcd\xef\x01"), ("dc", 5)])
    p1 = sparse_file(tmp_path / "s.1", [("dc", 4), ("raw", b"\x07" * BLK), ("dc", 3)])
    out = b"".join(sparse.expand([p0, p1], chunk=4096))
    assert len(out) == 8 * BLK
    assert out[:BLK] == a
    assert out[BLK:3 * BLK] == b"\xab\xcd\xef\x01" * (2 * BLK // 4)
    assert out[3 * BLK:4 * BLK] == bytes(BLK)
    assert out[4 * BLK:5 * BLK] == b"\x07" * BLK
    assert out[5 * BLK:] == bytes(3 * BLK)
    with pytest.raises(sparse.SparseError, match="another image"):
        list(sparse.expand([p0, sparse_file(tmp_path / "other", [("dc", 9)])]))


def test_disk_plan_lays_out_partitions_like_idp(tmp_path):
    boot = sparse_file(tmp_path / "boot", [("raw", b"B" * BLK), ("dc", 3)])
    r0 = sparse_file(tmp_path / "root.0", [("raw", b"R" * BLK), ("dc", 9)])
    r1 = sparse_file(tmp_path / "root.1", [("dc", 9), ("raw", b"S" * BLK)])
    plan = diskimage.DiskPlan.build(0x46492AF7, MiB, [(0x0C, 3 * MiB, [boot], True), (0x83, 0, [r0, r1], False)])
    assert [(p.start, p.size, p.content) for p in plan.partitions] == [(MiB, 3 * MiB, 4 * BLK), (4 * MiB, MiB, 10 * BLK)]
    assert plan.size == 5 * MiB
    data = b"".join(plan.iter_bytes(chunk=64 * 1024))
    assert len(data) == plan.size
    mbr = data[:512]
    assert struct.unpack("<I", mbr[440:444])[0] == 0x46492AF7 and mbr[510:512] == b"\x55\xaa"
    e1 = struct.unpack("<B3sB3sII", mbr[446:462])
    e2 = struct.unpack("<B3sB3sII", mbr[462:478])
    assert (e1[0], e1[2], e1[4], e1[5]) == (0x80, 0x0C, MiB // 512, 3 * MiB // 512)
    assert (e2[0], e2[2], e2[4], e2[5]) == (0x00, 0x83, 4 * MiB // 512, MiB // 512)
    assert data[478:510] == bytes(32) and data[512:MiB] == bytes(MiB - 512)
    assert data[MiB:MiB + BLK] == b"B" * BLK and data[MiB + BLK:4 * MiB] == bytes(3 * MiB - BLK)
    assert data[4 * MiB:4 * MiB + BLK] == b"R" * BLK
    assert data[4 * MiB + 9 * BLK:4 * MiB + 10 * BLK] == b"S" * BLK
    assert data[4 * MiB + 10 * BLK:] == bytes(MiB - 10 * BLK)
    with pytest.raises(ValueError, match="whole number of MiB"):
        diskimage.DiskPlan.build(1, 4096, [(0x83, 0, [boot], False)])
    assert diskimage.parse_size("8M") == 8 * MiB and diskimage.parse_size("4MiB") == 4 * MiB
    assert diskimage.parse_size(512) == 512 and diskimage.parse_size("1G") == 1024 * MiB


# ---------------------------------------------------------------------- ext4_sparse.py (dumpe2fs decides)
def _ext4_sparse():
    spec = importlib.util.spec_from_file_location("ext4_sparse", REPO / "docker" / "scripts" / "ext4_sparse.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DUMPE2FS = """Filesystem volume name:   rootfs
Block count:              16
Block size:               4096
First block:              0

Group 0: (Blocks 0-15)
  Primary superblock at 0, Group descriptors at 1-1
  Free blocks: 5-7, 10
  Free inodes: 12-32
"""


def test_ext4_sparse_writes_every_block_in_use_and_skips_free_ones(tmp_path):
    m = _ext4_sparse()
    img = bytearray(16 * BLK)
    for i in range(16):
        if i not in (2, 3):                     # blocks 2 and 3: in use but all zeros (e.g. an inode table)
            img[i * BLK:(i + 1) * BLK] = bytes([i + 1]) * BLK
    (tmp_path / "fs").write_bytes(bytes(img))
    st = m.convert(tmp_path / "fs", tmp_path / "fs.sparse", text=DUMPE2FS)
    assert st == {"fs_bytes": 16 * BLK, "fs_block_size": 4096, "used_bytes": 12 * BLK, "raw_bytes": 10 * BLK,
                  "fill_bytes": 2 * BLK, "chunks": st["chunks"]}
    info = sparse.check_pieces([tmp_path / "fs.sparse"])
    assert info["total_blocks"] == 16
    regions = {first: (n, kind) for first, n, kind, _off, _fill in sparse.data_chunks(tmp_path / "fs.sparse")[2]}
    covered = {b for first, (n, _) in regions.items() for b in range(first, first + n)}
    assert covered == set(range(16)) - {5, 6, 7, 10}, "free blocks are DONT_CARE, every block in use is written"
    assert regions[2] == (2, 0xCAC2), "zero blocks in use become FILL, not DONT_CARE"
    out = b"".join(sparse.expand([tmp_path / "fs.sparse"]))
    for i in set(range(16)) - {5, 6, 7, 10}:
        assert out[i * BLK:(i + 1) * BLK] == bytes(img[i * BLK:(i + 1) * BLK])


def test_ext4_sparse_other_block_sizes(tmp_path):
    m = _ext4_sparse()
    # 1 KiB blocks: a 4 KiB block is written when any of its four is in use
    assert m.used_4k_runs(1024, 16, [(0, 3), (4, 6), (12, 15)]) == [(1, 2)]
    assert m.used_4k_runs(1024, 16, [(0, 5)]) == [(1, 3)]
    # 16 KiB blocks: each is four 4 KiB blocks
    assert m.used_4k_runs(16384, 4, [(1, 2)]) == [(0, 4), (12, 4)]
    with pytest.raises(m.Error, match="not a multiple"):
        m.used_4k_runs(1024, 15, [])
    with pytest.raises(m.Error, match="no per-group"):
        m.free_ranges("Block count: 4\nBlock size: 4096\n")


# ---------------------------------------------------------------------- image.json of a custom image
FACTS = {
    "variant": "clear",
    "disk": {"label": "dos", "id": "0x8a438930", "sector_size": 512, "bytes": 6442450944},
    "partitions": [{"n": 1, "start": 8192, "sectors": 1048576, "type": "c", "fs": "vfat", "fs_label": "bootfs",
                    "fs_uuid": "4EF5-6F55"},
                   {"n": 2, "start": 1056768, "sectors": 11526111, "type": "83", "fs": "ext4", "fs_label": "rootfs",
                    "fs_uuid": "ce208fd3-38a8-424a-87a2-cd44114eb820"}],
    "boot": {"simage": "boot.vfat.sparse", "bytes": 536870912, "mountpoint": "/boot/firmware", "pieces": []},
    "root": {"simage": "root.ext4.sparse", "fs_bytes": 5368709120, "pieces": []},
    "os": {"pretty_name": "Debian GNU/Linux 12 (bookworm)", "cloud_init": False},
    "crypt": None,
}


def test_custom_image_json_clear_keeps_the_image_as_it_is():
    ij = imagejson.custom_image_json(FACTS, name="os.img", version="custom-3d0c4b7e")
    assert ij["layout"]["partitiontable"] == {"label": "dos", "id": "0x8a438930"}
    assert ij["attributes"] == {"image-name": "os.img", "image-size": 6442450944, "image-palign-bytes": "4M"}
    pi = ij["layout"]["partitionimages"]
    assert (pi["boot"]["size"], pi["boot"]["partition-type"], pi["boot"]["simage"]) == (536870912, "0xC", "boot.vfat.sparse")
    assert (pi["root"]["size"], pi["root"]["partition-type"]) == (11526111 * 512, "0x83")
    assert not imagejson.is_encrypted(ij)
    assert "expand-to-fit" not in json.dumps(ij["layout"]["provisionmap"]), "the clear image is not grown"
    assert imagejson.simages(ij) == ["boot.vfat.sparse", "root.ext4.sparse"]
    assert imagejson.boot_simages(ij) == ["boot.vfat.sparse"]
    assert imagejson.partition_order(ij) == ["boot", "root"]
    assert ij["IGmeta"]["IGconf_device_storage_type"] == "sd" and ij["IGmeta"]["IGconf_device_class"] == "pi5"


def test_custom_image_json_crypt_is_what_station_luks_takes():
    ij = imagejson.custom_image_json(FACTS, name="os.img", version="v", luks={"uuid": "3d0c4b7e-6a51-4f2e-9b8d-2c7e1f0a9b31",
                                                                            "mname": "cryptroot"})
    assert imagejson.is_encrypted(ij)
    assert ij["layout"]["partitionimages"]["root"]["size"] == 5368709120
    board, containers = imagejson.station_luks(ij, 16 << 20)
    assert [(c["index"], c["plain_simage"], c["simage"], c["uuid"], c["mname"], c["label"]) for c in containers] == \
        [(2, "root.ext4.sparse", "root.luks.sparse", "3d0c4b7e-6a51-4f2e-9b8d-2c7e1f0a9b31", "cryptroot", "OSROOT_CRYPT")]
    assert board["layout"]["partitionimages"]["root"]["size"] == 5368709120 + (16 << 20)
    assert imagejson.partition_order(board) == ["boot", "root"]


def test_custom_image_json_alignment_follows_the_first_partition():
    f = json.loads(json.dumps(FACTS))
    f["partitions"][0]["start"] = 2048
    assert imagejson.custom_image_json(f, name="x", version="v")["attributes"]["image-palign-bytes"] == "1M"
    f["partitions"][0]["start"] = 2049                     # not on a MiB: IDP's 4M
    assert imagejson.custom_image_json(f, name="x", version="v")["attributes"]["image-palign-bytes"] == "4M"


# ---------------------------------------------------------------------- the station with an uploaded image
CUSTOM_LUKS_SEEN: list[str] = []


def h_custom(call, *, cloud_init: bool = False):
    """custom-image.sh: what the real script writes, for a 64-block boot and a 64-block root."""
    assert call["privileged"] is True and call["mounts"]["/in"].readonly
    assert "source.img" in call["in_files"]
    out = Path(call["mounts"]["/out"].source)
    env = call["env"]
    v = env["VARIANT"]
    make_sparse(out / "boot.vfat.sparse", [("raw", 2), ("dc", 62)])
    make_sparse(out / "root.ext4.sparse.0", [("raw", 3), ("dc", 61)])
    make_sparse(out / "root.ext4.sparse.1", [("dc", 3), ("raw", 1), ("dc", 60)])
    pieces = lambda *names: [{"file": n, "size": (out / n).stat().st_size} for n in names]  # noqa: E731
    crypt = None
    if v == "crypt":
        CUSTOM_LUKS_SEEN.append(env["LUKS_UUID"])
        assert env["MAPPER"] == "cryptroot"
        crypt = {"mapper": "cryptroot", "uuid": env["LUKS_UUID"], "packages": {"rpifwcrypto": "20251002-1~bookworm"},
                 "initramfs": ["initramfs_2712"], "cmdline": "root=/dev/mapper/cryptroot rootwait"}
    facts = json.loads(json.dumps(FACTS))
    facts.update(variant=v, crypt=crypt)
    facts["disk"]["bytes"] = 4 * MiB
    facts["partitions"][0].update(start=2048, sectors=64 * 8)
    facts["partitions"][1].update(start=4096, sectors=64 * 8)
    facts["boot"].update(bytes=64 * BLK, pieces=pieces("boot.vfat.sparse"))
    facts["root"].update(fs_bytes=64 * BLK, pieces=pieces("root.ext4.sparse.0", "root.ext4.sparse.1"))
    facts["os"]["cloud_init"] = cloud_init
    (out / "custom.json").write_text(json.dumps(facts), encoding="utf-8")


@pytest.fixture
def cenv(make_env, small_images, tmp_path):
    env = make_env()
    for rel in SCRIPT_FILES:                            # the scripts the sets depend on
        f = env.cfg.repo_root / "docker" / "scripts" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"# {rel}\n", encoding="utf-8")
    env.docker.labels[TOOLS_TAG] = {"otp.tools.hash": env.arts.tools.hash()}
    env.docker.handlers["custom-image.sh"] = h_custom
    return env


def upload(env, path: Path, name: str = "C:\\fakepath\\My OS.img"):
    data = path.read_bytes()
    up = env.arts.custom.begin_upload(name, len(data))
    for i in range(0, len(data), 1 << 20):
        up.write(data[i:i + (1 << 20)])
    return up.finish()


def test_upload_files_the_image_under_its_hash(cenv, tmp_path):
    img = make_disk(tmp_path / "os.img")
    info, new = upload(cenv, img)
    sha = hashlib.sha256(img.read_bytes()).hexdigest()
    assert new and info["id"] == sha[:16] and info["sha256"] == sha and info["name"] == "My_OS.img"
    assert info["size"] == 4 * MiB and info["layout"]["id"] == "0x8a438930"
    d = cenv.arts.custom.dir(info["id"])
    assert (d / "source.img").read_bytes() == img.read_bytes()
    assert json.loads((d / "upload.json").read_text(encoding="utf-8"))["id"] == info["id"]
    again, new2 = upload(cenv, img, "again.img")
    assert not new2 and again["name"] == "My_OS.img"
    assert not list(cenv.arts.custom.root.glob("upload-*"))       # the second copy is not kept
    assert cenv.arts.custom.ids() == [info["id"]]


def test_upload_refuses_a_file_that_is_not_an_image_and_keeps_nothing(cenv, tmp_path):
    bad = tmp_path / "bad.img"
    bad.write_bytes(bytes(2 * MiB))
    with pytest.raises(ValueError, match="no MBR"):
        upload(cenv, bad)
    assert not list(cenv.arts.custom.root.glob("upload-*")) and cenv.arts.custom.ids() == []
    with pytest.raises(ValueError, match="empty"):
        cenv.arts.custom.begin_upload("x.img", 0)
    up = cenv.arts.custom.begin_upload("x.img", 10)
    with pytest.raises(ValueError, match="longer than announced"):
        up.write(b"x" * 11)
    up.abort()
    up = cenv.arts.custom.begin_upload("x.img", 10)
    up.write(b"x" * 4)
    with pytest.raises(ValueError, match="ended after 4 of 10"):
        up.finish()
    assert not list(cenv.arts.custom.root.glob("upload-*"))


def prepared(env, tmp_path, **kw):
    info, _ = upload(env, make_disk(tmp_path / "os.img"))
    job = env.arts.custom.start_prepare(info["id"])
    assert job.wait(20) and job.status == "succeeded", job.error
    return info["id"]


def test_prepare_makes_both_sets(cenv, tmp_path):
    cid = prepared(cenv, tmp_path)
    runs = cenv.docker.runs_of("custom-image.sh")
    assert [r["env"]["VARIANT"] for r in runs] == ["clear", "crypt"]
    assert "ensure_arm64" in cenv.docker.calls
    for v in ("clear", "crypt"):
        d, man = cenv.arts.custom.current_set(cid, v)
        assert man["variant"] == v and man["custom"] == cid and man["encrypted"] == (v == "crypt")
        assert man["cloud_init"] is False and man["os"]["pretty_name"].startswith("Debian")
        assert list(man["simages"]) == ["boot.vfat.sparse", "root.ext4.sparse"]
        ij = imagejson.load(d / "image.json")
        assert imagejson.is_encrypted(ij) == (v == "crypt")
        if v == "crypt":
            luks = imagejson.crypt_containers(ij)[0]
            assert luks["mname"] == "cryptroot"
            enc = ij["layout"]["provisionmap"][2]["encrypted"]["luks2"]
            assert enc["uuid"] == CUSTOM_LUKS_SEEN[-1] == man["crypt"]["uuid"]
    st = cenv.arts.custom_images()
    assert [(x["id"], x["ready"], x["selected"], x["cloud_init"]) for x in st] == [(cid, True, False, False)]
    assert st[0]["variants"]["crypt"]["ready"] and st[0]["job"]["status"] == "succeeded"
    # already prepared: nothing runs again; a changed script makes both stale
    job = cenv.arts.custom.start_prepare(cid)
    assert job.wait(20) and len(cenv.docker.runs_of("custom-image.sh")) == 2
    (cenv.cfg.repo_root / "docker" / "scripts" / "custom-image.sh").write_text("# changed\n", encoding="utf-8")
    assert cenv.arts.custom.current_set(cid, "clear") is None
    assert "prepare it again" in cenv.arts.custom.rebuild_reason(cenv.arts.custom.published_set(cid, "clear")[1], "clear")
    job = cenv.arts.custom.start_prepare(cid)
    assert job.wait(20) and len(cenv.docker.runs_of("custom-image.sh")) == 4
    sets = sorted(p.name for p in cenv.arts.custom.dir(cid).iterdir() if p.is_dir())
    assert len(sets) == 2, sets                         # the older sets were removed


def test_prepare_failure_is_recorded_per_variant(cenv, tmp_path):
    info, _ = upload(cenv, make_disk(tmp_path / "os.img"))
    cenv.docker.fail.add("custom-image.sh")
    job = cenv.arts.custom.start_prepare(info["id"])
    assert job.wait(20) and job.status == "failed" and "clear:" in job.error and "crypt:" in job.error
    st = cenv.arts.custom_images()[0]
    assert not st["ready"] and st["variants"]["crypt"]["error"]
    assert set(cenv.arts.custom.errors(info["id"])) == {"clear", "crypt"}
    cenv.cfg.image.custom = info["id"]
    assert not [j for j in cenv.arts.auto_build() if getattr(j, "target", "").startswith("custom:")], \
        "a failing preparation is not restarted by every auto build"
    cenv.cfg.builds.auto = True
    with pytest.raises(NotReady, match="failed"):
        cenv.arts.custom.servable_set(info["id"], "clear")
    assert cenv.jobs.active(f"custom:{info['id']}") is None, "stage 3 does not restart a failed preparation"
    cenv.cfg.builds.auto = False
    cenv.docker.fail.clear()
    job = cenv.arts.custom.start_prepare(info["id"])
    assert job.wait(20) and job.status == "succeeded"
    assert cenv.arts.custom.errors(info["id"]) == {}


def test_delete_rules(cenv, tmp_path):
    cid = prepared(cenv, tmp_path)
    cenv.cfg.image.custom = cid
    with pytest.raises(ValueError, match="choose another image first"):
        cenv.arts.custom.delete(cid)
    cenv.cfg.image.custom = ""
    cenv.arts.custom.delete(cid)
    assert cenv.arts.custom.ids() == [] and not cenv.arts.custom.dir(cid).exists()
    with pytest.raises(KeyError):
        cenv.arts.custom.delete(cid)
    with pytest.raises(KeyError):
        cenv.arts.custom.delete("not-an-id")


def test_stage3_open_writes_the_custom_image_as_it_is(cenv, tmp_path):
    build_image(cenv)
    cid = prepared(cenv, tmp_path)
    cenv.cfg.image.custom = cid
    cenv.board(mode="open")
    n_slots = len(cenv.docker.runs_of("boot-slot.sh"))
    m = cenv.arts.stage_manifest(SERIAL, 3, base_url="http://h")
    assert m["image"]["source"] == "custom" and m["image"]["custom"] == cid and m["image"]["name"] == "My_OS.img"
    assert len(cenv.docker.runs_of("boot-slot.sh")) == n_slots, "no cloud-init, unsigned: the boot partition as it is"
    d, _man = cenv.arts.custom.current_set(cid, "clear")
    assert cenv.arts.stage_file(SERIAL, 3, "boot.vfat.sparse").parent == d
    assert any("has no cloud-init" in n for n in m["notes"]) and any("custom image My_OS.img" in n for n in m["notes"])
    assert m["firstboot"] == {"applied": False}


def test_stage3_custom_image_with_cloud_init_gets_the_first_boot_files(cenv, tmp_path):
    build_image(cenv)
    cenv.docker.handlers["custom-image.sh"] = lambda call: h_custom(call, cloud_init=True)
    cid = prepared(cenv, tmp_path)
    cenv.cfg.image.custom = cid
    cenv.board(mode="open")
    m = cenv.arts.stage_manifest(SERIAL, 3)
    r = cenv.docker.runs_of("boot-slot.sh")[-1]
    assert r["env"]["SIGN"] == "0" and r["env"]["INPLACE"] == "0" and {"user-data", "meta-data"} <= set(r["seed"])
    assert any("first boot (cloud-init" in n for n in m["notes"])


def test_stage3_secure_custom_image(cenv, tmp_path):
    build_image(cenv)
    cid = prepared(cenv, tmp_path)
    cenv.cfg.image.custom = cid
    cenv.board(mode="secure", lock="ours")
    cenv.export_key(SERIAL)
    m = cenv.arts.stage_manifest(SERIAL, 3)
    assert m["mode"] == "signed" and m["image"]["source"] == "custom" and m["image"]["encrypted"] is True
    slot = cenv.docker.runs_of("boot-slot.sh")[-1]
    assert (slot["env"]["SIGN"], slot["env"]["INPLACE"], slot["env"]["PRUNE"]) == ("1", "1", "pi5")
    assert slot["seed"] == {}, "no cloud-init: no first-boot files"
    luks = cenv.docker.runs_of("root-luks.sh")[-1]
    assert luks["env"]["UUID"] == CUSTOM_LUKS_SEEN[-1] and luks["env"]["LABEL"] == "OSROOT_CRYPT"
    assert m["verify_key"] == [{"dev": "mmcblk0p2", "label": "OSROOT_CRYPT"}]
    assert list(m["parts"]) == ["boot.vfat.sparse", "root.luks.sparse"]


def test_stage3_waits_for_a_custom_image_that_is_not_here(cenv, tmp_path):
    build_image(cenv)
    cenv.cfg.image.custom = "0123456789abcdef"
    cenv.board(mode="open")
    with pytest.raises(NotReady, match="is not on this station"):
        cenv.arts.stage_manifest(SERIAL, 3)


# ---------------------------------------------------------------------- the image file for Raspberry Pi Imager
def test_imager_image_of_a_locked_board(cenv, tmp_path):
    build_image(cenv)
    cenv.board(mode="secure", lock="ours")
    with pytest.raises(NotReady, match="does not hold the OTP device key"):
        cenv.arts.imager_image(SERIAL, "")
    cenv.export_key(SERIAL)
    out = cenv.arts.imager_image(SERIAL, "")
    assert out["ready"] and out["name"] == f"{SERIAL}-deb13-arm64-min-secure.img" and out["source"] == "station"
    assert out["url"] == f"/api/modules/{SERIAL}/imager-image/{out['name']}" and "shas" not in out
    assert out["mmc_cid"] == CID and any(CID in n for n in out["notes"])
    slot = cenv.docker.runs_of("boot-slot.sh")[-1]
    assert slot["env"]["SIGN"] == "1" and slot["env"]["INPLACE"] == "0"
    plan = cenv.arts.imager_file(SERIAL, out["name"])
    assert plan.size == out["size"] == [p["start"] + p["size"] for p in out["partitions"]][-1]
    assert [p["type"] for p in out["partitions"]] == ["0x0c", "0x83"]
    assert out["partitions"][0]["start"] == 8 * MiB                        # image-palign-bytes of the set
    data = b"".join(plan.iter_bytes())
    assert len(data) == plan.size and data[510:512] == b"\x55\xaa"
    luks_dir = Path(cenv.docker.runs_of("root-luks.sh")[-1]["mounts"]["/out"].source).with_suffix("")
    expanded = b"".join(sparse.expand([luks_dir / f"root.luks.sparse.{i}" for i in (0, 1)]))
    start = out["partitions"][1]["start"]
    assert data[start:start + len(expanded)] == expanded
    with pytest.raises(FileNotFoundError):
        cenv.arts.imager_file(SERIAL, "other.img")


def test_imager_image_needs_a_board_locked_to_its_key(cenv, tmp_path):
    build_image(cenv)
    cenv.board(mode="open")
    with pytest.raises(NotReady, match="not locked to its key"):
        cenv.arts.imager_image(SERIAL, "")
    with pytest.raises(NotReady, match="has not been prepared"):
        cenv.arts.imager_file(SERIAL, "x.img")


def test_imager_image_from_a_custom_image(cenv, tmp_path):
    build_image(cenv)
    cid = prepared(cenv, tmp_path)
    cenv.board(mode="secure", lock="ours")
    cenv.export_key(SERIAL)
    out = cenv.arts.imager_image(SERIAL, cid)
    assert out["source"] == "custom" and out["custom"] == cid and out["name"] == f"{SERIAL}-My_OS-secure.img"
    assert out["disk_id"] == "0x8a438930"
    assert out["partitions"][0]["start"] == MiB                         # the custom image's own alignment (1 MiB)
    slot = cenv.docker.runs_of("boot-slot.sh")[-1]
    assert (slot["env"]["INPLACE"], slot["env"]["PRUNE"]) == ("1", "pi5")
    plan = cenv.arts.imager_file(SERIAL, out["name"])
    assert sum(len(b) for b in plan.iter_bytes()) == out["size"]
    # a piece that changed after the preparation: the file is refused until it is prepared again
    piece = Path(cenv.docker.runs_of("root-luks.sh")[-1]["mounts"]["/out"].source).with_suffix("") / "root.luks.sparse.1"
    piece.write_bytes(piece.read_bytes() + b"x")
    with pytest.raises(NotReady, match="prepare it again"):
        cenv.arts.imager_file(SERIAL, out["name"])


# ---------------------------------------------------------------------- the station image grows its root too
def test_station_crypt_layer_carries_the_same_otp_growroot():
    import yaml

    layer = yaml.safe_load((REPO / "image" / "layer" / "otp-rpios-setup.yaml").read_text(encoding="utf-8"))
    hook = next(h for h in layer["mmdebstrap"]["customize-hooks"] if 'cat > "$1/usr/local/sbin/otp-growroot"' in h)
    assert '[ "${IGconf_image_pmap:-clear}" = crypt ] || exit 0' in hook
    blocks = hook.split("<<'OTPEOF'\n")[1:]
    script, unit = (b.split("\nOTPEOF\n", 1)[0] + "\n" for b in blocks)
    crypt = REPO / "docker" / "scripts" / "custom-crypt"
    assert script == (crypt / "otp-growroot").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert unit == (crypt / "otp-growroot.service").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert "systemctl enable otp-growroot.service" in hook


# ---------------------------------------------------------------------- the constant-time AES on a CM4
LAYER_INITRAMFS = REPO / "image" / "layer" / "otp-rpios-setup.d" / "device" / "initramfs-tools"


def test_station_layer_and_custom_crypt_load_the_same_bit_sliced_aes():
    script = (LAYER_INITRAMFS / "scripts" / "init-top" / "otp-aes").read_bytes()
    assert script == (REPO / "docker" / "scripts" / "custom-crypt" / "otp-aes").read_bytes()
    hook = (LAYER_INITRAMFS / "hooks" / "otp-aes").read_bytes()
    for body in (script, hook):
        assert body.startswith(b"#!/bin/sh\n") and b"\r" not in body
    assert b"manual_add_modules aes-neon-bs" in hook
    cryptroot = (REPO / "docker" / "scripts" / "custom-crypt" / "otp-cryptroot.hook").read_text(encoding="utf-8")
    assert "aes-neon-bs" in cryptroot                    # the custom image's hook puts the module in
    custom = (REPO / "docker" / "scripts" / "custom-image.sh").read_text(encoding="utf-8")
    assert '"${R}/etc/initramfs-tools/scripts/init-top/otp-aes"' in custom
    assert "scripts/init-top/otp-aes scripts/init-premount/otp-growpart" in custom      # the initramfs check
    assert "CRYPTO_AES_ARM64_BS:aes-neon-bs" in custom


def test_initramfs_scripts_of_the_layer_are_executable_in_git():
    """rpi-image-gen copies <layer>.d/device/initramfs-tools with rsync -a, and build.sh gives the staged files
    the modes git records: a hook or script without 100755 would be skipped by mkinitramfs / the initramfs."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("no git")
    rels = [p.relative_to(REPO).as_posix() for p in LAYER_INITRAMFS.rglob("*") if p.is_file()]
    out = subprocess.run([git, "-C", str(REPO), "ls-files", "-s", "--", *rels], capture_output=True, text=True)
    modes = {line.split("\t", 1)[1]: line.split()[0] for line in out.stdout.splitlines()}
    assert sorted(modes) == sorted(rels), "every file of the layer's initramfs-tools dir is tracked"
    assert set(modes.values()) == {"100755"}, modes


def _run_otp_aes(root: Path, cpuinfo: str, modprobe_rc: int = 0) -> tuple[subprocess.CompletedProcess, str]:
    """scripts/init-top/otp-aes with /proc/cpuinfo under ``root`` and a modprobe stub that records its arguments."""
    (root / "proc").mkdir(parents=True, exist_ok=True)
    (root / "proc" / "cpuinfo").write_text(cpuinfo, encoding="utf-8")
    bindir = root / "bin"
    bindir.mkdir(exist_ok=True)
    posix = str(root).replace("\\", "/")
    (bindir / "modprobe").write_bytes(f'#!/bin/sh\necho "$*" >> "{posix}/modprobe.log"\nexit {modprobe_rc}\n'.encode())
    (bindir / "modprobe").chmod(0o755)
    body = (LAYER_INITRAMFS / "scripts" / "init-top" / "otp-aes").read_text(encoding="utf-8")
    body = body.replace("/proc/cpuinfo", posix + "/proc/cpuinfo").replace("/dev/kmsg", posix + "/kmsg")
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run([SH, "-c", body, "otp-aes"], capture_output=True, env=env, timeout=60)
    log = root / "modprobe.log"
    return r, log.read_text(encoding="utf-8") if log.exists() else ""


CPUINFO_A72 = "processor\t: 0\nFeatures\t: fp asimd evtstrm crc32 cpuid\nCPU part\t: 0xd08\n"
CPUINFO_A76 = "processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid\n"


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh on PATH (on Windows Git Bash provides one)")
def test_otp_aes_loads_the_bit_sliced_aes_only_without_the_aes_instructions(tmp_path):
    r, log = _run_otp_aes(tmp_path / "cm4", CPUINFO_A72)
    assert r.returncode == 0 and log == "-q aes_neon_bs\n", (r.stderr, log)
    r, log = _run_otp_aes(tmp_path / "pi5", CPUINFO_A76)
    assert r.returncode == 0 and log == "", "aes-ce is there: nothing to load"
    r, log = _run_otp_aes(tmp_path / "fail", CPUINFO_A72, modprobe_rc=1)
    assert r.returncode == 0 and log == "-q aes_neon_bs\n", "a module that does not load never stops the boot"
    assert "table-based AES" in (tmp_path / "fail" / "kmsg").read_text(encoding="utf-8")


# ---------------------------------------------------------------------- growing the encrypted root
def test_station_layer_and_custom_crypt_grow_the_partition_the_same_way():
    crypt = REPO / "docker" / "scripts" / "custom-crypt"
    script = (LAYER_INITRAMFS / "scripts" / "init-premount" / "otp-growpart").read_bytes()
    hook = (LAYER_INITRAMFS / "hooks" / "otp-growpart").read_bytes()
    assert script == (crypt / "otp-growpart").read_bytes() and hook == (crypt / "otp-growpart.hook").read_bytes()
    for body in (script, hook, (crypt / "otp-hwlock").read_bytes()):
        assert body.startswith(b"#!/bin/sh\n") and b"\r" not in body
    for tool in (b"sfdisk", b"resizepart", b"blkid"):
        assert tool in hook
    custom = (crypt.parent / "custom-image.sh").read_text(encoding="utf-8")
    for dest in ("scripts/init-premount/otp-growpart", "hooks/otp-growpart", "scripts/local-premount/otp-hwlock"):
        assert f'"${{R}}/etc/initramfs-tools/{dest}"' in custom
    assert "systemctl mask rpi-resize.service" in custom
    layer = (REPO / "image" / "layer" / "otp-rpios-setup.yaml").read_text(encoding="utf-8")
    assert 'chroot "$1" systemctl mask rpi-resize.service' in layer          # crypt: otp-growroot grows the root


def _symlink_dir(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        pytest.skip("no symbolic links on this host")


def _fake_disk(root: Path, parts: dict[int, tuple[int, int]], disk_size: int) -> Path:
    """A sysfs tree like the kernel's: class/block/<name> links to devices/mmcblk0[/mmcblk0pN] with start/size."""
    sysd = root / "sys"
    disk = sysd / "devices" / "mmcblk0"
    disk.mkdir(parents=True)
    (disk / "size").write_text(f"{disk_size}\n")
    (sysd / "class" / "block").mkdir(parents=True)
    _symlink_dir(sysd / "class" / "block" / "mmcblk0", disk)
    for num, (start, size) in parts.items():
        p = disk / f"mmcblk0p{num}"
        p.mkdir()
        (p / "partition").write_text(f"{num}\n")
        (p / "start").write_text(f"{start}\n")
        (p / "size").write_text(f"{size}\n")
        _symlink_dir(sysd / "class" / "block" / f"mmcblk0p{num}", p)
    dev = root / "dev"
    dev.mkdir()
    for name in ["mmcblk0", *(f"mmcblk0p{n}" for n in parts)]:
        (dev / name).write_bytes(b"")
    return root


def _stub(bindir: Path, name: str, body: str) -> None:
    bindir.mkdir(exist_ok=True)
    (bindir / name).write_bytes(("#!/bin/sh\n" + body).encode())
    (bindir / name).chmod(0o755)


def _posix(p: Path) -> str:
    return str(p).replace("\\", "/")


def _run_growpart(root: Path, crypttab: str | None, label: str = "dos",
                  **env_extra: str) -> tuple[subprocess.CompletedProcess, str]:
    bindir = root / "bin"
    log = _posix(root / "calls.log")
    _stub(bindir, "blkid", f'[ "$4" = LABEL=OSROOT_CRYPT ] && echo "{_posix(root)}/dev/mmcblk0p2"\nexit 0\n')
    _stub(bindir, "findfs", "exit 1\n")
    _stub(bindir, "sfdisk", f'case "$1" in --dump) echo "label: {label}" ;; '
                            f'*) echo "sfdisk $* <$(cat)" >> "{log}" ;; esac\n')
    _stub(bindir, "partx", f'echo "partx $*" >> "{log}"; exit "${{FAKE_PARTX_RC:-0}}"\n')
    _stub(bindir, "resizepart", f'echo "resizepart $*" >> "{log}"; exit "${{FAKE_RESIZEPART_RC:-0}}"\n')
    _stub(bindir, "blockdev", f'echo "blockdev $*" >> "{log}"\n')
    tab = root / "crypttab"
    if crypttab is not None:
        tab.write_text(crypttab)
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
               OTP_GROWPART_CRYPTTAB=_posix(tab), OTP_GROWPART_SYS=_posix(root / "sys"),
               OTP_GROWPART_DEV=_posix(root / "dev"), **env_extra)
    body = (LAYER_INITRAMFS / "scripts" / "init-premount" / "otp-growpart").read_text(encoding="utf-8")
    r = subprocess.run([SH, "-c", body, "otp-growpart"], capture_output=True, env=env, timeout=60)
    calls = root / "calls.log"
    return r, calls.read_text() if calls.exists() else ""


TAB = "# <name> <source> <key> <options>\nosroot_crypt LABEL=OSROOT_CRYPT none luks,initramfs,keyscript=hwkey\n"


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh on PATH (on Windows Git Bash provides one)")
def test_otp_growpart_grows_the_last_partition_before_the_container_is_opened(tmp_path):
    # a card written from the Imager file: a 4 GiB root partition on a 16 GiB card
    root = _fake_disk(tmp_path / "small", {1: (8192, 524288), 2: (532480, 8388608)}, 31116288)
    r, calls = _run_growpart(root, TAB)
    want = (31116288 - 532480) // 2048 * 2048
    dev = _posix(root / "dev" / "mmcblk0")
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    # partx tells the kernel (util-linux; resizepart is in util-linux-extra, which Raspberry Pi OS Lite lacks)
    assert calls == f"sfdisk --no-reread --no-tell-kernel -N 2 {dev} <532480,{want}\npartx -u -n 2 {dev}\n"
    root = _fake_disk(tmp_path / "nopartx", {1: (8192, 524288), 2: (532480, 8388608)}, 31116288)
    calls = _run_growpart(root, TAB, FAKE_PARTX_RC="1", FAKE_RESIZEPART_RC="1")[1]
    dev = _posix(root / "dev" / "mmcblk0")
    assert calls.splitlines()[1:] == [f"partx -u -n 2 {dev}", f"resizepart {dev} 2 {want}", f"blockdev --rereadpt {dev}"]
    # a board the station flashed: the partition already ends at the card's end
    root = _fake_disk(tmp_path / "full", {1: (8192, 524288), 2: (532480, 30582784)}, 31116288)
    assert _run_growpart(root, TAB)[1] == ""
    # not the last partition: left alone
    root = _fake_disk(tmp_path / "later", {1: (8192, 524288), 2: (532480, 8388608), 3: (8921088, 2048)}, 31116288)
    assert _run_growpart(root, TAB)[1] == ""
    # GPT: the backup header moves to the end and the last 33 sectors stay free
    root = _fake_disk(tmp_path / "gpt", {1: (8192, 524288), 2: (532480, 8388608)}, 31116288)
    r, calls = _run_growpart(root, TAB, label="gpt")
    assert f"<532480,{(31116288 - 33 - 532480) // 2048 * 2048}\n" in calls
    # no crypttab (the clear image): nothing at all
    root = _fake_disk(tmp_path / "clear", {1: (8192, 524288), 2: (532480, 8388608)}, 31116288)
    r, calls = _run_growpart(root, None)
    assert r.returncode == 0 and calls == ""


def _run_growroot(root: Path, moff: int, msize: int, resize_rc: int, keyscript_rc: int,
                  source: str = "disk/by-slot/system") -> tuple[subprocess.CompletedProcess, str]:
    """otp-growroot with /sys/class/block, /etc/crypttab and its marker under ``root``; cryptsetup, findmnt,
    sfdisk, resize2fs, df stubbed (cryptsetup resize answers ``resize_rc`` without a key, the keyscript
    ``keyscript_rc``). The root is mounted from ``<root>/dev/<source>``, a link to ``dev/dm-0`` as on a board:
    ``disk/by-slot/system`` (the station image's fstab) or ``mapper/cryptroot`` (a custom image's)."""
    bindir = root / "bin"
    log = _posix(root / "calls.log")
    p = _posix(root)
    (root / "dev" / "dm-0").write_bytes(b"")
    for link in ("mapper/cryptroot", "disk/by-slot/system"):
        (root / "dev" / link).parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(root / "dev" / "dm-0", root / "dev" / link)
        except OSError:
            pytest.skip("no symbolic links on this host")
    (root / "sys" / "devices" / "dm-0" / "dm").mkdir(parents=True)
    (root / "sys" / "devices" / "dm-0" / "dm" / "name").write_text("cryptroot\n")
    _symlink_dir(root / "sys" / "class" / "block" / "dm-0", root / "sys" / "devices" / "dm-0")
    _stub(bindir, "findmnt", f'echo "{p}/dev/{source}"\n')
    _stub(bindir, "cryptsetup", f'case "$1" in\n'
                                f'  status) printf "  device:  {p}/dev/mmcblk0p2\\n  offset:  {moff} sectors\\n'
                                f'  size:    {msize} sectors\\n" ;;\n'
                                f'  resize) echo "cryptsetup $*" >> "{log}"; key=$(cat); '
                                f'case "$*" in *key-file*) [ -n "$key" ] && exit 0; exit 2 ;; esac; exit {resize_rc} ;;\n'
                                f'esac\n')
    _stub(bindir, "sfdisk", 'case "$1" in --dump) echo "label: dos" ;; esac\n')
    _stub(bindir, "resize2fs", f'echo "resize2fs $*" >> "{log}"\n')
    _stub(bindir, "df", 'echo "Filesystem Size"; echo "x 7.1G"\n')
    _stub(bindir, "hwkey", f'echo "keyscript" >> "{log}"; [ {keyscript_rc} = 0 ] && printf 0123abcd; exit {keyscript_rc}\n')
    (root / "etc").mkdir(exist_ok=True)
    (root / "etc" / "crypttab").write_text(f"cryptroot UUID=x none luks,initramfs,keyscript={_posix(bindir)}/hwkey\n")
    body = (REPO / "docker" / "scripts" / "custom-crypt" / "otp-growroot").read_text(encoding="utf-8")
    body = (body.replace("/sys/class/block/", f"{p}/sys/class/block/").replace("/var/lib/otp-station", f"{p}/state")
                .replace("/etc/crypttab", f"{p}/etc/crypttab").replace('"/dev/$disk"', f'"{p}/dev/$disk"')
                .replace('[ -b "$part" ]', '[ -e "$part" ]'))                 # a plain file stands in for the device
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run([SH, "-c", body], capture_output=True, env=env, timeout=60)
    calls = root / "calls.log"
    return r, calls.read_text() if calls.exists() else ""


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh on PATH (on Windows Git Bash provides one)")
def test_otp_growroot_leaves_a_mapping_that_fills_its_partition_alone(tmp_path):
    """cryptsetup resize of a LUKS2 mapping with its key in the kernel keyring asks for the passphrase even when
    there is nothing to do, and the keyscript fails once the firmware HMAC is locked: a mapping that already ends
    where the partition ends is not touched, only the file system grows. The station image mounts its root as
    /dev/disk/by-slot/system: otp-growroot took that for a root without dm-crypt and never grew anything, which
    showed once rpi-resize was masked (a 5.9G file system on a 14.3G mapping, Pi 5 ebbdf4fd, 2026-11-12)."""
    psize = 30582784
    root = _fake_disk(tmp_path / "full", {1: (8192, 524288), 2: (532480, psize)}, 31116288)
    r, calls = _run_growroot(root, 32768, psize - 32768, resize_rc=1, keyscript_rc=1)
    assert r.returncode == 0, r.stderr.decode(errors="replace") + r.stdout.decode(errors="replace")
    # (the shell may spell the resolved path its own way, e.g. /tmp/... under Git Bash)
    assert "cryptsetup" not in calls and "keyscript" not in calls
    assert calls.startswith("resize2fs ") and calls.strip().endswith("/full/dev/dm-0"), calls
    assert (root / "state" / "root-grown").is_file()
    # a custom image's fstab names the mapping itself: the same
    root = _fake_disk(tmp_path / "mapper", {1: (8192, 524288), 2: (532480, psize)}, 31116288)
    r, calls = _run_growroot(root, 32768, psize - 32768, resize_rc=1, keyscript_rc=1, source="mapper/cryptroot")
    assert r.returncode == 0 and calls.strip().endswith("/mapper/dev/dm-0"), calls
    # a mapping shorter than its partition: resized with the key from the keyscript when the keyring has none
    root = _fake_disk(tmp_path / "short", {1: (8192, 524288), 2: (532480, psize)}, 31116288)
    r, calls = _run_growroot(root, 32768, 8355840, resize_rc=1, keyscript_rc=0)
    assert r.returncode == 0 and "keyscript" in calls and "--key-file=-" in calls
    # ... and when the keyscript fails too (HMAC locked), it says so and tries again at the next boot
    root = _fake_disk(tmp_path / "locked", {1: (8192, 524288), 2: (532480, psize)}, 31116288)
    r, calls = _run_growroot(root, 32768, 8355840, resize_rc=1, keyscript_rc=1)
    assert r.returncode == 1 and b"cannot grow without the key" in r.stdout
    assert not (root / "state" / "root-grown").exists()


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh on PATH (on Windows Git Bash provides one)")
def test_otp_hwlock_locks_the_hmac_after_the_unlock(tmp_path):
    bindir = tmp_path / "bin"
    log = _posix(tmp_path / "calls.log")
    _stub(bindir, "rpi-fw-crypto", f'echo "$*" >> "{log}"; exit "${{FAKE_RC:-0}}"\n')
    body = (REPO / "docker" / "scripts" / "custom-crypt" / "otp-hwlock").read_text(encoding="utf-8")
    body = body.replace("/dev/kmsg", _posix(tmp_path / "kmsg"))
    tab = tmp_path / "crypttab"
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""), OTP_HWLOCK_CRYPTTAB=_posix(tab))
    r = subprocess.run([SH, "-c", body, "otp-hwlock"], capture_output=True, env=env, timeout=60)
    assert r.returncode == 0 and not (tmp_path / "calls.log").exists(), "no crypttab: nothing to lock"
    tab.write_text(TAB)
    r = subprocess.run([SH, "-c", body, "otp-hwlock"], capture_output=True, env=env, timeout=60)
    assert r.returncode == 0 and (tmp_path / "calls.log").read_text() == "set-key-status 1 HMAC_LOCKED\n"
    r = subprocess.run([SH, "-c", body, "otp-hwlock"], capture_output=True, env=dict(env, FAKE_RC="3"), timeout=60)
    assert r.returncode == 0 and "could not lock" in (tmp_path / "kmsg").read_text(), "an old firmware never stops the boot"


# ---------------------------------------------------------------------- the keyscript, run
SH = shutil.which("sh")

# bookworm's rpi-fw-crypto 20251002 sizes --in with fseek/ftell: anything but a regular file fails without a
# word (exit 255). The "HMAC" here is SHA-256 of the message, enough to see which bytes went in.
FAKE_FW_CRYPTO = """#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in --in) in=$2; shift ;; esac
    shift
done
[ -f "$in" ] || exit 255
[ -z "$FAKE_FAIL" ] || exit "$FAKE_FAIL"
sha256sum "$in" | cut -c1-64
"""


def _run_keyscript(root: Path, source: str, **env_extra: str) -> subprocess.CompletedProcess:
    """otp-hwkey with /sys/class/block and /run under ``root`` and a fake rpi-fw-crypto first on PATH."""
    bindir = root / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "rpi-fw-crypto").write_bytes(FAKE_FW_CRYPTO.encode())
    (bindir / "rpi-fw-crypto").chmod(0o755)
    posix = str(root).replace("\\", "/")
    body = (REPO / "docker" / "scripts" / "custom-crypt" / "otp-hwkey").read_text(encoding="utf-8")
    body = body.replace("/sys/class/block/", posix + "/sys/class/block/").replace("/run/", posix + "/run/")
    env = dict(os.environ, CRYPTTAB_SOURCE=source, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
               **env_extra)
    return subprocess.run([SH, "-c", body], capture_output=True, env=env, timeout=60)


@pytest.mark.skipif(SH is None, reason="no POSIX sh on PATH (on Windows Git Bash provides one)")
def test_keyscript_hands_the_cid_to_rpi_fw_crypto_in_a_regular_file(tmp_path):
    cid = "275048534431364760da8e4a60013c00"
    (tmp_path / "sys/class/block/mmcblk0/device").mkdir(parents=True)
    (tmp_path / "sys/class/block/mmcblk0/device/cid").write_bytes(cid.encode() + b"\n")
    (tmp_path / "run").mkdir()

    r = _run_keyscript(tmp_path, "/dev/mmcblk0")
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert r.stdout.decode() == hashlib.sha256(cid.encode() + b"\n").hexdigest(), "CID + LF, nothing else"
    assert list((tmp_path / "run").iterdir()) == [], "the message file is removed"

    r = _run_keyscript(tmp_path, "/dev/mmcblk0", FAKE_FAIL="3")
    assert r.returncode == 1 and r.stdout == b""
    assert b"rpi-fw-crypto hmac --key-id 1 failed (exit 3" in r.stderr
    assert list((tmp_path / "run").iterdir()) == [], "removed on failure too"

    r = _run_keyscript(tmp_path, "/dev/sda2")
    assert r.returncode == 1 and r.stdout == b"" and b"not on an SD/eMMC card" in r.stderr


def test_keyscript_never_pipes_into_rpi_fw_crypto():
    body = (REPO / "docker" / "scripts" / "custom-crypt" / "otp-hwkey").read_text(encoding="utf-8")
    code = [line for line in body.splitlines() if not line.lstrip().startswith("#")]
    assert not any("rpi-fw-crypto" in line and "|" in line.split("rpi-fw-crypto")[0] for line in code)
    assert not any("/dev/stdin" in line for line in code)


# ---------------------------------------------------------------------- the HTTP API
@pytest.fixture
def api(cenv):
    from fastapi.testclient import TestClient

    from otp_server.app import create_app

    app = create_app(cenv.cfg, store=cenv.store, docker=cenv.docker, jobs=cenv.jobs, modules=cenv.modules,
                     artifacts=cenv.arts, auto_build=False)
    cenv.client = TestClient(app, base_url="http://127.0.0.1:8765")
    return cenv


def test_api_upload_list_prepare_delete(api, tmp_path):
    data = make_disk(tmp_path / "os.img").read_bytes()
    r = api.client.put("/api/custom-images?name=field%20os.img", content=data,
                       headers={"Origin": "http://127.0.0.1:8765"})
    assert r.status_code == 200, r.text
    body = r.json()
    cid = body["image"]["id"]
    assert body["new"] is True and body["image"]["name"] == "field_os.img" and body["job"]["target"] == f"custom:{cid}"
    assert api.jobs.get(body["job"]["id"]).wait(20)
    lst = api.client.get("/api/custom-images").json()
    assert [(x["id"], x["ready"]) for x in lst] == [(cid, True)]
    assert api.client.get("/api/status").json()["custom_images"][0]["id"] == cid
    r = api.client.put("/api/custom-images?name=again.img", content=data)
    assert r.status_code == 200 and r.json()["new"] is False and r.json()["job"] is None
    r = api.client.put("/api/custom-images?name=x.img", content=b"\x1f\x8b" + bytes(2 * MiB))
    assert r.status_code == 400 and "gzip-compressed" in r.json()["detail"]
    assert not list(api.arts.custom.root.glob("upload-*"))
    r = api.client.put("/api/custom-images", content=data, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = api.client.post(f"/api/custom-images/{cid}/prepare", json={"force": True})
    assert r.status_code == 200 and api.jobs.get(r.json()["job"]["id"]).wait(20)
    assert len(api.docker.runs_of("custom-image.sh")) == 4
    assert api.client.post(f"/api/custom-images/{cid}/prepare", json={"force": "yes"}).status_code == 400
    assert api.client.post("/api/custom-images/0123456789abcdef/prepare", json={}).status_code == 404
    r = api.client.post("/api/image", json={"custom": cid})
    assert r.status_code == 200 and r.json()["saved"] == ["image.custom"] and r.json()["settings"]["custom"] == cid
    assert api.client.post("/api/image", json={"custom": "nope"}).status_code == 400
    r = api.client.delete(f"/api/custom-images/{cid}")
    assert r.status_code == 400 and "choose another image first" in r.json()["detail"]
    api.client.post("/api/image", json={"custom": ""})
    assert api.client.delete(f"/api/custom-images/{cid}").status_code == 200
    assert api.client.delete(f"/api/custom-images/{cid}").status_code == 404
    assert api.client.get("/api/custom-images").json() == []


def test_api_imager_image(api, tmp_path):
    build_image(api)
    api.board(mode="open")
    r = api.client.post(f"/api/modules/{SERIAL}/imager-image", json={"source": ""})
    assert r.status_code == 409 and "not locked to its key" in r.json()["reason"]
    api.board(mode="secure", lock="ours")
    api.export_key(SERIAL)
    assert api.client.post(f"/api/modules/{SERIAL}/imager-image", json={"source": 3}).status_code == 400
    r = api.client.post(f"/api/modules/{SERIAL}/imager-image", json={"source": ""})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ready"] is True and out["name"].endswith("-secure.img") and "shas" not in out
    g = api.client.get(out["url"])
    assert g.status_code == 200 and len(g.content) == out["size"] == int(g.headers["content-length"])
    assert g.headers["content-disposition"] == f'attachment; filename="{out["name"]}"'
    assert g.content[510:512] == b"\x55\xaa"
    assert api.client.get(f"/api/modules/{SERIAL}/imager-image/other.img").status_code == 404
    assert api.client.get(f"/api/modules/{SERIAL}/imager-image/a%5Cb.img").status_code == 404


# ---------------------------------------------------------------------- the OTP device key lock in signed boot.img
def _slot_helper(name: str) -> str:
    """The Python of a boot-slot.sh helper function (``<name>() { python3 - "$1" <<'EOF' ... EOF``)."""
    text = (REPO / "docker" / "scripts" / "boot-slot.sh").read_text(encoding="utf-8").replace("\r\n", "\n")
    start = text.index(f"{name}() {{\n    python3 - \"$1\" <<'EOF'\n") + len(f"{name}() {{\n    python3 - \"$1\" <<'EOF'\n")
    return text[start:text.index("\nEOF\n", start)]


def _run_helper(name: str, path: Path) -> int:
    import subprocess
    import sys

    return subprocess.run([sys.executable, "-B", "-c", _slot_helper(name), str(path)]).returncode


def test_boot_slot_locks_the_device_key_in_all(tmp_path):
    cfg = tmp_path / "config.txt"
    cfg.write_text("arm_64bit=1\n[cm5]\notg_mode=1\nlock_device_private_key=0\n", encoding="utf-8")
    assert _run_helper("key_locked", cfg) == 1, "=0 inside [cm5] is not locked"
    assert _run_helper("lock_device_key", cfg) == 0 and _run_helper("lock_device_key", cfg) == 0
    text = cfg.read_text(encoding="utf-8")
    assert text.endswith("[all]\n# OTP provisioning station: the OS cannot read the OTP device private key "
                         "(hmac/sign still work)\nlock_device_private_key=1\n"), text
    assert text.count("lock_device_private_key") == 1 and text.count("[all]") == 1, "applied twice: one lock"
    assert "otg_mode=1" in text and _run_helper("key_locked", cfg) == 0
    cfg.write_text("[all]\nlock_device_private_key=1\n[pi4]\nfoo=1\n", encoding="utf-8")
    assert _run_helper("key_locked", cfg) == 0
    cfg.write_text("[pi5]\nlock_device_private_key=1\n", encoding="utf-8")
    assert _run_helper("key_locked", cfg) == 1, "only for a Pi 5 section is not [all]"
    missing = tmp_path / "none.txt"
    assert _run_helper("lock_device_key", missing) == 0 and _run_helper("key_locked", missing) == 0


def test_a_signed_slot_without_the_key_lock_is_refused(cenv, tmp_path):
    from test_artifacts import h_boot_slot

    def unlocked(call):
        h_boot_slot(call)
        out = Path(call["mounts"]["/out"].source)
        res = json.loads((out / "slot.json").read_text(encoding="utf-8"))
        res["key_locked"] = False
        (out / "slot.json").write_text(json.dumps(res), encoding="utf-8")

    build_image(cenv)
    cenv.board(mode="secure", lock="ours")
    cenv.export_key(SERIAL)
    m = cenv.arts.stage_manifest(SERIAL, 3)
    assert any("lock_device_private_key=1" in n for n in m["notes"])
    cenv.board("0badc0de", mode="secure", lock="ours")
    cenv.docker.handlers["boot-slot.sh"] = unlocked
    with pytest.raises(NotReady, match="did not lock the OTP device key"):
        cenv.arts.stage_manifest("0badc0de", 3)
