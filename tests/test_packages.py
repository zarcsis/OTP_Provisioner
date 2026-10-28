"""Packages for the station image: system packages and sandboxed apps.

* :mod:`otp_server.debpkg` on the demo packages of examples/apps (built here with examples/apps/build.py);
* :mod:`otp_server.sandbox`: permission catalogs, the files of an app's sandbox, clashes;
* ``image.packages`` / ``image.apps`` in :mod:`otp_server.imageconfig` and :mod:`otp_server.config`;
* :class:`otp_server.artifacts.packages.Packages` with the fake Docker of test_artifacts: upload, the app's
  preparation (VM kit, root file system, install in the VM, the archive check), status, delete;
* the image build with apps: the config's layer and packages, the config dir (shifted root file system, sandbox
  files), the app prepared inside the build job.
"""
from __future__ import annotations

import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

from otp_server import debpkg, imageconfig, sandbox
from otp_server.artifacts.packages import AppBuilderImage
from otp_server.config import DEFAULTS, parse_image
from test_artifacts import APP_TAG, build_image, make_env  # noqa: F401 (make_env: fixture)

REPO = Path(__file__).resolve().parent.parent
GRANTS = ("demo.detections.report", "demo.frames.read")


@pytest.fixture(scope="module")
def debs(tmp_path_factory) -> dict[str, Path]:
    """The two demo packages, built from examples/apps."""
    spec = importlib.util.spec_from_file_location("apps_build", REPO / "examples" / "apps" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.DIST = tmp_path_factory.mktemp("dist")
    return {name: mod.build(REPO / "examples" / "apps" / name) for name in ("vn-demo-provider", "vn-demo-detector")}


def demo_permissions(debs) -> dict[str, sandbox.Permission]:
    info = debpkg.read(debs["vn-demo-provider"], want=(sandbox.CATALOG_DIR,))
    return sandbox.merge_catalogs(sandbox.parse_catalog(d, info.package) for d in info.read.values())


# ---------------------------------------------------------------------- debpkg
def test_debpkg_reads_the_demo_packages(debs):
    prov = debpkg.read(debs["vn-demo-provider"], want=(sandbox.CATALOG_DIR,))
    assert (prov.package, prov.version, prov.architecture) == ("vn-demo-provider", "1.0.0", "all")
    assert prov.scripts == ["postinst", "postrm", "prerm"]
    assert "usr/lib/vn-demo-provider/provider.py" in prov.files
    assert list(prov.read) == ["usr/share/vn-apps/permissions/io.github.DetectInt.Demo.json"]
    det = debpkg.read(debs["vn-demo-detector"])
    assert det.depends() == "python3, python3-gi, gir1.2-glib-2.0, systemd"
    assert det.fields["X-Sandbox-Permissions"] == "demo.frames.read, demo.detections.report"
    assert det.read == {}


def test_debpkg_control_parsing():
    f = debpkg.parse_control("Package: a\nDescription: one\n more\n .\n end\n\nPackage: ignored\n")
    assert f == {"Package": "a", "Description": "one\nmore\n.\nend"}
    for bad in (" cont\n", "Package a\n", "Package: a\nPackage: b\n"):
        with pytest.raises(debpkg.DebError):
            debpkg.parse_control(bad)


def test_debpkg_refuses_what_is_not_a_package(tmp_path, debs):
    junk = tmp_path / "junk.deb"
    junk.write_bytes(b"PK\x03\x04 not a deb")
    with pytest.raises(debpkg.DebError, match="no ar archive"):
        debpkg.read(junk)
    raw = debs["vn-demo-detector"].read_bytes()
    noctl = tmp_path / "noctl.deb"
    noctl.write_bytes(raw.replace(b"control.tar.xz", b"controX.tar.xz"))
    with pytest.raises(debpkg.DebError, match="control.tar or data.tar missing"):
        debpkg.read(noctl)


# ---------------------------------------------------------------------- sandbox
def test_permission_catalog_and_proxy_rules(debs):
    perms = demo_permissions(debs)
    assert sorted(perms) == ["demo.detections.report", "demo.frames.read"]
    app = sandbox.App("vn-demo-detector", "1.0.0", 1, GRANTS)
    assert sandbox.proxy_rules(app, perms) == [
        "--call=io.github.DetectInt.Demo=io.github.DetectInt.Demo1.GetFrameHandle@/io/github/DetectInt/Demo",
        "--call=io.github.DetectInt.Demo=io.github.DetectInt.Demo1.ReportDetection@/io/github/DetectInt/Demo"]
    with pytest.raises(sandbox.SandboxError, match="not declared"):
        sandbox.proxy_rules(sandbox.App("x", "1", 2, ("camera.raw",)), perms)


@pytest.mark.parametrize("doc, msg", [
    ({"service": "nodots", "permissions": {"a": {"calls": [{}]}}}, "not a bus name"),
    ({"service": "a.b", "permissions": {}}, "lists no permissions"),
    ({"service": "a.b", "permissions": {"Bad Name": {}}}, "bad permission"),
    ({"service": "a.b", "permissions": {"p": {"calls": []}}}, "grants no call"),
    ({"service": "a.b", "permissions": {"p": {"calls": [{"interface": "a.b", "method": "M", "path": "x"}]}}}, "bad call"),
])
def test_bad_permission_catalogs(doc, msg):
    with pytest.raises(sandbox.SandboxError, match=msg):
        sandbox.parse_catalog(json.dumps(doc).encode(), "pkg")


def test_sandbox_files_of_one_app(debs):
    r = sandbox.render([sandbox.App("vn-demo-detector", "1.0.0", 1, GRANTS, memory_mb=128, cpus=0.5, tasks=64)],
                       demo_permissions(debs))
    n = "vn-app-vn-demo-detector"
    assert sorted(r.files) == sorted([f"etc/containers/systemd/{n}.container", f"etc/systemd/system/{n}-bus.service",
                                      f"etc/apparmor.d/{n}", f"usr/lib/sysusers.d/{n}.conf",
                                      "usr/lib/sysusers.d/vn-apps.conf", "usr/lib/tmpfiles.d/vn-apps.conf",
                                      "etc/systemd/system/vnapps.slice", "etc/vn-apps/registry.json"])
    quadlet = r.files[f"etc/containers/systemd/{n}.container"][0].decode()
    for line in (f"Rootfs=/var/lib/vn-apps/{n}/rootfs", "UIDMap=0:1114112:65536", "GIDMap=0:1114112:65536",
                 "Network=none", f"Volume=/run/vn-apps/{n}/bus:/run/dbus:ro",
                 f"PodmanArgs=--systemd=always --security-opt=apparmor={n}", "MemoryMax=128M", "CPUQuota=50%",
                 "TasksMax=64", "Slice=vnapps.slice", f"Requires={n}-bus.service"):
        assert line in quadlet.splitlines(), line
    proxy = r.files[f"etc/systemd/system/{n}-bus.service"][0].decode()
    assert "User=vnapp1" in proxy and "SupplementaryGroups=vnapps" in proxy and "--filter" in proxy
    assert "GetFrameHandle@/io/github/DetectInt/Demo" in proxy and "PrivateNetwork=yes" in proxy
    profile = r.files[f"etc/apparmor.d/{n}"][0].decode()
    assert f"profile {n} flags=(attach_disconnected,mediate_deleted)" in profile
    assert "deny network inet," in profile and "deny /dev/vcio rwklx," in profile
    assert r.files[f"usr/lib/sysusers.d/{n}.conf"][0].decode().splitlines()[1:] == [
        "g vnapp1 1114112", 'u vnapp1 1114112:1114112 "Sandboxed app vn-demo-detector" /nonexistent /usr/sbin/nologin',
        "m vnapp1 vnapps"]
    reg = json.loads(r.files["etc/vn-apps/registry.json"][0])
    assert reg == {"version": 1, "apps": [{"id": "vn-demo-detector", "version": "1.0.0",
                                           "unit": f"{n}.service", "uid": 1114112, "uids": [1114112, 1179647],
                                           "permissions": list(GRANTS)}]}


def test_sandbox_clashes(debs):
    perms = demo_permissions(debs)
    a = sandbox.App("one", "1", 1)
    with pytest.raises(sandbox.SandboxError, match="same slot"):
        sandbox.render([a, sandbox.App("two", "1", 1)], perms)
    with pytest.raises(sandbox.SandboxError, match="twice"):
        sandbox.render([a, sandbox.App("one", "2", 2)], perms)
    with pytest.raises(sandbox.SandboxError, match="slot 65"):
        sandbox.render([sandbox.App("one", "1", 65)], perms)
    with pytest.raises(sandbox.SandboxError, match="memory_mb"):
        sandbox.render([sandbox.App("one", "1", 1, memory_mb=1)], perms)
    assert sandbox.unit_name("g++-x") == "vn-app-g__-x" and sandbox.render([], perms).files == {}


# ---------------------------------------------------------------------- settings
PID = "0123456789abcdef"


def test_app_lines():
    e = imageconfig.parse_app_line(f"{PID} slot=3 grant=b.x,a.y memory=128 cpus=0.5")
    assert e == {"id": PID, "slot": 3, "grant": ["a.y", "b.x"], "memory_mb": 128, "cpus": 0.5, "tasks": 512}
    assert imageconfig.format_app_line(e) == f"{PID} slot=3 grant=a.y,b.x memory=128 cpus=0.5"
    assert imageconfig.check_apps([f"{PID.upper()}  slot=1"]) == [f"{PID} slot=1"]
    for bad, msg in ((f"{PID}", "no slot="), (f"{PID} slot=0", "slot 0"), (f"{PID} slot=1 slot=2", "once each"),
                     (f"{PID} slot=1 grant=Bad!", "permission"), (f"{PID} slot=1 memory=lots", "memory=lots"),
                     ("xyz slot=1", "16 hex digits"), (f"{PID} slot=1 cpus=9", "cpus")):
        with pytest.raises(ValueError, match=msg):
            imageconfig.parse_app_line(bad)
    with pytest.raises(ValueError, match="slot 1 is given to two apps"):
        imageconfig.check_apps([f"{PID} slot=1", f"{'f' * 16} slot=1"])
    with pytest.raises(ValueError, match="listed twice"):
        imageconfig.check_apps([f"{PID} slot=1", f"{PID} slot=2"])


def test_image_settings_take_packages_and_apps():
    img = parse_image({**DEFAULTS["image"], "packages": f"{PID}\n{PID}\n", "apps": [f"{'a' * 16} slot=2 grant=p.q"]})
    assert img.packages == [PID] and img.apps == [f"{'a' * 16} slot=2 grant=p.q"]
    with pytest.raises(ValueError, match="image.apps"):
        parse_image({**DEFAULTS["image"], "apps": ["nope"]})


# ---------------------------------------------------------------------- the store
def rootfs_tar_bytes() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name in ("./", "./etc/", "./usr/", "./usr/sbin/", "./etc/passwd", "./usr/sbin/init"):
            i = tarfile.TarInfo(name)
            if name.endswith("/"):
                i.type, i.mode = tarfile.DIRTYPE, 0o755
                t.addfile(i)
            else:
                data = b"root:x:0:0::/root:/bin/sh\n" if "passwd" in name else b"#!/bin/sh\n"
                i.size, i.mode, i.uid = len(data), 0o755, 0
                t.addfile(i, io.BytesIO(data))
    return buf.getvalue() + bytes(8192)                  # a raw disk: the archive, then zeros


def h_vmkit(call):
    out = Path(call["mounts"]["/out"].source)
    (out / "vmlinuz").write_bytes(b"kernel")
    (out / "initrd.img").write_bytes(b"initrd")
    (out / "vmkit.json").write_text('{"kernel": "linux-image-6.12-arm64", "modules": ["virtio_blk"]}')


def h_rootfs(call):
    out = Path(call["mounts"]["/out"].source)
    call["in_debs"] = sorted(p.name for p in Path(call["mounts"]["/in"].source).iterdir())
    (out / "root.img").write_bytes(b"ext4")
    (out / "rootfs.json").write_text(json.dumps({"suite": "trixie", "depends": call["env"]["DEPENDS"],
                                                 "packages": {"systemd": "257"}}))


def h_install(call):
    out = Path(call["mounts"]["/out"].source)
    (out / "root.img").unlink()
    (out / "result.img").write_bytes(call["docker"].result)
    (out / "install.log").write_text("vn-install: result dpkg=0 tar=0\n")
    (out / "install.json").write_text('{"dpkg": "0", "tar": "0", "seconds": 20}')


@pytest.fixture
def penv(make_env):
    env = make_env()
    env.docker.result = rootfs_tar_bytes()
    env.docker.handlers.update({"app-vmkit.sh": h_vmkit, "app-rootfs.sh": h_rootfs, "app-install.sh": h_install})
    env.pk = env.arts.image.packages
    env.docker.labels[APP_TAG] = {AppBuilderImage.LABEL: env.pk.builder.hash()}
    return env


def upload(pk, path: Path, kind: str) -> tuple[dict, bool]:
    data = path.read_bytes()
    up = pk.begin_upload(path.name, len(data), kind)
    up.write(data)
    return up.finish()


def test_upload_system_and_app_packages(penv, debs):
    info, new = upload(penv.pk, debs["vn-demo-provider"], "system")
    assert new and info["kind"] == "system" and info["deb"]["package"] == "vn-demo-provider"
    assert sorted(info["permissions"]) == ["demo.detections.report", "demo.frames.read"]
    again, new = upload(penv.pk, debs["vn-demo-provider"], "system")
    assert not new and again["id"] == info["id"]
    with pytest.raises(ValueError, match="already on the station as a system package"):
        upload(penv.pk, debs["vn-demo-provider"], "app")
    app, _ = upload(penv.pk, debs["vn-demo-detector"], "app")
    assert app["requested"] == ["demo.detections.report", "demo.frames.read"]
    rows = {r["id"]: r for r in penv.pk.status()}
    assert rows[app["id"]]["prepared"] is None and rows[info["id"]]["kind"] == "system"


def test_upload_refuses_other_architectures(penv, debs, tmp_path):
    raw = debs["vn-demo-detector"].read_bytes()
    f = tmp_path / "x.deb"
    f.write_bytes(raw)
    up = penv.pk.begin_upload("x.deb", len(raw), "app")
    up.write(raw)
    import otp_server.artifacts.packages as packages_mod
    orig = debpkg.read

    def amd64(path, want=()):
        d = orig(path, want=want)
        d.fields["Architecture"] = "amd64"
        return d
    packages_mod.debpkg.read = amd64
    try:
        with pytest.raises(ValueError, match="built for amd64"):
            up.finish()
    finally:
        packages_mod.debpkg.read = orig
    assert penv.pk.ids() == []


def test_prepare_an_app(penv, debs):
    app, _ = upload(penv.pk, debs["vn-demo-detector"], "app")
    job = penv.pk.start_prepare(app["id"])
    assert job.wait(20) and job.status == "succeeded", "\n".join(job.lines)
    kit, = penv.docker.runs_of("app-vmkit.sh")
    rootfs, = penv.docker.runs_of("app-rootfs.sh")
    install, = penv.docker.runs_of("app-install.sh")
    assert not kit["privileged"] and not kit["isolated"]
    assert rootfs["privileged"] and not rootfs["isolated"] and rootfs["env"]["DEPENDS"].startswith("python3")
    assert rootfs["in_debs"] == ["vn-demo-detector_1.0.0.deb"]
    assert install["isolated"] and not install["privileged"] and install["mounts"]["/kit"].readonly
    s, man = penv.pk.prepared(app["id"])
    assert (s / "rootfs.tar").is_file() and (s / "install.log").is_file() and not (s / "work").exists()
    assert man["package"] == "vn-demo-detector" and man["install"]["seconds"] == 20
    assert man["rootfs"]["report"]["members"] == 6 and man["base"]["packages"] == 1
    with tarfile.open(s / "rootfs.tar") as t:
        assert {m.name: m.uid for m in t.getmembers()}["./etc/passwd"] == 0       # container IDs
    again = penv.pk.start_prepare(app["id"])
    assert again.wait(20) and again.status == "succeeded"
    assert len(penv.docker.runs_of("app-install.sh")) == 1                      # nothing to do
    penv.docker.runs.clear()
    job = penv.pk.start_prepare(app["id"], force=True)
    assert job.wait(20) and job.status == "succeeded"
    assert penv.docker.runs_of("app-vmkit.sh") == []                            # the kit is kept


def test_prepare_refuses_a_bad_result(penv, debs):
    app, _ = upload(penv.pk, debs["vn-demo-detector"], "app")
    penv.docker.result = b"\x01" * 4096
    job = penv.pk.start_prepare(app["id"])
    assert job.wait(20) and job.status == "failed"
    assert "refused" in job.error and penv.pk.prepared(app["id"]) is None
    assert "refused" in penv.pk.status()[0]["error"]
    assert not any(p.name.endswith(".partial") for p in penv.pk.dir(app["id"]).iterdir())


def test_system_packages_are_not_prepared_and_delete_rules(penv, debs):
    info, _ = upload(penv.pk, debs["vn-demo-provider"], "system")
    with pytest.raises(ValueError, match="nothing to prepare"):
        penv.pk.start_prepare(info["id"])
    penv.cfg.image.packages = [info["id"]]
    with pytest.raises(ValueError, match="part of the station image"):
        penv.pk.delete(info["id"])
    penv.cfg.image.packages = []
    penv.pk.delete(info["id"])
    assert penv.pk.ids() == []
    with pytest.raises(KeyError):
        penv.pk.delete(info["id"])


# ---------------------------------------------------------------------- the image with apps
def test_image_build_with_a_system_package_and_an_app(penv, debs):
    prov, _ = upload(penv.pk, debs["vn-demo-provider"], "system")
    det, _ = upload(penv.pk, debs["vn-demo-detector"], "app")
    img = penv.arts.image
    plain = img.config_hash("clear")
    penv.cfg.image.packages = [prov["id"]]
    penv.cfg.image.apps = [f"{det['id']} slot=1 grant={','.join(GRANTS)}"]
    r = img.rendered()
    assert r.problems == [f"app {det['id']} is not prepared yet"] and img.config_hash("clear") != plain
    assert "  apps: otp-apps" in r.text and 'dir: "/cfg/apps"' in r.text
    assert f'local1: "/cfg/system/vn-demo-provider_{prov["id"]}.deb"' in r.text
    build_image(penv)                                       # prepares the app inside the build job
    assert penv.pk.prepared(det["id"]) is not None
    call = penv.docker.runs_of(penv.cfg.builds.image.builder_tag)[0]
    files = call["secret_files"]
    assert sorted(files) == ["apps/apps.list", "apps/sandbox.tar", "apps/vn-app-vn-demo-detector.tar",
                             f"system/vn-demo-provider_{prov['id']}.deb"]
    assert files["apps/apps.list"] == b"vn-app-vn-demo-detector 1114112\n"
    assert files[f"system/vn-demo-provider_{prov['id']}.deb"] == debs["vn-demo-provider"].read_bytes()
    with tarfile.open(fileobj=io.BytesIO(files["apps/vn-app-vn-demo-detector.tar"])) as t:
        assert {m.uid for m in t.getmembers()} == {1114112}           # moved into the app's range
    with tarfile.open(fileobj=io.BytesIO(files["apps/sandbox.tar"])) as t:
        names = t.getnames()
    assert "./etc/containers/systemd/vn-app-vn-demo-detector.container" in names
    assert img.rendered().problems == [] and img.current_set("clear") is not None
    penv.cfg.image.apps = [f"{det['id']} slot=2 grant={','.join(GRANTS)}"]
    assert img.current_set("clear") is None                           # another slot: another image


def test_apps_layer_hook_checks():
    text = (REPO / "image" / "layer" / "otp-apps.yaml").read_text(encoding="utf-8")
    for needle in ("X-Env-VarPrefix: otpapps", "- podman", "- xdg-dbus-proxy", "chroot \"$1\" systemd-sysusers",
                   "apparmor_parser -Q -K", "--xattrs-include=security.capability",
                   'install -d -m 0711 -o 0 -g 0 "$1/var/lib/vn-apps"'):
        assert needle in text, needle
    # the memory cgroup comes from a linux-base fragment (tests/test_imageconfig.py runs the assembler)
    fragment = REPO / "image" / "layer" / "otp-apps.d" / "for" / "linux-base" / "cmdline.d" / "60-memcg"
    assert fragment.read_bytes() == b"cgroup_enable=memory\n"


# ---------------------------------------------------------------------- the HTTP API
@pytest.fixture
def api(penv):
    from fastapi.testclient import TestClient

    from otp_server.app import create_app

    app = create_app(penv.cfg, store=penv.store, docker=penv.docker, jobs=penv.jobs, modules=penv.modules,
                     artifacts=penv.arts, auto_build=False)
    penv.client = TestClient(app, base_url="http://127.0.0.1:8765")
    return penv


def test_api_packages(api, debs):
    c = api.client
    r = c.put("/api/packages?kind=system&name=vn-demo-provider_1.0.0_all.deb",
              content=debs["vn-demo-provider"].read_bytes())
    assert r.status_code == 200, r.text
    prov = r.json()["package"]
    assert r.json()["job"] is None and prov["kind"] == "system"
    r = c.put("/api/packages?kind=app&name=det.deb", content=debs["vn-demo-detector"].read_bytes())
    assert r.status_code == 200, r.text
    det = r.json()["package"]
    assert r.json()["job"]["target"] == f"package:{det['id']}"
    assert api.jobs.get(r.json()["job"]["id"]).wait(20)
    assert c.put("/api/packages?kind=bogus&name=x.deb", content=b"x").status_code == 400
    assert c.put("/api/packages?kind=app&name=x.deb", content=b"not a deb").status_code == 400
    assert not list(api.pk.root.glob("upload-*"))
    assert c.put("/api/packages?kind=app", content=b"x", headers={"Origin": "https://evil.example"}).status_code == 403

    st = c.get("/api/packages").json()
    assert {p["id"]: p["kind"] for p in st["packages"]} == {prov["id"]: "system", det["id"]: "app"}
    assert st["permissions"] == {} and st["next_slot"] == 1
    r = c.post("/api/image", json={"packages": [prov["id"]],
                                   "apps": [f"{det['id']} slot=1 grant=demo.frames.read,demo.detections.report"]})
    assert r.status_code == 200, r.text
    assert r.json()["saved"] == ["image.apps", "image.packages"]
    st = c.get("/api/packages").json()
    assert sorted(st["permissions"]) == ["demo.detections.report", "demo.frames.read"]
    assert st["problems"] == [] and st["next_slot"] == 2
    prev = c.get(f"/api/packages/{det['id']}/sandbox").json()
    assert prev["in_image"] and prev["app"]["uid"] == 1114112
    assert "UIDMap=0:1114112:65536" in prev["files"]["etc/containers/systemd/vn-app-vn-demo-detector.container"]
    assert c.get(f"/api/packages/{prov['id']}/sandbox").status_code == 404
    assert c.post("/api/image", json={"apps": ["nope"]}).status_code == 400
    assert c.post(f"/api/packages/{det['id']}/prepare", json={"force": "yes"}).status_code == 400
    r = c.post(f"/api/packages/{det['id']}/prepare", json={"force": True})
    assert r.status_code == 200 and api.jobs.get(r.json()["job"]["id"]).wait(20)
    assert c.post(f"/api/packages/{prov['id']}/prepare", json={}).status_code == 400
    assert c.delete(f"/api/packages/{det['id']}").status_code == 400            # in image.apps
    c.post("/api/image", json={"packages": [], "apps": []})
    assert c.delete(f"/api/packages/{det['id']}").status_code == 200
    assert c.delete(f"/api/packages/{det['id']}").status_code == 404
