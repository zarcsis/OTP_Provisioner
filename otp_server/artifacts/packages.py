"""Debian packages for the station image, uploaded on the page, of two kinds:

* ``system``: trusted. Installed into the image like any of its own packages (rpi-image-gen ``packages:``),
  maintainer scripts and all, as root on the board. A system package may declare permissions for sandboxed
  apps (``usr/share/vn-apps/permissions/<service>.json``, :func:`otp_server.sandbox.parse_catalog`).
* ``app``: untrusted. Any ordinary package (its own dependencies, units, maintainer scripts): it runs in its own
  container on the board (:mod:`otp_server.sandbox`). It is installed on the station, before the image is
  built, into its own root file system:

  1. ``app-vmkit.sh`` (once): the installer VM's kernel and initramfs, from Debian;
  2. ``app-rootfs.sh`` (privileged, network): Debian trixie arm64 + systemd + the app's dependencies from
     Debian (only Debian's maintainer scripts run there), as the VM's disk with the app's .deb on it;
  3. ``app-install.sh`` (no network, no capabilities): dpkg installs the app in a throwaway
     qemu-system-aarch64 VM, so the app's own maintainer scripts run behind the VM's kernel and nowhere else;
     the VM writes the result as a tar archive;
  4. :func:`otp_server.rootfs_tar.sanitize` reads that untrusted archive into the prepared ``rootfs.tar``
     (container IDs; the image build moves them into the app's host range).

Layout, ``<work>/artifacts/packages/``: ``<id>/`` per upload (id = the first 16 hex digits of its sha256) with
``package.deb``, ``package.json``; for an app also the prepared sets ``<fingerprint>[-rN]/`` (``rootfs.tar``,
``prepared.json``, ``install.log``, ``.complete``), ``current.json`` and ``error.json`` while the last
preparation failed. ``vmkit-<fingerprint>/`` is the VM kit all apps share. A set is used only while its
fingerprint (the builder image, the scripts, the archive check) matches the station's.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from .. import debpkg, rootfs_tar, sandbox
from ..docker import Mount
from .common import (NotReady, commit_partial, fingerprint, fresh_partial, heavy_lock, is_complete, now_iso,
                     read_json, rmtree, write_json)
from .tools import ToolsImage

KINDS = ("system", "app")
_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_NAME_RE = re.compile(r"[^A-Za-z0-9._+-]+")
MAX_UPLOAD = 2 * 1024 ** 3
#: docker/scripts every prepared app depends on.
PREPARE_SCRIPTS = ("app-rootfs.sh", "app-install.sh", "app-vm-init", "app-vmkit.sh")
VMKIT_SCRIPTS = ("app-vmkit.sh", "app-vm-init")
#: Seconds the installer VM may run.
INSTALL_TIMEOUT = 1800


class AppBuilderImage(ToolsImage):
    """otp-app-builder (docker/apps.Dockerfile): qemu-system-aarch64, mmdebstrap, mke2fs; runs docker/scripts."""

    DOCKERFILE = "apps.Dockerfile"
    LABEL = "otp.apps.hash"
    TITLE = "Build otp-app-builder image"
    TARGET = "app-builder"
    TAG = "otp-app-builder:trixie"

    @property
    def tag(self) -> str:
        return self.TAG


def check_id(pid: str) -> str:
    pid = str(pid or "").strip().lower()
    if not _ID_RE.fullmatch(pid):
        raise KeyError(f"no package {pid!r}")
    return pid


def target(pid: str) -> str:
    """Job target of an app's preparation."""
    return f"package:{pid}"


def display_name(name: str) -> str:
    base = re.split(r"[\\/]", str(name or ""))[-1].strip()
    return (_NAME_RE.sub("_", base).strip("._") or "package.deb")[:100]


class Upload:
    """One package being received; :meth:`finish` reads it (:mod:`otp_server.debpkg`) and files it under its id."""

    def __init__(self, owner: "Packages", name: str, size: int, kind: str):
        self.owner = owner
        self.name = display_name(name)
        self.size = int(size)
        self.kind = kind
        owner.root.mkdir(parents=True, exist_ok=True)
        self.tmp = owner.root / f"upload-{uuid.uuid4().hex[:12]}.partial"
        self.f = open(self.tmp, "wb")
        self.h = hashlib.sha256()
        self.n = 0

    def write(self, data: bytes) -> None:
        if self.n + len(data) > self.size:
            raise ValueError(f"the upload is longer than announced ({self.size} bytes)")
        self.f.write(data)
        self.h.update(data)
        self.n += len(data)

    def abort(self) -> None:
        try:
            self.f.close()
        finally:
            try:
                self.tmp.unlink()
            except OSError:
                pass

    def finish(self) -> tuple[dict, bool]:
        """``(package info, new)``; ValueError (the file is removed) when the station does not take it."""
        self.f.close()
        try:
            if self.n != self.size:
                raise ValueError(f"the upload ended after {self.n} of {self.size} bytes")
            info = describe(self.tmp, self.kind)
        except debpkg.DebError as exc:
            self.abort()
            raise ValueError(str(exc)) from None
        except BaseException:
            self.abort()
            raise
        sha = self.h.hexdigest()
        pid = sha[:16]
        d = self.owner.dir(pid)
        if (d / "package.deb").is_file() and (d / "package.json").is_file():
            self.abort()
            old = read_json(d / "package.json")
            if old.get("kind") != self.kind:
                raise ValueError(f"this package is already on the station as a {old.get('kind')} package; delete it "
                                 "there first")
            return old, False
        d.mkdir(parents=True, exist_ok=True)
        os.replace(self.tmp, d / "package.deb")
        info.update(id=pid, kind=self.kind, name=self.name, size=self.n, sha256=sha, uploaded=now_iso())
        write_json(d / "package.json", info)
        return info, True


def describe(path: Path, kind: str) -> dict:
    """What the station keeps about a package (DebError when it is not one it takes)."""
    if kind not in KINDS:
        raise ValueError(f"package kind must be one of {', '.join(KINDS)}")
    deb = debpkg.read(path, want=(sandbox.CATALOG_DIR,) if kind == "system" else ())
    if deb.architecture not in debpkg.BOARD_ARCHES:
        raise debpkg.DebError(f"{deb.package} is built for {deb.architecture}; the board runs arm64 (or 'all')")
    info: dict[str, Any] = {"deb": deb.to_dict()}
    if kind == "system":
        catalog = {}
        for name, data in sorted(deb.read.items()):
            try:
                perms = sandbox.parse_catalog(data, deb.package)
            except sandbox.SandboxError as exc:
                raise debpkg.DebError(f"{name}: {exc}") from None
            for p in perms.values():
                catalog[p.name] = {"description": p.description,
                                   "calls": [{"service": c.service, "interface": c.interface, "method": c.method,
                                              "path": c.path} for c in p.calls]}
        info["permissions"] = catalog
    else:
        hint = deb.fields.get("X-Sandbox-Permissions", "")
        info["requested"] = sorted({p.strip() for p in re.split(r"[,\s]+", hint) if p.strip()})
    return info


def catalog_of(info: dict) -> dict[str, sandbox.Permission]:
    """The permissions a system package's ``package.json`` records."""
    out = {}
    for name, p in (info.get("permissions") or {}).items():
        calls = tuple(sandbox.Call(c["service"], c["interface"], c["method"], c["path"]) for c in p.get("calls") or [])
        out[name] = sandbox.Permission(name, str(p.get("description") or ""), calls,
                                       str((info.get("deb") or {}).get("package") or ""))
    return out


class Packages:
    """The uploaded packages, the preparation of the apps among them, and what an image build takes from them."""

    def __init__(self, cfg: Any, docker: Any, jobs: Any, hashes: Any, builder: AppBuilderImage | None = None):
        self.cfg = cfg
        self.docker = docker
        self.jobs = jobs
        self.hashes = hashes
        self.builder = builder or AppBuilderImage(cfg, docker)

    # ------------------------------------------------------------------ paths / identity
    @property
    def root(self) -> Path:
        return Path(self.cfg.work_dir) / "artifacts" / "packages"

    def dir(self, pid: str) -> Path:
        return self.root / check_id(pid)

    def ids(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(d.name for d in self.root.iterdir()
                      if d.is_dir() and _ID_RE.fullmatch(d.name) and (d / "package.json").is_file())

    def info(self, pid: str) -> dict | None:
        try:
            return read_json(self.dir(pid) / "package.json")
        except (OSError, ValueError, KeyError):
            return None

    def fingerprint(self) -> str:
        """Changes whenever an app prepared now would differ: builder image, scripts, the archive check."""
        return fingerprint("app-rootfs", self.builder.hash(), self.builder.script_hash(*PREPARE_SCRIPTS),
                           _source_hash(rootfs_tar))[:12]

    def vmkit_fingerprint(self) -> str:
        return fingerprint("app-vmkit", self.builder.hash(), self.builder.script_hash(*VMKIT_SCRIPTS))[:12]

    # ------------------------------------------------------------------ prepared apps
    def prepared(self, pid: str) -> tuple[Path, dict] | None:
        """(set dir, prepared.json) of an app prepared for the current scripts, or None."""
        d = self.dir(pid)
        try:
            name = read_json(d / "current.json").get("set")
        except (OSError, ValueError, AttributeError):
            return None
        s = d / str(name or "")
        if not name or not is_complete(s) or not (s / "rootfs.tar").is_file():
            return None
        try:
            man = read_json(s / "prepared.json")
        except (OSError, ValueError):
            return None
        if man.get("fingerprint") != self.fingerprint():
            return None
        return s, man

    def error(self, pid: str) -> dict | None:
        try:
            return read_json(self.dir(pid) / "error.json")
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------ upload / delete
    def begin_upload(self, name: str, size: int, kind: str) -> Upload:
        if kind not in KINDS:
            raise ValueError(f"package kind must be one of {', '.join(KINDS)}")
        if size <= 0:
            raise ValueError("the upload is empty")
        if size > MAX_UPLOAD:
            raise ValueError(f"the upload has {size} bytes; the station takes packages up to {MAX_UPLOAD} bytes")
        self.root.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(self.root).free < size + 4 * 1024 ** 3:
            raise ValueError("not enough free space on the station's disk (a package and its preparation need room)")
        return Upload(self, name, size, kind)

    def selected(self) -> set[str]:
        img = self.cfg.image
        ids = set(getattr(img, "packages", []) or [])
        for line in getattr(img, "apps", []) or []:
            ids.add(line.split()[0])
        return ids

    def delete(self, pid: str) -> None:
        pid = check_id(pid)
        if self.info(pid) is None:
            raise KeyError(f"no package {pid!r}")
        if self.jobs.active(target(pid)) is not None:
            raise ValueError("the package is being prepared; wait for the job to end")
        if pid in self.selected():
            raise ValueError("the package is part of the station image (image.packages / image.apps): remove it there "
                             "first")
        if not rmtree(self.dir(pid)):
            raise ValueError(f"could not remove {self.dir(pid)} (a file in use?)")

    # ------------------------------------------------------------------ preparation
    def start_prepare(self, pid: str, force: bool = False) -> Any:
        pid = check_id(pid)
        info = self.info(pid)
        if info is None:
            raise KeyError(f"no package {pid!r}")
        if info.get("kind") != "app":
            raise ValueError(f"{info.get('name', pid)} is a system package: it is installed by the image build, "
                             "there is nothing to prepare")
        return self.jobs.submit(target(pid), f"Prepare app {info['deb']['package']}",
                                lambda job: self.prepare(job, pid, force=force), dedupe=True)

    def prepare(self, job: Any, pid: str, force: bool = False, *, locked: bool = False) -> Path:
        """Job body: install the app into its own root file system (see the module). ``locked``: the caller
        holds the heavy lock already (an image build preparing its apps)."""
        info = self.info(pid)
        if info is None or info.get("kind") != "app":
            raise RuntimeError(f"no app {pid} on the station")
        if not force and (cur := self.prepared(pid)) is not None:
            job.log(f"==> {info['deb']['package']} already prepared: {cur[0].name}")
            return cur[0]
        if locked:
            return self._prepare(job, pid, info)
        with heavy_lock(self.cfg.work_dir, job.log):
            return self._prepare(job, pid, info)

    def _prepare(self, job: Any, pid: str, info: dict) -> Path:
        d = self.dir(pid)
        deb = info["deb"]
        try:
            self.docker.ensure_daemon(job.log)
            self.docker.ensure_arm64(job.log)
            self.builder.ensure(job.log)
            kit = self.vmkit(job)
            fp = self.fingerprint()
            job.log(f"==> app {deb['package']} {deb['version']} ({pid}): its own root file system")
            part = fresh_partial(d / f"build-{job.id}")
            try:
                inbox = part / "in"
                inbox.mkdir()
                shutil.copyfile(d / "package.deb", inbox / f"{deb['package']}_{deb['version']}.deb")
                work = part / "work"
                work.mkdir()
                self.builder.run_script("app-rootfs.sh", env={"DEPENDS": deb.get("depends") or ""},
                                        mounts=[Mount.bind(inbox, "/in", readonly=True), Mount.bind(work, "/out")],
                                        log=job.log, privileged=True)
                job.log("==> installing the app in the installer VM (no network; its maintainer scripts run there)")
                try:
                    self.builder.run_script("app-install.sh", env={"TIMEOUT": str(INSTALL_TIMEOUT)},
                                            mounts=[Mount.bind(kit, "/kit", readonly=True), Mount.bind(work, "/out")],
                                            log=job.log, isolated=True)
                finally:
                    if (work / "install.log").is_file():
                        shutil.copyfile(work / "install.log", part / "install.log")
                job.log("==> checking the VM's result (owners, file types, capabilities)")
                try:
                    report = rootfs_tar.sanitize(work / "result.img", part / "rootfs.tar", uid_base=0)
                except rootfs_tar.RootfsError as exc:
                    raise RuntimeError(f"the installed root file system was refused: {exc}") from None
                base = read_json(work / "rootfs.json")
                install = read_json(work / "install.json")
                rmtree(work)
                rmtree(inbox)
                job.log(f"==> {report.members} files and directories, {report.bytes} bytes"
                        + (f"; dropped: {report.dropped}" if report.dropped else "")
                        + (f"; file capabilities on {len(report.capabilities)}" if report.capabilities else ""))
                name = fp
                final = d / name
                n = 2
                while final.exists():
                    final = d / f"{name}-r{n}"
                    n += 1
                manifest = {
                    "package": deb["package"], "version": deb["version"], "id": pid, "set": final.name,
                    "fingerprint": fp, "built": now_iso(), "vmkit": read_json(kit / "vmkit.json"),
                    "base": {"suite": base.get("suite"), "depends": base.get("depends"),
                             "packages": len(base.get("packages") or {})},
                    "install": install,
                    "rootfs": {"file": "rootfs.tar", "size": (part / "rootfs.tar").stat().st_size,
                               "sha256": self.hashes.sha256(part / "rootfs.tar"), "report": report.to_dict()},
                }
                write_json(part / "prepared.json", manifest)
                commit_partial(part, final, {"set": final.name})
            except BaseException:
                job.log(f"preparation failed; the partial set is removed: {part.name}")
                rmtree(part)
                raise
        except Exception as exc:
            write_json(d / "error.json", {"error": str(exc) or exc.__class__.__name__, "at": now_iso(), "job": job.id})
            raise
        write_json(d / "current.json", {"set": final.name})
        try:
            (d / "error.json").unlink()
        except OSError:
            pass
        for old in d.iterdir():
            if old.is_dir() and old != final and not old.name.endswith(".partial") and old.name != "in":
                rmtree(old)
        job.log(f"==> {deb['package']} prepared: {final}")
        return final

    def vmkit(self, job: Any) -> Path:
        """The installer VM's kit for the current scripts (built here when missing)."""
        final = self.root / f"vmkit-{self.vmkit_fingerprint()}"
        if is_complete(final):
            return final
        job.log("==> the installer VM's kernel and initramfs (Debian arm64, once)")
        part = fresh_partial(final)
        try:
            self.builder.run_script("app-vmkit.sh", mounts=[Mount.bind(part, "/out")], log=job.log)
            for f in ("vmlinuz", "initrd.img", "vmkit.json"):
                if not (part / f).is_file() or not (part / f).stat().st_size:
                    raise RuntimeError(f"app-vmkit.sh did not write {f}")
            commit_partial(part, final, {"vmkit": final.name})
        except BaseException:
            rmtree(part)
            raise
        for old in self.root.glob("vmkit-*"):
            if old.is_dir() and old != final and not old.name.endswith(".partial"):
                rmtree(old)
        return final

    # ------------------------------------------------------------------ what an image build takes
    def image_inputs(self, img: Any) -> dict:
        """The system packages and apps the settings put into the station image, resolved against the
        uploads: ``{"system": [{id, package, version, path, sha256}], "apps": [sandbox.App],
        "rootfs": {app name: (path, sha256)}, "permissions": {...}, "missing": [app ids not prepared],
        "problems": [text]}``. Cheap: reads only the small JSON files."""
        from ..imageconfig import parse_app_line

        out: dict[str, Any] = {"system": [], "apps": [], "rootfs": {}, "permissions": {}, "missing": [],
                               "problems": []}
        catalogs = []
        for pid in getattr(img, "packages", []) or []:
            info = self.info(pid)
            if info is None or info.get("kind") != "system":
                out["problems"].append(f"system package {pid} is not on the station")
                continue
            deb = info["deb"]
            out["system"].append({"id": pid, "package": deb["package"], "version": deb["version"],
                                  "path": self.dir(pid) / "package.deb", "sha256": info["sha256"]})
            catalogs.append(catalog_of(info))
        try:
            out["permissions"] = sandbox.merge_catalogs(catalogs)
        except sandbox.SandboxError as exc:
            out["problems"].append(str(exc))
        for line in getattr(img, "apps", []) or []:
            entry = parse_app_line(line)
            info = self.info(entry["id"])
            if info is None or info.get("kind") != "app":
                out["problems"].append(f"app {entry['id']} is not on the station")
                continue
            deb = info["deb"]
            app = sandbox.App(deb["package"], deb["version"], entry["slot"], tuple(entry["grant"]),
                              entry["memory_mb"], entry["cpus"], entry["tasks"])
            out["apps"].append(app)
            cur = self.prepared(entry["id"])
            if cur is None:
                out["missing"].append(entry["id"])
            else:
                out["rootfs"][app.name] = (cur[0] / "rootfs.tar", str(cur[1]["rootfs"]["sha256"]))
        return out

    def sandbox_preview(self, pid: str) -> dict:
        """The files of an app's sandbox as the image would get them now: its ``image.apps`` line, or slot
        ``next free`` and no grants when it is not in the image yet. ``{"app": {...}, "files": {path: text}}``."""
        from ..imageconfig import parse_app_line

        pid = check_id(pid)
        info = self.info(pid)
        if info is None or info.get("kind") != "app":
            raise KeyError(f"no app {pid!r}")
        img = self.cfg.image
        entry = next((parse_app_line(line) for line in img.apps if line.split()[0] == pid), None)
        if entry is None:
            slot = next_free_slot(img.apps)
            if slot is None:
                raise ValueError(f"all {sandbox.MAX_SLOT} app slots are taken")
            entry = {"slot": slot, "grant": [], **sandbox.DEFAULT_LIMITS}
        deb = info["deb"]
        app = sandbox.App(deb["package"], deb["version"], entry["slot"], tuple(entry["grant"]), entry["memory_mb"],
                          entry["cpus"], entry["tasks"])
        perms = self.image_inputs(img)["permissions"]
        try:
            rendered = sandbox.render([app], perms)
        except sandbox.SandboxError as exc:
            raise ValueError(str(exc)) from None
        return {"app": rendered.apps[0], "in_image": any(line.split()[0] == pid for line in img.apps),
                "files": {path: data.decode("utf-8") for path, (data, _mode) in sorted(rendered.files.items())}}

    # ------------------------------------------------------------------ status
    def status(self) -> list[dict]:
        """Every upload, newest first: what it is, and for an app whether it is prepared."""
        selected = self.selected()
        out = []
        for pid in self.ids():
            info = self.info(pid) or {}
            row = {k: info.get(k) for k in ("id", "kind", "name", "size", "sha256", "uploaded", "deb", "permissions",
                                           "requested")}
            row["selected"] = pid in selected
            if info.get("kind") == "app":
                cur = self.prepared(pid)
                err = self.error(pid)
                row["prepared"] = cur[1] if cur else None
                row["error"] = (err or {}).get("error", "")
                job = self.jobs.current(target(pid))
                row["job"] = job.to_dict() if job is not None else None
            out.append(row)
        out.sort(key=lambda x: str(x.get("uploaded") or ""), reverse=True)
        return out


def next_free_slot(lines: list[str]) -> int | None:
    """The lowest slot no ``image.apps`` line holds (None when all are taken)."""
    from ..imageconfig import parse_app_line

    taken = set()
    for line in lines:
        try:
            taken.add(parse_app_line(line)["slot"])
        except ValueError:
            continue
    return next((s for s in range(1, sandbox.MAX_SLOT + 1) if s not in taken), None)


def _source_hash(module: Any) -> str:
    try:
        return hashlib.sha256(inspect.getsource(module).replace("\r\n", "\n").encode("utf-8")).hexdigest()[:16]
    except (OSError, TypeError):
        return "unknown"


__all__ = ["AppBuilderImage", "KINDS", "Packages", "Upload", "catalog_of", "check_id", "describe", "target"]
