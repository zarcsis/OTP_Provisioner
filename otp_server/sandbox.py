"""The sandbox of every app the station builds into an image: what the board runs it in, as text files.

One app = one ordinary Debian package, installed into its own root file system on the station
(:mod:`otp_server.artifacts.apps`), and on the board:

* its own range of 65536 host UIDs/GIDs (:func:`uid_base`, slot N): a user namespace maps the container's
  0..65535 onto it, so root in the container is an unprivileged user on the host; the base UID is the
  user ``vnapp<N>``, member of ``vnapps``;
* a rootful podman container (quadlet ``vn-app-<name>.container``) on ``/var/lib/vn-apps/<name>/rootfs`` with
  systemd as init: no network, its own AppArmor profile, capabilities that hold only in its user namespace
  (CAP_SYS_ADMIN included: systemd mounts and makes namespaces for the services it sandboxes), memory, CPU
  and task limits on the unit;
* the system bus only through its own xdg-dbus-proxy (``vn-app-<name>-bus.service``, as ``vnapp<N>``) that lets
  through exactly the calls of the permissions the operator granted, as listed by the trusted packages'
  permission catalogs (``/usr/share/vn-apps/permissions/*.json``). The socket is mounted at ``/run/dbus``, so
  the app finds the bus where every program looks for it;
* ``/etc/vn-apps/registry.json``: UID -> app and its permissions, for the trusted services to check callers.

Everything here is pure: :func:`render` returns ``{path in the image: (bytes, mode)}``; the image layer
(``image/layer/otp-apps.yaml``) copies the files and unpacks each rootfs.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable

#: The first app's base UID: slot N owns BASE + N * RANGE .. BASE + N * RANGE + 65535. 0x100000 is inside
#: systemd's range for container UIDs (524288..1879048191) and far above any regular or system user.
BASE = 0x100000
RANGE = 65536
MAX_SLOT = 64
GROUP = "vnapps"
APPS_DIR = "/var/lib/vn-apps"
RUN_DIR = "/run/vn-apps"
REGISTRY = "/etc/vn-apps/registry.json"
CATALOG_DIR = "usr/share/vn-apps/permissions/"
LIMITS = {"memory_mb": (32, 8192), "cpus": (0.05, 4.0), "tasks": (16, 8192)}
DEFAULT_LIMITS = {"memory_mb": 256, "cpus": 1.0, "tasks": 512}
_PERM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_BUS_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)+$")
_MEMBER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PATH_RE = re.compile(r"^/([A-Za-z0-9_]+(/[A-Za-z0-9_]+)*)?$")
_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")


class SandboxError(ValueError):
    """An app, a grant or a permission catalog the station cannot turn into a sandbox."""


def uid_base(slot: int) -> int:
    if not 1 <= slot <= MAX_SLOT:
        raise SandboxError(f"app slot {slot} outside 1..{MAX_SLOT}")
    return BASE + slot * RANGE


def unit_name(package: str) -> str:
    """``vn-app-<package>`` with the one character of a Debian package name a unit name cannot have ('+')."""
    if not _PACKAGE_RE.fullmatch(package):
        raise SandboxError(f"{package!r} is not a Debian package name")
    return "vn-app-" + package.replace("+", "_")


def host_name(package: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", package)[:63].strip("-") or "app"


@dataclass(frozen=True)
class Call:
    """One D-Bus method a permission lets through the proxy."""

    service: str
    interface: str
    method: str
    path: str

    def proxy_rule(self) -> str:
        return f"--call={self.service}={self.interface}.{self.method}@{self.path}"


@dataclass(frozen=True)
class Permission:
    name: str
    description: str
    calls: tuple[Call, ...]
    provider: str = ""            # the trusted package that declares it


def parse_catalog(data: bytes, provider: str = "") -> dict[str, Permission]:
    """A permission catalog of a trusted package (``usr/share/vn-apps/permissions/<service>.json``)::

        {"service": "io.github.DetectInt.Demo",
         "permissions": {"demo.frames.read": {"description": "...",
                         "calls": [{"interface": "...", "method": "GetFrameHandle", "path": "/..."}]}}}
    """
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SandboxError(f"permission catalog of {provider or '?'} is not JSON: {exc}") from None
    service = str(doc.get("service") or "") if isinstance(doc, dict) else ""
    if not _BUS_NAME_RE.fullmatch(service):
        raise SandboxError(f"permission catalog of {provider or '?'}: service {service!r} is not a bus name")
    perms = doc.get("permissions")
    if not isinstance(perms, dict) or not perms:
        raise SandboxError(f"permission catalog of {provider or '?'} lists no permissions")
    out: dict[str, Permission] = {}
    for name, p in perms.items():
        if not _PERM_RE.fullmatch(str(name)) or not isinstance(p, dict):
            raise SandboxError(f"permission catalog of {provider or '?'}: bad permission {name!r}")
        calls = []
        for c in p.get("calls") or []:
            call = Call(service, str(c.get("interface", "")), str(c.get("method", "")), str(c.get("path", "")))
            if not (_BUS_NAME_RE.fullmatch(call.interface) and _MEMBER_RE.fullmatch(call.method)
                    and _PATH_RE.fullmatch(call.path)):
                raise SandboxError(f"permission {name}: bad call {c!r}")
            calls.append(call)
        if not calls:
            raise SandboxError(f"permission {name} grants no call")
        out[name] = Permission(name, str(p.get("description") or ""), tuple(calls), provider)
    return out


def merge_catalogs(catalogs: Iterable[dict[str, Permission]]) -> dict[str, Permission]:
    out: dict[str, Permission] = {}
    for cat in catalogs:
        for name, perm in cat.items():
            if name in out and out[name] != perm:
                raise SandboxError(f"permission {name} is declared by both {out[name].provider} and {perm.provider}")
            out[name] = perm
    return out


@dataclass(frozen=True)
class App:
    """One sandboxed app as the image gets it."""

    package: str
    version: str
    slot: int
    grants: tuple[str, ...] = ()
    memory_mb: int = DEFAULT_LIMITS["memory_mb"]
    cpus: float = DEFAULT_LIMITS["cpus"]
    tasks: int = DEFAULT_LIMITS["tasks"]

    @property
    def name(self) -> str:
        return unit_name(self.package)

    @property
    def uid(self) -> int:
        return uid_base(self.slot)

    @property
    def user(self) -> str:
        return f"vnapp{self.slot}"

    def check(self) -> None:
        unit_name(self.package)
        uid_base(self.slot)
        for key in ("memory_mb", "cpus", "tasks"):
            lo, hi = LIMITS[key]
            if not lo <= getattr(self, key) <= hi:
                raise SandboxError(f"{self.package}: {key} {getattr(self, key)} outside {lo}..{hi}")


@dataclass
class Rendered:
    files: dict[str, tuple[bytes, int]] = field(default_factory=dict)
    apps: list[dict] = field(default_factory=list)

    def add(self, path: str, text: str, mode: int = 0o644) -> None:
        self.files[path.lstrip("/")] = (text.encode("utf-8"), mode)


def proxy_rules(app: App, permissions: dict[str, Permission]) -> list[str]:
    rules = []
    for g in app.grants:
        perm = permissions.get(g)
        if perm is None:
            raise SandboxError(f"{app.package}: permission {g} is not declared by any system package in the image")
        rules += [c.proxy_rule() for c in perm.calls]
    return sorted(set(rules))


def container_unit(app: App) -> str:
    n = app.name
    return f"""# Sandboxed app {app.package} {app.version}: written by OTP_Provisioner (otp_server/sandbox.py).
[Unit]
Description=Sandboxed app {app.package} {app.version}
Requires={n}-bus.service
After={n}-bus.service

[Container]
ContainerName={n}
Rootfs={APPS_DIR}/{n}/rootfs
Exec=/sbin/init
HostName={host_name(app.package)}
# Container IDs 0..65535 are host IDs {app.uid}..{app.uid + RANGE - 1}: root in there is nobody here.
UIDMap=0:{app.uid}:{RANGE}
GIDMap=0:{app.uid}:{RANGE}
Network=none
# Holds in the app's own user namespace only: systemd in there sandboxes the package's services.
AddCapability=CAP_SYS_ADMIN
Volume={RUN_DIR}/{n}/bus:/run/dbus:ro
PodmanArgs=--systemd=always --security-opt=apparmor={n}

[Service]
# vnapps, not vn-apps: a dash in a slice name means a parent slice (vn.slice).
Slice=vnapps.slice
MemoryMax={app.memory_mb}M
CPUQuota={round(app.cpus * 100)}%
TasksMax={app.tasks}
Restart=on-failure
RestartSec=10
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
"""


def proxy_unit(app: App, rules: list[str]) -> str:
    n = app.name
    sock = f"{RUN_DIR}/{n}/bus/system_bus_socket"
    args = " \\\n    ".join(["/usr/bin/xdg-dbus-proxy", "unix:path=/run/dbus/system_bus_socket", sock, "--filter",
                             *rules])
    return f"""# The system bus as sandboxed app {app.package} sees it: written by OTP_Provisioner (otp_server/sandbox.py).
# It runs as the app's base UID, so services on the bus tell the app apart by the caller's UID.
[Unit]
Description=D-Bus proxy of sandboxed app {app.package}
Requires=dbus.socket
After=dbus.socket
PartOf={n}.service

[Service]
User={app.user}
Group={app.user}
SupplementaryGroups={GROUP}
RuntimeDirectory=vn-apps/{n}
RuntimeDirectoryMode=0700
ExecStartPre=/usr/bin/install -d -m 0755 {RUN_DIR}/{n}/bus
# The socket must be connectable by every user of the container (all of them are this app).
UMask=0000
ExecStart={args}
ExecStartPost=/bin/sh -c 'for i in $(seq 100); do [ -S {sock} ] && exit 0; sleep 0.1; done; exit 1'
Restart=on-failure
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
"""


def apparmor_profile(app: App) -> str:
    n = app.name
    return f"""# AppArmor profile of sandboxed app {app.package}: written by OTP_Provisioner (otp_server/sandbox.py).
# podman's containers-default, plus what systemd in the container needs to sandbox its own services (mount,
# pivot_root, user namespaces: all owned by the app's user namespace), minus IP and packet networking.
abi <abi/4.0>,
include <tunables/global>

profile {n} flags=(attach_disconnected,mediate_deleted) {{
  capability,
  file,
  mount,
  umount,
  pivot_root,
  userns,
  network unix,
  network netlink,
  deny network inet,
  deny network inet6,
  deny network packet,
  unix,
  dbus,

  signal (receive) peer=unconfined,
  signal (send,receive) peer={n},
  signal (receive) peer={{/usr/bin/,/usr/sbin/,}}runc,
  signal (receive) peer={{/usr/bin/,/usr/sbin/,}}crun*,
  signal (receive) peer={{/usr/bin/,/usr/sbin/,}}podman,
  ptrace (trace,read,readby,tracedby) peer={n},

  deny @{{PROC}}/* w,
  deny @{{PROC}}/{{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}}/** w,
  deny @{{PROC}}/sys/[^k]** w,
  deny @{{PROC}}/sys/kernel/{{?,??,[^s][^h][^m]**}} w,
  deny @{{PROC}}/sysrq-trigger rwklx,
  deny @{{PROC}}/kcore rwklx,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,
  deny /dev/vcio rwklx,
}}
"""


def sysusers(app: App) -> str:
    return (f"# Sandboxed app {app.package}: its base UID (container root) on the host.\n"
            f"g {app.user} {app.uid}\n"
            f"u {app.user} {app.uid}:{app.uid} \"Sandboxed app {app.package}\" /nonexistent /usr/sbin/nologin\n"
            f"m {app.user} {GROUP}\n")


COMMON_SYSUSERS = f"# Every sandboxed app's base user is a member (D-Bus policies of system services name it).\ng {GROUP} -\n"
COMMON_TMPFILES = (f"# The D-Bus proxies' sockets live below here; others may pass, not list.\n"
                   f"d {RUN_DIR} 0711 root root -\n")
SLICE = """# All sandboxed apps: written by OTP_Provisioner (otp_server/sandbox.py). Each app has its own limits on
# its unit; together they get a lower CPU weight than the system's own services.
[Unit]
Description=Sandboxed apps

[Slice]
CPUWeight=50
IOWeight=50
"""


def render(apps: list[App], permissions: dict[str, Permission]) -> Rendered:
    """The files of every app's sandbox, plus the registry. SandboxError when two apps clash or a grant names
    a permission no system package of the image declares."""
    out = Rendered()
    seen_pkg: dict[str, App] = {}
    seen_slot: dict[int, App] = {}
    registry = []
    for app in sorted(apps, key=lambda a: a.slot):
        app.check()
        if app.package in seen_pkg:
            raise SandboxError(f"{app.package} is in the image twice")
        if app.slot in seen_slot:
            raise SandboxError(f"{app.package} and {seen_slot[app.slot].package} have the same slot {app.slot}")
        seen_pkg[app.package] = seen_slot[app.slot] = app
        n = app.name
        rules = proxy_rules(app, permissions)
        out.add(f"etc/containers/systemd/{n}.container", container_unit(app))
        out.add(f"etc/systemd/system/{n}-bus.service", proxy_unit(app, rules))
        out.add(f"etc/apparmor.d/{n}", apparmor_profile(app))
        out.add(f"usr/lib/sysusers.d/{n}.conf", sysusers(app))
        entry = {"id": app.package, "version": app.version, "unit": f"{n}.service", "uid": app.uid,
                 "uids": [app.uid, app.uid + RANGE - 1], "permissions": sorted(app.grants)}
        registry.append(entry)
        out.apps.append({**entry, "name": n, "slot": app.slot, "proxy": rules,
                         "limits": {"memory_mb": app.memory_mb, "cpus": app.cpus, "tasks": app.tasks}})
    if apps:
        out.add("usr/lib/sysusers.d/vn-apps.conf", COMMON_SYSUSERS)
        out.add("usr/lib/tmpfiles.d/vn-apps.conf", COMMON_TMPFILES)
        out.add("etc/systemd/system/vnapps.slice", SLICE)
        out.add(REGISTRY, json.dumps({"version": 1, "apps": registry}, indent=2) + "\n")
    return out


__all__ = ["App", "BASE", "Call", "CATALOG_DIR", "DEFAULT_LIMITS", "LIMITS", "MAX_SLOT", "Permission", "RANGE",
           "Rendered", "SandboxError", "merge_catalogs", "parse_catalog", "render", "uid_base", "unit_name"]
