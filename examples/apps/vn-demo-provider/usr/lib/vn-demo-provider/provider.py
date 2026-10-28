#!/usr/bin/python3
"""vn-demo-provider: the trusted half of the sandboxed-app demo (a system package, runs on the host).

It stands in for camhub + targeting: it owns the data and the decisions. It renders a synthetic camera
(a bright blob moving over a grey gradient) into a frame ring in shared memory, and takes detections over
D-Bus from sandboxed apps, scoring each one against the blob's true position.

The shared memory is a sealed memfd, never a path: GetFrameHandle returns a read-only file descriptor, so
an app can map the frames but never write them, and needs no /dev/shm of the host. Three walls: the
descriptor is opened O_RDONLY; the memfd is mode 0444 (a memfd starts as 0777, so anyone holding a
descriptor could re-open it for writing through /proc/self/fd); F_SEAL_FUTURE_WRITE refuses writes and
writable mappings even then. The ring is camhub's seqlock ring in miniature:

    header (64 bytes, little-endian): magic "VNDEMO1\\0", version u32, width u32, height u32, slots u32,
        slot_stride u32, data_offset u32, published u64 (frames written; the newest is published-1)
    slot n at data_offset + n * slot_stride: seq u64 (odd while being written), frame u64,
        stamp_us u64 (CLOCK_MONOTONIC), reserved u64, then width * height grey pixels

Every caller is told apart by its UID (GetConnectionUnixUser). A sandboxed app reaches the bus only
through its own xdg-dbus-proxy, which runs as the app's base UID; /etc/vn-apps/registry.json (written by
the station when it builds the image) maps that UID to the app and the permissions the operator granted.
The proxy already lets through only the granted calls; the check here is the second wall.
"""
import fcntl
import json
import math
import mmap
import os
import struct
import sys
import time

from gi.repository import Gio, GLib

BUS_NAME = "io.github.DetectInt.Demo"
OBJECT_PATH = "/io/github/DetectInt/Demo"
INTERFACE = "io.github.DetectInt.Demo1"
REGISTRY = "/etc/vn-apps/registry.json"
#: What each method needs (the permission catalog this package installs says the same).
PERMISSIONS = {"GetFrameHandle": "demo.frames.read", "ReportDetection": "demo.detections.report"}

WIDTH, HEIGHT, SLOTS, FPS = 320, 240, 4, 30
BLOB = 21                                   # blob side in pixels (odd: it has a centre pixel)
MAGIC = b"VNDEMO1\0"
VERSION = 1
HEADER = struct.Struct("<8sIIIIIIQ")       # magic, version, width, height, slots, stride, offset, published
HEADER_SIZE = 64
SLOT = struct.Struct("<QQQQ")              # seq, frame, stamp_us, reserved
SLOT_HEADER = 32
STRIDE = (SLOT_HEADER + WIDTH * HEIGHT + 63) // 64 * 64
SIZE = HEADER_SIZE + SLOTS * STRIDE
PUBLISHED_AT = 32
F_SEAL_FUTURE_WRITE = getattr(fcntl, "F_SEAL_FUTURE_WRITE", 0x0010)
MAX_REPORTS_PER_S = 20
SUMMARY_EVERY_S = 5.0

XML = f"""<node>
  <interface name="{INTERFACE}">
    <method name="GetFrameHandle">
      <arg name="frames" type="h" direction="out"/>
    </method>
    <method name="ReportDetection">
      <arg name="frame" type="t" direction="in"/>
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
      <arg name="score" type="d" direction="in"/>
      <arg name="accepted" type="b" direction="out"/>
    </method>
    <property name="Width" type="u" access="read"/>
    <property name="Height" type="u" access="read"/>
    <property name="Published" type="t" access="read"/>
  </interface>
</node>"""


def log(msg):
    print(msg, flush=True)


class Registry:
    """UID -> {"id", "permissions"} from the station's registry, re-read when the file changes."""

    def __init__(self, path):
        self.path = path
        self.stamp = None
        self.apps = {}

    def lookup(self, uid):
        try:
            st = os.stat(self.path)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            stamp = None
        if stamp != self.stamp:
            self.stamp = stamp
            self.apps = {}
            if stamp is not None:
                try:
                    with open(self.path, encoding="utf-8") as f:
                        for app in json.load(f).get("apps", []):
                            self.apps[int(app["uid"])] = {"id": str(app["id"]),
                                                          "permissions": set(app.get("permissions", []))}
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    log(f"registry {self.path} unreadable: {exc}")
            log(f"registry: {len(self.apps)} app(s)")
        return self.apps.get(uid)


class Ring:
    """The frame ring in a sealed memfd, and the synthetic camera that fills it."""

    def __init__(self):
        self.fd = os.memfd_create("vn-demo-frames", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.ftruncate(self.fd, SIZE)
        os.fchmod(self.fd, 0o444)
        self.mm = mmap.mmap(self.fd, SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        # Our mapping stays writable; nothing can map it writable again, resize it or lift the seals.
        fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | F_SEAL_FUTURE_WRITE | fcntl.F_SEAL_SEAL)
        self.mm[0:HEADER.size] = HEADER.pack(MAGIC, VERSION, WIDTH, HEIGHT, SLOTS, STRIDE, HEADER_SIZE, 0)
        self.background = bytes(40 + (x * 120) // WIDTH for _y in range(HEIGHT) for x in range(WIDTH))
        self.published = 0
        self.truth = {}                         # frame -> (x, y) of the blob centre, the last few seconds
        self.t0 = time.monotonic()

    def readonly_fd(self):
        """A new read-only descriptor of the ring (the caller closes it)."""
        return os.open(f"/proc/self/fd/{self.fd}", os.O_RDONLY | os.O_CLOEXEC)

    def position(self, t):
        half = BLOB // 2
        x = WIDTH / 2 + (WIDTH / 2 - half - 4) * math.sin(t * 0.9)
        y = HEIGHT / 2 + (HEIGHT / 2 - half - 4) * math.sin(t * 1.3 + 0.5)
        return int(round(x)), int(round(y))

    def publish(self):
        frame = self.published + 1
        slot = HEADER_SIZE + (frame % SLOTS) * STRIDE
        seq = struct.unpack_from("<Q", self.mm, slot)[0]
        struct.pack_into("<Q", self.mm, slot, seq + 1)                  # odd: being written
        px = slot + SLOT_HEADER
        self.mm[px:px + WIDTH * HEIGHT] = self.background
        cx, cy = self.position(time.monotonic() - self.t0)
        half = BLOB // 2
        row = b"\xff" * BLOB
        for y in range(cy - half, cy + half + 1):
            off = px + y * WIDTH + cx - half
            self.mm[off:off + BLOB] = row
        struct.pack_into("<QQ", self.mm, slot + 8, frame, time.monotonic_ns() // 1000)
        struct.pack_into("<Q", self.mm, slot, seq + 2)                  # even: stable
        struct.pack_into("<Q", self.mm, PUBLISHED_AT, frame)
        self.published = frame
        self.truth[frame] = (cx, cy)
        self.truth.pop(frame - FPS * 10, None)
        return True


class Service:
    def __init__(self, conn):
        self.conn = conn
        self.ring = Ring()
        self.registry = Registry(REGISTRY)
        self.uids = {}                          # unique bus name -> UID (names are never reused)
        self.stats = {}                         # app id -> counters since the last summary
        node = Gio.DBusNodeInfo.new_for_xml(XML)
        conn.register_object(OBJECT_PATH, node.interfaces[0], self.on_call, self.on_get_property, None)
        GLib.timeout_add(1000 // FPS, self.ring.publish)
        GLib.timeout_add(int(SUMMARY_EVERY_S * 1000), self.summary)

    def caller(self, sender):
        uid = self.uids.get(sender)
        if uid is None:
            reply = self.conn.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                                        "GetConnectionUnixUser", GLib.Variant("(s)", (sender,)),
                                        GLib.VariantType("(u)"), Gio.DBusCallFlags.NONE, -1, None)
            uid = reply.unpack()[0]
            if len(self.uids) > 4096:
                self.uids.clear()
            self.uids[sender] = uid
        if uid == 0:
            return uid, {"id": "root", "permissions": set(PERMISSIONS.values())}
        return uid, self.registry.lookup(uid)

    def on_call(self, conn, sender, path, iface, method, params, invocation):
        uid, app = self.caller(sender)
        need = PERMISSIONS.get(method)
        if app is None or need not in app["permissions"]:
            who = app["id"] if app else "an unknown caller"
            log(f"DENIED {method} to {who} (uid {uid}): needs {need}")
            invocation.return_dbus_error("org.freedesktop.DBus.Error.AccessDenied",
                                         f"{method} needs the permission {need}")
            return
        if method == "GetFrameHandle":
            fd = self.ring.readonly_fd()
            try:
                fds = Gio.UnixFDList.new()
                index = fds.append(fd)
            finally:
                os.close(fd)
            log(f"{app['id']} (uid {uid}): frame ring handed out read-only")
            invocation.return_value_with_unix_fd_list(GLib.Variant("(h)", (index,)), fds)
        elif method == "ReportDetection":
            frame, x, y, score = params.unpack()
            invocation.return_value(GLib.Variant("(b)", (self.report(app["id"], uid, frame, x, y, score),)))

    def report(self, app_id, uid, frame, x, y, score):
        s = self.stats.setdefault(app_id, {"uid": uid, "n": 0, "err": 0.0, "late": 0, "dropped": 0,
                                           "window": time.monotonic(), "in_window": 0, "last": None,
                                           "first": True})
        now = time.monotonic()
        if now - s["window"] >= 1.0:
            s["window"], s["in_window"] = now, 0
        s["in_window"] += 1
        if s["in_window"] > MAX_REPORTS_PER_S:
            s["dropped"] += 1
            return False
        truth = self.ring.truth.get(frame)
        if truth is None:
            s["late"] += 1
            return False
        err = math.hypot(x - truth[0], y - truth[1])
        if s["first"]:
            s["first"] = False
            log(f"{app_id} (uid {uid}): first detection: frame {frame} at ({x}, {y}), "
                f"truth ({truth[0]}, {truth[1]}), error {err:.1f} px")
        s["n"] += 1
        s["err"] += err
        s["last"] = (frame, x, y, truth, score)
        return True

    def summary(self):
        for app_id, s in self.stats.items():
            if s["n"] or s["late"] or s["dropped"]:
                frame, x, y, truth, score = s["last"] or (0, 0, 0, (0, 0), 0.0)
                log(f"{app_id} (uid {s['uid']}): {s['n']} detections in {SUMMARY_EVERY_S:.0f} s, mean error "
                    f"{s['err'] / max(s['n'], 1):.1f} px; last frame {frame} at ({x}, {y}) truth {truth} score "
                    f"{score:.2f}; {s['late']} for unknown frames, {s['dropped']} over the rate limit")
            s.update(n=0, err=0.0, late=0, dropped=0)
        return True

    def on_get_property(self, conn, sender, path, iface, name):
        if name == "Width":
            return GLib.Variant("u", WIDTH)
        if name == "Height":
            return GLib.Variant("u", HEIGHT)
        if name == "Published":
            return GLib.Variant("t", self.ring.published)
        return None


def main():
    loop = GLib.MainLoop()
    conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    service = Service(conn)            # noqa: F841 -- the bus and the timers hold on to it

    def lost(_conn, _name):
        log(f"lost the bus name {BUS_NAME}")
        loop.quit()

    Gio.bus_own_name_on_connection(conn, BUS_NAME, Gio.BusNameOwnerFlags.NONE,
                                   lambda *_: log(f"serving {BUS_NAME}: {WIDTH}x{HEIGHT} grey at {FPS} Hz, "
                                                  f"ring of {SLOTS} slots ({SIZE} bytes)"), lost)
    loop.run()
    return 1


if __name__ == "__main__":
    sys.exit(main())
