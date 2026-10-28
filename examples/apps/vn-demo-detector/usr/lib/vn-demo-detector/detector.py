#!/usr/bin/python3
"""vn-demo-detector: the untrusted half of the sandboxed-app demo (a third-party app in its own container).

It stands in for a partner's detector: it reads frames from the trusted provider (io.github.DetectInt.Demo)
through the read-only shared memory handle it gets over D-Bus, finds the bright blob in them and reports
where it is, five times a second. It knows nothing about the sandbox: it uses the system bus at the usual
address and is an ordinary Debian package with a systemd unit.

``--probe`` instead checks what its sandbox lets through and prints one line per check: PASS when the sandbox
stopped it, FAIL when it went through, INFO for what is allowed only inside the app's own namespaces (systemd
in the container needs to mount and to make namespaces for the services it sandboxes).
vn-demo-detector-probe.service runs it once at start as root inside the container (root there is an
unprivileged UID on the host).
"""
import errno
import mmap
import os
import socket
import struct
import sys
import time
import warnings

from gi.repository import Gio, GLib

BUS_NAME = "io.github.DetectInt.Demo"
OBJECT_PATH = "/io/github/DetectInt/Demo"
INTERFACE = "io.github.DetectInt.Demo1"
MAGIC = b"VNDEMO1\0"
HEADER = struct.Struct("<8sIIIIIIQ")
SLOT_HEADER = 32
RATE_HZ = 5


def log(msg):
    print(msg, flush=True)


def frame_handle(conn):
    """(fd, size) of the provider's frame ring."""
    reply, fds = conn.call_with_unix_fd_list_sync(BUS_NAME, OBJECT_PATH, INTERFACE, "GetFrameHandle", None,
                                                  GLib.VariantType("(h)"), Gio.DBusCallFlags.NONE, -1, None,
                                                  None)
    fd = fds.get(reply.unpack()[0])
    return fd, os.fstat(fd).st_size


class Frames:
    def __init__(self, fd, size):
        self.mm = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ)
        magic, version, self.w, self.h, self.slots, self.stride, self.offset, _ = HEADER.unpack_from(self.mm, 0)
        if magic != MAGIC or version != 1:
            raise RuntimeError(f"not a frame ring this detector knows: {magic!r} version {version}")

    def latest(self):
        """(frame number, pixels) of the newest stable frame, or None."""
        for _ in range(5):
            published = struct.unpack_from("<Q", self.mm, 32)[0]
            if not published:
                return None
            slot = self.offset + (published % self.slots) * self.stride
            seq1, frame = struct.unpack_from("<QQ", self.mm, slot)
            if seq1 & 1:
                continue
            px = self.mm[slot + SLOT_HEADER:slot + SLOT_HEADER + self.w * self.h]
            seq2 = struct.unpack_from("<Q", self.mm, slot)[0]
            if seq1 == seq2:
                return frame, px
        return None


def find_blob(px, w, h):
    """Centre of the 255-valued pixels: (x, y, share of the frame they cover), or None."""
    xs = ys = n = 0
    for y in range(h):
        row = px[y * w:(y + 1) * w]
        first = row.find(255)
        if first < 0:
            continue
        last = row.rfind(255)
        count = last - first + 1
        xs += (first + last) / 2 * count
        ys += y * count
        n += count
    if not n:
        return None
    return round(xs / n), round(ys / n), n / (w * h)


def run():
    conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    fd, size = frame_handle(conn)
    frames = Frames(fd, size)
    os.close(fd)
    log(f"frame ring: {frames.w}x{frames.h}, {frames.slots} slots, {size} bytes, mapped read-only")
    last = 0
    while True:
        got = frames.latest()
        if got and got[0] != last:
            frame, px = got
            last = frame
            blob = find_blob(px, frames.w, frames.h)
            if blob:
                x, y, share = blob
                conn.call_sync(BUS_NAME, OBJECT_PATH, INTERFACE, "ReportDetection",
                               GLib.Variant("(tiid)", (frame, x, y, min(1.0, share * 100))),
                               GLib.VariantType("(b)"), Gio.DBusCallFlags.NONE, 2000, None)
        time.sleep(1 / RATE_HZ)


# ---------------------------------------------------------------------------------------------- probes
def _expect_error(what, fn, *errnos):
    try:
        fn()
    except OSError as exc:
        if not errnos or exc.errno in errnos:
            return "PASS", f"{what}: {errno.errorcode.get(exc.errno, exc.errno)}"
        return "PASS", f"{what}: {exc}"
    except GLib.Error as exc:
        return "PASS", f"{what}: {exc.message}"
    return "FAIL", f"{what}: it worked"


def _inside_only(what, fn):
    """Something the app may do in its own namespaces only: INFO when it works, PASS when it does not."""
    verdict, line = _expect_error(what, fn)
    return ("INFO", f"{what}: allowed, inside its own namespaces") if verdict == "FAIL" else (verdict, line)


def probes():
    conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    fd, size = frame_handle(conn)
    out = []
    out.append(_expect_error("map the frame ring writable",
                             lambda: mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)))
    out.append(_expect_error("write to the frame ring", lambda: os.pwrite(fd, b"x", 0)))
    out.append(_expect_error("re-open the frame ring for writing", lambda: _write_reopened(fd, size)))
    names = conn.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames",
                           None, GLib.VariantType("(as)"), Gio.DBusCallFlags.NONE, -1, None).unpack()[0]
    foreign = [n for n in names if not n.startswith(":") and n not in ("org.freedesktop.DBus", BUS_NAME)]
    out.append(("FAIL" if foreign else "PASS", f"names on the bus it can see: {sorted(names)}"))
    out.append(_expect_error("call systemd on the host (org.freedesktop.systemd1 ListUnits)",
                             lambda: conn.call_sync("org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                                    "org.freedesktop.systemd1.Manager", "ListUnits", None, None,
                                                    Gio.DBusCallFlags.NONE, 3000, None)))
    out.append(_expect_error("own a name on the bus (io.github.DetectInt.Demo)",
                             lambda: _own(conn, BUS_NAME)))
    out.append(_expect_error("TCP to 1.1.1.1:53", lambda: socket.create_connection(("1.1.1.1", 53), timeout=3)))
    out.append(_expect_error("UDP to 8.8.8.8:53", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                             .sendto(b"x", ("8.8.8.8", 53))))
    out.append(_expect_error("raw socket", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW)))
    for path in ("/dev/vcio", "/dev/mem", "/dev/mmcblk0", "/dev/video0", "/dev/shm/camhub_frames",
                 "/boot/firmware/cmdline.txt", "/var/lib/vn-apps", "/run/vn-apps"):
        out.append(_expect_error(f"open {path}", lambda p=path: os.close(os.open(p, os.O_RDONLY))))
    out.append(_inside_only("mount a tmpfs", _mount_tmpfs))
    out.append(_inside_only("new user namespace", _unshare_user))
    out.append(_expect_error("load a kernel module (init_module)", lambda: _syscall_init_module()))
    visible = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
    out.append(("PASS" if len(visible) < 40 else "FAIL", f"processes it can see: {len(visible)} (its own container)"))
    out.append(_expect_error("signal PID 1 of the host (kill -0 of a host PID it cannot see: 1 is its own init)",
                             lambda: os.kill(99999, 0)))
    with open("/proc/self/uid_map") as f:
        out.append(("PASS", f"uid_map: {' '.join(f.read().split())}"))
    with open("/proc/self/status") as f:
        caps = [line.split()[1] for line in f if line.startswith("CapEff")]
    out.append(("PASS", f"capabilities (valid only in its own user namespace): {caps[0] if caps else '?'}"))
    try:
        with open("/proc/self/attr/current") as f:
            out.append(("PASS", f"AppArmor: {f.read().strip()}"))
    except OSError as exc:
        out.append(("FAIL", f"AppArmor: {exc}"))
    os.close(fd)
    count = {v: sum(1 for verdict, _ in out if verdict == v) for v in ("PASS", "INFO", "FAIL")}
    for verdict, line in out:
        log(f"probe {verdict}  {line}")
    log(f"probe summary: {count['PASS']} PASS, {count['INFO']} INFO, {count['FAIL']} FAIL")
    fails = count["FAIL"]
    return 1 if fails else 0


def _own(conn, name):
    reply = conn.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
                           GLib.Variant("(su)", (name, 4)), GLib.VariantType("(u)"), Gio.DBusCallFlags.NONE, -1,
                           None).unpack()[0]
    if reply != 1:
        raise OSError(errno.EEXIST, f"RequestName answered {reply}")


def _write_reopened(fd, size):
    """Re-open the read-only handle through /proc for writing, and write through it."""
    rw = os.open(f"/proc/self/fd/{fd}", os.O_RDWR)
    try:
        os.pwrite(rw, b"x", 0)
        mmap.mmap(rw, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE).close()
    finally:
        os.close(rw)


def _unshare_user():
    """unshare(CLONE_NEWUSER) in a child: this process has threads (GDBus), which alone makes it EINVAL."""
    with warnings.catch_warnings():         # threads (GDBus) make fork() warn; the child only calls os
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:
        try:
            os.unshare(os.CLONE_NEWUSER)
            os._exit(0)
        except OSError as exc:
            os._exit(exc.errno or 1)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code:
        raise OSError(code, os.strerror(code))


def _mount_tmpfs():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    os.makedirs("/tmp/vn-probe", exist_ok=True)
    if libc.mount(b"none", b"/tmp/vn-probe", b"tmpfs", 0, None) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    libc.umount(b"/tmp/vn-probe")


def _syscall_init_module():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    nr = {"aarch64": 105, "x86_64": 175}.get(os.uname().machine)
    if nr is None:
        raise OSError(errno.ENOSYS, "unknown architecture")
    if libc.syscall(nr, None, 0, b"") != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def main():
    if sys.argv[1:] == ["--probe"]:
        return probes()
    while True:
        try:
            run()
        except GLib.Error as exc:
            log(f"provider not reachable ({exc.message}); retrying in 5 s")
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
