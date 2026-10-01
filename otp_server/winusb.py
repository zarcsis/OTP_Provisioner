"""Windows USB driver check (read-only).

Chrome's WebUSB can only open a device on Windows when the device is bound to the WinUSB driver.
Neither the BCM2712 boot ROM (USB ``0a5c:2712``, "RPIBOOT") nor the pi-gen-micro fastboot gadget
(``18d1:4e40``) provides Microsoft OS descriptors, so Windows binds WinUSB only when a driver
package for those hardware ids is installed in the driver store.

The official Raspberry Pi ``rpiboot_setup.exe`` (usbboot releases) installs ``rpiboot-winusb.inf``,
which binds WinUSB to both ids. This module scans the installed third-party driver packages
(``C:\\Windows\\INF\\oem*.inf``) for those ids and reports what it found; it never changes anything.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path

RPIBOOT_HWID = r"USB\VID_0A5C&PID_2712"
FASTBOOT_HWID = r"USB\VID_18D1&PID_4E40"

INSTALL_HINT = (
    "Install the official Raspberry Pi rpiboot_setup.exe (https://github.com/raspberrypi/usbboot/releases) "
    "as administrator: its rpiboot-winusb.inf binds WinUSB to both 0a5c:2712 (RPIBOOT) and 18d1:4e40 "
    "(fastboot gadget). Then unplug and replug the board and reload this page."
)

_cache_lock = threading.Lock()
_cache: tuple[float, str, dict] | None = None

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def default_inf_dir() -> Path:
    """``%SystemRoot%\\INF`` (the directory holding the installed ``oem*.inf`` driver packages)."""
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return Path(root) / "INF"


def _read_inf(path: Path) -> str:
    """INF files are UTF-16 (with BOM) or 8-bit text; decode either."""
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if len(data) >= 2 and data[1:2] == b"\x00" and data[0:1] != b"\x00":
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def _sections(text: str) -> dict[str, list[str]]:
    """Map lower-case section name -> its lines (comments stripped)."""
    out: dict[str, list[str]] = {}
    cur = ""
    out[cur] = []
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        m = _SECTION_RE.match(line)
        if m:
            cur = m.group(1).strip().lower()
            out.setdefault(cur, [])
            continue
        if line.strip():
            out.setdefault(cur, []).append(line.strip())
    return out


def _section_uses_winusb(sections: dict[str, list[str]], name: str) -> bool:
    """True when install section ``name`` (or its decorated/.Services variants) pulls in WinUSB."""
    name = name.strip().lower()
    for sec, lines in sections.items():
        if sec != name and not sec.startswith(name + "."):
            continue
        for line in lines:
            key, _, value = line.partition("=")
            k = key.strip().lower()
            v = value.strip().lower()
            if k == "include" and "winusb.inf" in v:
                return True
            if k == "needs" and "winusb" in v:
                return True
            if k == "addservice" and v.split(",", 1)[0].strip().strip('"') == "winusb":
                return True
    return False


def inf_binds_winusb(text: str, hwid: str) -> bool:
    """True when the INF ``text`` has a model line for ``hwid`` whose install section uses WinUSB.

    ``hwid`` is matched case-insensitively and also as a prefix of a longer id (``...&REV_0100``,
    ``...&MI_00``). If the install section cannot be resolved, a file that mentions WinUSB at all is
    accepted (Zadig/wdi and Raspberry Pi packages always do).
    """
    want = hwid.lower()
    sections = _sections(text)
    found_line = False
    for lines in sections.values():
        for line in lines:
            lower = line.lower()
            if want not in lower or "=" not in line:
                continue
            ids = [x.strip().strip('"').lower() for x in line.partition("=")[2].split(",")]
            if not any(i == want or i.startswith(want + "&") for i in ids[1:]):
                continue
            found_line = True
            install = line.partition("=")[2].split(",", 1)[0].strip()
            if install and _section_uses_winusb(sections, install):
                return True
    return found_line and "winusb" in text.lower()


def scan(inf_dir: Path | None = None) -> dict:
    """Scan ``oem*.inf`` in ``inf_dir`` and build the ``usb_driver`` status object (SPEC section 8).

    :returns: ``{"platform": "windows", "rpiboot": bool, "fastboot": bool, "detail": str}``
    """
    d = Path(inf_dir) if inf_dir is not None else default_inf_dir()
    rpiboot: list[str] = []
    fastboot: list[str] = []
    error = ""
    try:
        files = sorted(d.glob("oem*.inf"), key=lambda p: p.name.lower())
    except OSError as exc:
        files = []
        error = f"cannot read {d}: {exc}"
    for p in files:
        try:
            text = _read_inf(p)
        except OSError:
            continue
        if "vid_0a5c" not in text.lower() and "vid_18d1" not in text.lower():
            continue
        if inf_binds_winusb(text, RPIBOOT_HWID):
            rpiboot.append(p.name)
        if inf_binds_winusb(text, FASTBOOT_HWID):
            fastboot.append(p.name)

    ok_r, ok_f = bool(rpiboot), bool(fastboot)
    if ok_r and ok_f:
        names = sorted(set(rpiboot) | set(fastboot))
        detail = (f"WinUSB driver package installed for 0a5c:2712 (RPIBOOT) and 18d1:4e40 (fastboot gadget): "
                  f"{', '.join(names)}")
    else:
        missing = [label for ok, label in ((ok_r, "0a5c:2712 (RPIBOOT)"), (ok_f, "18d1:4e40 (fastboot gadget)"))
                   if not ok]
        present = []
        if ok_r:
            present.append(f"0a5c:2712 in {', '.join(rpiboot)}")
        if ok_f:
            present.append(f"18d1:4e40 in {', '.join(fastboot)}")
        detail = f"No WinUSB driver package for {' and '.join(missing)}, so Chrome cannot open it. "
        if present:
            detail += f"Found: {'; '.join(present)}. "
        detail += INSTALL_HINT
    if error:
        detail = f"{error}. {detail}"
    return {"platform": "windows", "rpiboot": ok_r, "fastboot": ok_f, "detail": detail}


def check_usb_driver(inf_dir: Path | None = None, *, max_age: float = 30.0, force_platform: bool = False) -> dict | None:
    """The ``usb_driver`` object of ``/api/status``; ``None`` on non-Windows hosts.

    The result is cached for ``max_age`` seconds (the page polls the status every few seconds).
    ``force_platform`` runs the scan on any OS (tests).
    """
    global _cache
    if sys.platform != "win32" and not force_platform:
        return None
    key = str(inf_dir) if inf_dir is not None else ""
    with _cache_lock:
        if _cache is not None and _cache[1] == key and time.monotonic() - _cache[0] < max_age:
            return dict(_cache[2])
    result = scan(inf_dir)
    with _cache_lock:
        _cache = (time.monotonic(), key, dict(result))
    return result


__all__ = ["RPIBOOT_HWID", "FASTBOOT_HWID", "INSTALL_HINT", "check_usb_driver", "scan", "inf_binds_winusb"]
