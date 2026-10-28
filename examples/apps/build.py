#!/usr/bin/env python3
"""Build the demo packages of examples/apps into .deb files (any OS, standard library only).

Every directory here with a DEBIAN/control is a package tree as dpkg-deb --root-owner-group would take it:
DEBIAN/ holds the control file and the maintainer scripts, everything else is installed as it lies. The
build is reproducible (fixed mtime from SOURCE_DATE_EPOCH, sorted members, root:root) and works from a
Windows checkout: text files lose their CR line endings, and a file starting with "#!" (or a maintainer
script) gets mode 0755, every other file 0644.

    python -B examples/apps/build.py [--out DIR] [package-dir ...]

The packages go to DIR, by default <temp>/otp-example-debs (never into the repository: it has no .gitignore).
"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIST = Path(tempfile.gettempdir()) / "otp-example-debs"
MAINTAINER_SCRIPTS = {"preinst", "postinst", "prerm", "postrm", "config"}
MTIME = int(os.environ.get("SOURCE_DATE_EPOCH", "1767225600"))       # 2026-01-01


def text_or_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if b"\0" not in data:
        try:
            data.decode("utf-8")
            return data.replace(b"\r\n", b"\n")
        except UnicodeDecodeError:
            pass
    return data


def control_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line
        elif ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    return fields


def add(tar: tarfile.TarFile, name: str, data: bytes | None, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.mtime = MTIME
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mode = mode
    if data is None:
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    else:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def ar_member(name: str, data: bytes) -> bytes:
    header = (f"{name:<16}{MTIME:<12}{0:<6}{0:<6}{0o100644:<8o}{len(data):<10}`\n").encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def build(pkg: Path) -> Path:
    control_text = text_or_bytes(pkg / "DEBIAN" / "control").decode("utf-8")
    fields = control_fields(control_text)
    files: list[tuple[str, bytes | None, int]] = []
    md5 = []
    size = 0
    for path in sorted(p for p in pkg.rglob("*") if "DEBIAN" not in p.relative_to(pkg).parts[:1]):
        rel = path.relative_to(pkg).as_posix()
        if path.is_dir():
            files.append((f"./{rel}/", None, 0o755))
            continue
        data = text_or_bytes(path)
        files.append((f"./{rel}", data, 0o755 if data.startswith(b"#!") else 0o644))
        md5.append(f"{hashlib.md5(data).hexdigest()}  {rel}\n")
        size += (len(data) + 1023) // 1024
    if "Installed-Size" not in fields:
        control_text = control_text.rstrip("\n") + f"\nInstalled-Size: {max(size, 1)}\n"

    control = io.BytesIO()
    with tarfile.open(fileobj=control, mode="w:xz", format=tarfile.GNU_FORMAT) as t:
        add(t, "./", None, 0o755)
        add(t, "./control", control_text.encode("utf-8"), 0o644)
        add(t, "./md5sums", "".join(md5).encode("utf-8"), 0o644)
        for script in sorted((pkg / "DEBIAN").iterdir()):
            if script.name in MAINTAINER_SCRIPTS:
                add(t, f"./{script.name}", text_or_bytes(script), 0o755)
            elif script.name not in ("control",):
                add(t, f"./{script.name}", text_or_bytes(script), 0o644)
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:xz", format=tarfile.GNU_FORMAT) as t:
        add(t, "./", None, 0o755)
        for name, content, mode in files:
            add(t, name, content, mode)

    DIST.mkdir(exist_ok=True)
    out = DIST / f"{fields['Package']}_{fields['Version']}_{fields['Architecture']}.deb"
    out.write_bytes(b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
                    + ar_member("control.tar.xz", control.getvalue()) + ar_member("data.tar.xz", data.getvalue()))
    return out


def main(argv: list[str]) -> int:
    global DIST
    if argv[:1] == ["--out"] and len(argv) >= 2:
        DIST, argv = Path(argv[1]).resolve(), argv[2:]
    pkgs = [Path(a).resolve() for a in argv] or sorted(p for p in HERE.iterdir() if (p / "DEBIAN" / "control").is_file())
    for pkg in pkgs:
        out = build(pkg)
        print(f"{out}  sha256 {hashlib.sha256(out.read_bytes()).hexdigest()[:16]}  {out.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
