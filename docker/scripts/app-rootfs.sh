#!/bin/bash
# app-rootfs.sh - the root file system a sandboxed app is installed into, as the installer VM's disk.
#
# Debian trixie arm64, minbase plus systemd (the container's init), and the app's dependencies taken from
# its own Depends/Pre-Depends with "apt-get satisfy" from Debian. Only Debian's packages are installed here,
# under qemu-user in an arm64 chroot; the app's own .debs are only copied in (/vn-install), they are
# installed in the VM (app-install.sh). The result is an ext4 image made from the tarball with mke2fs -d
# (no loop device), with room for the app.
#
# Mounts:  /in      ro  the app's .debs (*.deb)
#          /out     rw  the work directory: root.img, rootfs.json
# Env:     DEPENDS   the dependency expression of the app (Pre-Depends, then Depends; may be empty)
#          FREE_MB   free space in the image for the app (1024)
# Needs:   --privileged (mmdebstrap mounts proc/sys/dev in the chroot), the arm64 binfmt handler, network.
# Outputs: /out/root.img, /out/rootfs.json {"suite", "packages": {name: version}, "depends", "bytes"}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

IN="${IN:-/in}"
OUT="${OUT:-/out}"
DEPENDS="${DEPENDS:-}"
FREE_MB="${FREE_MB:-1024}"
SUITE=trixie
#: The container's base: what every app gets. systemd-sysv is /sbin/init.
BASE_PACKAGES="systemd,systemd-sysv"

[ -d "$OUT" ] || die "$OUT is not mounted"
ls "$IN"/*.deb >/dev/null 2>&1 || die "no .deb in $IN"
case "$FREE_MB" in ''|*[!0-9]*) die "FREE_MB must be a number of MiB" ;; esac
export DEPENDS
work=$(mktemp -d /tmp/rootfs.XXXXXX)
trap 'rm -rf "$work"' EXIT

step "mmdebstrap: Debian $SUITE arm64, minbase + $BASE_PACKAGES"
[ -n "$DEPENDS" ] && step "the app's dependencies: $DEPENDS"
mmdebstrap --arch=arm64 --variant=minbase --include="$BASE_PACKAGES" \
    --aptopt='APT::Install-Recommends "false"' \
    --customize-hook='if [ -n "$DEPENDS" ]; then chroot "$1" apt-get satisfy -y --no-install-recommends "$DEPENDS"; fi' \
    --customize-hook='chroot "$1" dpkg-query -W -f "\${Package}\t\${Version}\n" > "'"$work"'/packages.tsv"' \
    --customize-hook='rm -rf "$1"/var/lib/apt/lists/* "$1"/var/cache/apt/*.bin "$1"/var/cache/apt/archives/*.deb' \
    --customize-hook='rm -f "$1"/etc/apt/apt.conf.d/99mmdebstrap "$1"/etc/dpkg/dpkg.cfg.d/99mmdebstrap' \
    --customize-hook='printf "uninitialized\n" > "$1"/etc/machine-id; : > "$1"/etc/resolv.conf' \
    "$SUITE" "$work/rootfs.tar" \
    "deb http://deb.debian.org/debian $SUITE main" \
    "deb http://deb.debian.org/debian $SUITE-updates main" \
    "deb http://security.debian.org/debian-security $SUITE-security main"

step "adding the app's packages under /vn-install"
mkdir -p "$work/stage/vn-install"
cp "$IN"/*.deb "$work/stage/vn-install/"
tar --owner=0 --group=0 --numeric-owner -C "$work/stage" -rf "$work/rootfs.tar" ./vn-install

bytes=$(stat -c %s "$work/rootfs.tar")
size_mb=$(( bytes * 3 / 2 / 1048576 + FREE_MB ))
step "ext4 image of ${size_mb} MiB"
rm -f "$OUT/root.img"
mke2fs -q -t ext4 -L vnroot -d "$work/rootfs.tar" "$OUT/root.img" "${size_mb}M"
e2fsck -fn "$OUT/root.img" >/dev/null || die "the new root file system does not check clean"

jq -R 'split("\t") | {(.[0]): .[1]}' "$work/packages.tsv" | jq -s 'add' > "$work/packages.json"
jq -n --arg suite "$SUITE" --arg depends "$DEPENDS" --argjson bytes "$bytes" \
    --slurpfile packages "$work/packages.json" \
    '{suite: $suite, depends: $depends, bytes: $bytes, packages: $packages[0]}' > "$OUT/rootfs.json"
step "root file system ready: $(jq '.packages | length' "$OUT/rootfs.json") packages"
