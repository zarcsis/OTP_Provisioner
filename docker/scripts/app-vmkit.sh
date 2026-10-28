#!/bin/bash
# app-vmkit.sh - the kernel and initramfs of the VM in which the station installs sandboxed apps.
#
# The VM (app-install.sh) boots Debian trixie's own arm64 kernel. That kernel builds virtio-pci in but
# virtio_blk and ext4 as modules, so the initramfs carries them (and their dependencies, read from each
# module's .modinfo since a kernel package ships no modules.dep), busybox-static, and app-vm-init as /init.
# Both packages come from deb.debian.org through apt, which checks their signatures; nothing from them runs
# here (dpkg-deb -x only).
#
# Mounts:  /out     rw  the kit directory being built
#          /scripts ro  docker/scripts (app-vm-init)
# Needs:   network. No privileges.
# Outputs: /out/vmlinuz, /out/initrd.img (gzip newc cpio), /out/vmkit.json:
#          {"kernel": "<package>", "kernel_version": "<uname -r>", "busybox": "<version>", "modules": [...]}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

OUT="${OUT:-/out}"
SCRIPTS="${SCRIPTS:-/scripts}"
#: What the VM needs from its kernel's modules: the disk, its file system, ext4's checksums.
WANT_MODULES="virtio_blk ext4 crc32c_generic libcrc32c"

[ -d "$OUT" ] || die "$OUT is not mounted"
[ -f "$SCRIPTS/app-vm-init" ] || die "$SCRIPTS/app-vm-init is missing"
work=$(mktemp -d /tmp/vmkit.XXXXXX)
chmod 0755 "$work"                  # apt-get download drops privileges to _apt
trap 'rm -rf "$work"' EXIT

step "apt: Debian trixie arm64 package lists"
dpkg --add-architecture arm64
apt-get update -qq
kpkg=$(apt-cache depends linux-image-arm64:arm64 \
       | sed -n 's/^ *Depends: \(linux-image-[0-9][^ :]*\).*/\1/p' | head -n1)
[ -n "$kpkg" ] || die "no kernel package behind linux-image-arm64"
step "downloading $kpkg and busybox-static (arm64)"
(cd "$work" && apt-get download -q "$kpkg:arm64" busybox-static:arm64)
kdeb=$(ls "$work"/linux-image-*_arm64.deb)
bdeb=$(ls "$work"/busybox-static_*_arm64.deb)
dpkg-deb -x "$kdeb" "$work/k"
dpkg-deb -x "$bdeb" "$work/bb"

kver=$(ls "$work/k/usr/lib/modules")
[ "$(echo "$kver" | wc -l)" = 1 ] || die "the kernel package holds more than one module tree: $kver"
moddir="$work/k/usr/lib/modules/$kver"
vmlinuz="$work/k/boot/vmlinuz-$kver"
[ -f "$vmlinuz" ] || die "no /boot/vmlinuz-$kver in $kpkg"
busybox=$(find "$work/bb" -type f -name busybox | head -n1)
[ -n "$busybox" ] || die "no busybox binary in busybox-static"

# Every wanted module and, before it, what it depends on.
declare -A done_mod=()
order=()
modfile() { find "$moddir/kernel" -name "$1.ko*" | head -n1; }
add_module() {
    local m=$1 f dep
    [ -n "${done_mod[$m]:-}" ] && return 0
    f=$(modfile "$m")
    [ -n "$f" ] || die "kernel $kver has no module $m"
    done_mod[$m]=1
    for dep in $(modinfo -F depends "$f" | tr ',' ' '); do
        add_module "$dep"
    done
    order+=("$m")
}
for m in $WANT_MODULES; do add_module "$m"; done
step "modules, in load order: ${order[*]}"

root="$work/initramfs"
mkdir -p "$root/bin" "$root/lib/modules" "$root/proc" "$root/sys" "$root/dev" "$root/target"
install -m 0755 "$busybox" "$root/bin/busybox"
sed 's/\r$//' "$SCRIPTS/app-vm-init" > "$root/init"
chmod 0755 "$root/init"
: > "$root/modules.order"
for m in "${order[@]}"; do
    f=$(modfile "$m")
    case "$f" in
        *.ko.xz)  xz -dc "$f" > "$root/lib/modules/$m.ko" ;;
        *.ko.zst) zstd -qdc "$f" > "$root/lib/modules/$m.ko" ;;
        *.ko.gz)  gzip -dc "$f" > "$root/lib/modules/$m.ko" ;;
        *.ko)     cp "$f" "$root/lib/modules/$m.ko" ;;
        *)        die "unexpected module file $f" ;;
    esac
    echo "$m" >> "$root/modules.order"
done

step "packing the initramfs"
(cd "$root" && find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc -R 0:0 --quiet) | gzip -9n > "$OUT/initrd.img"
install -m 0644 "$vmlinuz" "$OUT/vmlinuz"
bbver=$(dpkg-deb -f "$bdeb" Version)
printf '%s\n' "${order[@]}" | jq -R . | jq -s \
    --arg kernel "$kpkg" --arg kver "$kver" --arg bb "$bbver" \
    '{kernel: $kernel, kernel_version: $kver, busybox: $bb, modules: .}' > "$OUT/vmkit.json"

[ -s "$OUT/vmlinuz" ] && [ -s "$OUT/initrd.img" ] || die "the kit is incomplete"
gzip -t "$OUT/initrd.img" || die "initrd.img is not a valid gzip file"
step "kit ready: $(jq -c . "$OUT/vmkit.json")"
