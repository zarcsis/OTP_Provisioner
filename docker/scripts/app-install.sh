#!/bin/bash
# app-install.sh - installs a sandboxed app's .debs in a throwaway arm64 VM.
#
# qemu-system-aarch64 (TCG) boots the kit of app-vmkit.sh with two disks: the root file system of
# app-rootfs.sh (written in place) and an empty one for the result. Its /init (app-vm-init) runs dpkg in a
# chroot of the first disk and writes it as a tar archive to the second. The packages' maintainer scripts
# run only inside the VM; the VM has no network and no other device, and this container has neither
# network nor privileges. The archive is checked by the station afterwards (otp_server.rootfs_tar), it is
# not trusted here.
#
# Mounts:  /kit  ro  vmlinuz, initrd.img
#          /out  rw  root.img (from app-rootfs.sh, consumed), result.img and install.json written here
# Env:     TIMEOUT   seconds the VM may run (1800)   MEMORY_MB (1536)   CPUS (2)
#          RESULT_MB the result disk (the root image's size + 512: a tar of a file system is hardly larger;
#                    the disk is written in full on a Windows host, where it does not stay sparse)
# Outputs: /out/result.img (a tar archive followed by zeros), /out/install.log (the VM's console),
#          /out/install.json {"dpkg": <status>, "tar": <status>, "seconds": <n>}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

KIT="${KIT:-/kit}"
OUT="${OUT:-/out}"
TIMEOUT="${TIMEOUT:-1800}"
MEMORY_MB="${MEMORY_MB:-1536}"
CPUS="${CPUS:-2}"
RESULT_MB="${RESULT_MB:-}"

for f in "$KIT/vmlinuz" "$KIT/initrd.img" "$OUT/root.img"; do
    [ -f "$f" ] || die "$f is missing"
done
[ -n "$RESULT_MB" ] || RESULT_MB=$(( $(stat -c %s "$OUT/root.img") / 1048576 + 512 ))
for v in TIMEOUT MEMORY_MB CPUS RESULT_MB; do
    case "${!v}" in ''|*[!0-9]*) die "$v must be a number" ;; esac
done

rm -f "$OUT/result.img" "$OUT/install.log" "$OUT/install.json"
truncate -s "${RESULT_MB}M" "$OUT/result.img"
step "booting the installer VM (${CPUS} CPUs, ${MEMORY_MB} MiB, no network, at most ${TIMEOUT} s)"
start=$(date +%s)
set +e
timeout --kill-after=30 "$TIMEOUT" qemu-system-aarch64 \
    -machine virt -cpu max -smp "$CPUS" -m "$MEMORY_MB" \
    -kernel "$KIT/vmlinuz" -initrd "$KIT/initrd.img" \
    -append "console=ttyAMA0 panic=-1 loglevel=4" \
    -drive "file=$OUT/root.img,if=virtio,format=raw,cache=unsafe" \
    -drive "file=$OUT/result.img,if=virtio,format=raw,cache=unsafe" \
    -nic none -nographic -no-reboot -monitor none -serial stdio \
    < /dev/null 2>&1 | tr -d '\r' | tee "$OUT/install.log"
qrc=${PIPESTATUS[0]}
set -e
seconds=$(( $(date +%s) - start ))
rm -f "$OUT/root.img"
[ "$qrc" = 124 ] || [ "$qrc" = 137 ] && die "the installer VM ran longer than ${TIMEOUT} s"
[ "$qrc" = 0 ] || die "qemu-system-aarch64 exited with $qrc"

line=$(grep -a '^vn-install: result ' "$OUT/install.log" | tail -n1 || true)
[ -n "$line" ] || die "the installer VM gave no result (see its console above)"
dpkg_rc=$(echo "$line" | sed -n 's/.* dpkg=\([^ ]*\).*/\1/p')
tar_rc=$(echo "$line" | sed -n 's/.* tar=\([^ ]*\).*/\1/p')
jq -n --arg dpkg "$dpkg_rc" --arg tar "$tar_rc" --argjson seconds "$seconds" \
    '{dpkg: $dpkg, tar: $tar, seconds: $seconds}' > "$OUT/install.json"
[ "$dpkg_rc" = 0 ] || die "dpkg failed in the installer VM (status $dpkg_rc)"
[ "$tar_rc" = 0 ] || die "the installer VM could not write its result (tar status $tar_rc)"
step "installed in ${seconds} s"
