#!/bin/bash
# custom-image.sh - an operator's own OS image as an IDP set the station flashes at stage 3.
#
# The image is a raw .img with an MBR and two primary partitions: a FAT boot partition and an ext4 root
# (what Raspberry Pi OS and pi-gen produce). Two variants, one per scenario:
#
#   VARIANT=clear  the image as it is: its boot partition and its root file system as sparse images.
#   VARIANT=crypt  the secure scenario: a copy of the image that unlocks a LUKS2 root with the board's OTP
#                  key at every boot. Inside the image (an arm64 chroot, packages from the image's own apt
#                  sources): cryptsetup-initramfs and rpifwcrypto, the otp-hwkey keyscript and an
#                  initramfs hook (custom-crypt/), /etc/crypttab (MAPPER on UUID=LUKS_UUID), the root in
#                  /etc/fstab and in cmdline.txt on /dev/mapper/MAPPER, otp-growroot.service, the automatic
#                  bootloader EEPROM update masked (a secure board's bootloader is signed for it); then
#                  update-initramfs with MODULES=most for this run only (MODULES=dep in a chroot guesses the
#                  build container's modules: 15 instead of the image's 264). apt runs with a tmpfs on /tmp
#                  (an image may have no /tmp), policy-rc.d and the container's resolv.conf; all three are
#                  undone, and only the .debs downloaded here leave the apt cache. The station encrypts the
#                  result for each board (root-luks.sh).
#
# Mounts:  /in      ro  the upload directory: source.img
#          /out     rw  the set directory being built
#          /scripts ro  docker/scripts (ext4_sparse.py, custom-crypt/)
# Env:     VARIANT=clear|crypt   MAX_PIECE=<bytes> (268435456)
#          crypt only: LUKS_UUID (the container's UUID, in crypttab)   MAPPER (cryptroot)
#                      MIN_FREE=<bytes> free space the root file system gets before apt runs (805306368)
# Needs:   --privileged (loop mounts); crypt: the arm64 binfmt handler registered on the host, and network.
# Outputs: /out/boot.vfat.sparse[.n], /out/root.ext4.sparse[.n] (split at MAX_PIECE), /out/custom.json:
#          {"variant", "disk": {"label", "id", "sector_size", "bytes"},
#           "partitions": [{"n", "start", "sectors", "type", "fs", "fs_label", "fs_uuid"}],
#           "boot": {"simage", "bytes", "mountpoint", "pieces": [{"file", "size"}]},
#           "root": {"simage", "fs_bytes", "fs_block_size", "used_bytes", "pieces": [...]},
#           "os": {"pretty_name", "id", "version_codename", "kernels": [...], "cloud_init", "initramfs_tools"},
#           "crypt": null | {"mapper", "uuid", "packages": {name: version}, "initramfs": [names], "cmdline"}}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

IN="${IN:-/in}"
OUT="${OUT:-/out}"
SCRIPTS="${SCRIPTS:-/scripts}"
SRC="${IN}/source.img"
VARIANT="${VARIANT:-clear}"
MAX_PIECE="${MAX_PIECE:-268435456}"
LUKS_UUID="${LUKS_UUID:-}"
MAPPER="${MAPPER:-cryptroot}"
MIN_FREE="${MIN_FREE:-805306368}"
CRYPT_FILES="${SCRIPTS}/custom-crypt"

WORK="$(mktemp -d /var/tmp/custom-image.XXXXXX)"
R="${WORK}/root"
MOUNTS=()

cleanup() {
    local i
    for ((i = ${#MOUNTS[@]} - 1; i >= 0; i--)); do
        umount -l "${MOUNTS[i]}" 2>/dev/null || true
    done
    rm -rf "${WORK}"
}
trap cleanup EXIT

mnt() {     # mnt <target> <mount args...>
    local target="$1"; shift
    mkdir -p "${target}"
    mount "$@" "${target}"
    MOUNTS+=("${target}")
}

umount_all() {
    local i
    sync
    for ((i = ${#MOUNTS[@]} - 1; i >= 0; i--)); do
        umount "${MOUNTS[i]}" || umount -l "${MOUNTS[i]}"
    done
    MOUNTS=()
}

# "<total blocks> <block size>" of an Android sparse image, from its header.
sparse_geometry() {
    python3 - "$1" <<'EOF'
import struct, sys
with open(sys.argv[1], "rb") as f:
    hdr = f.read(28)
if len(hdr) < 28:
    sys.exit("short file")
magic, major, minor, fhs, chs, blk_sz, total_blks, total_chunks, crc = struct.unpack("<IHHHHIIII", hdr)
if magic != 0xED26FF3A:
    sys.exit("not an Android sparse image (magic %08x)" % magic)
print(total_blks, blk_sz)
EOF
}

# Split <file> into self-contained sparse pieces <file>.0, .1, ... when it exceeds MAX_PIECE.
split_sparse() {
    local file="$1" dir base size n i geom piece_geom
    dir="$(dirname "${file}")"; base="$(basename "${file}")"
    size="$(stat -c %s "${file}")"
    rm -f "${dir}/${base}".[0-9]*
    if [ "${size}" -le "${MAX_PIECE}" ]; then
        echo "${base}"
        return 0
    fi
    geom="$(sparse_geometry "${file}")"
    echo "    ${base}: ${size} bytes > MAX_PIECE ${MAX_PIECE}, splitting" >&2
    simg2simg "${file}" "${file}" "${MAX_PIECE}" >&2 || die "simg2simg failed on ${base}"
    n=0
    while [ -f "${dir}/${base}.${n}" ]; do n=$((n + 1)); done
    [ "${n}" -ge 2 ] || die "simg2simg produced ${n} pieces for ${base}"
    for ((i = 0; i < n; i++)); do
        [ "$(stat -c %s "${dir}/${base}.${i}")" -le "${MAX_PIECE}" ] || die "piece ${base}.${i} exceeds MAX_PIECE"
        piece_geom="$(sparse_geometry "${dir}/${base}.${i}")" || die "piece ${base}.${i} is not a sparse image"
        [ "${piece_geom}" = "${geom}" ] || die "piece ${base}.${i} covers '${piece_geom}', expected '${geom}'"
    done
    rm -f "${file}"
    for ((i = 0; i < n; i++)); do echo "${base}.${i}"; done
}

# <sparse file in WORK> -> pieces in OUT; prints the JSON list of pieces.
publish() {
    local name="$1" p json="[]"
    rm -f "${OUT}/${name}" "${OUT}/${name}".[0-9]*
    mv "${WORK}/${name}" "${OUT}/${name}"
    split_sparse "${OUT}/${name}" > "${WORK}/pieces.txt"
    while IFS= read -r p; do
        json="$(jq -c --arg f "${p}" --argjson s "$(stat -c %s "${OUT}/${p}")" '. + [{file: $f, size: $s}]' <<< "${json}")"
        echo "    ${p}: $(stat -c %s "${OUT}/${p}") bytes" >&2
    done < "${WORK}/pieces.txt"
    echo "${json}"
}

# The value of KEY= in an os-release file.
os_field() {
    sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n1 | sed 's/^"\(.*\)"$/\1/'
}

# ---------------------------------------------------------------------------
step "custom-image: VARIANT=${VARIANT} MAX_PIECE=${MAX_PIECE}"
case "${VARIANT}" in clear|crypt) ;; *) die "VARIANT must be clear or crypt, got '${VARIANT}'" ;; esac
[[ "${MAX_PIECE}" =~ ^[0-9]+$ ]] && [ "${MAX_PIECE}" -ge 1048576 ] || die "MAX_PIECE must be an integer >= 1048576"
[ -f "${SRC}" ] || die "${SRC} missing"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
if [ "${VARIANT}" = crypt ]; then
    [[ "${LUKS_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || die "LUKS_UUID must be a lowercase UUID"
    [[ "${MAPPER}" =~ ^[a-z][a-z0-9_]{0,31}$ ]] || die "MAPPER must be a plain mapping name"
    for f in otp-hwkey otp-cryptroot.hook otp-growroot otp-growroot.service; do
        [ -f "${CRYPT_FILES}/${f}" ] || die "${CRYPT_FILES}/${f} missing"
    done
fi

step "partition table"
sfdisk --json "${SRC}" > "${WORK}/pt.json" 2>/dev/null || die "the image has no partition table sfdisk can read"
python3 - "${WORK}/pt.json" "$(stat -c %s "${SRC}")" > "${WORK}/pt.env" <<'EOF'
import json, sys
pt = json.load(open(sys.argv[1]))["partitiontable"]
size = int(sys.argv[2])
def fail(msg):
    sys.exit("ERROR: " + msg)
if pt.get("label") != "dos":
    fail(f"the partition table is {pt.get('label')!r}; the station takes MBR (dos) images only")
ss = int(pt.get("sectorsize") or 512)
if ss != 512:
    fail(f"sector size {ss}, expected 512")
parts = pt.get("partitions") or []
if len(parts) != 2:
    fail(f"the image has {len(parts)} partitions; expected exactly two: a FAT boot partition and an ext4 root")
boot, root = parts
if boot["type"].lower() not in ("c", "b", "e", "6"):
    fail(f"partition 1 has type 0x{boot['type']}, expected a FAT boot partition (0x0c, 0x0b, 0x0e or 0x06)")
if root["type"].lower() != "83":
    fail(f"partition 2 has type 0x{root['type']}, expected a Linux root partition (0x83)")
for n, p in ((1, boot), (2, root)):
    if p["start"] * 512 + p["size"] * 512 > size:
        fail(f"partition {n} ends at byte {(p['start'] + p['size']) * 512}, past the end of the file ({size} bytes): truncated upload?")
if root["start"] < boot["start"] + boot["size"]:
    fail("the root partition overlaps the boot partition")
print(f"PT_ID={pt.get('id', '')}")
print(f"BOOT_START={boot['start']} BOOT_SECTORS={boot['size']} BOOT_TYPE={boot['type']}")
print(f"ROOT_START={root['start']} ROOT_SECTORS={root['size']}")
EOF
# shellcheck disable=SC1091
. "${WORK}/pt.env"
echo "    MBR ${PT_ID}: boot ${BOOT_START}+${BOOT_SECTORS} (0x${BOOT_TYPE}), root ${ROOT_START}+${ROOT_SECTORS} sectors"

step "extracting the partitions"
dd if="${SRC}" of="${WORK}/boot.vfat" bs=4M iflag=skip_bytes,count_bytes skip=$((BOOT_START * 512)) \
    count=$((BOOT_SECTORS * 512)) status=none
BOOT_BYTES=$(( (BOOT_SECTORS * 512 + 4095) / 4096 * 4096 ))
truncate -s "${BOOT_BYTES}" "${WORK}/boot.vfat"
[ "$(blkid -p -o value -s TYPE "${WORK}/boot.vfat" 2>/dev/null)" = vfat ] || die "partition 1 does not hold a FAT file system"
dd if="${SRC}" of="${WORK}/root.ext4" bs=4M iflag=skip_bytes,count_bytes skip=$((ROOT_START * 512)) \
    count=$((ROOT_SECTORS * 512)) status=none
[ "$(blkid -p -o value -s TYPE "${WORK}/root.ext4" 2>/dev/null)" = ext4 ] || die "partition 2 does not hold an ext4 file system"
dumpe2fs -h "${WORK}/root.ext4" > "${WORK}/root.hdr" 2>/dev/null || die "dumpe2fs cannot read the root file system"
hdr() { sed -n "s/^$1:[[:space:]]*//p" "${WORK}/root.hdr" | head -n1; }
FS_BLOCK="$(hdr 'Block size')"; FS_COUNT="$(hdr 'Block count')"
FS_BYTES=$((FS_BLOCK * FS_COUNT))
[ "${FS_BYTES}" -le $((ROOT_SECTORS * 512)) ] || die "the root file system (${FS_BYTES} bytes) is larger than its partition"
[ $((FS_BYTES % 4096)) -eq 0 ] || die "the root file system is ${FS_BYTES} bytes, not a multiple of 4096"
truncate -s "${FS_BYTES}" "${WORK}/root.ext4"
echo "    boot: $(blkid -p -o value -s LABEL "${WORK}/boot.vfat" || true) ${BOOT_BYTES} bytes"
echo "    root: $(hdr 'Filesystem volume name') ${FS_COUNT} blocks of ${FS_BLOCK} bytes, $(hdr 'Free blocks') free"
e2fsck -fn "${WORK}/root.ext4" > "${WORK}/fsck.txt" 2>&1 || { sed 's/^/    /' "${WORK}/fsck.txt" | tail -n 20; die "the root file system has errors (e2fsck -fn); repair the image first"; }

step "what the image holds"
debugfs_cat() { debugfs -R "cat $1" "${WORK}/root.ext4" 2>/dev/null; }
debugfs_has() { debugfs -R "stat $1" "${WORK}/root.ext4" 2>&1 | grep -q '^Inode:'; }
debugfs_cat /usr/lib/os-release > "${WORK}/os-release" || true
[ -s "${WORK}/os-release" ] || debugfs_cat /etc/os-release > "${WORK}/os-release" || true
list_dir() { debugfs -R "ls -p $1" "${WORK}/root.ext4" 2>/dev/null | awk -F/ '$6 != "." && $6 != ".." && $6 != "" { print $6 }' | sort; }
KERNELS="$(list_dir /usr/lib/modules)"
[ -n "${KERNELS}" ] || KERNELS="$(list_dir /lib/modules)"
CLOUD_INIT=false; debugfs_has /usr/bin/cloud-init && CLOUD_INIT=true
INITRAMFS_TOOLS=false; debugfs_has /usr/sbin/update-initramfs && INITRAMFS_TOOLS=true
echo "    $(os_field "${WORK}/os-release" PRETTY_NAME); kernels: ${KERNELS//$'\n'/ }; cloud-init: ${CLOUD_INIT}"
[ -n "${KERNELS}" ] || die "the root file system has no kernel modules (/usr/lib/modules): not a Raspberry Pi OS image?"
mkdir -p "${WORK}/bootfiles"
mcopy -n -i "${WORK}/boot.vfat" ::/config.txt ::/cmdline.txt "${WORK}/bootfiles/" 2>/dev/null \
    || die "the boot partition has no config.txt and cmdline.txt"
mdir -b -i "${WORK}/boot.vfat" ::/ > "${WORK}/bootlist.txt" 2>/dev/null || true
grep -qi '^::/kernel_2712.img$\|^::/kernel8.img$' "${WORK}/bootlist.txt" \
    || die "the boot partition has no Raspberry Pi 5 kernel (kernel_2712.img or kernel8.img)"

BOOT_MP=""
CRYPT_JSON=null
if [ "${VARIANT}" = crypt ]; then
    "${INITRAMFS_TOOLS}" || die "the image has no initramfs-tools (update-initramfs): its root cannot be unlocked at boot"

    free_bytes=$(( $(hdr 'Free blocks') * FS_BLOCK ))
    if [ "${free_bytes}" -lt "${MIN_FREE}" ]; then
        step "growing the root file system for the new packages"
        new_bytes=$(( (FS_BYTES + MIN_FREE - free_bytes + 16777215) / 16777216 * 16777216 ))
        truncate -s "${new_bytes}" "${WORK}/root.ext4"
        resize2fs "${WORK}/root.ext4" >/dev/null 2>&1 || die "resize2fs failed"
        dumpe2fs -h "${WORK}/root.ext4" > "${WORK}/root.hdr" 2>/dev/null
        FS_COUNT="$(hdr 'Block count')"; FS_BYTES=$((FS_BLOCK * FS_COUNT))
        echo "    ${FS_BYTES} bytes, $(( $(hdr 'Free blocks') * FS_BLOCK )) free"
    fi

    step "mounting the image"
    mnt "${R}" -o loop "${WORK}/root.ext4" || die "cannot mount the root file system (${FS_BLOCK}-byte blocks)"
    BOOT_MP="$(awk '$1 !~ /^#/ && $3 == "vfat" { print $2; exit }' "${R}/etc/fstab")"
    [ -n "${BOOT_MP}" ] || { [ -d "${R}/boot/firmware" ] && BOOT_MP=/boot/firmware || BOOT_MP=/boot; }
    echo "    boot partition at ${BOOT_MP}"
    mnt "${R}${BOOT_MP}" -o loop "${WORK}/boot.vfat"
    mnt "${R}/proc" -t proc proc
    mnt "${R}/sys" --bind /sys
    mnt "${R}/dev" --bind /dev
    mnt "${R}/dev/pts" --bind /dev/pts
    # apt and update-initramfs need a /tmp; an image may have none (systemd-tmpfiles makes it at boot)
    tmp_made=0
    [ -d "${R}/tmp" ] || { mkdir -m 1777 "${R}/tmp"; tmp_made=1; }
    mnt "${R}/tmp" -t tmpfs -o mode=1777 tmpfs
    resolv_kind=none
    if [ -L "${R}/etc/resolv.conf" ]; then resolv_kind=link; resolv_link="$(readlink "${R}/etc/resolv.conf")"
    elif [ -e "${R}/etc/resolv.conf" ]; then resolv_kind=file; cp -a "${R}/etc/resolv.conf" "${WORK}/resolv.conf.image"; fi
    rm -f "${R}/etc/resolv.conf"
    cp /etc/resolv.conf "${R}/etc/resolv.conf"
    printf '#!/bin/sh\nexit 101\n' > "${R}/usr/sbin/policy-rc.d"
    chmod 0755 "${R}/usr/sbin/policy-rc.d"
    in_root() { chroot "${R}" /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
                    DEBIAN_FRONTEND=noninteractive "$@"; }
    in_root /bin/true || die "cannot run the image's arm64 programs: register the arm64 binfmt handler (QEMU) on the host"

    step "packages from the image's own apt sources"
    in_root apt-get update 2>&1 | sed 's/^/    /' || echo "    warning: apt-get update reported errors (an unreachable source?)"
    for pkg in cryptsetup-initramfs rpifwcrypto; do
        cand="$(in_root apt-cache policy "${pkg}" 2>/dev/null | awk '$1 == "Candidate:" { print $2 }')"
        [ -n "${cand}" ] && [ "${cand}" != "(none)" ] || die "the image's apt sources offer no ${pkg} (cryptsetup-initramfs comes from Debian, rpifwcrypto from archive.raspberrypi.com, bookworm or later)"
    done
    ls "${R}/var/cache/apt/archives/" > "${WORK}/debs-before.txt" 2>/dev/null || true
    if ! in_root apt-get install -y --no-install-recommends cryptsetup cryptsetup-initramfs rpifwcrypto 2>&1 | sed 's/^/    /'; then
        die "apt-get install failed"
    fi
    in_root sh -c 'command -v rpi-fw-crypto && command -v cryptsetup' >/dev/null || die "rpi-fw-crypto or cryptsetup missing after the install"

    step "unlocking at boot: keyscript, initramfs hook, crypttab, fstab, cmdline.txt"
    install -m 0755 -D "${CRYPT_FILES}/otp-hwkey" "${R}/usr/lib/cryptsetup/keyscripts/otp-hwkey"
    install -m 0755 -D "${CRYPT_FILES}/otp-cryptroot.hook" "${R}/etc/initramfs-tools/hooks/otp-cryptroot"
    install -m 0755 -D "${CRYPT_FILES}/otp-growroot" "${R}/usr/local/sbin/otp-growroot"
    install -m 0644 -D "${CRYPT_FILES}/otp-growroot.service" "${R}/etc/systemd/system/otp-growroot.service"
    sed -i 's/\r$//' "${R}/usr/lib/cryptsetup/keyscripts/otp-hwkey" "${R}/etc/initramfs-tools/hooks/otp-cryptroot" \
        "${R}/usr/local/sbin/otp-growroot" "${R}/etc/systemd/system/otp-growroot.service"
    in_root systemctl enable otp-growroot.service 2>&1 | sed 's/^/    /'
    if [ -e "${R}/usr/lib/systemd/system/rpi-eeprom-update.service" ] || [ -e "${R}/lib/systemd/system/rpi-eeprom-update.service" ]; then
        in_root systemctl mask rpi-eeprom-update.service 2>&1 | sed 's/^/    /'
    fi
    touch "${R}/etc/crypttab"
    awk -v m="${MAPPER}" '$1 != m' "${R}/etc/crypttab" > "${WORK}/crypttab"
    echo "${MAPPER} UUID=${LUKS_UUID} none luks,initramfs,keyscript=/usr/lib/cryptsetup/keyscripts/otp-hwkey" >> "${WORK}/crypttab"
    cat "${WORK}/crypttab" > "${R}/etc/crypttab"
    python3 - "${R}/etc/fstab" "/dev/mapper/${MAPPER}" <<'EOF'
import sys
path, dev = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().splitlines()
out, done = [], False
for line in lines:
    f = line.split()
    if f and not f[0].startswith("#") and len(f) >= 2 and f[1] == "/":
        f[0] = dev
        line = "\t".join(f)
        done = True
    out.append(line)
if not done:
    out.append(f"{dev}\t/\text4\tdefaults,noatime\t0\t1")
open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
EOF
    mkdir -p "${R}/etc/cryptsetup-initramfs"
    touch "${R}/etc/cryptsetup-initramfs/conf-hook"
    sed -i '/^CRYPTSETUP=/d' "${R}/etc/cryptsetup-initramfs/conf-hook"
    echo "CRYPTSETUP=y" >> "${R}/etc/cryptsetup-initramfs/conf-hook"
    CMDLINE="${R}${BOOT_MP}/cmdline.txt"
    [ -f "${CMDLINE}" ] || die "no cmdline.txt in the boot partition"
    python3 - "${CMDLINE}" "/dev/mapper/${MAPPER}" <<'EOF'
import sys
path, dev = sys.argv[1], sys.argv[2]
words = open(path, encoding="utf-8").read().split()
# the image's own first-boot resizer would try to grow the root partition behind the mapping
words = [w for w in words if not w.startswith("root=") and w != "init=/usr/lib/raspberrypi-sys-mods/firstboot"]
words.insert(0, f"root={dev}")
open(path, "w", encoding="utf-8").write(" ".join(words) + "\n")
EOF
    CONFIG="${R}${BOOT_MP}/config.txt"
    if ! grep -Eq '^[[:space:]]*(auto_initramfs[[:space:]]*=[[:space:]]*1|initramfs[[:space:]])' "${CONFIG}"; then
        printf '\n[all]\n# The encrypted root is unlocked in the initramfs (OTP provisioning station)\nauto_initramfs=1\n' >> "${CONFIG}"
        echo "    config.txt: auto_initramfs=1 added"
    fi
    echo "    crypttab: $(tail -n1 "${R}/etc/crypttab")"
    echo "    fstab:    $(awk '$2 == "/"' "${R}/etc/fstab")"
    echo "    cmdline:  $(cat "${CMDLINE}")"

    step "update-initramfs"
    # MODULES=dep would guess the modules from this container instead of the board (it finds next to
    # none); "most" is what an image built in a chroot normally gets. Only for this run: the image's own
    # initramfs.conf stays as it was.
    printf 'MODULES=most\n' > "${R}/etc/initramfs-tools/conf.d/zz-otp-station-build"
    if ! in_root update-initramfs -u -k all 2>&1 | sed 's/^/    /'; then
        die "update-initramfs failed"
    fi
    rm -f "${R}/etc/initramfs-tools/conf.d/zz-otp-station-build"
    initramfs_ok=()
    for f in "${R}${BOOT_MP}"/initramfs*; do
        [ -f "${f}" ] || continue
        rel="${BOOT_MP}/$(basename "${f}")"
        in_root lsinitramfs "${rel}" > "${WORK}/lsinitramfs.txt" 2>/dev/null || die "lsinitramfs cannot read ${rel}"
        for want in usr/lib/cryptsetup/keyscripts/otp-hwkey usr/bin/rpi-fw-crypto cryptroot/crypttab; do
            grep -q "^${want}\$" "${WORK}/lsinitramfs.txt" || grep -q "/${want##*/}\$" "${WORK}/lsinitramfs.txt" \
                || die "${rel} lacks ${want}"
        done
        grep -Eq '(^|/)(busybox|readlink)$' "${WORK}/lsinitramfs.txt" || die "${rel} has neither busybox nor readlink (the keyscript needs it)"
        for km in DM_CRYPT:dm-crypt BLK_DEV_DM:dm-mod CRYPTO_USER_API_SKCIPHER:algif_skcipher CRYPTO_AES:aes_generic; do
            if grep -q "^CONFIG_${km%%:*}=m" "${R}/boot/config-"* 2>/dev/null; then
                grep -q "/${km#*:}\.ko" "${WORK}/lsinitramfs.txt" || die "${rel} lacks the ${km#*:} module"
            fi
        done
        initramfs_ok+=("$(basename "${f}")")
        echo "    ${rel}: keyscript, rpi-fw-crypto, crypttab, dm-crypt; $(grep -c '\.ko' "${WORK}/lsinitramfs.txt") modules, $(stat -c %s "${f}") bytes"
    done
    [ "${#initramfs_ok[@]}" -ge 1 ] || die "no initramfs in the boot partition after update-initramfs"
    for f in "${initramfs_ok[@]}"; do
        rm -rf "${R}/tmp/otp-ird"
        in_root unmkinitramfs "${BOOT_MP}/${f}" /tmp/otp-ird >/dev/null 2>&1 || die "unmkinitramfs cannot unpack ${f}"
        ct="$(find "${R}/tmp/otp-ird" -path '*cryptroot/crypttab' | head -n1)"
        [ -n "${ct}" ] && grep -q "UUID=${LUKS_UUID}" "${ct}" || die "the crypttab in ${f} does not name UUID=${LUKS_UUID}"
        echo "    ${f} crypttab: $(grep -v '^#' "${ct}" | head -n1)"
    done
    rm -rf "${R}/tmp/otp-ird"
    PKGS="$(in_root dpkg-query -W -f '${Package}\t${Version}\n' cryptsetup cryptsetup-initramfs rpifwcrypto librpifwcrypto0 2>/dev/null \
        | jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {}')"
    CMDLINE_TEXT="$(cat "${CMDLINE}")"

    step "cleaning up the image"
    # only the .debs downloaded here (the image may keep its own cache)
    for d in "${R}"/var/cache/apt/archives/*.deb; do
        [ -e "${d}" ] || continue
        grep -qxF "$(basename "${d}")" "${WORK}/debs-before.txt" || rm -f "${d}"
    done
    rm -f "${R}/usr/sbin/policy-rc.d" "${R}/etc/resolv.conf"
    case "${resolv_kind}" in
        link) ln -s "${resolv_link}" "${R}/etc/resolv.conf" ;;
        file) cp -a "${WORK}/resolv.conf.image" "${R}/etc/resolv.conf" ;;
    esac
    umount_all
    if [ "${tmp_made}" = 1 ]; then      # the image had no /tmp: leave it so (its root is mounted once more)
        mnt "${R}" -o loop "${WORK}/root.ext4"
        rmdir "${R}/tmp"
        umount_all
    fi
    e2fsck -fy "${WORK}/root.ext4" >/dev/null 2>&1 || true
    e2fsck -fn "${WORK}/root.ext4" > "${WORK}/fsck.txt" 2>&1 || { tail -n 20 "${WORK}/fsck.txt"; die "the prepared root file system has errors"; }
    fsck.fat -n "${WORK}/boot.vfat" > /dev/null 2>&1 || echo "    warning: fsck.fat reports problems in the boot partition"
    CRYPT_JSON="$(jq -n -c --arg mapper "${MAPPER}" --arg uuid "${LUKS_UUID}" --argjson packages "${PKGS}" \
        --arg cmdline "${CMDLINE_TEXT}" --argjson initramfs "$(printf '%s\n' "${initramfs_ok[@]}" | jq -R . | jq -s -c .)" \
        '{mapper: $mapper, uuid: $uuid, packages: $packages, initramfs: $initramfs, cmdline: $cmdline}')"
fi

step "sparse images"
BOOT_LABEL="$(blkid -p -o value -s LABEL "${WORK}/boot.vfat" 2>/dev/null || true)"
BOOT_UUID="$(blkid -p -o value -s UUID "${WORK}/boot.vfat" 2>/dev/null || true)"
img2simg "${WORK}/boot.vfat" "${WORK}/boot.vfat.sparse"
geom="$(sparse_geometry "${WORK}/boot.vfat.sparse")"
[ $(( ${geom% *} * ${geom#* } )) -eq "${BOOT_BYTES}" ] || die "boot.vfat.sparse covers ${geom}, expected ${BOOT_BYTES} bytes"
python3 "${SCRIPTS}/ext4_sparse.py" "${WORK}/root.ext4" "${WORK}/root.ext4.sparse" > "${WORK}/root-sparse.json" \
    || die "ext4_sparse.py failed"
echo "    root: $(cat "${WORK}/root-sparse.json")"
geom="$(sparse_geometry "${WORK}/root.ext4.sparse")"
[ $(( ${geom% *} * ${geom#* } )) -eq "${FS_BYTES}" ] || die "root.ext4.sparse covers ${geom}, expected ${FS_BYTES} bytes"
rm -f "${WORK}/boot.vfat" "${WORK}/root.ext4"

step "pieces -> ${OUT}"
rm -f "${OUT}/custom.json"
BOOT_PIECES="$(publish boot.vfat.sparse)"
ROOT_PIECES="$(publish root.ext4.sparse)"
jq -n \
    --arg variant "${VARIANT}" --arg id "${PT_ID}" --argjson bytes "$(stat -c %s "${SRC}")" \
    --argjson bs "${BOOT_START}" --argjson bn "${BOOT_SECTORS}" --arg bt "${BOOT_TYPE}" \
    --argjson rs "${ROOT_START}" --argjson rn "${ROOT_SECTORS}" \
    --arg blabel "${BOOT_LABEL}" --arg buuid "${BOOT_UUID}" \
    --arg rlabel "$(hdr 'Filesystem volume name' | sed 's/^<none>$//')" --arg ruuid "$(hdr 'Filesystem UUID')" \
    --argjson boot_bytes "${BOOT_BYTES}" --arg boot_mp "${BOOT_MP}" --argjson boot_pieces "${BOOT_PIECES}" \
    --slurpfile rootst "${WORK}/root-sparse.json" --argjson root_pieces "${ROOT_PIECES}" \
    --arg pretty "$(os_field "${WORK}/os-release" PRETTY_NAME)" --arg osid "$(os_field "${WORK}/os-release" ID)" \
    --arg codename "$(os_field "${WORK}/os-release" VERSION_CODENAME)" \
    --argjson kernels "$(printf '%s\n' "${KERNELS}" | jq -R . | jq -s -c 'map(select(length > 0))')" \
    --argjson cloud_init "${CLOUD_INIT}" --argjson initramfs_tools "${INITRAMFS_TOOLS}" \
    --argjson crypt "${CRYPT_JSON}" \
    '{variant: $variant,
      disk: {label: "dos", id: $id, sector_size: 512, bytes: $bytes},
      partitions: [{n: 1, start: $bs, sectors: $bn, type: $bt, fs: "vfat", fs_label: $blabel, fs_uuid: $buuid},
                   {n: 2, start: $rs, sectors: $rn, type: "83", fs: "ext4", fs_label: $rlabel, fs_uuid: $ruuid}],
      boot: {simage: "boot.vfat.sparse", bytes: $boot_bytes, mountpoint: $boot_mp, pieces: $boot_pieces},
      root: ({simage: "root.ext4.sparse", pieces: $root_pieces} + $rootst[0]),
      os: {pretty_name: $pretty, id: $osid, version_codename: $codename, kernels: $kernels,
           cloud_init: $cloud_init, initramfs_tools: $initramfs_tools},
      crypt: $crypt}' > "${OUT}/custom.json"
cat "${OUT}/custom.json"
step "custom-image done"
