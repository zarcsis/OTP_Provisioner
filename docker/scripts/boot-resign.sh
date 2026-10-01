#!/bin/bash
# boot-resign.sh - turn an IDP boot-slot sparse image into a signed boot_ramdisk slot
# for a board whose OTP holds the customer key hash (same recipe as rpi-sb-provisioner's
# prepare_signed_boot_simg, but with mtools instead of loop mounts: no --privileged).
#
# Mounts:  /in   ro  the boot slot sparse image, file name in env SIMAGE
#          /keys ro  private.pem, public.pem (RSA-2048)
#          /out  rw
#          /ext  ro  <repo>/external (usbboot + rpi-eeprom submodules)
# Env:     SIMAGE=<file name in /in>   MAX_PIECE=<bytes> (default 268435456)   [SOURCE_DATE_EPOCH]
# Steps:   simg2img -> raw vfat; mcopy -s the files out; if the slot already holds boot.img
#          sign it as-is, else rpi-make-boot-image -b pi5 -a 64; boot.sig via rpi-eeprom-digest -k;
#          new FAT32 of the same byte size (mkfs.fat -s 1 -F 32 -n BOOT) holding boot.img,
#          boot.sig and config.txt (boot_ramdisk=1, uart_2ndstage=1); img2simg -> /out/<SIMAGE>;
#          when larger than MAX_PIECE: simg2simg split into /out/<SIMAGE>.0, .1, ...
# Outputs: /out/<SIMAGE> or /out/<SIMAGE>.<n> pieces, /out/resign.json {"simage","pieces":[{"file","size"}]}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

EXT="${EXT:-/ext}"
IN="${IN:-/in}"
OUT="${OUT:-/out}"
KEYS="${KEYS:-/keys}"
EEPROM_DIR="${EXT}/usbboot/rpi-eeprom"
SIMAGE="${SIMAGE:-}"
MAX_PIECE="${MAX_PIECE:-268435456}"
export MTOOLS_SKIP_CHECK=1

WORK="$(mktemp -d /tmp/boot-resign.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

stage_tools() {
    local bin="${WORK}/bin" src name
    mkdir -p "${bin}"
    for src in "${EEPROM_DIR}/rpi-eeprom-digest" "${EXT}/usbboot/tools/rpi-make-boot-image"; do
        [ -f "${src}" ] || die "tool not found: ${src} (are the submodules checked out?)"
        [ "$(stat -c %s "${src}")" -gt 200 ] || die "tool ${src} looks like an unresolved git symlink"
        name="$(basename "${src}")"
        sed 's/\r$//' "${src}" > "${bin}/${name}"
        chmod 0755 "${bin}/${name}"
    done
    export PATH="${bin}:${EEPROM_DIR}:${EEPROM_DIR}/tools:${PATH}"
}

check_rsa_sig() {
    local sig="$1" hex
    hex="$(sed -n 's/^rsa2048:[[:space:]]*//p' "${sig}" | tr -d '\r\n')"
    [ -n "${hex}" ] || die "$(basename "${sig}"): no rsa2048 signature"
    [ "${#hex}" -eq 512 ] || die "$(basename "${sig}"): rsa2048 signature has ${#hex} hex chars, expected 512"
    case "${hex}" in *[!0-9a-fA-F]*) die "$(basename "${sig}"): rsa2048 signature is not hex" ;; esac
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
# Prints the resulting file names (basenames), in flashing order.
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
    [ -z "$(find "${dir}" -maxdepth 1 -name "${base}.${n}*" -print -quit)" ] || die "unexpected piece names for ${base}"
    for ((i = 0; i < n; i++)); do
        [ "$(stat -c %s "${dir}/${base}.${i}")" -le "${MAX_PIECE}" ] || die "piece ${base}.${i} exceeds MAX_PIECE"
        piece_geom="$(sparse_geometry "${dir}/${base}.${i}")" || die "piece ${base}.${i} is not a sparse image"
        [ "${piece_geom}" = "${geom}" ] || die "piece ${base}.${i} covers '${piece_geom}', expected '${geom}'"
    done
    rm -f "${file}"
    for ((i = 0; i < n; i++)); do echo "${base}.${i}"; done
}

# ---------------------------------------------------------------------------
step "boot-resign: SIMAGE=${SIMAGE} MAX_PIECE=${MAX_PIECE}"
[ -n "${SIMAGE}" ] || die "SIMAGE is not set"
case "${SIMAGE}" in */*|.*) die "SIMAGE must be a bare file name, got '${SIMAGE}'" ;; esac
[[ "${MAX_PIECE}" =~ ^[0-9]+$ ]] && [ "${MAX_PIECE}" -ge 1048576 ] || die "MAX_PIECE must be an integer >= 1048576"
[ -f "${IN}/${SIMAGE}" ] || die "${IN}/${SIMAGE} missing"
[ -f "${KEYS}/private.pem" ] || die "${KEYS}/private.pem missing"
[ -f "${KEYS}/public.pem" ] || die "${KEYS}/public.pem missing"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
stage_tools
sparse_geometry "${IN}/${SIMAGE}" >/dev/null || die "${SIMAGE} is not an Android sparse image"

step "expanding ${SIMAGE}"
simg2img "${IN}/${SIMAGE}" "${WORK}/source.vfat"
SIZE="$(stat -c %s "${WORK}/source.vfat")"
echo "    raw size ${SIZE} bytes"
[[ "$(file -b "${WORK}/source.vfat")" == *FAT* ]] || die "${SIMAGE} does not hold a FAT filesystem"

step "extracting the slot files (mtools)"
mkdir -p "${WORK}/slot"
mcopy -s -m -n -i "${WORK}/source.vfat" ::/ "${WORK}/slot/"
[ -n "$(ls -A "${WORK}/slot")" ] || die "the boot slot is empty"
rm -f "${WORK}/source.vfat"

if [ -f "${WORK}/slot/boot.img" ]; then
    step "slot already holds boot.img: signing it as-is"
    cp "${WORK}/slot/boot.img" "${WORK}/boot.img"
    boot_img_source="existing"
else
    step "rpi-make-boot-image -b pi5 -a 64"
    rpi-make-boot-image -b pi5 -a 64 -d "${WORK}/slot" -o "${WORK}/boot.img"
    boot_img_source="rpi-make-boot-image"
fi
[ -s "${WORK}/boot.img" ] || die "no boot.img"
echo "    boot.img: $(stat -c %s "${WORK}/boot.img") bytes (${boot_img_source})"

step "boot.sig"
rpi-eeprom-digest -k "${KEYS}/private.pem" -i "${WORK}/boot.img" -o "${WORK}/boot.sig"
check_rsa_sig "${WORK}/boot.sig"
rpi-eeprom-digest -k "${KEYS}/public.pem" -i "${WORK}/boot.img" -v "${WORK}/boot.sig" \
    || die "boot.sig does not verify with public.pem"
printf 'boot_ramdisk=1\nuart_2ndstage=1\n' > "${WORK}/config.txt"

step "new FAT32 slot of ${SIZE} bytes"
truncate -s "${SIZE}" "${WORK}/out.vfat"
mkfs.fat -s 1 -F 32 -n BOOT "${WORK}/out.vfat" >/dev/null \
    || die "mkfs.fat -s 1 -F 32 failed (a ${SIZE}-byte slot is too small for FAT32 with 512-byte clusters?)"
need=$(( $(stat -c %s "${WORK}/boot.img") + 65536 ))
free_bytes="$(mdir -i "${WORK}/out.vfat" ::/ | awk '/bytes free/ {gsub(/[^0-9]/, ""); print}')"
[ -n "${free_bytes}" ] && [ "${free_bytes}" -ge "${need}" ] \
    || die "boot.img ($(stat -c %s "${WORK}/boot.img") bytes) does not fit into the ${SIZE}-byte slot"
mcopy -m -i "${WORK}/out.vfat" "${WORK}/boot.img" "${WORK}/boot.sig" "${WORK}/config.txt" ::/

step "self-check of the new slot"
mkdir -p "${WORK}/verify"
mcopy -n -i "${WORK}/out.vfat" ::/boot.img ::/boot.sig ::/config.txt "${WORK}/verify/"
cmp -s "${WORK}/verify/boot.img" "${WORK}/boot.img" || die "boot.img read back differs"
rpi-eeprom-digest -k "${KEYS}/public.pem" -i "${WORK}/verify/boot.img" -v "${WORK}/verify/boot.sig" \
    || die "boot.sig read back does not verify"
cmp -s "${WORK}/verify/config.txt" "${WORK}/config.txt" || die "config.txt read back differs"
rm -rf "${WORK}/verify" "${WORK}/slot"

step "img2simg -> ${OUT}/${SIMAGE}"
rm -f "${OUT}/${SIMAGE}" "${OUT}/${SIMAGE}".[0-9]* "${OUT}/resign.json"
img2simg -s "${WORK}/out.vfat" "${WORK}/${SIMAGE}"
geom="$(sparse_geometry "${WORK}/${SIMAGE}")"
blocks="${geom% *}"; bsz="${geom#* }"
[ $((blocks * bsz)) -eq "${SIZE}" ] || die "sparse image covers $((blocks * bsz)) bytes, expected ${SIZE}"
mv "${WORK}/${SIMAGE}" "${OUT}/${SIMAGE}"
split_sparse "${OUT}/${SIMAGE}" > "${WORK}/pieces.txt"
mapfile -t pieces < "${WORK}/pieces.txt"
[ "${#pieces[@]}" -ge 1 ] || die "no output pieces"

pieces_json="[]"
for p in "${pieces[@]}"; do
    pieces_json="$(jq -c --arg f "${p}" --argjson s "$(stat -c %s "${OUT}/${p}")" '. + [{file: $f, size: $s}]' <<< "${pieces_json}")"
    echo "    ${p}: $(stat -c %s "${OUT}/${p}") bytes"
done
jq -n --arg simage "${SIMAGE}" --argjson pieces "${pieces_json}" '{simage: $simage, pieces: $pieces}' > "${OUT}/resign.json"
cat "${OUT}/resign.json"
step "boot-resign done"
