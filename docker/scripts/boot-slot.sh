#!/bin/bash
# boot-slot.sh - one board's boot slot, made from the image's IDP boot-slot sparse image:
#   * the board's first-boot files (the cloud-init NoCloud seed: user-data, network-config, meta-data)
#     go to the root of the boot partition, replacing the image's templates, and cmdline.txt gets the
#     board's additions (Wi-Fi country, the NoCloud instance) -- what Raspberry Pi Imager does;
#   * SIGN=1 (the board's OTP holds the customer key hash): the slot becomes a signed boot_ramdisk slot,
#     rpi-sb-provisioner's prepare_signed_boot_simg recipe with mtools instead of loop mounts (no
#     --privileged): boot.img (rpi-make-boot-image) + boot.sig + config.txt, plus the first-boot files,
#     which the OS reads from the boot partition (/boot/firmware) like on an unsigned board.
#
# Mounts:  /in   ro  the image set; the boot slot sparse image is named by SIMAGE
#          /seed ro  files/<name> (copied to the root of the boot partition) and cmdline.append (one line
#                    of kernel parameters; parameters of the same name are removed from cmdline.txt first)
#          /keys ro  private.pem, public.pem (RSA-2048), SIGN=1 only
#          /out  rw
#          /ext  ro  <repo>/external (usbboot + rpi-eeprom submodules), SIGN=1 only
# Env:     SIMAGE=<file name in /in>  SIGN=0|1  MAX_PIECE=<bytes> (default 268435456)  [SOURCE_DATE_EPOCH]
# Steps:   simg2img -> raw vfat.
#          SIGN=0: cmdline.txt edited and the seed files written into that FAT as it is (same geometry,
#          label and volume id).
#          SIGN=1: mcopy -s the files out; cmdline.txt edited; if the slot already holds boot.img it is
#          signed as-is (cmdline.txt cannot be edited then), else rpi-make-boot-image -b pi5 -a 64;
#          boot.sig via rpi-eeprom-digest -k; new FAT32 of the same byte size (mkfs.fat -s 1 -F 32 -n BOOT)
#          holding boot.img, boot.sig, config.txt (boot_ramdisk=1, uart_2ndstage=1) and the seed files.
#          img2simg -> /out/<SIMAGE>; when larger than MAX_PIECE: simg2simg split into /out/<SIMAGE>.0, .1, ...
# Outputs: /out/<SIMAGE> or /out/<SIMAGE>.<n> pieces, /out/slot.json
#          {"simage","signed","cmdline","seed":[names],"pieces":[{"file","size"}]}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

EXT="${EXT:-/ext}"
IN="${IN:-/in}"
OUT="${OUT:-/out}"
KEYS="${KEYS:-/keys}"
SEED="${SEED:-/seed}"
EEPROM_DIR="${EXT}/usbboot/rpi-eeprom"
SIMAGE="${SIMAGE:-}"
SIGN="${SIGN:-0}"
MAX_PIECE="${MAX_PIECE:-268435456}"
export MTOOLS_SKIP_CHECK=1

WORK="$(mktemp -d /tmp/boot-slot.XXXXXX)"
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

# <cmdline.txt> <additions>: drop the parameters the additions set, append them, keep one line.
edit_cmdline() {
    python3 - "$1" "$2" <<'EOF'
import sys
path, extra = sys.argv[1], sys.argv[2].split()
with open(path, "rb") as f:
    words = f.read().decode("utf-8").split()
keys = {w.split("=", 1)[0] for w in extra}
words = [w for w in words if w.split("=", 1)[0] not in keys] + extra
with open(path, "wb") as f:
    f.write((" ".join(words) + "\n").encode("utf-8"))
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
step "boot-slot: SIMAGE=${SIMAGE} SIGN=${SIGN} MAX_PIECE=${MAX_PIECE}"
[ -n "${SIMAGE}" ] || die "SIMAGE is not set"
case "${SIMAGE}" in */*|.*) die "SIMAGE must be a bare file name, got '${SIMAGE}'" ;; esac
case "${SIGN}" in 0|1) ;; *) die "SIGN must be 0 or 1, got '${SIGN}'" ;; esac
[[ "${MAX_PIECE}" =~ ^[0-9]+$ ]] && [ "${MAX_PIECE}" -ge 1048576 ] || die "MAX_PIECE must be an integer >= 1048576"
[ -f "${IN}/${SIMAGE}" ] || die "${IN}/${SIMAGE} missing"
[ -d "${SEED}/files" ] || die "${SEED}/files missing"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
if [ "${SIGN}" = 1 ]; then
    [ -f "${KEYS}/private.pem" ] || die "${KEYS}/private.pem missing"
    [ -f "${KEYS}/public.pem" ] || die "${KEYS}/public.pem missing"
    stage_tools
fi
sparse_geometry "${IN}/${SIMAGE}" >/dev/null || die "${SIMAGE} is not an Android sparse image"

mapfile -t SEED_FILES < <(find "${SEED}/files" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
[ "${#SEED_FILES[@]}" -ge 1 ] || die "no first-boot files in ${SEED}/files"
for f in "${SEED_FILES[@]}"; do
    case "${f}" in *[!A-Za-z0-9._-]*|.*) die "unsafe first-boot file name '${f}'" ;; esac
done
CMDLINE_EXTRA=""
[ -f "${SEED}/cmdline.append" ] && CMDLINE_EXTRA="$(head -n1 "${SEED}/cmdline.append" | tr -d '\r\n')"
echo "    first-boot files: ${SEED_FILES[*]}"
echo "    cmdline additions: ${CMDLINE_EXTRA:-none}"

step "expanding ${SIMAGE}"
simg2img "${IN}/${SIMAGE}" "${WORK}/source.vfat"
SIZE="$(stat -c %s "${WORK}/source.vfat")"
echo "    raw size ${SIZE} bytes"
[[ "$(file -b "${WORK}/source.vfat")" == *FAT* ]] || die "${SIMAGE} does not hold a FAT filesystem"

CMDLINE_OUT=""
if [ "${SIGN}" = 0 ]; then
    mv "${WORK}/source.vfat" "${WORK}/out.vfat"
    if [ -n "${CMDLINE_EXTRA}" ]; then
        step "cmdline.txt"
        mcopy -n -i "${WORK}/out.vfat" ::/cmdline.txt "${WORK}/cmdline.txt" || die "the boot partition has no cmdline.txt"
        edit_cmdline "${WORK}/cmdline.txt" "${CMDLINE_EXTRA}"
        mcopy -o -i "${WORK}/out.vfat" "${WORK}/cmdline.txt" ::/cmdline.txt
        CMDLINE_OUT="$(cat "${WORK}/cmdline.txt")"
        echo "    ${CMDLINE_OUT}"
    fi
    step "first-boot files into the boot partition"
    for f in "${SEED_FILES[@]}"; do
        mcopy -o -i "${WORK}/out.vfat" "${SEED}/files/${f}" "::/${f}"
    done
else
    step "extracting the slot files (mtools)"
    mkdir -p "${WORK}/slot"
    mcopy -s -m -n -i "${WORK}/source.vfat" ::/ "${WORK}/slot/"
    [ -n "$(ls -A "${WORK}/slot")" ] || die "the boot slot is empty"
    rm -f "${WORK}/source.vfat"

    if [ -f "${WORK}/slot/boot.img" ]; then
        step "slot already holds boot.img: signing it as-is"
        [ -z "${CMDLINE_EXTRA}" ] || echo "    WARNING: cmdline.txt is inside the prebuilt boot.img; '${CMDLINE_EXTRA}' not applied"
        cp "${WORK}/slot/boot.img" "${WORK}/boot.img"
        boot_img_source="existing"
    else
        if [ -n "${CMDLINE_EXTRA}" ]; then
            step "cmdline.txt"
            [ -f "${WORK}/slot/cmdline.txt" ] || die "the boot slot has no cmdline.txt"
            edit_cmdline "${WORK}/slot/cmdline.txt" "${CMDLINE_EXTRA}"
            CMDLINE_OUT="$(cat "${WORK}/slot/cmdline.txt")"
            echo "    ${CMDLINE_OUT}"
        fi
        # The templates the image put there; the board's own go next to boot.img, where the OS reads them.
        for f in "${SEED_FILES[@]}"; do rm -f "${WORK}/slot/${f}"; done
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
    for f in "${SEED_FILES[@]}"; do need=$(( need + $(stat -c %s "${SEED}/files/${f}") + 4096 )); done
    free_bytes="$(mdir -i "${WORK}/out.vfat" ::/ | awk '/bytes free/ {gsub(/[^0-9]/, ""); print}')"
    [ -n "${free_bytes}" ] && [ "${free_bytes}" -ge "${need}" ] \
        || die "boot.img ($(stat -c %s "${WORK}/boot.img") bytes) and the first-boot files do not fit into the ${SIZE}-byte slot"
    mcopy -m -i "${WORK}/out.vfat" "${WORK}/boot.img" "${WORK}/boot.sig" "${WORK}/config.txt" ::/
    for f in "${SEED_FILES[@]}"; do
        mcopy -i "${WORK}/out.vfat" "${SEED}/files/${f}" "::/${f}"
    done
    rm -rf "${WORK}/slot"
fi

step "self-check of the new slot"
mkdir -p "${WORK}/verify"
for f in "${SEED_FILES[@]}"; do
    mcopy -n -i "${WORK}/out.vfat" "::/${f}" "${WORK}/verify/${f}"
    cmp -s "${WORK}/verify/${f}" "${SEED}/files/${f}" || die "${f} read back differs"
done
if [ "${SIGN}" = 0 ]; then
    if [ -n "${CMDLINE_OUT}" ]; then
        mcopy -n -i "${WORK}/out.vfat" ::/cmdline.txt "${WORK}/verify/cmdline.txt"
        cmp -s "${WORK}/verify/cmdline.txt" "${WORK}/cmdline.txt" || die "cmdline.txt read back differs"
    fi
else
    mcopy -n -i "${WORK}/out.vfat" ::/boot.img ::/boot.sig ::/config.txt "${WORK}/verify/"
    cmp -s "${WORK}/verify/boot.img" "${WORK}/boot.img" || die "boot.img read back differs"
    rpi-eeprom-digest -k "${KEYS}/public.pem" -i "${WORK}/verify/boot.img" -v "${WORK}/verify/boot.sig" \
        || die "boot.sig read back does not verify"
    cmp -s "${WORK}/verify/config.txt" "${WORK}/config.txt" || die "config.txt read back differs"
fi
rm -rf "${WORK}/verify"

step "img2simg -> ${OUT}/${SIMAGE}"
rm -f "${OUT}/${SIMAGE}" "${OUT}/${SIMAGE}".[0-9]* "${OUT}/slot.json"
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
seed_json="$(printf '%s\n' "${SEED_FILES[@]}" | jq -R . | jq -s -c .)"
jq -n --arg simage "${SIMAGE}" --argjson signed "$([ "${SIGN}" = 1 ] && echo true || echo false)" \
    --arg cmdline "${CMDLINE_OUT}" --argjson seed "${seed_json}" --argjson pieces "${pieces_json}" \
    '{simage: $simage, signed: $signed, cmdline: $cmdline, seed: $seed, pieces: $pieces}' > "${OUT}/slot.json"
cat "${OUT}/slot.json"
step "boot-slot done"
