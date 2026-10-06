#!/bin/bash
# root-luks.sh - one board's encrypted root: a LUKS2 container holding the image's root file system,
# built here so that only ciphertext leaves the station. The board writes it raw to its root partition.
#
# The container is what rpi-fastbootd's IDP would have made on the board ("oem idpwrite" with a luks2
# block), except that the station builds it: keyslot 0 opens with the board's key, the 64 lowercase hex
# characters of HMAC-SHA256(OTP device key, SD CID + "\n") that the board's initramfs derives with
# rpi-fw-crypto (cryptroot keyscript "hwkey"), so the board unlocks it at every boot.
#
# Mounts:  /in   ro  the image set (the plain root pieces named by PIECES)
#          /keys ro  luks.key (keyslot 0 passphrase, no newline); recovery.key (optional, keyslot 1)
#          /out  rw
# Env:     PIECES="<piece> ..." (file names in /in, flashing order)   OUT_SIMAGE=<name> (root.luks.sparse)
#          LABEL (OSROOT_CRYPT)   UUID (the LUKS UUID of the image's provisioning map)
#          DATA_OFFSET=<bytes> (16777216)   SECTOR_SIZE (4096)   MAX_PIECE=<bytes> (268435456)
# Steps:   random 64-byte volume key; cryptsetup luksFormat on a file (LUKS2, aes-xts-plain64, 512-bit key,
#          the label and UUID, low-cost argon2id: the passphrases are 256-bit secrets); luksAddKey for
#          recovery.key; checks: every passphrase opens the header and yields that volume key;
#          luks_encrypt.py: header + the encrypted file system as one sparse image; simg2simg split.
# Outputs: /out/<OUT_SIMAGE> or /out/<OUT_SIMAGE>.<n>, /out/luks.json
#          {"simage","uuid","label","data_offset","sector_size","keyslots","fs_bytes","pieces":[{"file","size"}]}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

IN="${IN:-/in}"
OUT="${OUT:-/out}"
KEYS="${KEYS:-/keys}"
SCRIPTS="${SCRIPTS:-/scripts}"
PIECES="${PIECES:-}"
OUT_SIMAGE="${OUT_SIMAGE:-root.luks.sparse}"
LABEL="${LABEL:-OSROOT_CRYPT}"
UUID="${UUID:-}"
DATA_OFFSET="${DATA_OFFSET:-16777216}"
SECTOR_SIZE="${SECTOR_SIZE:-4096}"
MAX_PIECE="${MAX_PIECE:-268435456}"
PBKDF=(--pbkdf argon2id --pbkdf-memory 65536 --pbkdf-parallel 1 --pbkdf-force-iterations 4)

WORK="$(mktemp -d /tmp/root-luks.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p /run/cryptsetup

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

# The volume key cryptsetup yields for the header with this passphrase file (lowercase hex).
dump_volume_key() {
    cryptsetup luksDump --batch-mode --dump-volume-key --key-file "$1" "${WORK}/hdr.img" \
        | awk '/^MK dump:/ {f=1; sub(/^MK dump:/, "")} f && NF {gsub(/[ \t]/, ""); printf "%s", $0} /^$/ {f=0}' \
        | tr 'A-F' 'a-f'
}

# ---------------------------------------------------------------------------
step "root-luks: ${OUT_SIMAGE} label=${LABEL} uuid=${UUID} data offset ${DATA_OFFSET} sector ${SECTOR_SIZE}"
[ -n "${PIECES}" ] || die "PIECES is not set"
[ -n "${UUID}" ] || die "UUID is not set"
case "${OUT_SIMAGE}" in */*|.*|"") die "OUT_SIMAGE must be a bare file name" ;; esac
[[ "${DATA_OFFSET}" =~ ^[0-9]+$ ]] && [ $((DATA_OFFSET % 1048576)) -eq 0 ] && [ "${DATA_OFFSET}" -ge 16777216 ] \
    || die "DATA_OFFSET must be a multiple of 1 MiB, at least 16 MiB"
[[ "${MAX_PIECE}" =~ ^[0-9]+$ ]] && [ "${MAX_PIECE}" -ge 1048576 ] || die "MAX_PIECE must be an integer >= 1048576"
[ -s "${KEYS}/luks.key" ] || die "${KEYS}/luks.key missing"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
inputs=()
for p in ${PIECES}; do
    case "${p}" in */*|.*) die "unsafe piece name '${p}'" ;; esac
    [ -f "${IN}/${p}" ] || die "${IN}/${p} missing"
    inputs+=("${IN}/${p}")
done
fs_geom="$(sparse_geometry "${inputs[0]}")"
fs_bytes=$(( ${fs_geom% *} * ${fs_geom#* } ))
echo "    file system: ${fs_bytes} bytes in ${#inputs[@]} piece(s)"

step "volume key and LUKS2 header"
head -c 64 /dev/urandom > "${WORK}/vk"
truncate -s $((DATA_OFFSET + 1048576)) "${WORK}/hdr.img"
cryptsetup luksFormat --batch-mode --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha256 \
    --sector-size "${SECTOR_SIZE}" --offset $((DATA_OFFSET / 512)) --label "${LABEL}" --uuid "${UUID}" \
    "${PBKDF[@]}" --volume-key-file "${WORK}/vk" --key-file "${KEYS}/luks.key" "${WORK}/hdr.img" \
    || die "cryptsetup luksFormat failed"
slots='[0]'
if [ -s "${KEYS}/recovery.key" ]; then
    cryptsetup luksAddKey --batch-mode "${PBKDF[@]}" --key-slot 1 --key-file "${KEYS}/luks.key" \
        "${WORK}/hdr.img" "${KEYS}/recovery.key" || die "cryptsetup luksAddKey (recovery) failed"
    slots='[0, 1]'
fi

step "self-check of the header"
want="$(od -An -v -tx1 "${WORK}/vk" | tr -d ' \n')"
for k in luks.key recovery.key; do
    [ -s "${KEYS}/${k}" ] || continue
    got="$(dump_volume_key "${KEYS}/${k}")" || die "${k} does not open the header"
    [ "${got}" = "${want}" ] || die "${k} opens the header but yields another volume key"
    echo "    ${k}: opens the header, same volume key"
done
cryptsetup luksDump "${WORK}/hdr.img" | grep -E "^(Label|UUID)|cipher:|sector:|offset:" | sed 's/^/    /' || true

step "encrypting the file system"
python3 "${SCRIPTS}/luks_encrypt.py" --header "${WORK}/hdr.img" --volume-key "${WORK}/vk" \
    --data-offset "${DATA_OFFSET}" --sector-size "${SECTOR_SIZE}" --out "${WORK}/${OUT_SIMAGE}" "${inputs[@]}" \
    || die "luks_encrypt.py failed"
rm -f "${WORK}/vk"
geom="$(sparse_geometry "${WORK}/${OUT_SIMAGE}")"
[ $(( ${geom% *} * ${geom#* } )) -eq $((DATA_OFFSET + fs_bytes)) ] || die "the container covers ${geom}, expected $((DATA_OFFSET + fs_bytes)) bytes"

step "pieces -> ${OUT}"
rm -f "${OUT}/${OUT_SIMAGE}" "${OUT}/${OUT_SIMAGE}".[0-9]* "${OUT}/luks.json"
mv "${WORK}/${OUT_SIMAGE}" "${OUT}/${OUT_SIMAGE}"
split_sparse "${OUT}/${OUT_SIMAGE}" > "${WORK}/pieces.txt"
mapfile -t pieces < "${WORK}/pieces.txt"
[ "${#pieces[@]}" -ge 1 ] || die "no output pieces"
pieces_json="[]"
for p in "${pieces[@]}"; do
    pieces_json="$(jq -c --arg f "${p}" --argjson s "$(stat -c %s "${OUT}/${p}")" '. + [{file: $f, size: $s}]' <<< "${pieces_json}")"
    echo "    ${p}: $(stat -c %s "${OUT}/${p}") bytes"
done
jq -n --arg simage "${OUT_SIMAGE}" --arg uuid "${UUID}" --arg label "${LABEL}" --argjson data_offset "${DATA_OFFSET}" \
    --argjson sector_size "${SECTOR_SIZE}" --argjson keyslots "${slots}" --argjson fs_bytes "${fs_bytes}" \
    --argjson pieces "${pieces_json}" \
    '{simage: $simage, uuid: $uuid, label: $label, data_offset: $data_offset, sector_size: $sector_size,
      keyslots: $keyslots, fs_bytes: $fs_bytes, pieces: $pieces}' > "${OUT}/luks.json"
cat "${OUT}/luks.json"
step "root-luks done"
