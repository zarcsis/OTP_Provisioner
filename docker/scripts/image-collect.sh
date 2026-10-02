#!/bin/bash
# image-collect.sh - copy one rpi-image-gen IDP set out of the image build volume.
#
# Mounts:  /work ro  the image work volume (rpi-image-gen -B /work)
#          /out  rw  the image set directory being built (<set>.partial)
# Env:     MAX_PIECE=<bytes> (default 268435456 = rpi-fastbootd max-download-size)
# Reads:   /work/bootstrap/final.env (IGconf_image_outputdir, IGconf_image_name, IGconf_deploy_dir),
#          <outputdir>/image.json and every layout.partitionimages[*].simage next to it.
#          When the output dir is gone (rpi-image-gen clean) but the deploy dir still holds
#          image.json.zst and <simage>.zst from the same build, those are decompressed instead.
# Writes:  /out/image.json, /out/<simage> (or /out/<simage>.0, .1, ... when larger than MAX_PIECE,
#          split with simg2simg into self-contained sparse files), /out/collect.json:
#          {"image_name","outputdir","image_version","device_class","storage_type",
#           "simages":{"<simage>":{"size":N,"pieces":[{"file","size","sha256"}]}}}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

WORK_DIR="${WORK_DIR:-/work}"
OUT="${OUT:-/out}"
MAX_PIECE="${MAX_PIECE:-268435456}"
FINAL_ENV="${WORK_DIR}/bootstrap/final.env"

TMP="$(mktemp -d /tmp/image-collect.XXXXXX)"
trap 'rm -rf "${TMP}"' EXIT

# Value of KEY from final.env (KEY="value" or KEY=value); never sources the file.
env_get() {
    awk -v k="$1" '
        index($0, k "=") == 1 {
            v = substr($0, length(k) + 2)
            if (v ~ /^".*"$/ || v ~ /^'"'"'.*'"'"'$/) v = substr(v, 2, length(v) - 2)
            val = v
        }
        END { print val }' "${FINAL_ENV}"
}

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

# ---------------------------------------------------------------------------
step "image-collect: MAX_PIECE=${MAX_PIECE}"
[[ "${MAX_PIECE}" =~ ^[0-9]+$ ]] && [ "${MAX_PIECE}" -ge 1048576 ] || die "MAX_PIECE must be an integer >= 1048576"
[ -d "${WORK_DIR}" ] || die "${WORK_DIR} is not mounted (the image work volume)"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
[ -f "${FINAL_ENV}" ] || die "${FINAL_ENV} not found: has the OS image been built into this volume?"

IMAGE_NAME="$(env_get IGconf_image_name)"
OUTPUTDIR="$(env_get IGconf_image_outputdir)"
DEPLOY_DIR="$(env_get IGconf_deploy_dir)"
[ -n "${IMAGE_NAME}" ] || die "IGconf_image_name missing from final.env"
[ -n "${OUTPUTDIR}" ] || die "IGconf_image_outputdir missing from final.env"
case "${OUTPUTDIR}" in "${WORK_DIR}"/*) ;; *) die "IGconf_image_outputdir '${OUTPUTDIR}' is not under ${WORK_DIR}" ;; esac
echo "    image: ${IMAGE_NAME}"
echo "    outputdir: ${OUTPUTDIR}"

source_kind=""
if [ -f "${OUTPUTDIR}/image.json" ]; then
    source_kind="outputdir"
    cp "${OUTPUTDIR}/image.json" "${TMP}/image.json"
elif [ -n "${DEPLOY_DIR}" ] && [ -f "${DEPLOY_DIR}/image.json.zst" ]; then
    source_kind="deploy"
    echo "    ${OUTPUTDIR}/image.json missing; using the deploy dir ${DEPLOY_DIR}"
    zstd -q -d -c "${DEPLOY_DIR}/image.json.zst" > "${TMP}/image.json"
else
    die "no image.json in ${OUTPUTDIR} (nor image.json.zst in '${DEPLOY_DIR}'): build the image first"
fi
jq -e '.layout.partitionimages | type == "object"' "${TMP}/image.json" >/dev/null \
    || die "image.json has no layout.partitionimages object"

IMAGE_VERSION="$(jq -r '.IGmeta.IGconf_image_version // ""' "${TMP}/image.json")"
DEVICE_CLASS="$(jq -r '.IGmeta.IGconf_device_class // ""' "${TMP}/image.json")"
STORAGE_TYPE="$(jq -r '.IGmeta.IGconf_device_storage_type // ""' "${TMP}/image.json")"
mapfile -t SIMAGES < <(jq -r '.layout.partitionimages[] | .simage // empty' "${TMP}/image.json" | awk 'NF && !seen[$0]++')
[ "${#SIMAGES[@]}" -ge 1 ] || die "image.json lists no simage files"
echo "    version=${IMAGE_VERSION} device_class=${DEVICE_CLASS} storage_type=${STORAGE_TYPE}"
echo "    simages: ${SIMAGES[*]}"

for s in "${SIMAGES[@]}"; do
    case "${s}" in */*|.*|"") die "unsafe simage name '${s}' in image.json" ;; esac
    if [ "${source_kind}" = outputdir ]; then
        [ -f "${OUTPUTDIR}/${s}" ] || die "${OUTPUTDIR}/${s} (named in image.json) is missing"
    else
        [ -f "${DEPLOY_DIR}/${s}.zst" ] || die "${DEPLOY_DIR}/${s}.zst (named in image.json) is missing"
    fi
done

step "copying to ${OUT}"
rm -f "${OUT}/collect.json"
cp "${TMP}/image.json" "${OUT}/image.json"
simages_json="{}"
for s in "${SIMAGES[@]}"; do
    rm -f "${OUT}/${s}" "${OUT}/${s}".[0-9]*
    if [ "${source_kind}" = outputdir ]; then
        cp "${OUTPUTDIR}/${s}" "${OUT}/${s}"
    else
        zstd -q -d -c "${DEPLOY_DIR}/${s}.zst" > "${OUT}/${s}"
    fi
    size="$(stat -c %s "${OUT}/${s}")"
    geom="$(sparse_geometry "${OUT}/${s}")" || die "${s} is not an Android sparse image"
    echo "    ${s}: ${size} bytes, ${geom% *} blocks of ${geom#* } bytes"
    split_sparse "${OUT}/${s}" > "${TMP}/pieces.txt"
    pieces_json="[]"
    while IFS= read -r p; do
        psize="$(stat -c %s "${OUT}/${p}")"
        psha="$(sha256sum "${OUT}/${p}" | awk '{print $1}')"
        echo "      ${p}: ${psize} bytes sha256 ${psha}"
        pieces_json="$(jq -c --arg f "${p}" --argjson sz "${psize}" --arg h "${psha}" \
            '. + [{file: $f, size: $sz, sha256: $h}]' <<< "${pieces_json}")"
    done < "${TMP}/pieces.txt"
    simages_json="$(jq -c --arg s "${s}" --argjson sz "${size}" --argjson p "${pieces_json}" \
        '. + {($s): {size: $sz, pieces: $p}}' <<< "${simages_json}")"
done

jq -n \
    --arg image_name "${IMAGE_NAME}" \
    --arg outputdir "${OUTPUTDIR}" \
    --arg image_version "${IMAGE_VERSION}" \
    --arg device_class "${DEVICE_CLASS}" \
    --arg storage_type "${STORAGE_TYPE}" \
    --arg source "${source_kind}" \
    --argjson simages "${simages_json}" \
    '{image_name: $image_name, outputdir: $outputdir, image_version: $image_version,
      device_class: $device_class, storage_type: $storage_type, source: $source,
      simages: $simages}' > "${OUT}/collect.json"
cat "${OUT}/collect.json"
step "image-collect done"
