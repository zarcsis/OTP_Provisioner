#!/bin/bash
# gadget-entrypoint: build the pi-gen-micro "fastboot" gadget inside otp-gadget-builder.
#
# Mounts:  /src  ro  <repo>/external/pi-gen-micro (a Windows checkout is fine)
#          /work rw  named volume (staged sources + build tree + apt cache survive runs)
#          /out  rw  output dir
# Env:     PGM_TARGETS (default pi5-family)   PGM_COMMIT (pi-gen-micro commit, from the host)
# Outputs: /out/fastboot-gadget-${PGM_TARGETS}.img  (= /work/build/boot.img)
#          /out/build-info.json {"targets","built","pi_gen_micro_commit","fastbootd_deb","size"}
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

SRC="${PGM_SRC:-/src}"
WORK="${PGM_WORK:-/work}"
OUT="${PGM_OUT:-/out}"
TARGETS="${PGM_TARGETS:-pi5-family}"
COMMIT="${PGM_COMMIT:-unknown}"
STAGE="${WORK}/src"
BUILD="${WORK}/build"
START="$(date -u +%s)"

[[ "${TARGETS}" =~ ^[A-Za-z0-9,-]+$ ]] || die "PGM_TARGETS must be a comma-separated device list, got '${TARGETS}'"
[ -x "${SRC}/pi-gen-micro" ] || [ -f "${SRC}/pi-gen-micro" ] || die "${SRC}/pi-gen-micro not found: mount external/pi-gen-micro at ${SRC}"
[ -d "${SRC}/configurations/fastboot" ] || die "${SRC}/configurations/fastboot missing"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
[ "$(uname -m)" = aarch64 ] || die "this builder must run as linux/arm64 (uname -m = $(uname -m))"
mkdir -p "${WORK}"

step "staging ${SRC} -> ${STAGE} (CR stripped from text files, modes normalised)"
mkdir -p "${STAGE}"
rsync -a --delete --exclude '/.git' --chmod=D0755,F0644 "${SRC}/" "${STAGE}/"
# CRLF from a Windows checkout would break the scripts and, worse, end up in package
# names (packages.list) and the kernel cmdline. Never touch binaries (.deb, .tga, ...).
crlf=0
while IFS= read -r -d '' f; do
    case "${f}" in "${STAGE}/internal/packages/"*) continue ;; esac
    case "$(file -b --mime-type "${f}")" in
        text/*|application/x-shellscript|application/json|inode/x-empty)
            sed -i 's/\r$//' "${f}"; crlf=$((crlf + 1)) ;;
    esac
done < <(grep -rIlZ $'\r' "${STAGE}" 2>/dev/null || true)
echo "    CR stripped from ${crlf} file(s)"
# Executable bits are lost on a Windows bind mount (everything reads 0777): restore them
# for scripts (shebang) and for what pi-gen-micro executes directly.
while IFS= read -r -d '' f; do
    if [ "$(head -c2 "${f}")" = '#!' ]; then chmod 0755 "${f}"; fi
done < <(find "${STAGE}" -type f -not -path "${STAGE}/internal/packages/*" -print0)
find "${STAGE}/configurations" -type f \( -name installer_scripts.list -o -name post_creation.sh -o -name '*.sh' \) \
    -exec chmod 0755 {} +
[ -x "${STAGE}/pi-gen-micro" ] || die "staged pi-gen-micro is not executable"
FASTBOOTD_DEB="$(find "${STAGE}/internal/packages" -maxdepth 1 -name 'rpi-fastbootd_*.deb' -printf '%f\n' | sort | tail -n1)"
[ -n "${FASTBOOTD_DEB}" ] || die "internal/packages/rpi-fastbootd_*.deb missing from the pi-gen-micro checkout"
echo "    rpi-fastbootd: ${FASTBOOTD_DEB}"

step "pi-gen-micro fastboot ${TARGETS} (in ${BUILD})"
mkdir -p "${BUILD}"
cd "${BUILD}"
rm -f boot.img 2710_bootfiles.bin
env CONFIGURATION_ROOT="${STAGE}/configurations/" \
    APT_DPKG_CFG="${STAGE}/internal/apt" \
    PREBUILTS_DIR="${STAGE}/internal/prebuilts" \
    HELPER_PACKAGES_DIR="${STAGE}/helper-packages" \
    LIB_DIR="${STAGE}/internal/lib" \
    PATH="${STAGE}:/native/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "${STAGE}/pi-gen-micro" fastboot "${TARGETS}"
[ -s "${BUILD}/boot.img" ] || die "pi-gen-micro finished without ${BUILD}/boot.img"

step "copying the gadget to ${OUT}"
IMG="fastboot-gadget-${TARGETS}.img"
cp -f "${BUILD}/boot.img" "${OUT}/${IMG}.tmp"
mv -f "${OUT}/${IMG}.tmp" "${OUT}/${IMG}"
SIZE="$(stat -c %s "${OUT}/${IMG}")"
jq -n \
    --arg targets "${TARGETS}" \
    --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg commit "${COMMIT}" \
    --arg deb "${FASTBOOTD_DEB}" \
    --argjson size "${SIZE}" \
    '{targets: $targets, built: $built, pi_gen_micro_commit: $commit, fastbootd_deb: $deb, size: $size}' \
    > "${OUT}/build-info.json"
cat "${OUT}/build-info.json"
step "gadget done in $(( $(date -u +%s) - START )) s: ${OUT}/${IMG} (${SIZE} bytes)"
