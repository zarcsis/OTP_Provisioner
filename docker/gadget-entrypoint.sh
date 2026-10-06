#!/bin/bash
# gadget-entrypoint: build the pi-gen-micro "fastboot" gadget inside otp-gadget-builder.
#
# Mounts:  /src  ro  <repo>/external/pi-gen-micro (a Windows checkout is fine)
#          /work rw  named volume (staged sources + build tree + apt cache survive runs)
#          /out  rw  output dir
# Env:     PGM_TARGETS (default pi5-family)   PGM_COMMIT (pi-gen-micro commit, from the host)
# Outputs: /out/fastboot-gadget-${PGM_TARGETS}.img  (= /work/build/boot.img)
#          /out/build-info.json {"targets","built","pi_gen_micro_commit","fastbootd_deb","fastbootd_version",
#                                "helpers","size"}
# The gadget gets our rpi-fastbootd (/opt/otp-fastbootd, built by gadget.Dockerfile with
# fastbootd/otp-station.patch) instead of the deb pi-gen-micro vendors; the build fails if any other
# rpi-fastbootd ends up in it.
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

# Our helper packages (docker/gadget-helpers, baked into this image at /opt/otp-gadget-helpers):
# copy each into helper-packages/ (pi-gen-micro builds them into its local apt repo) and install it
# through the fastboot configuration's packages.list.
HELPERS="${PGM_HELPERS:-/opt/otp-gadget-helpers}"
PKGLIST="${STAGE}/configurations/fastboot/packages.list"
HELPER_PKGS=()
if [ -d "${HELPERS}" ]; then
    for d in "${HELPERS}"/*/; do
        [ -f "${d}control" ] || continue
        name="$(basename "${d}")"
        rsync -a --delete --chmod=D0755,F0644 "${d}" "${STAGE}/helper-packages/${name}/"
        find "${STAGE}/helper-packages/${name}" -type f -exec sed -i 's/\r$//' {} +
        pkg="$(sed -n 's/^Package: *//p' "${STAGE}/helper-packages/${name}/control")"
        [ -n "${pkg}" ] || die "helper package ${name} has no Package: line"
        if [ -s "${PKGLIST}" ] && [ -n "$(tail -c1 "${PKGLIST}")" ]; then echo >> "${PKGLIST}"; fi
        grep -qx "${pkg}" "${PKGLIST}" || echo "${pkg}" >> "${PKGLIST}"
        HELPER_PKGS+=("${pkg}")
    done
fi
echo "    helper packages: ${HELPER_PKGS[*]:-none}"
# rpi-fastbootd: ours in place of the vendored deb, pinned so no archive version can win over it.
OTP_FASTBOOTD="${PGM_FASTBOOTD:-/opt/otp-fastbootd}"
FASTBOOTD_DEB="$(find "${OTP_FASTBOOTD}" -maxdepth 1 -name 'rpi-fastbootd_*.deb' -printf '%f\n' 2>/dev/null | sort | tail -n1)"
[ -n "${FASTBOOTD_DEB}" ] || die "${OTP_FASTBOOTD}/rpi-fastbootd_*.deb missing: rebuild the gadget builder image"
FASTBOOTD_VERSION="$(dpkg-deb -f "${OTP_FASTBOOTD}/${FASTBOOTD_DEB}" Version)"
[ -n "$(find "${STAGE}/internal/packages" -maxdepth 1 -name 'rpi-fastbootd_*.deb' -print -quit)" ] \
    || die "internal/packages/rpi-fastbootd_*.deb missing from the pi-gen-micro checkout"
rm -f "${STAGE}"/internal/packages/rpi-fastbootd_*.deb
cp "${OTP_FASTBOOTD}/${FASTBOOTD_DEB}" "${STAGE}/internal/packages/"
mkdir -p "${STAGE}/internal/apt/preferences.d"
printf 'Package: rpi-fastbootd\nPin: version %s\nPin-Priority: 1001\n' "${FASTBOOTD_VERSION}" \
    > "${STAGE}/internal/apt/preferences.d/50-otp-fastbootd.pref"
echo "    rpi-fastbootd: ${FASTBOOTD_DEB} (station build, replaces the vendored deb)"

step "pi-gen-micro fastboot ${TARGETS} (in ${BUILD})"
mkdir -p "${BUILD}"
cd "${BUILD}"
rm -f boot.img 2710_bootfiles.bin
# pi-gen-micro copies internal/packages into packages/ without --delete: drop any rpi-fastbootd an
# earlier build left there (the vendored one), so only the station build is in the local repo.
rm -f "${BUILD}"/packages/rpi-fastbootd_*.deb
# pi-gen-micro's local repo (helper packages + vendored debs) has a Release file without hashes or a
# date, so "apt-get update" against the apt lists kept in this volume never notices a new or changed
# package ("Unable to locate package"). Drop the cached index of that repo before every build.
rm -f "${BUILD}"/apt_lists/*_build_packages_*
env CONFIGURATION_ROOT="${STAGE}/configurations/" \
    APT_DPKG_CFG="${STAGE}/internal/apt" \
    PREBUILTS_DIR="${STAGE}/internal/prebuilts" \
    HELPER_PACKAGES_DIR="${STAGE}/helper-packages" \
    LIB_DIR="${STAGE}/internal/lib" \
    PATH="${STAGE}:/native/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "${STAGE}/pi-gen-micro" fastboot "${TARGETS}"
[ -s "${BUILD}/boot.img" ] || die "pi-gen-micro finished without ${BUILD}/boot.img"
# pi-gen-micro keeps two dpkg databases: dpkg_admin (its first phase) and the rootfs's own (build/var/lib/dpkg,
# where the configuration's packages go). rpi-fastbootd must be in exactly one of them, as the station build,
# and the daemon packed into the gadget must be the patched one.
installed=""
for adm in "${BUILD}/build/var/lib/dpkg" "${BUILD}/dpkg_admin"; do
    v="$(dpkg-query --admindir="${adm}" -W -f '${Version}' rpi-fastbootd 2>/dev/null || true)"
    if [ -n "${v}" ]; then installed="${installed}${installed:+ }${v}"; fi
done
[ "${installed}" = "${FASTBOOTD_VERSION}" ] \
    || die "the gadget has rpi-fastbootd '${installed:-none}', not the station build ${FASTBOOTD_VERSION}"
grep -q 'oem cryptcheck' "${BUILD}/build/usr/bin/fastbootd" \
    || die "${BUILD}/build/usr/bin/fastbootd is not the station build"
echo "    rpi-fastbootd in the gadget: ${installed}"

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
    --arg fbver "${FASTBOOTD_VERSION}" \
    --arg helpers "${HELPER_PKGS[*]:-}" \
    --argjson size "${SIZE}" \
    '{targets: $targets, built: $built, pi_gen_micro_commit: $commit, fastbootd_deb: $deb,
      fastbootd_version: $fbver, helpers: ($helpers | split(" ") | map(select(length > 0))), size: $size}' \
    > "${OUT}/build-info.json"
cat "${OUT}/build-info.json"
step "gadget done in $(( $(date -u +%s) - START )) s: ${OUT}/${IMG} (${SIZE} bytes)"
