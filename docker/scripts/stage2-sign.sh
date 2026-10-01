#!/bin/bash
# stage2-sign.sh - sign the stage-2 (fastboot gadget) rpiboot files for a board
# whose OTP holds the customer key hash.
#
# Mounts:  /in   ro  boot.img (the gadget), bootfiles.bin (usbboot firmware tar)
#          /keys ro  private.pem, public.pem (RSA-2048)
#          /out  rw
#          /ext  ro  <repo>/external (usbboot + rpi-eeprom submodules)
# Env:     [SOURCE_DATE_EPOCH] (ts line of boot.sig)
# Outputs: /out/boot.sig       rpi-eeprom-digest -k over boot.img, verified with public.pem
#          /out/bootfiles.bin  same tar, same member order, only 2712/bootcode5.bin replaced by
#                              its customer counter-signed version (rpi-sign-bootcode -c 2712 -n 16 -v 0)
# Same commands as usbboot mass-storage-gadget64/sign.sh.
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

EXT="${EXT:-/ext}"
IN="${IN:-/in}"
OUT="${OUT:-/out}"
KEYS="${KEYS:-/keys}"
EEPROM_DIR="${EXT}/usbboot/rpi-eeprom"
MEMBER="2712/bootcode5.bin"

WORK="$(mktemp -d /tmp/stage2.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

stage_tools() {
    local bin="${WORK}/bin" src name
    mkdir -p "${bin}"
    for src in "${EEPROM_DIR}/rpi-eeprom-digest" "${EEPROM_DIR}/tools/rpi-sign-bootcode"; do
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

# Outermost signature block kinds, e.g. "customer:16 rpi:0" (no key material).
sig_chain() {
    local info
    info="$(rpi-sign-bootcode -c 2712 -e "$1")" || return 1
    printf '%s\n' "${info}" | awk '/^sig_type:/ { t = $2 } /^keynum:/ { printf "%s%s:%s", sep, t, $2; sep = " " } END { print "" }'
}

step "stage2-sign"
[ -f "${IN}/boot.img" ] || die "${IN}/boot.img missing"
[ -f "${IN}/bootfiles.bin" ] || die "${IN}/bootfiles.bin missing"
[ -f "${KEYS}/private.pem" ] || die "${KEYS}/private.pem missing"
[ -f "${KEYS}/public.pem" ] || die "${KEYS}/public.pem missing"
[ -d "${OUT}" ] || die "${OUT} is not mounted"
[ -d "${EEPROM_DIR}" ] || die "${EEPROM_DIR} missing: mount <repo>/external at ${EXT}"
stage_tools
rm -f "${OUT}/boot.sig" "${OUT}/bootfiles.bin"

step "boot.sig over boot.img ($(stat -c %s "${IN}/boot.img") bytes)"
rpi-eeprom-digest -k "${KEYS}/private.pem" -i "${IN}/boot.img" -o "${WORK}/boot.sig"
check_rsa_sig "${WORK}/boot.sig"
[ "$(head -n1 "${WORK}/boot.sig")" = "$(sha256sum "${IN}/boot.img" | awk '{print $1}')" ] \
    || die "boot.sig first line is not sha256(boot.img)"
rpi-eeprom-digest -k "${KEYS}/public.pem" -i "${IN}/boot.img" -v "${WORK}/boot.sig" \
    || die "boot.sig does not verify with public.pem"

step "counter-signing ${MEMBER} inside bootfiles.bin"
tar -tf "${IN}/bootfiles.bin" > "${WORK}/members.txt"
grep -qx "${MEMBER}" "${WORK}/members.txt" || die "bootfiles.bin has no ${MEMBER}"
[ "$(sort "${WORK}/members.txt" | uniq -d | wc -l)" -eq 0 ] || die "bootfiles.bin has duplicate members"
# Keep the archive's owner so the re-packed tar differs from the original only in bootcode5.bin.
# (awk consumes all input: head would SIGPIPE tar under pipefail)
owner="$(tar --numeric-owner -tvf "${IN}/bootfiles.bin" | awk 'NR == 1 {print $2}')"
names="$(tar -tvf "${IN}/bootfiles.bin" | awk 'NR == 1 {print $2}')"
uid="${owner%%/*}"; gid="${owner##*/}"
uname="${names%%/*}"; gname="${names##*/}"
mkdir -p "${WORK}/tree"
tar -C "${WORK}/tree" -xpf "${IN}/bootfiles.bin"
before="$(sig_chain "${WORK}/tree/${MEMBER}")"
echo "    ${MEMBER} before: ${before}"
case "${before}" in
    customer:*) die "${MEMBER} is already counter-signed; pass the original usbboot firmware/bootfiles.bin" ;;
esac
rpi-sign-bootcode -c 2712 -i "${WORK}/tree/${MEMBER}" -o "${WORK}/bootcode5.bin.signed" \
    -n 16 -v 0 -k "${KEYS}/private.pem"
after="$(sig_chain "${WORK}/bootcode5.bin.signed")"
echo "    ${MEMBER} after:  ${after}"
case "${after}" in customer:16\ rpi:*) ;; *) die "counter-signed ${MEMBER} has signature chain '${after}'" ;; esac
touch -r "${WORK}/tree/${MEMBER}" "${WORK}/bootcode5.bin.signed"
chmod --reference="${WORK}/tree/${MEMBER}" "${WORK}/bootcode5.bin.signed"
mv -f "${WORK}/bootcode5.bin.signed" "${WORK}/tree/${MEMBER}"

owner_args=()
if [[ "${uid}" =~ ^[0-9]+$ ]] && [[ "${gid}" =~ ^[0-9]+$ ]]; then
    [ -n "${uname}" ] && [[ ! "${uname}" =~ ^[0-9]+$ ]] && uid="${uname}:${uid}"
    [ -n "${gname}" ] && [[ ! "${gname}" =~ ^[0-9]+$ ]] && gid="${gname}:${gid}"
    owner_args=(--owner="${uid}" --group="${gid}")
fi
tar -C "${WORK}/tree" --format=gnu --no-recursion "${owner_args[@]}" \
    -cf "${WORK}/bootfiles.bin" -T "${WORK}/members.txt"

step "self-check"
tar -tf "${WORK}/bootfiles.bin" > "${WORK}/members.new"
cmp -s "${WORK}/members.txt" "${WORK}/members.new" || die "re-packed bootfiles.bin lists different members / order"
mkdir -p "${WORK}/orig" "${WORK}/new"
tar -C "${WORK}/orig" -xf "${IN}/bootfiles.bin"
tar -C "${WORK}/new" -xf "${WORK}/bootfiles.bin"
changed=0
while IFS= read -r m; do
    [ -f "${WORK}/orig/${m}" ] || continue
    if ! cmp -s "${WORK}/orig/${m}" "${WORK}/new/${m}"; then
        [ "${m}" = "${MEMBER}" ] || die "member ${m} changed unexpectedly"
        changed=$((changed + 1))
    fi
done < "${WORK}/members.txt"
[ "${changed}" -eq 1 ] || die "expected exactly ${MEMBER} to change, ${changed} members changed"
echo "    $(wc -l < "${WORK}/members.txt") members, same order, only ${MEMBER} changed"

cp "${WORK}/boot.sig" "${WORK}/bootfiles.bin" "${OUT}/"
ls -l "${OUT}"
step "stage2-sign done"
