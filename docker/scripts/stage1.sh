#!/bin/bash
# stage1.sh - build the stage-1 rpiboot directory (recovery.bin + EEPROM image).
#
# Mounts:  /ext  ro  <repo>/external (usbboot + rpi-eeprom submodules)
#          /out  rw  output dir; must already hold boot.conf and config.txt (written by the server)
#          /keys ro  signed mode only: private.pem, public.pem (RSA-2048)
# Env:     MODE=unsigned|signed   CHANNEL=default|latest   SIGN_RECOVERY=0|1   [SOURCE_DATE_EPOCH]
#          CHIP=2712|2711 (default 2712): the board's SoC (firmware-<CHIP>, second stage, EEPROM size)
#          LOCKED=0|1  signed mode: the board's OTP already holds (or is assumed to hold) this key hash, so
#                      config.txt has no program_pubkey=1 (a BCM2712 also needs SIGN_RECOVERY=1 then)
#          EXPECT_CKH=<64 hex>  signed mode only, required: the customer key hash the server expects
#                               (what program_pubkey=1 burns into OTP); public.pem and the key embedded
#                               in pieeprom.bin must both hash to it
# Outputs: /out/bootcode5.bin  (CHIP=2712) recovery.bin (counter-signed when SIGN_RECOVERY=1)
#          /out/bootcode4.bin  (CHIP=2711) recovery.bin as it is: the BCM2711 boot ROM checks only Raspberry Pi's
#                              signature, locked or not (usbboot docs/secure-boot.md)
#          /out/pieeprom.bin   EEPROM image with boot.conf (signed mode: signed config + public key; on a BCM2712
#                              also customer counter-signed bootcode/bootsys)
#          /out/pieeprom.sig   sha256 + ts of pieeprom.bin
#          /out/build-info.json
# config.txt is never modified. Uses the official usbboot tools/update-pieeprom.sh.
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "==> $*"; }

EXT="${EXT:-/ext}"
OUT="${OUT:-/out}"
KEYS="${KEYS:-/keys}"
EEPROM_DIR="${EXT}/usbboot/rpi-eeprom"
MODE="${MODE:-unsigned}"
CHANNEL="${CHANNEL:-default}"
SIGN_RECOVERY="${SIGN_RECOVERY:-0}"
CHIP="${CHIP:-2712}"
LOCKED="${LOCKED:-}"
EXPECT_CKH="$(printf '%s' "${EXPECT_CKH:-}" | tr 'A-F' 'a-f')"
case "${CHIP}" in
    2712) SECOND_STAGE=bootcode5.bin; PIEEPROM_BYTES=2097152 ;;
    2711) SECOND_STAGE=bootcode4.bin; PIEEPROM_BYTES=524288 ;;
    *) die "CHIP must be 2712 or 2711, got '${CHIP}'" ;;
esac
# Before LOCKED existed, a signed BCM2712 run on a locked board said so with SIGN_RECOVERY=1 alone.
[ -n "${LOCKED}" ] || LOCKED="${SIGN_RECOVERY}"

WORK="$(mktemp -d /tmp/stage1.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# Stage CR-free, executable copies of the real tools (never the usbboot/tools git
# symlinks, which a Windows checkout may have turned into small text files).
stage_tools() {
    local bin="${WORK}/bin" src name
    mkdir -p "${bin}"
    for src in "${EEPROM_DIR}/rpi-eeprom-config" "${EEPROM_DIR}/rpi-eeprom-digest" \
               "${EEPROM_DIR}/tools/rpi-sign-bootcode" "${EXT}/usbboot/tools/update-pieeprom.sh"; do
        [ -f "${src}" ] || die "tool not found: ${src} (are the submodules checked out?)"
        [ "$(stat -c %s "${src}")" -gt 200 ] || die "tool ${src} looks like an unresolved git symlink"
        name="$(basename "${src}")"
        sed 's/\r$//' "${src}" > "${bin}/${name}"
        chmod 0755 "${bin}/${name}"
    done
    export PATH="${bin}:${EEPROM_DIR}:${EEPROM_DIR}/tools:${PATH}"
}

# Exactly one "rsa2048: <512 hex>" line.
check_rsa_sig() {
    local sig="$1" hex
    hex="$(sed -n 's/^rsa2048:[[:space:]]*//p' "${sig}" | tr -d '\r\n')"
    [ -n "${hex}" ] || die "$(basename "${sig}"): no rsa2048 signature"
    [ "${#hex}" -eq 512 ] || die "$(basename "${sig}"): rsa2048 signature has ${#hex} hex chars, expected 512"
    case "${hex}" in *[!0-9a-fA-F]*) die "$(basename "${sig}"): rsa2048 signature is not hex" ;; esac
}

# sha256(n as 256 LE bytes || e as 8 LE bytes) - what recovery.bin burns into OTP.
customer_key_hash() {
    python3 - "$1" <<'EOF'
import hashlib, sys
from Cryptodome.PublicKey import RSA
k = RSA.importKey(open(sys.argv[1]).read())
if k.size_in_bits() != 2048:
    sys.exit("RSA key must be 2048 bit, got %d" % k.size_in_bits())
print(hashlib.sha256(k.n.to_bytes(256, "little") + k.e.to_bytes(8, "little")).hexdigest())
EOF
}

# Prints the sig_type/keynum lines of rpi-sign-bootcode -e (no key material). BCM2712 images only.
sig_summary() {
    local info
    info="$(rpi-sign-bootcode -c 2712 -e "$1")"
    printf '%s\n' "${info}" | grep -E '^(sig_type|keynum|version):' | paste -sd' ' -
}

# The outermost signature block is a customer one with keynum 16. BCM2712 images only.
is_customer_signed() {
    local info
    info="$(rpi-sign-bootcode -c 2712 -e "$1")" || return 1
    printf '%s\n' "${info}" | awk '
        /^sig_type:/ { n++; t[n] = $2 }
        /^keynum:/   { k[n] = $2 }
        END { exit !(n >= 2 && t[1] == "customer" && k[1] == 16 && t[n] == "rpi") }'
}

# ---------------------------------------------------------------------------
step "stage1: CHIP=${CHIP} MODE=${MODE} CHANNEL=${CHANNEL} SIGN_RECOVERY=${SIGN_RECOVERY} LOCKED=${LOCKED}"
case "${MODE}" in unsigned|signed) ;; *) die "MODE must be unsigned or signed, got '${MODE}'" ;; esac
case "${CHANNEL}" in default|latest) ;; *) die "CHANNEL must be default or latest, got '${CHANNEL}'" ;; esac
case "${SIGN_RECOVERY}" in 0|1) ;; *) die "SIGN_RECOVERY must be 0 or 1, got '${SIGN_RECOVERY}'" ;; esac
case "${LOCKED}" in 0|1) ;; *) die "LOCKED must be 0 or 1, got '${LOCKED}'" ;; esac
[ "${MODE}" = signed ] || [ "${SIGN_RECOVERY}" = 0 ] || die "SIGN_RECOVERY=1 requires MODE=signed"
[ "${MODE}" = signed ] || [ "${LOCKED}" = 0 ] || die "LOCKED=1 requires MODE=signed"
if [ "${CHIP}" = 2711 ]; then
    [ "${SIGN_RECOVERY}" = 0 ] || die "CHIP=2711: the BCM2711 boot ROM runs the plain recovery.bin; SIGN_RECOVERY must be 0"
else
    [ "${SIGN_RECOVERY}" = "${LOCKED}" ] \
        || die "CHIP=2712: the boot ROM of a locked board runs only a counter-signed recovery.bin, of a fresh one only the plain one (SIGN_RECOVERY must equal LOCKED)"
fi
if [ "${MODE}" = signed ]; then
    case "${EXPECT_CKH}" in
        "") die "MODE=signed needs EXPECT_CKH (the customer key hash the server expects)" ;;
        *[!0-9a-f]*) die "EXPECT_CKH must be 64 hex chars" ;;
    esac
    [ "${#EXPECT_CKH}" -eq 64 ] || die "EXPECT_CKH must be 64 hex chars, got ${#EXPECT_CKH}"
fi
[ -d "${OUT}" ] || die "${OUT} is not mounted"
[ -f "${OUT}/boot.conf" ] || die "${OUT}/boot.conf missing (written by the server)"
[ -f "${OUT}/config.txt" ] || die "${OUT}/config.txt missing (written by the server)"
[ -d "${EEPROM_DIR}" ] || die "${EEPROM_DIR} missing: mount <repo>/external at ${EXT}"

step "checking config.txt against the mode"
has_program_pubkey=0
if tr -d '\r' < "${OUT}/config.txt" | grep -Eq '^[[:space:]]*program_pubkey[[:space:]]*=[[:space:]]*1[[:space:]]*$'; then
    has_program_pubkey=1
fi
if [ "${MODE}" = unsigned ] && [ "${has_program_pubkey}" = 1 ]; then
    die "config.txt sets program_pubkey=1 but MODE=unsigned: the EEPROM carries no customer key"
fi
if [ "${MODE}" = signed ] && [ "${has_program_pubkey}" = 0 ] && [ "${LOCKED}" = 0 ]; then
    # A signed EEPROM on a board whose OTP holds no key hash does not boot at all.
    die "MODE=signed needs program_pubkey=1 in config.txt (fresh board) or LOCKED=1 (board already locked to this key)"
fi
if [ "${has_program_pubkey}" = 1 ] && [ "${LOCKED}" = 1 ]; then
    die "config.txt sets program_pubkey=1 but LOCKED=1: the board's OTP already holds the key hash"
fi
if [ "${MODE}" = unsigned ]; then
    # SIGNED_BOOT (any value but 0, any section) in an EEPROM that carries no customer key and no
    # bootconf.sig: the server strips it, so seeing it here is a bug upstream of this script.
    signed_boot_vals="$(tr -d '\r' < "${OUT}/boot.conf" \
        | { grep -Ei '^[[:space:]]*SIGNED_BOOT[[:space:]]*=' || true; } \
        | sed -e 's/^[^=]*=//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        | { grep -vx '0' || true; } | paste -sd' ' -)"
    [ -z "${signed_boot_vals}" ] \
        || die "boot.conf sets SIGNED_BOOT=${signed_boot_vals} but MODE=unsigned: the EEPROM carries no customer key"
fi
bootconf_size="$(stat -c %s "${OUT}/boot.conf")"
[ "${bootconf_size}" -lt 4076 ] || die "boot.conf is ${bootconf_size} bytes; the EEPROM limit is 4075"

step "resolving firmware in firmware-${CHIP}/${CHANNEL}"
FW_DIR="${EEPROM_DIR}/firmware-${CHIP}/${CHANNEL}"
[ -d "${FW_DIR}" ] || die "firmware directory not found: ${FW_DIR}"
PIEEPROM="$(find "${FW_DIR}/" -maxdepth 1 -type f -size "${PIEEPROM_BYTES}c" \
            -regex '.*/pieeprom-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\.bin' | sort -r | sed -n 1p)"
[ -n "${PIEEPROM}" ] || die "no ${PIEEPROM_BYTES}-byte pieeprom-YYYY-MM-DD.bin in ${FW_DIR}"
RECOVERY="${FW_DIR}/recovery.bin"
[ -f "${RECOVERY}" ] || die "recovery.bin not found in ${FW_DIR}"
[ "$(stat -c %s "${RECOVERY}")" -gt 65536 ] || die "${RECOVERY} is too small (unresolved git symlink?)"
PIEEPROM_REL="firmware-${CHIP}/${CHANNEL}/$(basename "${PIEEPROM}")"
RECOVERY_REL="firmware-${CHIP}/${CHANNEL}/recovery.bin"
BUILD_TIMESTAMP="$(strings "${PIEEPROM}" | sed -n 's/.*BUILD_TIMESTAMP=\([0-9][0-9]*\).*/\1/p' | sed -n 1p)"
[ -n "${BUILD_TIMESTAMP}" ] || die "no BUILD_TIMESTAMP in ${PIEEPROM_REL}"
echo "    pieeprom: ${PIEEPROM_REL} (BUILD_TIMESTAMP=${BUILD_TIMESTAMP})"
echo "    recovery: ${RECOVERY_REL}"
if tr -d '\r' < "${OUT}/config.txt" | grep -Eq '^[[:space:]]*program_arb[[:space:]]*=[[:space:]]*1[[:space:]]*$'; then
    # Bootloader anti-rollback: the version built into recovery.bin goes to OTP for good. Only with the
    # secure scenario's signed EEPROM, and only with a recovery.bin that knows the option (an unknown
    # config.txt key is ignored without a word, so the operator would believe it written).
    [ "${MODE}" = signed ] || die "config.txt sets program_arb=1 but MODE=unsigned: anti-rollback belongs to the secure scenario"
    # the key itself (NUL-terminated), not the "... and program_arb config settings require rpiboot mode" message
    # that the BCM2712 recovery.bin of 2026-10-23 has without the option
    grep -aqP '\x00program_arb\x00' "${RECOVERY}" || die "config.txt sets program_arb=1 but ${RECOVERY_REL} has no such option"
    echo "    program_arb=1: anti-rollback version $(strings "${RECOVERY}" | sed -n 's/^MFG_VER: *\([0-9][0-9]*\)$/\1/p' | sed -n 1p) of ${RECOVERY_REL}"
fi

stage_tools

# update-pieeprom.sh works in the current directory (pieeprom.original.bin,
# recovery.original.bin, bootcode5.bin, pieeprom.signed_boot.bin).
cd "${WORK}"
cp "${PIEEPROM}" pieeprom.original.bin
cp "${RECOVERY}" recovery.original.bin
tr -d '\r' < "${OUT}/boot.conf" > boot.conf
rm -f "${OUT}/bootcode5.bin" "${OUT}/bootcode4.bin" "${OUT}/pieeprom.bin" "${OUT}/pieeprom.sig" "${OUT}/build-info.json"

CKH=""
if [ "${MODE}" = unsigned ]; then
    step "update-pieeprom.sh (unsigned)"
    update-pieeprom.sh -c boot.conf -i pieeprom.original.bin -o pieeprom.bin
    cp recovery.original.bin "${SECOND_STAGE}"
elif [ "${CHIP}" = 2711 ]; then
    [ -f "${KEYS}/private.pem" ] || die "${KEYS}/private.pem missing (signed mode)"
    [ -f "${KEYS}/public.pem" ] || die "${KEYS}/public.pem missing (signed mode)"
    step "checking the signing key"
    CKH="$(customer_key_hash "${KEYS}/public.pem")" || die "cannot read ${KEYS}/public.pem as an RSA-2048 public key"
    echo "    customer key hash: ${CKH}"
    [ "${CKH}" = "${EXPECT_CKH}" ] || die "public.pem hashes to ${CKH}, but the server expects ${EXPECT_CKH}"
    PRIV_CKH="$(customer_key_hash "${KEYS}/private.pem")" || die "cannot read ${KEYS}/private.pem as an RSA-2048 key"
    [ "${PRIV_CKH}" = "${CKH}" ] || die "private.pem and public.pem are not a key pair"
    # The BCM2711 boot ROM checks only Raspberry Pi's signature of the bootloader: nothing is counter-signed
    # (update-pieeprom.sh -f would sign for a BCM2712), the EEPROM carries the signed config and the public key.
    step "update-pieeprom.sh (sign boot.conf, embed public key)"
    update-pieeprom.sh -k "${KEYS}/private.pem" -p "${KEYS}/public.pem" \
        -c boot.conf -i pieeprom.original.bin -o pieeprom.bin
    cp recovery.original.bin "${SECOND_STAGE}"
else
    [ -f "${KEYS}/private.pem" ] || die "${KEYS}/private.pem missing (signed mode)"
    [ -f "${KEYS}/public.pem" ] || die "${KEYS}/public.pem missing (signed mode)"
    step "checking the signing key"
    CKH="$(customer_key_hash "${KEYS}/public.pem")" || die "cannot read ${KEYS}/public.pem as an RSA-2048 public key"
    echo "    customer key hash: ${CKH}"
    [ "${CKH}" = "${EXPECT_CKH}" ] || die "public.pem hashes to ${CKH}, but the server expects ${EXPECT_CKH}"
    PRIV_CKH="$(customer_key_hash "${KEYS}/private.pem")" || die "cannot read ${KEYS}/private.pem as an RSA-2048 key"
    [ "${PRIV_CKH}" = "${CKH}" ] || die "private.pem and public.pem are not a key pair"
    flags="-f"
    [ "${SIGN_RECOVERY}" = 1 ] && flags="-fr"
    step "update-pieeprom.sh ${flags} (counter-sign bootcode/bootsys, sign boot.conf, embed public key)"
    update-pieeprom.sh "${flags}" -k "${KEYS}/private.pem" -p "${KEYS}/public.pem" \
        -c boot.conf -i pieeprom.original.bin -o pieeprom.bin
    [ -f bootcode5.bin ] || die "update-pieeprom.sh produced no bootcode5.bin"
fi
[ -f pieeprom.bin ] && [ -f pieeprom.sig ] || die "update-pieeprom.sh produced no pieeprom.bin/pieeprom.sig"

step "self-check"
[ "$(stat -c %s pieeprom.bin)" -eq "${PIEEPROM_BYTES}" ] || die "pieeprom.bin is not ${PIEEPROM_BYTES} bytes"
sig_hash="$(head -n1 pieeprom.sig | tr -d '\r')"
bin_hash="$(sha256sum pieeprom.bin | awk '{print $1}')"
[ "${sig_hash}" = "${bin_hash}" ] || die "pieeprom.sig first line does not match sha256(pieeprom.bin)"
grep -q '^ts: [0-9][0-9]*$' pieeprom.sig || die "pieeprom.sig has no ts line"
mkdir -p check
( cd check && rpi-eeprom-config -x ../pieeprom.bin >/dev/null )
[ -f check/bootconf.txt ] || die "rpi-eeprom-config -x extracted no bootconf.txt"
cmp -s check/bootconf.txt boot.conf || die "the config embedded in pieeprom.bin differs from boot.conf"
echo "    pieeprom.sig matches, embedded boot.conf matches"
if [ "${MODE}" = unsigned ]; then
    cmp -s "${SECOND_STAGE}" recovery.original.bin || die "${SECOND_STAGE} is not the plain recovery.bin"
else
    check_rsa_sig check/bootconf.sig
    rpi-eeprom-digest -k "${KEYS}/public.pem" -i check/bootconf.txt -v check/bootconf.sig \
        || die "the embedded bootconf.sig does not verify with public.pem"
    pub_hash="$(sha256sum check/pubkey.bin | awk '{print $1}')"
    [ "$(stat -c %s check/pubkey.bin)" -eq 264 ] || die "embedded pubkey.bin is not 264 bytes"
    [ "${pub_hash}" = "${CKH}" ] || die "embedded pubkey.bin hash ${pub_hash} != customer key hash ${CKH}"
    [ "${pub_hash}" = "${EXPECT_CKH}" ] || die "embedded pubkey.bin hash ${pub_hash} != expected ${EXPECT_CKH}"
    echo "    embedded pubkey.bin sha256 == customer key hash == EXPECT_CKH"
    if [ "${CHIP}" = 2711 ]; then
        cmp -s "${SECOND_STAGE}" recovery.original.bin || die "${SECOND_STAGE} is not the plain recovery.bin"
        echo "    ${SECOND_STAGE}: plain recovery.bin (the BCM2711 boot ROM checks Raspberry Pi's signature only)"
    else
        is_customer_signed check/bootcode.bin || die "bootcode.bin in pieeprom.bin carries no customer (keynum 16) signature"
        echo "    bootcode.bin: $(sig_summary check/bootcode.bin)"
        if [ -f check/bootsys ] && [ "$(stat -c %s check/bootsys)" -gt 0 ]; then
            is_customer_signed check/bootsys || die "bootsys in pieeprom.bin carries no customer signature"
            echo "    bootsys: $(sig_summary check/bootsys)"
        fi
        if [ "${SIGN_RECOVERY}" = 1 ]; then
            is_customer_signed bootcode5.bin || die "bootcode5.bin is not counter-signed"
            ! cmp -s bootcode5.bin recovery.original.bin || die "bootcode5.bin equals the unsigned recovery.bin"
            echo "    bootcode5.bin: $(sig_summary bootcode5.bin)"
        else
            cmp -s bootcode5.bin recovery.original.bin || die "bootcode5.bin is not the plain recovery.bin"
            echo "    bootcode5.bin: unsigned recovery.bin (fresh board)"
        fi
    fi
fi

step "writing outputs to ${OUT}"
cp "${SECOND_STAGE}" pieeprom.bin pieeprom.sig "${OUT}/"
jq -n \
    --arg chip "${CHIP}" \
    --arg mode "${MODE}" \
    --arg channel "${CHANNEL}" \
    --arg pieeprom_source "${PIEEPROM_REL}" \
    --arg recovery_source "${RECOVERY_REL}" \
    --argjson build_timestamp "${BUILD_TIMESTAMP}" \
    --argjson sign_recovery "$([ "${SIGN_RECOVERY}" = 1 ] && echo true || echo false)" \
    --arg ckh "${CKH}" \
    '{chip: $chip, mode: $mode, channel: $channel, pieeprom_source: $pieeprom_source,
      recovery_source: $recovery_source, build_timestamp: $build_timestamp,
      sign_recovery: $sign_recovery,
      customer_key_hash: (if $ckh == "" then null else $ckh end)}' > "${OUT}/build-info.json"
ls -l "${OUT}"
step "stage1 done"
