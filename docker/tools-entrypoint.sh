#!/bin/bash
# otp-run <script> [args...]
#
# ENTRYPOINT of the otp-tools image. Runs /scripts/<script> (the read-only mount
# of <repo>/docker/scripts) with bash, after stripping CR line endings so that a
# Windows checkout with core.autocrlf=true still works. The copy lives in a
# private temp dir; the script's arguments are passed through unchanged.
set -euo pipefail

SCRIPTS_DIR="${OTP_SCRIPTS_DIR:-/scripts}"

usage() {
    cat <<EOF
usage: otp-run <script> [args...]

Runs ${SCRIPTS_DIR}/<script> with bash (CR line endings stripped).
Mount <repo>/docker/scripts at ${SCRIPTS_DIR} (ro) and <repo>/external at /ext (ro).

Scripts (see SPEC section 11 / the header of each script for mounts and env):
  stage1.sh        EEPROM stage-1 rpiboot dir       /ext ro, /out rw, /keys ro (signed)
                   env MODE=unsigned|signed CHANNEL=default|latest SIGN_RECOVERY=0|1 [SOURCE_DATE_EPOCH]
  stage2-sign.sh   boot.sig + counter-signed bootfiles.bin   /in ro, /keys ro, /out rw
  boot-resign.sh   re-sign an IDP boot slot sparse           /in ro, /keys ro, /out rw
                   env SIMAGE=<name> MAX_PIECE=<bytes>
  image-collect.sh collect image.json + sparse pieces         /work ro, /out rw, env MAX_PIECE=<bytes>
EOF
    if [ -d "${SCRIPTS_DIR}" ]; then
        echo
        echo "Available in ${SCRIPTS_DIR}:"
        find "${SCRIPTS_DIR}" -maxdepth 1 -type f -name '*.sh' -printf '  %f\n' 2>/dev/null | sort
    else
        echo
        echo "(${SCRIPTS_DIR} is not mounted)"
    fi
}

if [ "$#" -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

name="$1"
shift

case "${name}" in
    */*|.*|"")
        echo "ERROR: invalid script name '${name}' (a bare file name from ${SCRIPTS_DIR} is expected)" >&2
        exit 2
        ;;
esac
if ! [[ "${name}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "ERROR: invalid script name '${name}'" >&2
    exit 2
fi

src="${SCRIPTS_DIR}/${name}"
if [ ! -f "${src}" ]; then
    echo "ERROR: script not found: ${src} (is ${SCRIPTS_DIR} mounted?)" >&2
    usage >&2
    exit 2
fi

tmp="$(mktemp -d /tmp/otp-run.XXXXXX)"
sed 's/\r$//' "${src}" > "${tmp}/${name}"
chmod 0755 "${tmp}/${name}"
exec bash "${tmp}/${name}" "$@"
