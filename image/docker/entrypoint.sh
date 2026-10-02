#!/bin/sh
# Container entry point for the station image builder. It runs under
# 'tini -g' (see the Dockerfile), so Ctrl+C and 'docker stop' reach the whole
# build, not just PID 1.
#
#   --binfmt-check   exit 0 when the kernel can run arm64 binaries inside a
#                    chroot: an enabled binfmt_misc handler with the aarch64
#                    ELF magic and the F flag, whatever its name. Same scan as
#                    binfmt_arm64_present in build.sh - keep the two in sync.
#                    Needs --privileged (it mounts binfmt_misc).
#   anything else    arguments for build.sh
#
# The station's image/ directory is bind-mounted (read-only) at $OTP_IMAGE_ROOT
# (/src by default). A checkout made on Windows may carry CRLF line endings, so build.sh
# is copied to /tmp with CRs stripped before it runs; build.sh then stages the
# rest of the tree into the work dir with the same treatment.
set -e

if [ "${1:-}" = --binfmt-check ]; then
    d=/proc/sys/fs/binfmt_misc
    mountpoint -q "$d" 2>/dev/null || mount -t binfmt_misc binfmt_misc "$d" 2>/dev/null || true
    for e in "$d"/*; do
        case ${e##*/} in register|status) continue ;; esac
        [ -f "$e" ] || continue
        [ "$(head -n1 "$e" 2>/dev/null)" = enabled ] || continue
        grep -qx 'magic 7f454c460201010000000000000000000200b700' "$e" 2>/dev/null || continue
        grep -q '^flags: .*F' "$e" 2>/dev/null || continue
        exit 0
    done
    exit 1
fi

src=${OTP_IMAGE_ROOT:-/src}
if [ ! -f "$src/build.sh" ]; then
    echo "otp-image-entrypoint: $src/build.sh not found - mount the station's image/ directory at $src" >&2
    exit 2
fi

sed 's/\r$//' "$src/build.sh" > /tmp/otp-image-build.sh
export OTP_IMAGE_IN_CONTAINER=1
export OTP_IMAGE_ROOT="$src"
exec bash /tmp/otp-image-build.sh "$@"
