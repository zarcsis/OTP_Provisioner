#!/bin/bash
# station-test.sh: the self-test of the station rpi-fastbootd, run by gadget.Dockerfile after dpkg-buildpackage.
#
#   station-test.sh <rpi-fastbootd source tree, built> [station_test.cpp]
#
# Builds station_test.cpp from the daemon's own objects (all of them but main.cpp, with the daemon's compile and
# link flags), makes a LUKS2 header with the board key in keyslot 0 and a recovery key in keyslot 1, and runs the
# test: the dispatcher must refuse everything outside the allowlist and reach the handlers of what is in it, and
# CryptCheckNative must name the right keyslot. Exits non-zero when any check fails.
set -euo pipefail

SRC="${1:?usage: station-test.sh <rpi-fastbootd source tree> [station_test.cpp]}"
TEST_CPP="${2:-$(dirname "$0")/station_test.cpp}"
OBJ="${SRC}/obj-aarch64-linux-gnu/fastboot"
DIR="${OBJ}/CMakeFiles/fastbootd.dir"
[ -f "${DIR}/link.txt" ] || { echo "no ${DIR}/link.txt: build rpi-fastbootd first" >&2; exit 1; }

cd "${OBJ}"
flag() { sed -n "s/^$1 = //p" "${DIR}/flags.make"; }
echo "==> compiling $(basename "${TEST_CPP}") with the fastbootd flags"
eval "c++ $(flag CXX_DEFINES) $(flag CXX_INCLUDES) -I${SRC}/fastboot/device $(flag CXX_FLAGS) -c ${TEST_CPP} -o station_test.o"
link="$(cat "${DIR}/link.txt")"
case "${link}" in
    *" CMakeFiles/fastbootd.dir/device/main.cpp.o "*" -o fastbootd "*) ;;
    *) echo "link.txt does not look like the fastbootd link line" >&2; exit 1 ;;
esac
link="${link/ CMakeFiles\/fastbootd.dir\/device\/main.cpp.o / station_test.o }"
link="${link/ -o fastbootd / -o station_test }"
echo "==> linking station_test from the fastbootd objects (main.cpp.o replaced)"
eval "${link}"

work="$(mktemp -d)"
trap 'rm -rf "${work}" /run/otp-keyexport "${OBJ}/station_test" "${OBJ}/station_test.o"' EXIT
hexkey() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
key0="$(hexkey)"
key1="$(hexkey)"
printf %s "${key0}" > "${work}/k0"
printf %s "${key1}" > "${work}/k1"
truncate -s 32M "${work}/t.luks"
echo "==> LUKS2 header: keyslot 0 = board key, keyslot 1 = recovery key"
cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-file "${work}/k0" "${work}/t.luks"
cryptsetup luksAddKey --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-file "${work}/k0" --new-key-slot 1 "${work}/t.luks" "${work}/k1"

mkdir -p /run/otp-keyexport
printf 'status-ok\n' > /run/otp-keyexport/status
rm -f /run/otp-keyexport/request
echo "==> station_test (the daemon's own log goes to a file, shown on failure)"
if ! ./station_test "${work}/t.luks" "${key0}" "${key1}" 2> "${work}/daemon.log"; then
    echo "--- last lines of the daemon log:" >&2
    tail -n 40 "${work}/daemon.log" >&2
    exit 1
fi
