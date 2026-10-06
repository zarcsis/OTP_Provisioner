# syntax=docker/dockerfile:1
#
# otp-gadget-builder: arm64 Debian trixie + Raspberry Pi archive tooling that runs the
# pi-gen-micro checkout (external/pi-gen-micro, mounted read-only at /src) in place and
# produces the rpi-fastbootd "fastboot" gadget boot.img (what rpi-sb-provisioner ships as
# host-support/fastboot-gadget-pi5-family.img), with two changes of ours: the otp-keyexport helper
# package (gadget-helpers/) and an rpi-fastbootd rebuilt with fastbootd/otp-station.patch, which
# cannot read anything back from the board (stage 3 below).
#
#   docker build --platform linux/arm64 -t otp-gadget-builder:trixie -f docker/gadget.Dockerfile docker/
#   docker run --rm --platform linux/arm64 -e PGM_TARGETS=pi5-family -e PGM_COMMIT=<commit> \
#     --mount type=bind,source=<repo>/external/pi-gen-micro,target=/src,readonly \
#     --mount type=volume,source=otp-pgm-work,target=/work \
#     --mount type=bind,source=<out dir>,target=/out \
#     otp-gadget-builder:trixie
#
# Needs the arm64 binfmt handler in the Docker VM (tonistiigi/binfmt --install arm64) and
# network access to deb.debian.org + archive.raspberrypi.com at build and run time, and to
# github.com (rpi-fastbootd and its submodules) at build time.
# No --privileged: pi-gen-micro uses fakeroot + dpkg --force-script-chrootless, and
# rpi-make-boot-image takes its mtools path (no loop devices).

# ---------------------------------------------------------------------------
# Stage 1 (amd64, runs natively): x86-64 zstd + cpio with their libraries, invoked
# through their own loader, so the arch-neutral packing steps (zstd --ultra -22 on the
# initramfs) do not run under qemu. Same trick as pi-gen-micro-sysroot native_tools().
# Also fetches and fingerprint-checks the Raspberry Pi archive key.
FROM --platform=linux/amd64 debian:trixie-slim AS native
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends zstd cpio curl gnupg ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN <<'EOF'
set -eu
mkdir -p /native/bin /native/lib
for t in zstd cpio; do
    bin="$(command -v "$t")"
    install -m0755 "$bin" "/native/bin/$t.host"
    ldd "$bin" | awk '/=>/ {print $3} /^\t\// {print $1}' | grep '^/' | sort -u \
        | xargs -r install -m0755 -t /native/lib
    loader="$(ldd "$bin" | awk '/^\t\// {print $1; exit}' | xargs basename)"
    printf '#!/bin/sh\nexec /native/lib/%s --library-path /native/lib /native/bin/%s.host "$@"\n' \
        "$loader" "$t" > "/native/bin/$t"
    chmod 0755 "/native/bin/$t"
    "/native/bin/$t" --version | head -n1
done
# Raspberry Pi archive signing key, pinned by fingerprint (pi-gen-micro-sysroot RPI_FPR).
mkdir -p /keys
curl -fsSL http://archive.raspberrypi.com/debian/raspberrypi.gpg.key \
    | gpg --dearmor > /keys/raspberrypi-bootstrap.pgp
gpg --show-keys --with-colons /keys/raspberrypi-bootstrap.pgp \
    | grep -q ':CF8A1AF502A2AA2D763BAE7E82B129927FA3303E:' \
    || { echo "Raspberry Pi archive key fingerprint mismatch" >&2; exit 1; }
EOF

# ---------------------------------------------------------------------------
# Stage 2 (arm64): Debian trixie + the Raspberry Pi archive, with the apt policy
# pi-gen-micro-sysroot sets up:
#  - SHA1 self-signatures of the RPi key are accepted by apt's Sequoia verifier (trixie
#    rejects them from 2026-02-01 otherwise; the image build's own apt reads this too),
#  - archive.raspberrypi.com pinned to 600.
FROM --platform=linux/arm64 debian:trixie-slim AS rpi
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

COPY --from=native /keys/raspberrypi-bootstrap.pgp /usr/share/keyrings/raspberrypi-bootstrap.pgp

RUN <<'EOF'
set -eu
mkdir -p /etc/crypto-policies/back-ends /etc/apt/preferences.d /etc/apt/sources.list.d
printf '[hash_algorithms]\nsha1.second_preimage_resistance = 2030-01-01\n' \
    > /etc/crypto-policies/back-ends/apt-sequoia.config
printf 'Package: *\nPin: origin archive.raspberrypi.com\nPin-Priority: 600\n' \
    > /etc/apt/preferences.d/10-raspi
printf 'Types: deb\nURIs: http://archive.raspberrypi.com/debian/\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/raspberrypi-bootstrap.pgp\n' \
    > /etc/apt/sources.list.d/raspi.sources
apt-get update
apt-get install -y --no-install-recommends raspberrypi-archive-keyring debian-archive-keyring
# From here on the packaged keyring is the trust anchor.
test -f /usr/share/keyrings/raspberrypi-archive-keyring.pgp
test -f /usr/share/keyrings/debian-archive-keyring.pgp
sed -i 's#/usr/share/keyrings/raspberrypi-bootstrap.pgp#/usr/share/keyrings/raspberrypi-archive-keyring.pgp#' \
    /etc/apt/sources.list.d/raspi.sources
rm -f /usr/share/keyrings/raspberrypi-bootstrap.pgp
apt-get update
rm -rf /var/lib/apt/lists/*
EOF

# ---------------------------------------------------------------------------
# Stage 3 (arm64): rpi-fastbootd for the gadget, built from the revision pi-gen-micro vendors
# (internal/packages/rpi-fastbootd_14.0.0~git20260902.cca05b2_arm64.deb) with our station patch
# (fastbootd/otp-station.patch: command allowlist, oem cryptcheck, USB only). fastbootd/station-test.sh then
# runs the compiled dispatcher against fastbootd/station_test.cpp (and a real LUKS2 header); a failed check
# fails the image build. The deb is versioned <upstream>+otp1; the entrypoint puts it in place of the
# vendored one.
FROM rpi AS fastbootd
ARG FASTBOOTD_REPO=https://github.com/raspberrypi/rpi-fastbootd.git
ARG FASTBOOTD_COMMIT=cca05b29f3ce1276151973398867b5c82c38ae40
ARG OTP_FASTBOOTD_SUFFIX=+otp1
# Build-Depends of debian/control at that revision (+ uuid-dev for <uuid/uuid.h>, cryptsetup-bin for the
# self-test's LUKS2 header).
RUN <<'EOF'
set -eu
apt-get update
apt-get install -y --no-install-recommends \
    build-essential debhelper dpkg-dev fakeroot git ca-certificates cmake pkg-config \
    android-liblog-dev android-libbase-dev android-libcutils-dev \
    libfdisk-dev uuid-dev liburing-dev libsystemd-dev zlib1g-dev libssl-dev libgpiod-dev \
    libcryptsetup-dev librpifwcrypto-dev libblockdeviceid-dev libjsoncpp-dev cryptsetup-bin
rm -rf /var/lib/apt/lists/*
EOF
COPY fastbootd /tmp/otp-fastbootd
RUN <<'EOF'
set -eu
git clone --quiet "${FASTBOOTD_REPO}" /build/rpi-fastbootd
cd /build/rpi-fastbootd
git -c advice.detachedHead=false checkout --quiet "${FASTBOOTD_COMMIT}"
[ "$(git rev-parse HEAD)" = "${FASTBOOTD_COMMIT}" ] || { echo "rpi-fastbootd is not at ${FASTBOOTD_COMMIT}" >&2; exit 1; }
git submodule update --quiet --init --recursive
sed -i 's/\r$//' /tmp/otp-fastbootd/*
git apply --whitespace=nowarn /tmp/otp-fastbootd/otp-station.patch
git diff --stat
export OTP_FASTBOOTD_SUFFIX
# dpkg-buildpackage reads debian/changelog before debian/rules regenerates it (build-package.sh order).
./debian/gen-version.sh
dpkg-buildpackage -b -uc -us -j"$(nproc)"
expected="14.0.0~git$(git show -s --format=%cd --date=format:%Y%m%d HEAD).$(git show -s --format=%h --abbrev=7 HEAD)${OTP_FASTBOOTD_SUFFIX}"
deb="/build/rpi-fastbootd_${expected}_arm64.deb"
[ -s "${deb}" ] || { ls -l /build >&2; echo "expected ${deb}" >&2; exit 1; }
[ "$(dpkg-deb -f "${deb}" Version)" = "${expected}" ] || { echo "deb version mismatch" >&2; exit 1; }
# The patched daemon, not the upstream one: the new command is in the binary.
mkdir -p /tmp/x && dpkg-deb -x "${deb}" /tmp/x
grep -q 'oem cryptcheck' /tmp/x/usr/bin/fastbootd || { echo "fastbootd lacks the station patch" >&2; exit 1; }
bash /tmp/otp-fastbootd/station-test.sh /build/rpi-fastbootd /tmp/otp-fastbootd/station_test.cpp
mkdir -p /opt/otp-fastbootd
cp "${deb}" /opt/otp-fastbootd/
rm -rf /tmp/x /build /tmp/otp-fastbootd
ls -l /opt/otp-fastbootd
EOF

# ---------------------------------------------------------------------------
# Stage 4 (arm64): the builder.
# Packages: pi-gen-micro debian/control Depends + Recommends, internal/sysroot/packages
# (for --force-script-chrootless maintainer scripts), plus file/jq for the entrypoint.
FROM rpi
RUN <<'EOF'
set -eu
apt-get update
apt-get install -y --no-install-recommends \
    rpi-make-boot-image rpi-modcopy \
    bash sed fakeroot rsync systemd kmod cpio zstd dpkg-dev \
    curl wget dctrl-tools coreutils gzip mtools dosfstools init-system-helpers \
    adduser passwd readline-common ucf ca-certificates apt-utils xz-utils \
    file jq
rm -rf /var/lib/apt/lists/*
for t in rpi-make-boot-image rpi-modcopy fakeroot depmod cpio zstd rsync dpkg-scanpackages mcopy; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
done
EOF

COPY --from=native /native /native
RUN /native/bin/zstd --version && /native/bin/cpio --version | head -n1

COPY gadget-entrypoint.sh /usr/local/bin/gadget-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/gadget-entrypoint && chmod 0755 /usr/local/bin/gadget-entrypoint
# Our pi-gen-micro helper packages (otp-keyexport): the entrypoint adds them to the fastboot
# configuration of the staged pi-gen-micro tree, the submodule itself is never touched.
COPY gadget-helpers /opt/otp-gadget-helpers
# The patched rpi-fastbootd (stage 3): the entrypoint swaps it in for the vendored deb.
COPY --from=fastbootd /opt/otp-fastbootd /opt/otp-fastbootd

VOLUME ["/work"]
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/gadget-entrypoint"]
