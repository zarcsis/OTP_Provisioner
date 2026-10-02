# Station image builder: Debian trixie plus everything rpi-image-gen needs.
# Built and run by the station (otp_server/artifacts/image.py) and by
# build.sh --docker. By hand, from the repository root:
#
#   docker build -t otp-image-builder:trixie image/docker/
#   docker run --rm -it --privileged \
#       -v <repo>/image:/src:ro -v otp-image-work:/work -v <out dir>:/out \
#       otp-image-builder:trixie [build.sh options]
#
# Inside the container build.sh defaults to the work dir /work and the out dir
# /out. --privileged is mandatory: mmdebstrap mounts proc/sys/devpts inside a
# mount namespace and needs CAP_SYS_ADMIN for that. The arm64 binfmt handler is
# NOT part of this image - it lives in the host kernel (Docker Desktop's VM
# registers one at start; elsewhere the station / build.sh use tonistiigi/binfmt).
# The container runs as root, so rpi-image-gen's bin/ns skips podman unshare;
# podman is still installed because rpi-image-gen's dependency check wants it.
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1

# Package list = rpi-image-gen/depends (v2.8.0) + tools its scripts call without
# declaring (zstd, file, git) + foreign-arch helpers (qemu-user-static, arch-test)
# + setuptools/wheel so pip can build the bdebstrap wheel without downloading them
# + tini (PID 1 that forwards signals to the whole build) + openssl (password
# hashes for IGconf_device_user1passhash: openssl passwd -6).
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils grep rsync curl ca-certificates git file xz-utils zstd zip \
        python3 python3-yaml python3-debian python3-jsonschema \
        python3-pip python3-setuptools python3-wheel \
        dpkg-dev debian-archive-keyring mmdebstrap \
        podman uidmap dbus-user-session \
        dosfstools e2fsprogs btrfs-progs mtools pv dctrl-tools uuid-runtime fdisk \
        cryptsetup-bin \
        make build-essential autoconf automake libtool autopoint flex gettext pkgconf \
        qemu-user-static arch-test \
        tini openssl \
    && rm -rf /var/lib/apt/lists/*

# Entry point: normalises the line endings of the mounted build.sh and runs it.
# sed -i covers the case where entrypoint.sh itself was checked out with CRLF.
COPY entrypoint.sh /usr/local/bin/otp-image-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/otp-image-entrypoint \
    && chmod 0755 /usr/local/bin/otp-image-entrypoint

VOLUME ["/work"]
WORKDIR /work
# tini -g: as PID 1, bash would ignore SIGINT/SIGTERM, so without a terminal
# Ctrl+C and 'docker stop' could not interrupt a build. tini forwards both to
# the build's whole process group.
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/bin/otp-image-entrypoint"]
