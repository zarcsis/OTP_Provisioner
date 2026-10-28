# otp-app-builder: prepares the root file systems of sandboxed apps (otp_server/artifacts/apps.py).
#
# Three scripts of docker/scripts run in it (ENTRYPOINT = otp-run, as in the tools image):
#
#   app-vmkit.sh    the installer VM's kernel and initramfs: Debian's arm64 kernel, the few modules a
#                   virtio disk with ext4 needs, busybox, app-vm-init. Network (apt), not privileged.
#   app-rootfs.sh   an app's root file system: Debian trixie arm64 (minbase + systemd) and the app's
#                   dependencies from Debian, as an ext4 disk image with the app's .deb in /vn-install.
#                   Only Debian's own maintainer scripts run here (arm64 chroot under qemu-user), so
#                   --privileged (mmdebstrap mounts proc/sys/dev) and network are acceptable.
#   app-install.sh  installs the app's .deb in a throwaway qemu-system-aarch64 VM: the package's own
#                   maintainer scripts run there, behind the VM's kernel. The container runs without
#                   network and without privileges; the VM has no network either.
#
#   qemu-system-arm          qemu-system-aarch64 (the installer VM, TCG: no KVM needed)
#   mmdebstrap, qemu-user-static, arch-test   the arm64 root file system
#   e2fsprogs, libarchive13t64   mke2fs -d <tar>: an ext4 image from a tarball, no loop device (mke2fs
#                            loads libarchive at run time)
#   kmod, cpio, xz-utils     the VM's initramfs (modinfo for module dependencies)
#
# Build (context = docker/):
#   docker build -t otp-app-builder:trixie -f docker/apps.Dockerfile docker/
# The server labels it otp.apps.hash=<sha256 of this file + tools-entrypoint.sh> to tell when it is stale.
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash coreutils findutils grep sed gawk tar xz-utils zstd gzip jq python3 \
        ca-certificates debian-archive-keyring \
        mmdebstrap qemu-user-static arch-test \
        qemu-system-arm \
        e2fsprogs libarchive13t64 kmod cpio \
    && rm -rf /var/lib/apt/lists/* \
    && for t in qemu-system-aarch64 mmdebstrap mke2fs modinfo cpio xz jq; do \
           command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; \
       done

COPY tools-entrypoint.sh /usr/local/bin/otp-run
RUN sed -i 's/\r$//' /usr/local/bin/otp-run && chmod 0755 /usr/local/bin/otp-run

WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/otp-run"]
