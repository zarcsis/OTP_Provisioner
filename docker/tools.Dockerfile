# otp-tools: runtime for the official Raspberry Pi EEPROM / signing / sparse tools.
#
# Nothing from the Raspberry Pi repositories is baked in: the tools are the
# shell/python scripts of the usbboot + rpi-eeprom submodules, mounted at run
# time under /ext (read-only). The image only carries their runtime and the
# OTP_Provisioner helper scripts' dependencies:
#
#   python3 + python3-pycryptodome   rpi-eeprom-config, rpi-sign-bootcode (Cryptodome namespace)
#   openssl, xxd, coreutils          rpi-eeprom-digest (.sig files, RSA-2048 PKCS#1 v1.5)
#   binutils (strings)               usbboot tools/update-pieeprom.sh version gate
#   dosfstools, mtools, file         usbboot tools/rpi-make-boot-image, boot-slot FAT32 rebuild
#   android-sdk-libsparse-utils      simg2img, img2simg, simg2simg, simg_dump
#   jq, zstd, tar, gawk, sed, grep   JSON manifests, droneos deploy artefacts, bootfiles.bin
#
# Build (context = docker/):
#   docker build -t otp-tools:latest -f docker/tools.Dockerfile docker/
# Run one of the scripts in docker/scripts (ENTRYPOINT = otp-run):
#   docker run --rm \
#     --mount type=bind,source=<repo>/docker/scripts,target=/scripts,readonly \
#     --mount type=bind,source=<repo>/external,target=/ext,readonly \
#     --mount type=bind,source=<out dir>,target=/out \
#     -e MODE=unsigned -e CHANNEL=default otp-tools:latest stage1.sh
#   docker run --rm otp-tools:latest            # prints usage
#
# The server passes --label otp.tools.hash=<sha256 of this file + tools-entrypoint.sh>
# so it can tell when the image is stale.
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash python3 python3-pycryptodome \
        openssl xxd binutils coreutils tar sed gawk grep findutils \
        file jq zstd mtools dosfstools \
        android-sdk-libsparse-utils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -c "import Cryptodome.PublicKey.RSA, Cryptodome.Signature.pkcs1_15" \
    && for t in simg2img img2simg simg2simg simg_dump mcopy mdir mkfs.fat strings xxd jq zstd; do \
           command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }; \
       done

# otp-run: strips CR from /scripts/<script> (Windows checkouts) and runs it with bash.
COPY tools-entrypoint.sh /usr/local/bin/otp-run
RUN sed -i 's/\r$//' /usr/local/bin/otp-run && chmod 0755 /usr/local/bin/otp-run

# The real rpi-eeprom tool locations come first. usbboot/tools/ is deliberately
# NOT on PATH: its rpi-eeprom-* entries are git symlinks that a Windows checkout
# may have materialised as small text files. The scripts additionally stage
# CR-free copies of the tools they call (see stage_tools in docker/scripts/*.sh).
ENV PATH="/ext/usbboot/rpi-eeprom:/ext/usbboot/rpi-eeprom/tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# mtools refuses FAT images whose geometry does not match a floppy/disk table.
ENV MTOOLS_SKIP_CHECK=1

WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/otp-run"]
