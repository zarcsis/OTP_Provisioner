#!/bin/bash
#
# build.sh - build the station's Raspberry Pi OS image (Linux entry point).
#
# The image is described by an rpi-image-gen config (the station writes one from
# its settings; example.yaml is the default for a manual run) and produced by the
# rpi-image-gen submodule (Raspberry Pi's image generator: mmdebstrap + bdebstrap
# + genimage). The station's own layers live in layer/ next to this script.
# rpi-image-gen runs on Linux only: it needs a Debian-based host with mount and
# user namespaces, plus an arm64 binfmt handler (QEMU) when the host is not arm64.
#
# Two ways to run this script:
#
#   ./build.sh            native build on Debian / Ubuntu / Raspberry Pi OS. On
#                         the first run the host packages are installed with
#                         sudo (rpi-image-gen/install_deps.sh + QEMU user mode).
#
#   ./build.sh --docker   hermetic build inside the otp-image-builder container
#                         (docker/Dockerfile: Debian trixie + every dependency).
#                         Works on any Linux that has docker or podman; the arm64
#                         binfmt handler is registered in the host kernel with
#                         tonistiigi/binfmt when it is missing.
#
# The station (otp_server/artifacts/image.py) is the Windows front end: it runs
# this script with --in-container in the builder image under Docker Desktop.
#
# Result: out/<image name>.img - flash it with Raspberry Pi Imager ("Use custom")
# or   sudo rpi-imager --cli out/<image name>.img /dev/mmcblk0
# rpi-image-gen's own deploy set (zstd-compressed image, IDP archive, SBOM,
# manifest) stays under <work dir>/deploy-<version>/.
#
# Sources that sit on a Windows filesystem (WSL /mnt/c, a Docker Desktop bind
# mount) are staged into <work dir>/src first: mmdebstrap cannot build a rootfs
# on drvfs/9p (ownership, device nodes, mounts), and a Windows checkout of the
# submodule carries CRLF in its extension-less scripts (rpi-image-gen, bin/ns,
# bin/ig, depends). The staged copy is refreshed on every run. Its file modes
# come from the git index: a Windows filesystem reports 0755 or 0777 for every
# file, and rootfs overlays copy file modes into the image.
#
# The work dir keeps what is expensive to redo (host tools, apt cache, keys)
# and exactly one build: rpi-image-gen names its rootfs and deploy dirs after
# the version (git describe), so every commit would otherwise leave ~1.5 GB
# behind. A successful build deletes the chroot-/deploy-/image- dirs of older
# versions and the .debs its rootfs does not use. A lock stops two builds from
# sharing one work dir, and a marker file stops build.sh from taking over (or
# --purge from deleting) a directory it did not create.

set -euo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
if [[ ! -t 1 ]]; then RED=''; GREEN=''; YELLOW=''; NC=''; fi

log()  { echo "${GREEN}==>${NC} $*"; }
info() { echo "    $*"; }
warn() { echo "${YELLOW}WARNING:${NC} $*" >&2; }
die()  { echo "${RED}ERROR:${NC} $*" >&2; exit 1; }

# Where the sources are. The container entry point runs a CRLF-normalised
# copy of this file from /tmp and tells us the real root.
# Normalised (no trailing slash, symlinks resolved) because it is compared
# with realpath'd paths below.
ROOT=${OTP_IMAGE_ROOT:-$(dirname "${BASH_SOURCE[0]}")}
ROOT=$(cd "$ROOT" 2>/dev/null && pwd -P) || die "checkout not found: ${OTP_IMAGE_ROOT:-$(dirname "${BASH_SOURCE[0]}")}"
IMAGE_TAG=${OTP_IMAGE_BUILDER:-otp-image-builder:trixie}
WORK_VOLUME=${OTP_IMAGE_WORK_VOLUME:-otp-image-work}

# Bookkeeping files in the work dir.
WORKROOT_MARKER=.otp-image-workroot # this directory is a build.sh work dir
LOCK_FILE=.otp-image.lock           # flock: one build per work dir
FS_MARKER=.otp-image-fs             # version and config of the last built filesystem
RUN_STAMP=.otp-image-run            # touched when a build starts; the image must be newer
TOOLS_STAMP=.otp-image-tools        # hash of what the built host tools depend on
# First 20 bytes of an aarch64 ELF executable, as binfmt_misc prints the magic.
ARM64_MAGIC=7f454c460201010000000000000000000200b700

usage() {
    cat <<'USAGE'
Usage: ./build.sh [options] [IGconf_key=value ...]

Builds the Raspberry Pi OS image described by an rpi-image-gen config.

Options:
  -c, --config <file>    Config to build (default: example.yaml)
  -B, --build-dir <dir>  Work dir (default: ./work, or ~/.cache/otp-image/work when
                         the sources sit on a Windows filesystem). Must be on a
                         Linux filesystem, and new or empty on first use: build.sh
                         keeps the staged sources in <dir>/src and rpi-image-gen's
                         work tree next to them.
  -o, --out <dir>        Where the finished .img is copied (default: ./out)
      --docker           Build inside the otp-image-builder container instead of
                         on this host (needs docker or podman). The work dir is
                         then the volume otp-image-work (OTP_IMAGE_WORK_VOLUME).
      --engine <name>    Container engine for --docker: docker (default), podman
      --rebuild          --docker: rebuild the builder image from scratch
      --shell            --docker: open a shell in the builder container
      --deps             Install / upgrade the host dependencies (sudo) and
                         exit; with --docker: refresh the builder image and exit
  -f, --fs-only          Build the filesystem only, skip image generation
  -i, --image-only       Skip the filesystem: regenerate the image from the
                         filesystem of the last successful full or --fs-only
                         build of the same config, even if the checkout changed
  -I, --interactive      Let rpi-image-gen ask before each stage
      --clean            Delete the built rootfs, image and deploy dirs from the
                         work dir (host tools, apt cache and keys stay)
      --purge            Delete the whole work dir (--docker: the work volume)
      --no-apt-cache     Do not keep downloaded .debs between builds
      --no-fix-perms     Never chmod o+x the work dir's parents (see notes)
      --dry-run          Print what would be done and exit
  -h, --help             This help

  key=value words (anywhere, or after --) are passed to rpi-image-gen as
  variable overrides, e.g.  ./build.sh IGconf_device_hostname=drone7
  For a login password use IGconf_device_user1passhash=<hash> (make the hash
  with: openssl passwd -6). IGconf_device_user1pass works too, but the plain
  password then ends up in the work dir and in the deploy set.

Notes:
  * apt inside the chroot runs as its own user and needs world-execute on every
    parent of the work dir. A Debian home directory is 0700 by default, so the
    script adds o+x to the parents it owns (what upstream CI does as well);
    --no-fix-perms turns that into a warning.
  * Downloaded .debs are kept in <work dir>/apt-cache and bind-mounted into the
    chroot, so a rebuild does not fetch Debian again (--no-apt-cache disables).
  * A successful build deletes the chroot-/deploy-/image- dirs of older versions
    and the cached .debs its rootfs does not use; out/ keeps the copied image.
USAGE
}

# ---- Arguments --------------------------------------------------------------
CONFIG=''
WORKROOT=''
OUTDIR=''
MODE=native
ENGINE=''
IN_CONTAINER=${OTP_IMAGE_IN_CONTAINER:-0}
DEPS=0; FS_ONLY=0; IMAGE_ONLY=0; INTERACTIVE=0; CLEAN=0; PURGE=0
REBUILD=0; SHELL_MODE=0; APT_CACHE=1; FIX_PERMS=1; DRY_RUN=0
OVERRIDES=()

need_arg() { [[ $# -ge 2 && -n $2 ]] || die "$1 needs a value"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--config)        need_arg "$@"; CONFIG=$2; shift 2 ;;
        --config=*)         CONFIG=${1#*=}; shift ;;
        -B|--build-dir)     need_arg "$@"; WORKROOT=$2; shift 2 ;;
        --build-dir=*)      WORKROOT=${1#*=}; shift ;;
        -o|--out)           need_arg "$@"; OUTDIR=$2; shift 2 ;;
        --out=*)            OUTDIR=${1#*=}; shift ;;
        --docker)           MODE=docker; shift ;;
        --engine)           need_arg "$@"; ENGINE=$2; shift 2 ;;
        --engine=*)         ENGINE=${1#*=}; shift ;;
        --rebuild)          REBUILD=1; shift ;;
        --shell)            SHELL_MODE=1; shift ;;
        --deps)             DEPS=1; shift ;;
        -f|--fs-only)       FS_ONLY=1; shift ;;
        -i|--image-only)    IMAGE_ONLY=1; shift ;;
        -I|--interactive)   INTERACTIVE=1; shift ;;
        --clean)            CLEAN=1; shift ;;
        --purge)            PURGE=1; shift ;;
        --no-apt-cache)     APT_CACHE=0; shift ;;
        --no-fix-perms)     FIX_PERMS=0; shift ;;
        --in-container)     IN_CONTAINER=1; shift ;;
        --dry-run)          DRY_RUN=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        --)                 shift; OVERRIDES+=("$@"); break ;;
        [A-Za-z_]*=*)       OVERRIDES+=("$1"); shift ;;
        *)                  usage >&2; die "Unknown argument: $1" ;;
    esac
done

USER_VERSION=''
for kv in "${OVERRIDES[@]}"; do
    [[ $kv =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || die "Override must be key=value: '$kv'"
    case $kv in
        IGconf_artefact_version=*) USER_VERSION=${kv#*=} ;;
        IGconf_device_user1pass=*)
            warn "IGconf_device_user1pass is stored in plain text in the work dir (bootstrap/, chroot-*/config.yaml) and in the deploy set. Prefer IGconf_device_user1passhash=<hash>, made with: openssl passwd -6" ;;
    esac
done
if [[ $FS_ONLY -eq 1 && $IMAGE_ONLY -eq 1 ]]; then
    die "--fs-only and --image-only exclude each other (together they would build nothing)"
fi
if (( PURGE + CLEAN + DEPS + SHELL_MODE > 1 )); then
    die "--purge, --clean, --deps and --shell exclude each other"
fi
if [[ $MODE == docker && -n $WORKROOT ]]; then
    die "-B is not used with --docker: the work dir is the volume $WORK_VOLUME (set OTP_IMAGE_WORK_VOLUME to use another one)"
fi
if [[ $MODE != docker ]] && { (( SHELL_MODE + REBUILD > 0 )) || [[ -n $ENGINE ]]; }; then
    die "--shell, --rebuild and --engine only apply together with --docker"
fi
# Name of the file in the out dir that lists the images this run produced
# (a front end may pass it; plain build.sh runs do not need one).
RESULT_NAME=${OTP_IMAGE_RESULT:-}
[[ -z $RESULT_NAME || $RESULT_NAME =~ ^[A-Za-z0-9._-]+$ ]] || die "OTP_IMAGE_RESULT must be a plain file name"

CONFIG=${CONFIG:-$ROOT/example.yaml}
[[ -f $CONFIG ]] || die "Config not found: $CONFIG"
CONFIG=$(realpath -e "$CONFIG")
# Identifies the config across runs (--image-only checks it). Relative to the
# checkout when inside it; a container only sees an outside config as
# /cfg/<name>, so the front end hands down the real path.
if [[ -n ${OTP_IMAGE_CONFIG_ID:-} ]]; then
    CONFIG_ID=${OTP_IMAGE_CONFIG_ID//$'\n'/ }
elif [[ $CONFIG == "$ROOT"/* ]]; then
    CONFIG_ID=${CONFIG#"$ROOT"/}
else
    CONFIG_ID=$CONFIG
fi
if [[ -z $OUTDIR ]]; then
    if [[ $IN_CONTAINER -eq 1 ]]; then OUTDIR=/out; else OUTDIR=$ROOT/out; fi
fi

# git describe of a tree, with -dirty for local changes. 'describe --dirty'
# refreshes and rewrites the index even with GIT_OPTIONAL_LOCKS=0, and this
# checkout's index may belong to Windows git (WSL /mnt/c) or be read-only;
# 'status' honours GIT_OPTIONAL_LOCKS and only refreshes in memory.
git_version() {
    local v
    v=$(git -c safe.directory='*' -C "$1" describe --tags --always 2>/dev/null) || return 1
    if [[ -n $(GIT_OPTIONAL_LOCKS=0 git -c safe.directory='*' -C "$1" status --porcelain --untracked-files=no 2>/dev/null) ]]; then
        v+=-dirty
    fi
    printf '%s\n' "$v"
}

# Version tag for rpi-image-gen's chroot-/deploy-<version> directories:
# git describe of the checkout (the station computes it on Windows and hands
# it down). Restricted to characters that are safe in a path component (a tag
# like release/1.0 must not nest dirs). An explicit IGconf_artefact_version=...
# override wins.
HOST_VERSION=''
if [[ -z $USER_VERSION && -z ${OTP_IMAGE_VERSION:-} ]]; then HOST_VERSION=$(git_version "$ROOT" || true); fi
if [[ -n $USER_VERSION ]]; then
    VERSION=$USER_VERSION
else
    VERSION=${OTP_IMAGE_VERSION:-$HOST_VERSION}
    VERSION=${VERSION:-$(date +%Y-%m-%d)}
    VERSION=${VERSION//[^A-Za-z0-9._-]/_}
fi

# ---- Helpers ----------------------------------------------------------------
ensure_submodule() {
    [[ -f "$ROOT/rpi-image-gen/rpi-image-gen" ]] && return 0
    if [[ $IN_CONTAINER -eq 1 ]]; then
        die "rpi-image-gen submodule is not checked out. On the host run: git submodule update --init --recursive"
    fi
    git -c safe.directory='*' -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 \
        || die "rpi-image-gen submodule missing and $ROOT is not in a git checkout"
    command -v git >/dev/null 2>&1 || die "git is required to fetch the rpi-image-gen submodule"
    log "Fetching the rpi-image-gen submodule..."
    git -c safe.directory='*' -C "$ROOT" submodule update --init --recursive rpi-image-gen
    [[ -f "$ROOT/rpi-image-gen/rpi-image-gen" ]] || die "Submodule checkout failed"
}

# Filesystem type of a path, or of its nearest existing parent (stat -f).
# Windows/network/FUSE mounts cannot host the build (no ownership, device
# nodes or bind mounts) and need staging.
fs_type() {
    local p=$1
    while [[ ! -e $p && $p != / && $p != . ]]; do p=$(dirname "$p"); done
    stat -f -c %T "$p" 2>/dev/null || echo unknown
}
fs_is_foreign() {
    case $(fs_type "$1") in
        v9fs|9p|drvfs|fuse*|virtiofs|cifs|smb*|nfs*|vboxsf|prl_fs|ntfs*|vfat|msdos|exfat|fat|hfs*|afs|sshfs|autofs) return 0 ;;
        *) return 1 ;;
    esac
}

# May this file have its CRLF rewritten? Callers only pass files that grep -I
# already considers text (no NUL bytes); file(1) then vetoes the binary
# families that can be NUL-free, so keyrings, images and archives stay intact
# while unit files, INI-style configs and templates are treated as text.
is_text_file() {
    local f=$1 mime=''
    command -v file >/dev/null 2>&1 && mime=$(file -b --mime-type "$f" 2>/dev/null || true)
    case $mime in
        image/svg+xml) return 0 ;;   # XML, not pixels
        image/*|audio/*|video/*|font/*) return 1 ;;
        application/pgp*|application/x-bytecode*|application/zip|application/gzip|application/x-xz|\
        application/x-bzip2|application/zstd|application/x-tar|application/x-7z-compressed|\
        application/x-rar|application/x-executable|application/x-sharedlib|application/x-object|\
        application/x-pie-executable|application/x-dosexec|application/x-mach-binary|\
        application/vnd.*|application/pdf|application/x-sqlite3|application/wasm) return 1 ;;
    esac
    return 0
}

# CRLF -> LF in the staged text files. The source's mtime is put back, so make
# (rpi-image-gen's host tool recipes) does not see a change on every run.
normalise_crlf() {
    local dst=$1 n=0 f rel
    while IFS= read -r -d '' f; do
        is_text_file "$f" || continue
        sed -i 's/\r$//' "$f"
        rel=${f#"$dst"/}
        if [[ -e $ROOT/$rel ]]; then touch -r "$ROOT/$rel" "$f" 2>/dev/null || true; fi
        n=$((n + 1))
    done < <(grep -rIlZ $'\r' "$dst" 2>/dev/null || true)
    if [[ $n -gt 0 ]]; then info "normalised CRLF -> LF in $n text file(s)"; fi
}

# File modes as git records them: the copy made every file 0644; tracked files
# that git lists as 100755 become 0755. Untracked files, or everything when git
# cannot read an index, are executable when they start with "#!".
apply_git_modes() {
    local dst=$1 sub tree entry mode path p f first
    local -A tracked=()
    for sub in '' rpi-image-gen; do
        tree=$ROOT${sub:+/$sub}
        if [[ ! -d $tree ]] || ! command -v git >/dev/null 2>&1; then continue; fi
        while IFS= read -r -d '' entry; do
            mode=${entry%% *}
            path=${entry#*$'\t'}
            case $mode in 120000|160000) continue ;; esac   # symlinks, submodules
            p="$dst/${sub:+$sub/}$path"
            tracked[$p]=1
            if [[ $mode == 100755 && -f $p && ! -L $p ]]; then chmod 0755 -- "$p"; fi
        done < <(git -c safe.directory='*' -C "$tree" ls-files -s -z 2>/dev/null || true)
    done
    if [[ ${#tracked[@]} -eq 0 ]]; then info "no git index readable - file modes from #! lines"; fi
    local -a rest=()
    while IFS= read -r -d '' f; do
        [[ -n ${tracked[$f]:-} ]] || rest+=("$f")
    done < <(find "$dst" -type f -print0)
    for f in "${rest[@]}"; do
        first=''
        IFS= read -r -n 2 -d '' first < "$f" 2>/dev/null || true
        if [[ $first == '#!' ]]; then chmod 0755 -- "$f"; fi
    done
    chmod 0755 "$dst/rpi-image-gen/rpi-image-gen" "$dst/rpi-image-gen/install_deps.sh"
}

# rpi-image-gen stamps 'git describe --dirty' of the source dir into
# /etc/rpi-issue (scripts/bdebstrap/cleanup01); the staged copy has no git
# metadata, so every image would say 999-unknown. It gets a linked-worktree
# admin dir of its own in the work dir: objects and refs come from the
# checkout (commondir), HEAD and the index are private copies - the index
# refresh that describe --dirty does never touches the checkout's index.
link_git_metadata() {
    local dst=$1 gd common admin=$WORKROOT/.git-src
    rm -rf -- "$dst/.git" "$admin"
    command -v git >/dev/null 2>&1 || return 0
    gd=$(git -c safe.directory='*' -C "$ROOT" rev-parse --absolute-git-dir 2>/dev/null) || return 0
    common=$(git -c safe.directory='*' -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || common=$gd
    [[ -f $gd/HEAD && -f $gd/index && -d $common/objects ]] || return 0
    mkdir -p "$admin"
    cp -- "$gd/HEAD" "$admin/HEAD"
    cp -- "$gd/index" "$admin/index"
    printf '%s\n' "$common" > "$admin/commondir"
    printf '%s\n' "$dst/.git" > "$admin/gitdir"
    printf 'gitdir: %s\n' "$admin" > "$dst/.git"
}

# Copy the checkout into <work dir>/src (see the header).
stage_sources() {
    local dst=$1
    [[ ! -L $dst ]] || die "$dst is a symlink; refusing to stage the sources through it"
    log "Staging sources: $ROOT -> $dst"
    mkdir -p "$dst"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete --chmod=D755,F644 \
            --exclude '/.git' --exclude '/rpi-image-gen/.git' \
            --exclude '/work' --exclude '/out' --exclude '__pycache__' \
            "$ROOT/" "$dst/"
    else
        # rsync is one of the packages install_deps installs; until then copy.
        info "rsync not available - copying with cp"
        rm -rf -- "$dst"
        mkdir -p "$dst"
        (cd "$ROOT" && find . -mindepth 1 -maxdepth 1 ! -name .git ! -name work ! -name out \
            -exec cp -a -t "$dst/" -- {} +) || die "copying the sources to $dst failed"
        rm -rf -- "$dst/rpi-image-gen/.git"
        find "$dst" -name __pycache__ -type d -prune -exec rm -rf {} +
        find "$dst" -type d -exec chmod 0755 {} +
        find "$dst" -type f -exec chmod 0644 {} +
    fi
    normalise_crlf "$dst"
    apply_git_modes "$dst"
    link_git_metadata "$dst"
}

host_is_arm64() {
    case $(uname -m) in aarch64|arm64) return 0 ;; *) return 1 ;; esac
}

# rpi-image-gen's own checker (plus arch-test, which mmdebstrap needs for a
# foreign architecture). dependencies_check exit()s instead of returning,
# hence the subshell.
deps_missing() {
    if ! host_is_arm64 && ! command -v arch-test >/dev/null 2>&1; then return 0; fi
    if ( source "$IG/lib/dependencies.sh" && dependencies_check --category all "$IG/depends" ) >/dev/null 2>&1; then
        return 1
    fi
    return 0
}
print_missing_deps() {
    if ! host_is_arm64 && ! command -v arch-test >/dev/null 2>&1; then
        echo "Missing: arch-test (mmdebstrap needs it to build arm64 on this host)"
    fi
    ( source "$IG/lib/dependencies.sh" && dependencies_check --category all "$IG/depends" ) || true
}

DEPS_EXTRA=(file zstd git ca-certificates rsync)
if ! host_is_arm64; then DEPS_EXTRA+=(qemu-user-static binfmt-support arch-test); fi

# Is there a binfmt_misc handler that runs arm64 binaries inside a chroot?
# Matched by content, not by name: Docker Desktop registers 'aarch64' at every
# VM start, Debian's packages and tonistiigi/binfmt use 'qemu-aarch64'. The F
# flag is required - without it the interpreter is looked up inside the arm64
# chroot, where it does not exist. Same scan as docker/entrypoint.sh
# --binfmt-check; keep the two in sync.
binfmt_arm64_present() {
    local d=/proc/sys/fs/binfmt_misc e
    if [[ $(id -u) -eq 0 ]] && ! mountpoint -q "$d" 2>/dev/null; then
        mount -t binfmt_misc binfmt_misc "$d" 2>/dev/null || true
    fi
    for e in "$d"/*; do
        case ${e##*/} in register|status) continue ;; esac
        [[ -f $e ]] || continue
        [[ $(head -n1 "$e" 2>/dev/null) == enabled ]] || continue
        grep -qx "magic $ARM64_MAGIC" "$e" 2>/dev/null || continue
        grep -q '^flags: .*F' "$e" 2>/dev/null || continue
        return 0
    done
    return 1
}

install_deps() {
    local -a sudo=()
    if [[ $(id -u) -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 || die "sudo is needed to install the host dependencies"
        sudo=(sudo)
    fi
    log "Installing host dependencies with apt..."
    "${sudo[@]}" apt-get update
    "${sudo[@]}" apt-get install -y --no-install-recommends "${DEPS_EXTRA[@]}"
    # install_deps.sh refuses to finish while binfmt_misc is not loaded, so load
    # it first (a no-op where it is built in, e.g. WSL2).
    if ! grep -q binfmt_misc /proc/filesystems 2>/dev/null; then
        "${sudo[@]}" modprobe binfmt_misc || warn "could not load binfmt_misc"
    fi
    "${sudo[@]}" "$IG/install_deps.sh" || die "rpi-image-gen/install_deps.sh failed"
    if host_is_arm64 || binfmt_arm64_present; then return 0; fi
    # trixie registers QEMU through systemd-binfmt (qemu-user-binfmt), bookworm
    # and Ubuntu through binfmt-support; without systemd, write the handler the
    # package ships straight into the kernel.
    if [[ -d /run/systemd/system ]]; then "${sudo[@]}" systemctl restart systemd-binfmt 2>/dev/null || true; fi
    "${sudo[@]}" update-binfmts --enable qemu-aarch64 >/dev/null 2>&1 || true
    if ! binfmt_arm64_present && [[ -r /usr/lib/binfmt.d/qemu-aarch64.conf ]]; then
        local line
        line=$(grep -m1 '^:qemu-aarch64:' /usr/lib/binfmt.d/qemu-aarch64.conf || true)
        if [[ -n $line ]]; then
            # shellcheck disable=SC2016  # $1 is expanded by the inner sh
            "${sudo[@]}" sh -c 'mountpoint -q /proc/sys/fs/binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc; printf "%s" "$1" > /proc/sys/fs/binfmt_misc/register' sh "$line" || true
        fi
    fi
}

check_binfmt() {
    host_is_arm64 && return 0
    binfmt_arm64_present && return 0
    if [[ $IN_CONTAINER -eq 1 ]]; then
        die "no arm64 binfmt handler in the host kernel. Register it once on the host:
         docker run --privileged --rm tonistiigi/binfmt --install arm64
       (build.sh --docker and the station do this automatically)"
    fi
    die "no arm64 binfmt handler that works inside a chroot (enabled, aarch64 magic, F flag).
       Run ./build.sh --deps (installs qemu-user-static), or start Docker Desktop on WSL (it registers one)."
}

# apt inside the chroot runs as _apt (a subuid on the host) and must traverse
# every parent of the work dir. Upstream CI does chmod o+x $HOME for this.
fix_parent_perms() {
    [[ $(id -u) -eq 0 ]] && return 0
    local p mode
    p=$(realpath -e "$1")
    while [[ $p != / ]]; do
        mode=$(stat -c %a "$p")
        if (( 8#$mode & 1 )); then
            p=$(dirname "$p"); continue
        fi
        if [[ $FIX_PERMS -eq 1 && -O $p ]]; then
            log "chmod o+x $p (apt inside the chroot must traverse it)"
            chmod o+x "$p"
        else
            warn "$p is mode $mode (no world-execute); apt inside the chroot will fail. Fix: chmod o+x '$p'"
        fi
        p=$(dirname "$p")
    done
    return 0
}

getvar() {
    local line
    line=$(grep -m1 "^$1=" "$2" 2>/dev/null) || return 1
    line=${line#*=}; line=${line#\"}; line=${line%\"}
    [[ -n $line ]] || return 1
    printf '%s\n' "$line"
}

# Run a command in the namespace the build's files and mounts live in: a
# rootless build's files are owned by subuids (the chroot's users) and its
# mounts sit in podman's pause namespace, which 'podman unshare' joins. fd 9
# (the work dir lock) is closed for podman: its pause process outlives the call
# and must not keep the lock.
in_build_ns() {
    if [[ $(id -u) -ne 0 ]] && command -v podman >/dev/null 2>&1; then
        podman --cgroup-manager=cgroupfs unshare "$@" 9>&-
    else
        "$@"
    fi
}

# Detaches what a killed build left mounted strictly below each given dir
# (mmdebstrap's proc, sys, dev/pts, a bind of the host's /dev/shm, the apt
# cache bind), then - unless --release-only - deletes the dirs without
# crossing into another filesystem: rm -rf through a leftover bind of /dev/shm
# would empty the host's /dev/shm. A dir that is itself a mount point is
# emptied, not removed.
# shellcheck disable=SC2016  # a script for 'bash -c': it expands its own variables
RM_SCRIPT='
release_only=0
if [ "$1" = --release-only ]; then release_only=1; shift; fi
rc=0
for p in "$@"; do
    mapfile -t ms < <(while read -r _ _ _ _ m _; do
                          m=${m//\\040/ }
                          if [[ $m == "$p"/* ]]; then printf "%s\n" "$m"; fi
                      done < /proc/self/mountinfo | sort -r)
    for m in "${ms[@]}"; do
        umount -l -- "$m" || { echo "cannot unmount $m" >&2; rc=1; }
    done
done
[ $rc -eq 0 ] || exit 1
[ $release_only -eq 1 ] && exit 0
rm -rf --one-file-system -- "$@"
for p in "$@"; do
    if [ -e "$p" ] && ! { mountpoint -q "$p" && [ -z "$(ls -A "$p")" ]; }; then
        echo "could not delete $p" >&2; rc=1
    fi
done
exit $rc
'

# Delete build output (see RM_SCRIPT).
rm_tree() {
    local -a paths=()
    local d
    for d in "$@"; do
        if [[ -e $d || -L $d ]]; then paths+=("$d"); fi
    done
    [[ ${#paths[@]} -gt 0 ]] || return 0
    in_build_ns bash -c "$RM_SCRIPT" rm_tree "${paths[@]}" \
        || die "could not delete ${paths[*]} (something still mounted there? 'podman system migrate' or 'wsl --shutdown' releases what a killed rootless build left)"
}

# Before a build: release leftover mounts in the work dir, so bdebstrap's own
# clean-up of chroot-<version> cannot reach through them either.
release_mounts() {
    [[ -d $1 ]] || return 0
    in_build_ns bash -c "$RM_SCRIPT" release_mounts --release-only "$1" \
        || die "something a killed build mounted below $1 cannot be unmounted ('podman system migrate' or 'wsl --shutdown' releases it)"
}

# A work dir belongs to build.sh when it is new or empty, carries the marker
# of an earlier run, or is the default location (adopted as is: work dirs from
# before the marker existed). Anything else is refused - a build would replace
# <dir>/src and --purge would delete <dir>.
workroot_is_ours() {
    [[ -d $WORKROOT ]] || return 0
    [[ -e $WORKROOT/$WORKROOT_MARKER ]] && return 0
    [[ $WORKROOT == "$DEFAULT_WORKROOT" ]] && return 0
    local e
    for e in "$WORKROOT"/* "$WORKROOT"/.[!.]* "$WORKROOT"/..?*; do
        [[ -e $e || -L $e ]] || continue
        [[ ${e##*/} == lost+found ]] && continue
        return 1
    done
    return 0
}
require_own_workroot() {
    workroot_is_ours || die "$WORKROOT is not empty and was not created by build.sh. A build would replace $WORKROOT/src and fill the directory with rpi-image-gen's work tree, and --purge would delete it. Pass an empty or new directory with -B."
    [[ ! -L $WORKROOT/src ]] || die "$WORKROOT/src is a symlink; refusing to stage the sources through it"
}
claim_workroot() {
    mkdir -p "$WORKROOT"
    if [[ ! -e $WORKROOT/$WORKROOT_MARKER ]]; then
        printf 'Work dir of the station image build.sh. Delete it with: build.sh --purge -B %s\n' "$WORKROOT" > "$WORKROOT/$WORKROOT_MARKER"
    fi
}

# One build per work dir. The lock lives on fd 9 of this shell only; commands
# that may leave long-lived children run with fd 9 closed (see rm_tree and the
# rpi-image-gen call), so the lock goes away when this script exits.
acquire_lock() {
    if ! command -v flock >/dev/null 2>&1; then
        warn "flock not found - no protection against a second build in $WORKROOT"
        return 0
    fi
    exec 9>"$WORKROOT/$LOCK_FILE"
    flock -n 9 || die "another build is using $WORKROOT (lock $WORKROOT/$LOCK_FILE). Wait for it to finish, or pass -B <other dir>."
}

# The chroot-/deploy-/image- dirs builds created. rpi-image-gen names them
# after the version, so they are globbed rather than derived from one config.
list_outputs() {
    local d
    for d in "$WORKROOT"/chroot-* "$WORKROOT"/deploy-* "$WORKROOT"/image-*; do
        if [[ -d $d ]]; then printf '%s\n' "$d"; fi
    done
    return 0
}

# --clean: everything a build produced, nothing it merely caches.
clean_outputs() {
    local -a dirs=()
    mapfile -t dirs < <(list_outputs)
    if [[ -d $WORKROOT/bootstrap ]]; then dirs+=("$WORKROOT/bootstrap"); fi
    if [[ ${#dirs[@]} -eq 0 ]]; then info "nothing to clean in $WORKROOT"; return 0; fi
    local d
    for d in "${dirs[@]}"; do info "removing $d"; done
    rm_tree "${dirs[@]}"
    rm -f -- "$WORKROOT/$FS_MARKER" "$WORKROOT/$RUN_STAMP"
}

# After a successful build keep only its own chroot-/deploy-/image- dirs.
prune_old_outputs() {
    local final=$1 keep_target keep_deploy keep_image d
    keep_target=$(getvar IGconf_target_dir "$final") || keep_target=''
    keep_deploy=$(getvar IGconf_deploy_dir "$final") || keep_deploy=''
    keep_image=$(getvar IGconf_image_outputdir "$final") || keep_image=''
    local -a old=()
    while IFS= read -r d; do
        [[ $d == "$keep_target" || $d == "$keep_deploy" || $d == "$keep_image" ]] && continue
        info "removing $(basename "$d") (older build)"
        old+=("$d")
    done < <(list_outputs)
    rm_tree "${old[@]}"
}

# Keep only the .debs the new rootfs has installed: superseded versions would
# pile up for ever (each Raspberry Pi kernel update alone is ~30 MB).
prune_apt_cache() {
    local rootfs=$1 cache=$WORKROOT/apt-cache status f base name ver arch
    status=$rootfs/var/lib/dpkg/status
    [[ -d $cache && -r $status ]] || return 0
    local -A keep=()
    while IFS='|' read -r name ver arch; do
        [[ -n $name ]] && keep["${name}_${ver//:/%3a}_${arch}"]=1
    done < <(awk -F': ' '/^Package: /{p=$2} /^Version: /{v=$2} /^Architecture: /{a=$2}
                         /^$/{if (p != "") print p "|" v "|" a; p = v = a = ""}
                         END{if (p != "") print p "|" v "|" a}' "$status")
    [[ ${#keep[@]} -gt 0 ]] || return 0
    local -a drop=()
    for f in "$cache"/*.deb; do
        [[ -f $f ]] || continue
        base=${f##*/}; base=${base%.deb}
        [[ -n ${keep[$base]:-} ]] || drop+=("$f")
    done
    if [[ ${#drop[@]} -gt 0 ]]; then
        info "apt cache: removing ${#drop[@]} .deb(s) the new rootfs does not use"
        rm_tree "${drop[@]}"
    fi
}

# rpi-image-gen builds its host tools (bdebstrap, genimage, ...) once into
# <work>/build and <work>/<gnu type>, and make only looks at its own stamps.
# A different rpi-image-gen revision or toolchain would keep the old binaries,
# so their inputs are hashed and the tools rebuilt when the hash changes. The
# downloaded source tarballs and the apt cache stay.
refresh_host_tools() {
    local kv gnu stamp_new stamp_old
    for kv in "${OVERRIDES[@]}"; do
        case $kv in
            IGconf_sys_buildroot=*|IGconf_sys_cachedir=*)
                info "custom IGconf_sys_buildroot/cachedir: host tools are not checked for staleness"
                return 0 ;;
        esac
    done
    gnu=$(dpkg-architecture -qDEB_BUILD_GNU_TYPE 2>/dev/null) || return 0
    stamp_new=$({
        (cd "$IG" && find package lib/tools.sh layer/sbom/gen.sh -type f -print0 2>/dev/null \
            | sort -z | xargs -0 sha256sum) || true
        python3 -c 'import sysconfig; print(sysconfig.get_python_version())' 2>/dev/null || true
        gcc -dumpfullversion 2>/dev/null || true
        grep -E '^(ID|VERSION_ID)=' /etc/os-release 2>/dev/null || true
    } | sha256sum | cut -d' ' -f1)
    stamp_old=$(cat "$WORKROOT/$TOOLS_STAMP" 2>/dev/null || true)
    [[ $stamp_new == "$stamp_old" ]] && return 0
    if [[ -n $stamp_old || -d $WORKROOT/build ]]; then
        info "rpi-image-gen's host tool recipes or the toolchain changed - rebuilding the host tools"
        rm_tree "$WORKROOT/build" "$WORKROOT/$gnu" "$WORKROOT/cache/pip-cache" "$WORKROOT/cache/pip-wheels"
    fi
    printf '%s\n' "$stamp_new" > "$WORKROOT/$TOOLS_STAMP"
}

# The out dir must exist and be writable before an image is built, not after
# minutes of building. In the container it must be a mount: otherwise the
# image stays in the container and --rm throws it away.
check_outdir() {
    if [[ $IN_CONTAINER -eq 1 && $OUTDIR == /out ]] && ! mountpoint -q /out; then
        die "/out is not a mount point: the image would stay in the container. Mount an output dir: -v <dir>:/out"
    fi
    mkdir -p -- "$OUTDIR" 2>/dev/null || die "cannot create the output dir $OUTDIR"
    local p
    p=$(mktemp "$OUTDIR/.otp-image-probe.XXXXXX" 2>/dev/null) || die "the output dir $OUTDIR is not writable"
    rm -f -- "$p"
}

# The build tree is case-sensitive; a Windows checkout is not. A -c path typed
# in another case exists there but not here, so look it up ignoring case.
resolve_config_case() {
    [[ -f $CFG ]] && return 0
    local pat hit
    pat=$(printf '%s' "$CFG" | sed 's/[][*?\\]/\\&/g')
    hit=$(find "$SRC" -type f -iwholename "$pat" -print -quit 2>/dev/null || true)
    [[ -n $hit ]] || die "config $CFG not found in the build tree (it is case-sensitive: give -c with the exact case)"
    info "config: using $hit (the case differs from $CFG)"
    CFG=$hit
}

# Copy an image into the out dir under a temporary name of its own (two builds
# may share one out dir), then rename it: an interrupted copy never leaves a
# truncated image under the final name, and the rename also replaces an image
# a root container wrote earlier.
PART_FILE=''
copy_out() {
    local f=$1 b
    b=${f##*/}
    PART_FILE=$(mktemp "$OUTDIR/.$b.XXXXXX.part") || die "cannot create a temporary file in $OUTDIR"
    if ! cp --sparse=always -- "$f" "$PART_FILE"; then
        rm -f -- "$PART_FILE"
        PART_FILE=''
        die "copying the image to $OUTDIR failed; the built image is $f"
    fi
    chmod 0644 -- "$PART_FILE" 2>/dev/null || true   # mktemp made it 0600
    mv -f -- "$PART_FILE" "$OUTDIR/$b"
    PART_FILE=''
}

purge_native() {
    if [[ ! -d $WORKROOT ]]; then info "nothing to purge ($WORKROOT does not exist)"; return 0; fi
    acquire_lock
    log "Deleting $WORKROOT"
    rm_tree "$WORKROOT"
}

CONTAINER_NAME=''
CONTAINER_ENGINE=''
on_exit() {
    if [[ -n $PART_FILE ]]; then rm -f -- "$PART_FILE"; fi
    if [[ -n $CONTAINER_NAME ]]; then "$CONTAINER_ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true; fi
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---- Container mode ---------------------------------------------------------
run_in_docker() {
    local eng=$ENGINE
    if [[ -z $eng ]]; then
        if command -v docker >/dev/null 2>&1; then eng=docker
        elif command -v podman >/dev/null 2>&1; then eng=podman
        else die "--docker needs docker or podman on PATH"; fi
    fi
    command -v "$eng" >/dev/null 2>&1 || die "$eng not found on PATH"

    local want_out=0
    if (( SHELL_MODE == 1 || (FS_ONLY + CLEAN + DEPS == 0) )); then want_out=1; fi
    local out_abs cfg_abs
    out_abs=$(realpath -m "$OUTDIR")
    cfg_abs=$CONFIG

    local -a inner=(--in-container -B /work)
    local -a mounts=(-v "$ROOT:/src:ro" -v "$WORK_VOLUME:/work")
    if [[ $want_out -eq 1 ]]; then mounts+=(-v "$out_abs:/out"); inner+=(-o /out); fi
    if [[ $cfg_abs == "$ROOT"/* ]]; then
        inner+=(-c "/src/${cfg_abs#"$ROOT"/}")
    else
        mounts+=(-v "$(dirname "$cfg_abs"):/cfg:ro")
        inner+=(-c "/cfg/$(basename "$cfg_abs")")
    fi
    if [[ $FS_ONLY -eq 1 ]];     then inner+=(--fs-only); fi
    if [[ $IMAGE_ONLY -eq 1 ]];  then inner+=(--image-only); fi
    if [[ $INTERACTIVE -eq 1 ]]; then inner+=(--interactive); fi
    if [[ $CLEAN -eq 1 ]];       then inner+=(--clean); fi
    if [[ $APT_CACHE -eq 0 ]];   then inner+=(--no-apt-cache); fi
    if [[ ${#OVERRIDES[@]} -gt 0 ]]; then inner+=(-- "${OVERRIDES[@]}"); fi

    local -a tty=(-i)
    if [[ -t 0 && -t 1 ]]; then tty+=(-t); fi
    local -a envs=(-e OTP_IMAGE_IN_CONTAINER=1 -e OTP_IMAGE_ROOT=/src -e "TERM=${TERM:-xterm}" -e "OTP_IMAGE_CONFIG_ID=$CONFIG_ID")
    # Without a version from the host the container runs git describe itself.
    local fwd_version=${OTP_IMAGE_VERSION:-$HOST_VERSION}
    if [[ -n $fwd_version ]]; then envs+=(-e "OTP_IMAGE_VERSION=$fwd_version"); fi
    if [[ -n ${SOURCE_DATE_EPOCH:-} ]]; then envs+=(-e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"); fi
    if [[ -n $RESULT_NAME ]]; then envs+=(-e "OTP_IMAGE_RESULT=$RESULT_NAME"); fi

    local -a bargs=(build -t "$IMAGE_TAG")
    if [[ $REBUILD -eq 1 ]]; then bargs+=(--pull --no-cache); fi
    if [[ $DEPS -eq 1 ]]; then bargs+=(--pull); fi

    if [[ $DRY_RUN -eq 1 ]]; then
        if [[ $PURGE -eq 1 ]]; then echo "$eng volume rm -f $WORK_VOLUME"; return 0; fi
        echo "$eng ${bargs[*]} $ROOT/docker"
        [[ $DEPS -eq 1 ]] && return 0
        if [[ $SHELL_MODE -eq 1 ]]; then
            echo "$eng run --rm -it --privileged ${envs[*]} ${mounts[*]} --entrypoint bash $IMAGE_TAG"
        else
            echo "$eng run --rm ${tty[*]} --privileged ${envs[*]} ${mounts[*]} $IMAGE_TAG ${inner[*]}"
        fi
        return 0
    fi

    "$eng" info >/dev/null 2>&1 || die "$eng daemon is not reachable (is it running? do you have permission?)"

    if [[ $PURGE -eq 1 ]]; then
        log "Removing work volume $WORK_VOLUME"
        "$eng" volume rm -f "$WORK_VOLUME" >/dev/null
        return 0
    fi

    ensure_submodule
    if [[ $want_out -eq 1 ]]; then mkdir -p "$OUTDIR"; fi

    log "Builder image $IMAGE_TAG"
    "$eng" "${bargs[@]}" "$ROOT/docker"
    if [[ $DEPS -eq 1 ]]; then
        log "Dependencies live in the builder image; it is up to date."
        return 0
    fi

    # arm64 binfmt handler in the host kernel (only needed on non-arm64 hosts,
    # and not for --clean). Check the host first: a rootless engine cannot see or
    # register it, but the host may already have one.
    if [[ $CLEAN -eq 0 ]] && ! host_is_arm64 && ! binfmt_arm64_present; then
        if ! "$eng" run --rm --privileged "$IMAGE_TAG" --binfmt-check >/dev/null 2>&1; then
            log "Registering the arm64 QEMU binfmt handler in the host kernel (tonistiigi/binfmt)"
            "$eng" run --rm --privileged tonistiigi/binfmt --install arm64 \
                || die "could not register the arm64 binfmt handler (rootless engine?). On the host run:
         sudo apt install qemu-user-static   (then ./build.sh --deps checks it)"
        fi
    fi

    if [[ $SHELL_MODE -eq 1 ]]; then
        [[ -t 0 && -t 1 ]] || die "--shell needs a terminal"
        exec "$eng" run --rm -it --privileged --hostname otp-image-builder "${envs[@]}" "${mounts[@]}" \
            --entrypoint bash "$IMAGE_TAG"
    fi

    log "Building in $eng ($IMAGE_TAG, work volume $WORK_VOLUME)"
    # Named, so an interrupted run can remove the container (see on_exit).
    CONTAINER_ENGINE=$eng
    CONTAINER_NAME="otp-image-build-$$-$RANDOM"
    "$eng" run --rm "${tty[@]}" --name "$CONTAINER_NAME" --privileged --hostname otp-image-builder \
        "${envs[@]}" "${mounts[@]}" "$IMAGE_TAG" "${inner[@]}"
    CONTAINER_NAME=''
    if [[ $want_out -eq 1 && $SHELL_MODE -eq 0 ]]; then log "Image(s) copied to $out_abs"; fi
}

# ---- Native mode ------------------------------------------------------------
run_native() {
    command -v dpkg >/dev/null 2>&1 \
        || die "rpi-image-gen needs a Debian-based host (dpkg/apt). On other distros use: ./build.sh --docker"

    local staged=0
    if [[ $IN_CONTAINER -eq 1 ]] || fs_is_foreign "$ROOT"; then staged=1; fi
    if [[ $IN_CONTAINER -eq 1 ]]; then
        DEFAULT_WORKROOT=/work
    elif [[ $staged -eq 1 ]]; then
        DEFAULT_WORKROOT=$(realpath -m "${XDG_CACHE_HOME:-$HOME/.cache}/otp-image/work")
    else
        DEFAULT_WORKROOT=$(realpath -m "$ROOT/work")
    fi
    WORKROOT=$(realpath -m "${WORKROOT:-$DEFAULT_WORKROOT}")

    if [[ $PURGE -eq 1 ]]; then
        if [[ -d $WORKROOT ]]; then
            workroot_is_ours || die "$WORKROOT was not created by build.sh; refusing to delete it"
        fi
        if [[ $DRY_RUN -eq 1 ]]; then echo "would delete $WORKROOT"; return 0; fi
        purge_native
        return 0
    fi
    require_own_workroot

    local SRC
    if [[ $staged -eq 1 ]]; then SRC="$WORKROOT/src"; else SRC=$ROOT; fi
    IG="$SRC/rpi-image-gen"
    if [[ $CONFIG == "$ROOT"/* ]]; then CFG="$SRC/${CONFIG#"$ROOT"/}"; else CFG=$CONFIG; fi

    # --image-only regenerates the image of the filesystem that is there. That
    # filesystem lives in chroot-<version of its build>; under any other version
    # rpi-image-gen would find no rootfs, skip genimage without an error and
    # leave the previous image in place. .otp-image-fs records version, config and
    # rootfs of the last filesystem build that finished; a build that starts
    # removes it (see below).
    if [[ $IMAGE_ONLY -eq 1 && $CLEAN -eq 0 && $DEPS -eq 0 ]]; then
        local fsver='' fscfg='' fspath=''
        if [[ -r $WORKROOT/$FS_MARKER ]]; then
            { IFS= read -r fsver; IFS= read -r fscfg; IFS= read -r fspath; } < "$WORKROOT/$FS_MARKER" || true
        fi
        if [[ -n $fsver ]]; then
            if [[ -n $fscfg && $fscfg != "$CONFIG_ID" ]]; then
                die "--image-only: the filesystem in $WORKROOT was built from $fscfg, not $CONFIG_ID. Run a full build of $CONFIG_ID."
            fi
            if [[ -n $USER_VERSION && $USER_VERSION != "$fsver" ]]; then
                die "--image-only: the filesystem in $WORKROOT was built as $fsver; IGconf_artefact_version=$USER_VERSION names one that does not exist. Drop the override, or run a full build."
            fi
            if [[ $DRY_RUN -eq 0 && -n $fspath && ! -d $fspath ]]; then
                die "--image-only: the filesystem $fspath is gone; run a full build"
            fi
            if [[ -z $USER_VERSION && $fsver != "$VERSION" ]]; then
                info "image only: using the filesystem built as $fsver (the checkout is $VERSION now)"
                VERSION=$fsver
            fi
        elif [[ $DRY_RUN -eq 0 ]]; then
            die "--image-only needs the filesystem of an earlier full or --fs-only build in $WORKROOT; there is none"
        fi
    fi

    local -a ov=()
    if [[ -z $USER_VERSION ]]; then ov+=("IGconf_artefact_version=$VERSION"); fi   # else it is in OVERRIDES
    if [[ $APT_CACHE -eq 1 ]]; then ov+=("IGconf_sys_apt_cachedir=$WORKROOT/apt-cache"); fi
    ov+=("${OVERRIDES[@]}")

    if [[ $CLEAN -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then
            echo "would delete from $WORKROOT:"
            list_outputs | sed 's/^/    /'
            if [[ -d $WORKROOT/bootstrap ]]; then echo "    $WORKROOT/bootstrap"; fi
            return 0
        fi
        [[ -d $WORKROOT ]] || { info "nothing to clean ($WORKROOT does not exist)"; return 0; }
        acquire_lock
        log "Cleaning $WORKROOT"
        clean_outputs
        return 0
    fi

    if [[ $DEPS -eq 1 && $DRY_RUN -eq 1 ]]; then
        echo "would run: apt-get install ${DEPS_EXTRA[*]}; rpi-image-gen/install_deps.sh (with sudo unless root)"
        return 0
    fi

    log "Raspberry Pi OS image build"
    info "config:   $CFG"
    info "sources:  $SRC"
    info "work:     $WORKROOT"
    info "output:   $OUTDIR"
    info "version:  $VERSION"
    if [[ $DRY_RUN -eq 1 ]]; then
        local -a show=("$IG/rpi-image-gen" build -S "$SRC" -c "$CFG" -B "$WORKROOT")
        if [[ $FS_ONLY -eq 1 ]];     then show+=(-f); fi
        if [[ $IMAGE_ONLY -eq 1 ]];  then show+=(-i); fi
        if [[ $INTERACTIVE -eq 1 ]]; then show+=(-I); fi
        printf '%q ' "${show[@]}" -- "${ov[@]}"; echo
        return 0
    fi

    ensure_submodule
    if fs_is_foreign "$WORKROOT"; then
        die "work dir $WORKROOT is on '$(fs_type "$WORKROOT")'; rpi-image-gen needs a Linux filesystem here (pass -B <dir on ext4/btrfs/xfs>)"
    fi
    claim_workroot
    acquire_lock

    if [[ $staged -eq 1 ]]; then
        stage_sources "$SRC"
        resolve_config_case
    elif grep -q $'\r' "$IG/rpi-image-gen" "$IG/depends" 2>/dev/null; then
        die "rpi-image-gen in $ROOT has Windows line endings (checked out by Windows git?). Check it out again with Linux git:
         git -C '$ROOT' submodule deinit -f rpi-image-gen && git -C '$ROOT' submodule update --init rpi-image-gen"
    fi

    if [[ $DEPS -eq 1 ]]; then
        install_deps
        deps_missing && { print_missing_deps; die "Dependencies are still missing after the install (see above)"; }
        check_binfmt
        log "Host dependencies OK"
        return 0
    fi
    if deps_missing; then
        print_missing_deps
        if [[ $IN_CONTAINER -eq 1 ]]; then
            die "The builder image lacks dependencies - rebuild it: ./build.sh --docker --rebuild (the station: Rebuild on the image)"
        fi
        warn "Host dependencies are missing - installing them now (sudo may ask for your password)."
        install_deps
        deps_missing && { print_missing_deps; die "Dependencies are still missing after the install (see above)"; }
    fi
    check_binfmt
    fix_parent_perms "$WORKROOT"

    # bdebstrap is pip-installed into rpi-image-gen's private sysroot (--root);
    # Debian's PEP 668 guard would otherwise refuse a system-python pip install.
    export PIP_BREAK_SYSTEM_PACKAGES=1
    export PYTHONDONTWRITEBYTECODE=1
    # The staged copy's .git points at the checkout's git dir; git commands in
    # the build must not rewrite that index (see link_git_metadata).
    export GIT_OPTIONAL_LOCKS=0
    # Rootless: rpi-image-gen only uses 'podman unshare', which needs no cgroups.
    # Without a systemd user session (wsl -e, ssh without lingering) podman
    # warns about its systemd cgroup manager on every call.
    if [[ $(id -u) -ne 0 && -z ${CONTAINERS_CONF_OVERRIDE:-} ]]; then
        printf '[engine]\ncgroup_manager = "cgroupfs"\n' > "$WORKROOT/.containers.conf"
        export CONTAINERS_CONF_OVERRIDE="$WORKROOT/.containers.conf"
    fi

    refresh_host_tools
    if [[ $FS_ONLY -eq 0 ]]; then check_outdir; fi
    # The image artefacts belong to the filesystem being replaced; left in place,
    # rpi-image-gen's deploy step would package them under the new version.
    if [[ $FS_ONLY -eq 1 ]]; then
        local -a stale=()
        mapfile -t stale < <(compgen -G "$WORKROOT/image-*" || true)
        rm_tree "${stale[@]}"
    fi
    if [[ $APT_CACHE -eq 1 ]]; then mkdir -p "$WORKROOT/apt-cache"; fi

    local -a cmd=("$IG/rpi-image-gen" build -S "$SRC" -c "$CFG" -B "$WORKROOT")
    if [[ $FS_ONLY -eq 1 ]];     then cmd+=(-f); fi
    if [[ $IMAGE_ONLY -eq 1 ]];  then cmd+=(-i); fi
    if [[ $INTERACTIVE -eq 1 ]]; then cmd+=(-I); fi
    cmd+=(-- "${ov[@]}")

    # A filesystem build empties chroot-<version> before it fails or finishes,
    # and the image dir it shares with older builds (img_uuids) changes too, so
    # the record of the last finished filesystem goes before anything else does.
    if [[ $IMAGE_ONLY -eq 0 ]]; then rm -f -- "$WORKROOT/$FS_MARKER"; fi
    release_mounts "$WORKROOT"

    local start=$SECONDS
    : > "$WORKROOT/$RUN_STAMP"
    # fd 9 (the lock) closed: podman's rootless pause process outlives the build.
    (cd "$SRC" && "${cmd[@]}" 9>&-)
    local took=$(( SECONDS - start ))
    log "rpi-image-gen finished in $((took / 60))m$((took % 60))s"

    local final="$WORKROOT/bootstrap/final.env" rootfs tdir
    [[ -r $final ]] || die "$final not found after the build"
    rootfs=$(getvar IGconf_target_path "$final") || rootfs=''
    tdir=$(getvar IGconf_target_dir "$final") || tdir=''

    # rpi-image-gen also exits 0 when -I is answered with 'n'. Only a filesystem
    # this run wrote counts (bdebstrap writes <target dir>/manifest last) - before
    # that nothing is recorded and no older build is deleted.
    if [[ $IMAGE_ONLY -eq 0 ]]; then
        if ! [[ -n $tdir && $tdir/manifest -nt $WORKROOT/$RUN_STAMP ]] \
           && ! [[ -n $rootfs && $rootfs/var/lib/dpkg/status -nt $WORKROOT/$RUN_STAMP ]]; then
            die "rpi-image-gen stopped before it built the filesystem; nothing was recorded or deleted"
        fi
        printf '%s\n%s\n%s\n' "$VERSION" "$CONFIG_ID" "$rootfs" > "$WORKROOT/$FS_MARKER"
        prune_old_outputs "$final"
        if [[ $APT_CACHE -eq 1 && -n $rootfs ]]; then prune_apt_cache "$rootfs"; fi
    fi

    if [[ $FS_ONLY -eq 1 ]]; then
        info "filesystem only (-f): no image to copy; build it with --image-only"
        return 0
    fi

    local name outdir suffix deploy
    name=$(getvar IGconf_image_name "$final") || die "IGconf_image_name missing in $final"
    outdir=$(getvar IGconf_image_outputdir "$final") || die "IGconf_image_outputdir missing in $final"
    suffix=$(getvar IGconf_image_suffix "$final") || suffix=img
    deploy=$(getvar IGconf_deploy_dir "$final") || deploy=''

    # Only images written by this run: an old one left in the output dir must
    # never be passed off as the new build. rpi-image-gen runs genimage only
    # when the rootfs exists, but its post-image.sh truncates (and so touches)
    # every old image regardless - hence both checks.
    [[ -n $rootfs && -d $rootfs ]] || die "rpi-image-gen made no image: the filesystem $rootfs does not exist"
    local -a fresh=()
    mapfile -t fresh < <(find "$outdir" -maxdepth 1 -type f -name "$name*.$suffix" -newer "$WORKROOT/$RUN_STAMP" 2>/dev/null | sort)
    [[ ${#fresh[@]} -gt 0 ]] || die "rpi-image-gen finished but wrote no new $name*.$suffix to $outdir"

    local f
    local -a copied=()
    for f in "${fresh[@]}"; do
        copy_out "$f"
        copied+=("${f##*/}")
        info "$(du -h "$f" | cut -f1)  $OUTDIR/${f##*/}"
    done
    if [[ -n $RESULT_NAME ]]; then printf '%s\n' "${copied[@]}" > "$OUTDIR/$RESULT_NAME"; fi
    if [[ -n $deploy && -d $deploy ]]; then info "deploy set (zstd image, IDP archive, SBOM): $deploy"; fi
    log "Done. Flash with Raspberry Pi Imager (Use custom) or: sudo rpi-imager --cli $OUTDIR/$name.$suffix /dev/mmcblk0"
}

IG=''
CFG=''
DEFAULT_WORKROOT=''
if [[ $MODE == docker ]]; then
    run_in_docker
else
    run_native
fi
