# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository. README.md is the operator's
manual and the reference for every setting, endpoint and file; this file is about how the project is put
together, why it is the way it is, what went wrong on the way and what to watch when touching it or
moving pieces of it elsewhere.

## What this is

**OTP_Provisioner** is a demo provisioning station for Raspberry Pi 5 boards (BCM2712). One Python server
(FastAPI, `otp_server/`) keeps the per-board secrets, builds every file a board needs inside Docker, and
serves one web page (`index.html`, `js/`) that drives the board over **WebUSB** from Chrome or Edge: it
speaks the `rpiboot` protocol to the boot ROM (stages 1 and 2) and the `fastboot` protocol to a
provisioning gadget running on the board (stage 3). No native host tool is involved at run time.

A board goes through three stages, in one of two scenarios chosen per board on the page:

| Stage | Open scenario | Secure scenario |
| --- | --- | --- |
| 1 · EEPROM & OTP (rpiboot, `recovery.bin` + `pieeprom.bin`) | unsigned EEPROM, OTP untouched | EEPROM signed with the board's own RSA-2048 key, `program_pubkey=1` burns the key hash into OTP (irreversible) |
| 2 · Fastboot gadget (rpiboot, `bootfiles.bin` + `boot.img`) | the station-built gadget | the same gadget with a `boot.sig`, later the board's own gadget with `otp_keyexport=off` |
| 3 · Image (fastboot IDP) | Raspberry Pi OS Lite, clear; the board's first-boot files on the boot partition | the OTP device key is generated and exported to the station once; the station builds the board's LUKS2 root container; the board writes ciphertext, proves its key opens keyslot 0, powers off |

Everything the station knows lives in a Google spreadsheet of the signed-in operator (`settings` and
`modules` worksheets). There is no config file, no local registry and no `.gitignore` (both on purpose).

**Status (2026-10-08):** both scenarios have provisioned a real Pi 5 (board `ebbdf4fd`) end to end,
including Wi-Fi/SSH/account setup at first boot and the secure chain (signed EEPROM, locked OTP, exported
device key, station-built encrypted root, `oem cryptcheck`, power-off).

## How it was written

Ten commits on `master`, each a working increment, all of it written in Claude Code sessions with the
owner and checked against a real board between steps:

1. `init`, `gadgets`: WebUSB rpiboot/fastboot in the browser, driven from local boot directories.
2. `12400b1` the server-driven flow: FastAPI registry, per-board secrets, Docker-built artifacts, stage
   manifests, the page's `Flow` state machine, mock-board tests.
3. `a9226e6` storage moved to Google Sheets only, the two scenarios, the OTP device key export helper.
4. `62a5842`, `3f9fd42` the OS image: rpi-image-gen directly, then Raspberry Pi OS Lite with per-board
   cloud-init files written at stage 3 (the Imager model) instead of baking settings into the image.
5. `d19abfd` the station encrypts the root itself, the key leaves the board once, the gadget runs a
   restricted `rpi-fastbootd`, first boot survives a power cut, stage 3 ends with power-off.
6. `4481f61` the first secure run on hardware and the four fixes it needed (see "What went wrong").

Design decisions that were the owner's and should not be re-litigated:

* **Google Sheets is the only storage**, OAuth is mandatory, there is no config file and the Windows
  registry is never touched. Local JSON and Drive backends existed and were deleted.
* **Demo station: no protection of secrets at rest.** Private keys sit in the sheet in the clear; the
  production system (a separate admin panel) owns that problem.
* **The open scenario will not exist in the future**; the server will run on another machine; a client
  must only ever receive ciphertext. The secure scenario is the real product, open is a convenience.
* **No `.gitignore`**, so run Python with `-B` and never leave `__pycache__`, `.pytest_cache` or
  scratch files in the tree. `google-oauth-client.json` is committed on purpose (Desktop-app client
  secrets are not confidential per Google; the owner allowed it through push protection).
* Code, comments, commit messages and docs are English.

Docstrings refer to "SPEC section N"; that design document is not in the repository. The README carries
everything that spec covered.

Size: about 14.6 k lines of code (Python server, page JS, shell/Python in Docker, the fastbootd patch
and its C++ test) and 16.4 k lines of tests.

## Repository map

```
server.py                     launcher (python server.py); python -m otp_server for login/build/modules/status
otp_server/
  app.py, api.py              FastAPI factory + routes; 401 until Google is signed in and the settings sheet read
  config.py, settings.py      DEFAULTS tree; the settings worksheet (re-read every 15 s; retired keys removed)
  google_account.py           OAuth (scope drive.file), the "OTP_Provisioner" spreadsheet per account
  storage/base.py, gsheets.py record schema (FIELDS, append-only) and the Sheets store (cached, quota-aware)
  modules.py                  board lifecycle: hello, scenarios, stage verdicts, OTP lock state, key export
  secrets_gen.py              RSA key, customer_key_hash, device_secret, LUKS key/passphrase derivation
  artifacts/                  tools image, stage 1 (EEPROM), gadget + stage 2, image + stage 3, LUKS per board
  firstboot.py                the board's cloud-init NoCloud seed (user-data/network-config/meta-data/ssh)
  imagejson.py, sparse.py     rpi-image-gen's image.json (IDP) and Android sparse images
  imageconfig.py, image_choices.py   OS image settings validation; tz / Wi-Fi country / keyboard lists
  jobs.py, docker.py          background jobs with SSE logs; docker CLI wrapper (idle watchdog, binfmt)
  winusb.py, passhash.py      Windows WinUSB driver check; sha512-crypt
js/
  rpiboot.js                  rpiboot protocol over WebUSB (RpiDevice, RpiBootSession, runSession)
  fastboot.js                 fastboot host (FastbootClient, idpProvision, key export via the helper)
  flow.js                     the three-stage state machine (Flow) against the server API
  bootdir.js, tar.js, duid.js ports of usbboot's check_file(), bootfiles.bin tar lookup, C40 DUID decoder
  server.js, app.js           API client; the UI
docker/
  tools.Dockerfile, tools-entrypoint.sh      otp-tools: openssl, rpi-eeprom tools, mtools, sparse tools, cryptsetup
  scripts/stage1.sh           recovery.bin + signed/unsigned pieeprom.bin (+ counter-signed recovery when locked)
  scripts/stage2-sign.sh      boot.sig + counter-signed bootfiles.bin (+ per-board cmdline in boot.img)
  scripts/boot-slot.sh        the board's boot partition: first-boot files, cmdline, re-sign on secure boards
  scripts/root-luks.sh, luks_encrypt.py      the board's LUKS2 container, encrypted exactly like dm-crypt
  scripts/image-collect.sh    rpi-image-gen output -> IDP set of sparse pieces + manifest
  gadget.Dockerfile, gadget-entrypoint.sh    arm64 pi-gen-micro builder (+ a stage that compiles rpi-fastbootd)
  gadget-helpers/otp-keyexport/              pi-gen-micro package: exports / generates the OTP device key
  fastbootd/otp-station.patch, station-test.sh, station_test.cpp   our rpi-fastbootd and its build-time test
image/
  build.sh, docker/           rpi-image-gen front end (Linux native or --docker; the station runs --in-container)
  layer/otp-rpios-*.yaml      the three station layers = Raspberry Pi OS Lite; rpios_packages.py regenerates one
  rpi-image-gen/              submodule (v2.8.0)
external/usbboot, external/pi-gen-micro   submodules (shallow); usbboot carries rpi-eeprom
tests/                        pytest (server), tests/web/ (page self-test, e2e with a real server + mock board)
```

Build artifacts never live in the repo: `%LOCALAPPDATA%\OTP_Provisioner` on Windows,
`$XDG_DATA_HOME/otp-provisioner` elsewhere (`--work`, `OTP_WORK_DIR`). README "Quick start" lists the layout.

## Run and test

```
python -m pip install -r requirements.txt
git submodule update --init --recursive
python server.py                              # http://127.0.0.1:8765/, opens Chrome; sign in to Google first
python -B -m otp_server build tools|gadget|image [--force]
python -B -m otp_server modules [--json] | mark-locked <serial> | mark-unlocked <serial>

python -B -m pytest -q                        # ~1120 tests, < 1 min; needs no Docker, no Google, no hardware
python -B tests/web/run_selftest.py           # ~580 checks: the page in headless Chrome against a fake API + mock board
python -B tests/web/run_e2e.py                # ~240 checks: real server + real artifacts + mock board, both scenarios
```

* The e2e runner starts its own server (no Google, in-memory registry) but **reuses the default work
  dir**, so it needs the tools image, the gadget and both image variants built (it waits up to 40 min for a
  live server on :8765 to finish them, never builds itself). It shares that work dir with a running
  station: one e2e check ("Google login files untouched") fails when the live server rewrites
  `google/spreadsheet.json` meanwhile; that is the live server, not the change under test.
* The page runners need Chrome (`--chrome`, `$OTP_CHROME`, the default Windows path or `PATH`).
* `OTP_DOCKER_TESTS=1` adds a smoke test against the real engine. Two `test_keyexport_script.py` cases
  skip on Windows (POSIX permissions); the first-boot block test runs under Git Bash's `sh`.
* Everything else in the suites is mocks: a fake docker runner that writes plausible outputs, an in-memory
  store, a fake Google account, a mock Pi 5 (`tests/web/mocks.js`: boot ROM, second-stage file server,
  the station's fastbootd with its allowlist). When a new behaviour is added, the mock gets it too.
* Real-hardware checks have been the final arbiter every time: several bugs below were invisible to every
  mock. Keep a sacrificial board; `program_pubkey`, the device key and `program_jtag_lock` are forever.

## Architecture in one pass

**Server side.** `create_app()` builds every service eagerly. Until Google is signed in, module/stage/build
endpoints answer 401. `ModuleService` (`modules.py`) is the only writer of board records and the only
place that decides stage verdicts; `Artifacts` (`artifacts/__init__.py`) turns a record into a stage
manifest (`/api/modules/{serial}/stage/{n}`) and pins the files it names so `/files/{name}` serves exactly
those bytes (409 if they changed since). Heavy builds (gadget, image) are `Jobs` streamed over SSE and
serialised by `<work>/tmp/heavy.lock`; "quick builds" (signing, the LUKS container) run inline in the
manifest request with the same job machinery. Every artifact directory is written as `*.partial` and
committed with a `.complete` marker; a build key/fingerprint covers every input, so editing a script
makes the artifact "not built" instead of stale.

**Page side.** `Flow` (`js/flow.js`) owns the run: scenario → stage manifests → confirmation of
irreversible steps (the operator types the serial) → stage runs → result POST → the server's verdict
decides whether the board advances. Stages 1 and 2 are `runSession()` from `rpiboot.js`: send the second
stage to the ROM, wait for the re-enumeration, serve files to the second stage until `Done`. Stage 3 is
`FastbootClient.idpProvision()`: key export (secure, once) → `oem fwcrypto init` → `getvar:public-key` →
erase → `oem idpinit/idpwrite` → for every `idpgetblk`: download + flash the sparse pieces → `oem
cryptcheck` (secure) → `oem idpdone` → `shutdown`.

**Trust boundaries.** The page is untrusted by design (the future client will be someone else's
machine): it receives only what the board must have, and in the secure scenario only ciphertext plus
signed boot files; it never receives passphrases or private keys. The board's own OTP device key passes
through the page once (secure, first run) and that is the accepted weak point of the demo.

## The secure chain, as built

* **Per-board secrets** (`secrets_gen.py`): RSA-2048 signing key; `customer_key_hash =
  sha256(n as 256 LE bytes ‖ e as 8 LE bytes)` (the 264-byte bootloader key blob, not the PEM/DER);
  `device_secret` (32 random bytes) rooting the optional recovery passphrase.
* **Stage 1** (`stage1.sh`, official `update-pieeprom.sh`): signed `boot.conf` + embedded public key in
  `pieeprom.bin`, `program_pubkey=1` in `config.txt` for a board not yet locked. The board reports
  `CUSTOMER_KEY_HASH`; the verdict requires it to equal ours.
* **The two second stages.** The BCM2712 ROM runs the plain `recovery.bin` only while OTP holds no key
  hash, and the counter-signed one only once it holds ours; the wrong one it accepts with status 0 and
  then silently keeps (usbboot `secure-boot-recovery5/README.md`). `Stage1Plan.sign_recovery` follows the
  lock state, and the lock state can be an assumption (`facts.otp_lock`, see below).
* **Stage 2**: `boot.sig` over `boot.img` with the board key; `bootfiles.bin`'s `2712/bootcode5.bin`
  counter-signed (`rpi-sign-bootcode -c 2712 -n 16 -v 0`). Once the station holds the device key, the
  board gets its own `boot.img` with `otp_keyexport=off` in `cmdline.txt`, inside the signature.
* **The device key** (`rpi-fw-crypto` key-id 1, ECDSA P-256, generated by the firmware): the
  `otp-keyexport` helper exports an existing key at gadget boot (before fastbootd READ-locks it) or
  generates one on request (`/run/otp-keyexport/request`), leaves `key.der`/`status` in
  `/run/otp-keyexport`, then READ-locks the slot. The page fetches it with `oem upload-file` + `upload`
  and posts it to `/device-key`; the server accepts it only if its public half matches `getvar:public-key`.
* **The LUKS key** the board derives: `hex(HMAC-SHA256(d as 32 BE bytes, <block-device-id output>))`,
  64 lowercase hex, no newline; the message is the raw sysfs text of the SD CID *including its trailing
  `\n`* (`block-device-id` prints exactly that). Confirmed on hardware on 2026-10-06 (`oem cryptcheck`
  answered keyslot 0 for a station-built container).
* **The container** (`root-luks.sh`, `luks_encrypt.py`): LUKS2, aes-xts-plain64, 512-bit volume key,
  sector size 4096, data offset 16 MiB, label/UUID from the image's provisioning map, low-cost argon2id
  (passphrases are 256-bit secrets); keyslot 0 = the board key, keyslot 1 = `HMAC(device_secret,
  "<mname>:<serial>")` when `provisioning.recovery_passphrase` is on. The plain sparse pieces are
  encrypted exactly as dm-crypt would (XTS tweak = sector offset **in 512-byte units** even with 4096-byte
  sectors; pinned by a dm-crypt test vector in `tests/test_luks_encrypt.py`). `imagejson.station_luks()`
  rewrites the board's `image.json` so the encrypted block is a plain `expand-to-fit` partition: the gadget
  only partitions, the ciphertext goes raw to `mmcblk0p2`, `rpi-resize` grows the FS at first boot.
* **The gadget's rpi-fastbootd** (`docker/fastbootd/`): upstream commit `cca05b2` (the one pi-gen-micro
  vendors) + `otp-station.patch`, built inside `gadget.Dockerfile` as version `…+otp1`. Allowlist:
  `download upload getvar shutdown reboot erase flash oem`; OEM `idp*`, `fwcrypto init`, the new
  `cryptcheck`, `upload-file`/`download-file` of the three helper files only. No `cryptopen`, `mount`,
  `cryptsetpassword`, `fwcrypto sign-hash`, `eeprom-*`, `getvar:private-key`; USB only; `shutdown` really
  powers off. `station-test.sh` links `station_test.cpp` with the daemon's objects and drives the compiled
  dispatcher (51 checks) before the deb is kept; `tests/test_artifacts.py` checks the patch against what
  `js/fastboot.js` sends. A signature cannot be withdrawn: gadgets signed for a board with the stock daemon
  stay valid for it, so rebuild before boards go out.

## What went wrong, and how it was fixed

Listed roughly in the order they bit. Each one is still guarded by a test or a comment at the spot.

**WebUSB / USB timing**
* **Opening the ROM too early.** Opened 2 ms after the `connect` event, the Pi 5 second stage stopped
  reading `pieeprom.bin` at a random offset. rpiboot sleeps 1 s before `libusb_open`; `runSession()` has
  `settleMs` (flow `rpibootSettleMs`, 1000). Queuing more bulk transfers did not help and was reverted.
* **Chrome/WinUSB ends a control transfer after ~5 s.** rpiboot waits up to 20 s in one `ep_read`. A
  request cut off while the board is busy (recovery.bin writing a signed EEPROM: ~4 s; the second stage
  checking a signed `boot.img`: 9-13 s) knocks it out of step: recovery.bin answered one more metadata
  field and went silent for minutes; after `boot.img` the last message came back garbled. `rpiboot.exe`
  went through on the same board and files, which is how it was proven to be the page. Fix:
  `busySettleMs` (12 s) after `pieeprom.bin` and after any served file ≥ 1 MiB, and, like rpiboot, a
  failed reply to the final `Done` is ignored.
* **Only one program may claim the interface.** `rpiboot.exe`, a second tab, or a dangling `ssh.exe` with
  an inherited handle all break the page. Chrome permissions are per device: ROM, second stage and gadget
  are three devices.
* **The gadget sends the data phase in 64 KiB io_uring reads**: every `transferOut` of a data phase except
  the last must be a multiple of 64 KiB (`DATA_ALIGN`), chunks are 1 MiB; commands ≤ 256 bytes; pieces ≤
  `max-download-size` (0x10000000), hence `simg2simg` splitting on the server.
* **Metadata arrives as `*KEY*VALUE*` file requests**, `FACTORY_UUID` C40-encoded: `duid.js` is a
  line-by-line port of `decode_duid.c` including C truncation semantics.

**Secure boot state**
* **OTP burnt, report lost.** The first secure stage 1 broke off after the EEPROM was written; the station
  still thought the board clean and sent the plain `recovery.bin`, which the locked ROM silently kept, in
  both scenarios. Now: a secure stage 1 that broke off after `program_pubkey=1` and the whole
  `pieeprom.bin` were served sets `facts.otp_lock = suspected`; the page detects a refused second stage
  (ROM still on USB 15 s after taking it, `secondStageRejectMs`) and reports which variant; the server
  flips the assumption; the page asks for a replug and retries once; the board's own `CUSTOMER_KEY_HASH`
  settles it; stages 2/3 never run on an assumption; both variants refused → stop with a reason.
  `modules mark-locked/mark-unlocked` remain as manual overrides.
* **fastbootd caches the OTP key status at start.** `otp-keyexport` generates the key later in the same
  boot, so `oem fwcrypto init` tried to generate it again ("Failed to provision key: Unrecognized error
  code"). The patch refreshes the status in `fwcrypto init` and `cryptcheck`.
* **rpi-fastbootd cannot be a submodule**: its tree has `dev-usb\x2dffs-fastboot.mount`, a file name
  Windows refuses. The builder clones it inside the container; reading it locally needs WSL or a
  container. `dpkg-buildpackage` reads `debian/changelog` before `rules` regenerates it: run
  `debian/gen-version.sh` first (our `OTP_FASTBOOTD_SUFFIX` goes through it).
* **Stock fastbootd was a master key to the board**: `cryptopen` + `mount` + `upload-file` of any path or
  block device, `fwcrypto sign-hash`, and a TCP data plane for anyone on the LAN. Hence the allowlist build.

**First boot and the image**
* **A first boot cut short lost Wi-Fi and SSH for good.** The board was unplugged from the station's USB
  while cloud-init ran; its per-instance markers survived as empty files, the next boot crashed on an
  empty `network-config.json`, then marked `scripts_user` done on a boot with no user-data, and `runcmd`
  never ran. Fix: the former `runcmd` is one `bootcmd` block guarded by our own marker written after
  `sync` (runs until it completed once), SSH also via the `ssh` flag file, and stage 3 ends with
  `shutdown` so the first boot happens on the board's own supply.
* **Raspberry Pi OS Lite keeps Wi-Fi off** (`WirelessEnabled=false`, rfkill files) and nothing in Imager's
  cloud-init files turns it on; `raspi-config nonint do_wifi_country XX` does (`nmcli radio wifi on` for
  country `00`). YAML 1.1 reads a bare `on` as `true`: quote it.
* **iwd failed on the real board** (profile correct, no association) and `raspi-config` did not know it;
  the image went to NetworkManager, then to the exact Raspberry Pi OS Lite package set (generated from the
  release `.info`), so behaviour matches the official image.
* **"Password doesn't fit"** turned out not to be the keyboard (that fix stayed: `image.keyboard`,
  default `us`, since Pi OS's console is `gb`); cloud-init in a chroot proved the hash applied. Diagnose
  such reports by dumping the board's `boot.vfat.sparse` from `<work>/modules/<serial>/stage3/` and
  running cloud-init in an overlay chroot of the built rootfs.
* **mmdebstrap leaves the build host's `/etc/resolv.conf`** (Docker's 192.168.65.7) when
  systemd-resolved is absent; `machine-id` must end as `uninitialized` (bdebstrap `skip:` +
  cleanup hook); rpi-image-gen's doc/man stripping is undone with `dpkgopts` to match the official image.
* **The image's ext4 uses 16 KiB blocks**: an x86 kernel cannot mount it; inspect with `debugfs`.
  `losetup --partscan` works on drvfs under WSL for raw `.img` files.

**Builds on Windows**
* **Docker Desktop registers its own `aarch64` binfmt handler**, but rpi-image-gen checks for
  `/proc/sys/fs/binfmt_misc/qemu-aarch64` by name; `docker.py` runs `tonistiigi/binfmt --install arm64`
  (lost on every Docker Desktop restart, re-checked before each arm64 build).
* **A Windows checkout has CRLF and no executable bits, and git symlinks become text files**: every
  script is staged CR-stripped with `chmod` restored inside the container; nothing relies on
  `usbboot/firmware/2712/*` symlinks; new files must be committed LF (`git ls-files --eol`).
* **pi-gen-micro's local apt repo has a `Release` without hashes**, so cached apt lists never notice a new
  helper deb: the entrypoint deletes `apt_lists/*_build_packages_*` and the previous `rpi-fastbootd` deb
  before each build. pi-gen-micro keeps **two dpkg databases** (`dpkg_admin` for its first phase,
  `build/var/lib/dpkg` for the rootfs); check the rootfs one.
* **Builds take long and sometimes hang**: a no-output watchdog (`docker.idle_timeout`, 30 min) kills the
  named container; one heavy build at a time across processes; forced rebuilds go to `-r2`, `-r3`
  directories so a served build is never replaced in place.

**Google Sheets**
* The Sheets quota is 60 requests/min/user: records are cached, writes re-read the row's serial before
  overwriting (rows may be sorted/deleted by hand), every request has 10 s/60 s timeouts, failures retry
  every 10 s and the server starts without Google (503 on module endpoints). An OAuth app left in
  *Testing* expires logins after 7 days; publish it (scope `drive.file` needs no verification). The
  `settings` worksheet is re-read every 15 s; retired keys and old defaults are rewritten on read.

## Invariants: do not break these

* `storage/base.py` `FIELDS` is append-only; an older sheet header must stay a prefix of the new one.
* `customer_key_hash` and the RSA PEMs of a record belong together; the server refuses stage 1 when they
  disagree and `stage1.sh` dies on `EXPECT_CKH` mismatch. Never edit one without the other.
* `luks_key()` must stay byte-identical to what the firmware computes for `rpi-fw-crypto hmac` over
  `block-device-id`'s output (CID text + `\n`); `luks_encrypt.py` must stay identical to dm-crypt.
* The secrets the page may see: nothing but ciphertext, signed boot files, the first-boot files (which
  do carry the account hash and the Wi-Fi PMK on a plain FAT, by design) and, once, the board's exported
  key. No passphrase, no private key, no plain root ever goes to a manifest.
* The gadget allowlist (`otp-station.patch`) and what `js/fastboot.js` sends are checked against each
  other by `test_fastbootd_patch_allows_what_the_page_sends`; `station-test.sh` must stay in
  `gadget.Dockerfile` before the deb is kept. Widening the allowlist is a security decision.
* Verdicts are the server's (`modules.py`): the page reports, the server advances the stage. A secure
  stage 3 is accepted only with the exported key and `verified = [{dev, keyslot: 0}]`.
* Every artifact input is in its fingerprint/key (`stage1.plan`, `GadgetBuilder.key`, the image set
  identity, the LUKS dir name). Add new inputs there, or edits will not rebuild.
* The file-server timings in `rpiboot.js` (`settleMs`, `busySettleMs`, retry every 1 s, idle 180 s) and
  `secondStageRejectMs` in `flow.js` were set against hardware; shortening them re-opens closed bugs.
* Logs must never contain key material, passphrases or tokens (`docker.py` masks env names matching
  KEY/PASS/SECRET/TOKEN/PRIVATE; the page redacts passphrases in command echoes).

## Conventions

* Python 3.11+, 4-space indent, type hints, docstrings that say why. Everything that touches secrets lives
  in `secrets_gen.py`/`modules.py`. Run tests with `python -B -m pytest -q -p no:cacheprovider`.
* JavaScript is plain ES2020 modules on `window.OTP`, no bundler, no dependencies; tests inject fakes
  through constructor arguments (`usb`, `api`, hooks). Node is not installed; syntax errors surface in
  `run_selftest.py`.
* Shell scripts run inside the Debian trixie tools/builder images; keep them `set -euo pipefail`, LF, and
  self-checking (every script verifies what it produced before copying to `/out`).
* When a behaviour changes, update together: the code, its mock in `tests/web/mocks.js`, the pytest
  fake (`tests/test_artifacts.py` handlers `h_*`), the README section, and the e2e expectations.
* Do not commit or push without being asked. Do not add a `.gitignore`.

## Pitfalls when porting this elsewhere

For the planned split (server on another machine, Sheets replaced, the open scenario dropped):

**WebUSB and the protocols**
* Chromium only; a secure context (`https://` or `127.0.0.1`); on Windows the devices must be bound to
  WinUSB (`rpiboot_setup.exe`'s inf covers `0a5c:2712` and `18d1:4e40`) and the 5 s control-transfer
  limit is Chrome's, not the board's. Linux needs udev `uaccess` rules. Permissions are per device.
* Re-enumeration means a *new* `USBDevice` object; code that keeps the old one hangs. `runSession()` and
  `Flow._waitForDevice()` encode the rules (same-board filter by serial, "same enumeration as before").
* Keep the timings (1 s settle, 12 s busy pauses, 10 s bulk-stall watchdog, 15 s refusal detection), the
  16 KiB bulk pieces, the 64 KiB-aligned fastboot data phases and the 256-byte command/response frames.
  The upstream references are `usbboot/main.c` and `rpi-fastbootd/fastboot/device/*.cpp`; when a
  transfer misbehaves, run the official `rpiboot.exe -v -d <stage dir> -j <dir>` against the same files
  first (close the page tab): it is the quickest way to tell the board from the client.

**Secure boot**
* `program_pubkey`, the device key and `program_jtag_lock` are one-way. RSA-2048 only; the hash is over
  the 264-byte bootloader blob. Losing a board's RSA key bricks it for the station, so the registry (or
  whatever replaces it) must back up `rsa_private_pem` before stage 1 runs.
* Two `bootcode5.bin` variants; the ROM never says which it wanted. Any port must keep the assumption
  logic or an operator override; `mark-locked` exists because the report can be lost after OTP is burnt.
* The ROM refuses a counter-signed recovery on a clean board, so "always send the signed one" does not
  work either.
* `fastbootd` READ-locks the key at start; a helper that must read it has to run `Before=fastbootd` and
  the status caching inside fastbootd must be refreshed by anything that creates the key later.

**The encrypted root**
* The derivation chain is three byte-exact contracts: `block-device-id` output (CID + newline) →
  firmware HMAC with the raw OTP scalar → 64-hex passphrase in keyslot 0; and the dm-crypt XTS geometry
  (512-byte tweak units, 4096-byte sectors, 16 MiB data offset). The boot-time unlocker is pi-gen-micro's
  `cryptroot` with the `hwkey` keyscript; its `by-slot` udev rules need the FAT label `BOOT`, the LUKS
  label `OSROOT_CRYPT` and the ext4 label `ROOT`. Change any name and the board will not boot.
* The container is ~2.4 GB per board because zero-filled FS metadata must be ciphertext; building it
  takes ~1.5 min and the per-board directory is pruned to the newest. Budget disk and time accordingly.
* `oem cryptcheck` is a station addition; a stock gadget only has `cryptopen`, which creates a decrypted
  device on the board.

**The server on another machine**
* The page assumes same-origin JSON and files; the server's Host/Origin checks assume loopback. Moving it
  means TLS, authentication (there is none beyond the Google login), and streaming 256 MiB pieces to a
  browser that then pushes them over USB: the page keeps one piece in memory at a time.
* Manifests pin file bytes (`/files/{name}` is 409 after a rebuild); a client must restart the stage, not
  resume. Stage 3's secure manifest is served twice (pending until the key export, then with the
  container); the page re-fetches it, so an intermediary must not cache it.
* `heavy.lock` and the `*.partial`/`.complete` discipline are per work directory; several servers sharing
  one work dir are not supported.
* Builds need Docker with arm64 emulation and internet (deb.debian.org, archive.raspberrypi.com,
  github.com for rpi-fastbootd); the first gadget build compiles rpi-fastbootd (~7 min), the image builds
  take ~12 min per variant. The station assumes it may start Docker Desktop itself on Windows.

**Storage and settings**
* The registry rows hold private keys in the clear by decision; a production store needs encryption at
  rest, access control and an audit of `events`. `normalize_record()` tolerates JSON-in-cells and old
  headers; a schema migration elsewhere must keep `FIELDS` order and semantics (`otp_key_hash` vs
  `customer_key_hash`, `secure_boot_provisioned`, `mode`, `facts.otp_lock`).
* Settings are read at most every 15 s and validated as a whole: an invalid value keeps the previous
  tree. The `image.*` settings are written to boards at stage 3, not baked into the image; only
  `image.name` rebuilds it. Porting the panel means keeping that split.

**The image**
* rpi-image-gen runs on Linux only (mount/user namespaces, `qemu-aarch64` by name); on Windows that means
  Docker Desktop with the binfmt handler registered after every restart. Its `Release` of the local repo,
  its two dpkg databases, its CRLF and symlink sensitivity are described above.
* The first-boot files are Imager's `cloudinit-rpi` format plus our `bootcmd` block and `ssh` flag; the
  `instance-id` must change when the files change (it is a hash of them) or cloud-init ignores the new
  seed. Secrets in those files (account hash, Wi-Fi PMK) sit on an unencrypted FAT partition on every
  board.
* The package set is pinned to one Raspberry Pi OS Lite release `.info`; regenerate
  `otp-rpios-packages.yaml` with `image/rpios_packages.py` when the base release moves, and re-verify
  the first boot on hardware (cloud-init, NetworkManager and raspi-config behaviour all changed between
  releases during this project).
