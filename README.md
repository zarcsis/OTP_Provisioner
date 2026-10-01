# OTP_Provisioner

A demo provisioning station for Raspberry Pi 5 boards. A small Python server (FastAPI) keeps the secrets
of every board, builds all the files a board needs (in Docker), and serves a web page. The page runs in
Chrome or Edge and drives the board over **WebUSB**: it speaks the `rpiboot` protocol to the BCM2712 boot
ROM and `fastboot` to the provisioning gadget.

Everything the station knows lives in **a Google spreadsheet of the signed-in operator**: the `settings`
worksheet holds the server settings and the `modules` worksheet the board registry. There is no
configuration file and no local registry. Signing in to Google (a button on the page) is required before
anything else works. Every Google account works in its own spreadsheet "OTP_Provisioner" in its own Drive:
the server finds it there (or creates it on the first sign-in), and spreadsheets of different accounts
never meet — the OAuth client only identifies the app, it gives nobody access to anybody's data.

Boards are identified by the 8-hex USB serial the boot ROM reports (for example `a7eb274c`). Each board
is provisioned in one of two **scenarios**, picked on the page per board (both are always available):

| | **Open** | **Secure** |
| --- | --- | --- |
| Stage 1 · EEPROM & OTP | unsigned EEPROM, OTP untouched | EEPROM signed with the board's RSA key, `program_pubkey=1` burns the key hash into OTP (+ `program_jtag_lock=1` with `provisioning.jtag_lock`) |
| Stage 2 · Fastboot gadget | the gadget built by this server | the same gadget, `boot.sig` once the board is locked |
| Stage 3 · Image | clear droneos image (`IGconf_image_pmap=clear`), nothing written to OTP | the OTP device key is generated (if blank) and **exported to the server**, then the LUKS2-encrypted droneos image (`IGconf_image_pmap=crypt`); the boot partition is re-signed per board |

In every scenario a board goes through the same three stages:

| Stage | What the board does | Files come from | Registry stage after success |
| --- | --- | --- | --- |
| 1 · EEPROM & OTP | Boots `bootcode5.bin` (recovery) over rpiboot and flashes `pieeprom.bin` + `.sig`. It reports metadata (MAC, DUID, `CUSTOMER_KEY_HASH`, …) and reboots straight back into RPIBOOT (`set_reboot_order=0x3`, `recovery_reboot=1`). | `external/usbboot/rpi-eeprom` firmware, packed by `docker/scripts/stage1.sh` | `eeprom` |
| 2 · Fastboot gadget | Boots `bootfiles.bin` + `boot.img` (pi-gen-micro "fastboot" ramdisk with rpi-fastbootd and our `otp-keyexport` helper). The board re-enumerates as USB `18d1:4e40` with its 16-hex serial. | gadget built from `external/pi-gen-micro` + `docker/gadget-helpers` | `gadget` |
| 3 · Image | Page drives rpi-fastbootd: (secure) device key export → `oem fwcrypto init` → `getvar:public-key` → `erase` → IDP (`oem idpinit` / `idpwrite` / `idpgetblk` + `flash` of sparse pieces ≤ 256 MiB / `idpdone`) → `reboot`. | droneos image (`external/droneos` submodule, rpi-image-gen), built in Docker in both variants | `flashed` |

Status: the Python and page test suites pass, and the gadget and both image variants build for real.
**Nothing has been run on a real board yet** (stage 3, the self-built gadget and the device key export
in particular).

## Requirements

* **Chrome or Edge** (any Chromium browser with WebUSB). Firefox and Safari have no WebUSB.
* **Python 3.11+** with the packages from `requirements.txt`.
* **A Google OAuth client** (once per team, about five minutes; operators then only click
  *Sign in with Google*):
  1. [console.cloud.google.com](https://console.cloud.google.com/): create a project.
  2. *APIs & Services → Library*: enable the **Google Sheets API** and the **Google Drive API**.
  3. *Google Auth Platform → Branding*: app name and support e-mail. *Audience*: **External**, then
     **Publish app** (*In production*). No verification is needed: the station asks only for the
     non-sensitive scope `drive.file` (access to the files it created itself), so any Google account can
     sign in and the login does not expire after 7 days.
  4. *Clients → Create client → Desktop app*, **Download JSON** and save it as `google-oauth-client.json`
     in the repository root. Google does not treat the secret of a desktop client as confidential, so the
     file can be committed for the team.
* **Docker** with arm64 emulation: Docker Desktop on Windows (Linux engine), or Docker Engine on Linux. The
  gadget and droneos builds run in `linux/arm64` containers. The server registers the arm64 binfmt handler
  when it is missing (see Troubleshooting). The builds need internet access.
* **USB driver on Windows:** Chrome can only open devices bound to WinUSB. Install the official
  `rpiboot_setup.exe` (from the [usbboot releases](https://github.com/raspberrypi/usbboot/releases)).
  Its `rpiboot-winusb.inf` binds WinUSB to both `0a5c:2712` (BCM2712 boot ROM) and `18d1:4e40` (the
  fastboot gadget). `rpiboot.exe` itself is not needed. The page header shows whether the driver package is present.
* **Linux:** give your user access to both devices, for example `/etc/udev/rules.d/99-otp-provisioner.rules`:

  ```
  SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", TAG+="uaccess"
  SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e40", MODE="0660", TAG+="uaccess"
  ```

  then `sudo udevadm control --reload && sudo udevadm trigger`.
* **Submodules** of this repo: `git submodule update --init --recursive` (usbboot with its nested
  rpi-eeprom, pi-gen-micro, droneos with its nested rpi-image-gen). droneos is cloned
  over SSH (`git@github.com:zarcsis/droneos.git`), so the clone needs a GitHub key with access to it.

## Quick start

```
git clone <this repo> OTP_Provisioner
cd OTP_Provisioner
git submodule update --init --recursive
python -m pip install -r requirements.txt
# put google-oauth-client.json (Desktop app OAuth client) into the repository root
python server.py
```

`python server.py` serves `http://127.0.0.1:8765/` and opens the page in Chrome (Edge if Chrome is missing,
otherwise the default browser; `--browser EXE` picks another one). If an OTP_Provisioner is already running
on that port, it just opens the page and exits. Options: `--host H`, `--port N`, `--browser EXE`,
`--no-browser`, `--no-auto-build`, `--work DIR`.

The page first shows **Sign in with Google**. After the consent screen Google sends the browser back to
the station, the server saves the token and opens the operator's spreadsheet "OTP_Provisioner": the one it
remembers for this account, else the one it created in the account's Drive earlier (for example on another
station), else a new one (worksheets `modules` and `settings`, the latter filled with every setting and
its default). From then on the page is fully usable; the header shows the account, links its spreadsheet
and has a **Sign out** button. When operators share a station, each signs in with their own account and
works in their own spreadsheet; a board provisioned under one account is unknown to the others (a board
locked to another account's key is refused).

### What happens after the first sign-in

With `builds.auto` (default true) the server starts the missing builds in the background. The page works
meanwhile and its **Server builds** card shows each job with a live log:

1. **tools**: the `otp-tools:latest` image from `docker/tools.Dockerfile` (Debian trixie with openssl,
   pycryptodome, mtools and the Android sparse tools). It is used for all signing and packing. The
   image is rebuilt whenever `docker/tools.Dockerfile` or `docker/tools-entrypoint.sh` changes.
2. **gadget**: the pi-gen-micro fastboot ramdisk plus our helper packages, built in an arm64 container
   (about 3 minutes). Stage 2 answers "not ready" until it exists — there is no prebuilt fallback, because
   only this gadget carries the device key export.
3. **image**: the droneos image in both variants, `clear` (open scenario) and `crypt` (secure scenario),
   several minutes each. The builder image comes from `<droneos>/docker`; each result is collected into an
   IDP set of sparse pieces ≤ `max_piece_size` with SHA-256 for each piece. Stage 3 answers "not ready" until
   the variant the board needs is there.

On Windows, if the Docker engine is not running, the server starts Docker Desktop and waits for it (up to 180 s).

Build rules worth knowing:

* **Rebuild triggers.** The gadget key is `<pi-gen-micro commit>-<hash of docker/gadget.Dockerfile,
  gadget-entrypoint.sh and every file under docker/gadget-helpers>-<targets>`, so editing any of them makes
  the gadget "not built". An image set is reported as `rebuild needed: …` (status not ready, stage 3 409)
  when it was built from another droneos commit than the one checked out now (`git describe --tags --always
  --dirty`), from another `builds.image.config` file content or `overrides`, as another variant, or split
  with a larger `max_piece_size` than the current setting. The stage-1 identity includes the sha256 of the
  selected `pieeprom-*.bin` and `recovery.bin` and the content of `rpi-eeprom-config`, `rpi-eeprom-digest`,
  `rpi-sign-bootcode` and `update-pieeprom.sh`, so a firmware or usbboot submodule update rebuilds stage 1
  (a quick build, about a minute) even when names and sizes stay the same. `builds.auto` rebuilds all of these.
* **Forced rebuilds never replace the served build in place.** A forced gadget build goes to
  `<key>-r2`, `-r3`, …; the newest complete version is served and older ones are kept (they are never pruned,
  so disk use grows with forced rebuilds).
* **One heavy build at a time, across processes.** Gadget and image builds take `<work>/tmp/heavy.lock`.
  `python -m otp_server build …` started while the server builds waits ("waiting for another image/gadget
  build to finish …") and skips the build if the other process finished it meanwhile.
* **No-output watchdog.** A streamed `docker build`/`docker run` that prints nothing for `docker.idle_timeout`
  seconds (default 1800; 0 disables it) is stopped: the container (always started as `--name otp-<id>`) is
  removed with `docker rm -f` and the job fails with "produced no output for N s and was stopped".
* **Start-up sweep.** The server and the CLI remove leftover signing-key directories `<work>/tmp/keys-*`
  that no live process holds, and `*.old-*` directories left by replaced builds.

Build artifacts live **outside the repo**, in the work directory. The default is
`%LOCALAPPDATA%\OTP_Provisioner` on Windows and `$XDG_DATA_HOME/otp-provisioner` or
`~/.local/share/otp-provisioner` elsewhere. Override it with `--work DIR` or `OTP_WORK_DIR`.

```
<work>/google/token.json               the Google OAuth token (the only login state on this machine)
<work>/google/spreadsheet.json         which spreadsheet belongs to which signed-in account
<work>/artifacts/stage1/<fp>/          shared unsigned stage-1 files
<work>/artifacts/stage2/config.txt
<work>/artifacts/gadget/<key>[-r<N>]/  built gadget + build-info.json (newest complete version served)
<work>/artifacts/image/<set>/          IDP set: image.json, sparse pieces, manifest.json
<work>/artifacts/image/current-clear.json, current-crypt.json   which set stage 3 serves per variant
<work>/modules/<serial>/stage{1,2,3}/<fp>/    per-board signed files (secure scenario only)
<work>/jobs/<id>.log                   build logs
<work>/tmp/keys-<id>/ + keys-<id>.lock  short-lived key files for signing (deleted after use, swept at start)
<work>/tmp/heavy.lock                  cross-process lock for gadget/image builds
```

Docker volumes `otp-pgm-work` and `otp-droneos-work` keep the build trees and apt caches between runs.

## Operator procedure

1. Pick the scenario in the **Provision** panel: **Open** or **Secure** (the default comes from
   `provisioning.default_mode`; the page remembers your choice).
2. Insert the target **SD card** into the board.
3. **Hold the power button**, connect **USB-C** to the station, release the button. The board enumerates
   as *BCM2712 Boot*. Use a port that can supply enough current.
4. Click **Connect board** and pick *BCM2712 Boot* in Chrome's chooser. The page registers the board with
   the server (`hello`). Its secrets are generated now if this serial has never been seen, and are reused otherwise.
5. Click **Provision**. The scenario is sent to the server first. Before any irreversible step (OTP writes,
   the device key generation, erase), the page shows what will happen and asks you to type the serial
   (`confirm_irreversible`). Stage 1 runs, the board reboots into RPIBOOT by itself, and stage 2 runs. If
   Chrome needs permission for the re-enumerated device, a **Select device** button appears.
6. When the gadget has booted, click **Connect fastboot gadget** and pick *Raspberry Pi …* in the chooser.
   Chrome's list updates while Linux boots. Stage 3 identifies the board, (secure) exports its device key,
   then flashes the image with a progress bar, and the board reboots into the new image.

The page skips stages that are already done. Switching a provisioned board to the other scenario resets it
to stage 1: every stage is redone (the EEPROM, the gadget signing and the image all differ). A board whose
OTP holds a key hash only runs signed code, so it is always provisioned in the secure scenario (the Open
switch is disabled for it). A board that already runs the gadget can be connected directly for stage 3.
If the cable is pulled, the page says which stage failed, and **Provision** resumes from there. Only one
program may claim the USB interface: close `rpiboot`, `fastboot` and other tabs of the page.

* **Long silences in stage 1 are normal.** recovery.bin can stay silent for longer than WinUSB's fixed ~5 s
  transfer timeout while it writes the EEPROM or OTP (Chrome reports that as `NetworkError`). The page's
  rpiboot file server retries every second for as long as the board is attached. It stops only when the board
  really left USB (disconnect event, device closed, or gone from `getDevices()`; the result is kept as
  interrupted with the metadata collected so far) or when an attached board asks for nothing for 180 s.
* A failed rpiboot stage that never reached the board (for example a missing file) can be re-run on the
  same connected board without replugging it.
* Stage 3 compares the gadget's `getvar:serialno` with the board being provisioned before it contacts the
  server; a gadget of another board is refused with "the fastboot gadget belongs to board X, not Y".

The collapsed **Advanced (manual)** section keeps the serverless tools: device list, rpiboot runs from a
local directory, and manual fastboot. It works without the server and without a Google login (also from
`file://`). Before a run it checks the `config.txt` that will actually be served to the selected device's
SoC, shows which file that is, and warns about other `config.txt` files that differ but are not served. The
exact bytes confirmed in the irreversible dialog are pinned and served even if the file changes on disk.

## The secure scenario and the device key export

The BCM2712 has one device-unique OTP key slot (`rpi-fw-crypto` key-id 1, ECDSA P-256). The droneos
image unlocks its LUKS root with `HMAC-SHA256(that key, the storage device id)` computed by the firmware
(keyslot 0, created on the board by rpi-fastbootd during IDP). In the secure scenario the station keeps
**a copy of that key**, so it can derive the LUKS key of any card used in the board:

```
luks_key = hex( HMAC-SHA256(key = d as 32 big-endian bytes, msg = <cid of the card> + "\n") )   # secrets_gen.luks_key
```

How the key gets to the server:

* The fastboot gadget carries our pi-gen-micro package `otp-keyexport` (`docker/gadget-helpers/`). At gadget
  boot, **before rpi-fastbootd starts** (rpi-fastbootd READ-locks a provisioned key at startup, and the lock
  lasts until the next boot), `otp-keyexport-boot.service` exports an existing key with
  `rpi-fw-crypto privkey` to `/run/otp-keyexport/key.der`. On a blank slot it does nothing.
* In stage 3 the page fetches `key.der` with `oem upload-file` + `upload`. When the slot is blank it first
  writes a request file (`download` + `oem download-file /run/otp-keyexport/request`); the helper's systemd
  path unit then **generates the key** (`rpi-fw-crypto genkey`: an irreversible OTP write, the same one
  `oem fwcrypto init` does, covered by the stage-3 confirmation) and exports it. After the export the
  helper READ-locks the key for the rest of the boot.
* The page sends the key to `POST /api/modules/{serial}/device-key` together with `getvar:public-key`. The
  server accepts it only when its public half equals the key the board reports (and the device key already
  recorded for the board, if any), and stores it in the registry (`device_private_pem`). Stage 3 continues
  (erase, IDP) only after that; a secure stage 3 without an exported key is not accepted.

Failure cases:

* **Power loss.** Nothing about the export is lost for good: the key stays in OTP and is read again the
  next time the gadget boots (run stage 2 + 3 again). A key whose generation was cut short keeps whatever
  bits were written; the server reports how many of its 8 OTP words are zero (a zero word in a random key
  has a probability of 2^-32), and the board event log records it.
* **No internet** (Google unreachable): the server cannot store the key, so stage 3 stops before anything
  is erased. Repeat when Google is reachable; the key is read from the board again.
* **Reading the key again later** needs only the board on USB and its stage-2 files: with secure boot the
  gadget must be signed with the board's RSA key, which the registry holds. Without secure boot anybody can
  read the key, so the protection of the encrypted image rests on secure boot.

## Secrets and storage

Generated per board at first contact and never regenerated:

| Field | Content |
| --- | --- |
| `rsa_private_pem` / `rsa_public_pem` | RSA-2048 boot-signing key (PKCS#8 / SPKI PEM) |
| `customer_key_hash` | `sha256(n as 256 bytes LE ‖ e as 8 bytes LE)`: the value the recovery burns with `program_pubkey` and reports as `CUSTOMER_KEY_HASH` |
| `device_secret` | 32 random bytes, hex; root of the optional LUKS recovery passphrase |

Learned later: `mode` (the scenario chosen for the board), `device_private_pem` (secure scenario: the
exported OTP device key, PKCS#8), `otp_key_hash` (what the board reports), `device_key_pem` (the OTP ECDSA
public key from `getvar:public-key`), `duid`, `mac`, `boardrev`, the full metadata, fastboot variables and
an event log.

**This is a demo station: the registry is not protected.** Every record, private keys included, sits in
the `modules` worksheet in the clear; anyone who can open the spreadsheet can read them. Protecting the keys
(encryption at rest, access control) is left to the production system.

**Optional LUKS recovery passphrase** (`provisioning.recovery_passphrase`, secure scenario, default off —
the exported device key already lets the server derive the LUKS key): keyslot 1 added by
`oem cryptsetpassword`, `HMAC-SHA256(key = bytes.fromhex(device_secret), msg = "<mname>:<serial>")`.

The page and `/api/modules` show only a public view: which secrets exist, the hashes and the fingerprints.
Private keys and device secrets never go back out over the API.

**The spreadsheet.** Worksheet `modules`: row 1 is the header (the record fields, in order), one row per
board; dict/list/bool fields are JSON. New fields are only ever appended, and a header written by an older
version is extended in place. Records are cached in memory to stay within the Sheets quota of 60
requests/min/user; before overwriting a row in place the store re-reads that row's serial, so rows may be
deleted, inserted or sorted by hand. If Google cannot be reached, the server still starts: the storage badge
turns red and the module endpoints answer 503; network failures are retried every 10 s. Every Sheets request
has a 10 s connect / 60 s read timeout.

## Settings

There is no configuration file. The settings live in the `settings` worksheet of the station spreadsheet:
`key | value | description`, one row per setting. The server adds a row (with the default value and a
description) for every setting the sheet lacks and never changes a value you wrote. An empty value means the
default; switches are `true`/`false`, lists one item per line. The server re-reads the sheet while it runs
(at most every 15 s), so **changes need no restart**. A value it cannot use keeps the previous settings and
is shown on the page; unknown keys produce a warning.

| Key | Default | Meaning |
| --- | --- | --- |
| `paths.droneos` | `external/droneos` | droneos checkout the image is built from (relative to the repository root) |
| `provisioning.default_mode` | `open` | scenario the page preselects for a new board: `open` or `secure` |
| `provisioning.jtag_lock` | `false` | secure scenario: also burn `program_jtag_lock=1` (IRREVERSIBLE) |
| `provisioning.recovery_passphrase` | `false` | secure scenario: add a server-derived LUKS passphrase as keyslot 1 |
| `provisioning.confirm_irreversible` | `true` | the page asks the operator to type the serial before OTP writes / erase |
| `provisioning.erase_storage` | `true` | stage 3: erase the storage device before the image is written |
| `provisioning.firmware_channel` | `default` | rpi-eeprom firmware channel for stage 1: `default` or `latest` |
| `provisioning.max_piece_size` | `268435456` | largest sparse piece sent to the board (bytes, rpi-fastbootd max-download-size) |
| `provisioning.boot_conf` | `[all]`, `BOOT_UART=1`, `POWER_OFF_ON_HALT=1`, `BOOT_ORDER=0xf2461` | EEPROM `boot.conf` written in stage 1 (multi-line) |
| `builds.auto` | `true` | build what is missing (tools, gadget, both images) once the station is signed in |
| `builds.tools.image_tag` | `otp-tools:latest` | Docker tag of the tools image |
| `builds.gadget.targets` | `pi5-family` | pi-gen-micro device list of the fastboot gadget |
| `builds.gadget.image_tag` | `otp-gadget-builder:trixie` | Docker tag of the gadget builder image |
| `builds.gadget.volume` | `otp-pgm-work` | Docker volume with the gadget build tree |
| `builds.image.config` | `droneos.yaml` | rpi-image-gen config inside the droneos checkout |
| `builds.image.overrides` | (none) | extra `KEY=VALUE` overrides for the droneos build, one per line (`IGconf_image_pmap` is set per scenario) |
| `builds.image.builder_tag` | `droneos-builder:trixie` | Docker tag of the droneos builder image |
| `builds.image.volume` | `otp-droneos-work` | Docker volume with the droneos build tree |
| `builds.image.keep_raw_image` | `false` | keep the raw `.img` next to the sparse pieces |
| `docker.binary` | `docker` | docker CLI to run |
| `docker.start_desktop` | `true` | Windows: start Docker Desktop when the engine is down |
| `docker.desktop_path` | (standard location) | Docker Desktop executable |
| `docker.idle_timeout` | `1800` | seconds without output before a docker build/run is stopped (0 = never) |

What the server needs before anyone has signed in is not a setting: the listen address and port
(`--host`, `--port`, `OTP_PORT`), the browser (`--browser`, `--no-browser`) and the work directory
(`--work`, `OTP_WORK_DIR`). Command-line flags also win over the sheet (`--no-auto-build`).
`GET /api/status` shows the effective configuration (paths, never secrets) and the settings state.

## Security model and irreversible operations

* The server listens on `127.0.0.1` by default. WebUSB needs a secure context, and `http://127.0.0.1` qualifies.
  Anyone who can reach the port can fetch per-board signed files, so the server warns when you bind to another
  address. There is no authentication besides the station's own Google login.
* **Host and Origin checks** (against DNS rebinding and cross-site requests). A request whose `Host` hostname
  is not `127.0.0.1`, `localhost`, `::1` or the listen address gets 403 with a JSON `detail`. When the server
  listens on `0.0.0.0` or `::`, any IP literal and the machine's own host name are accepted too. Any method other
  than GET/HEAD that carries an `Origin` (or, without one, a `Referer`) naming another host is refused with
  "cross-site POST rejected". Requests without either header (curl, scripts, the CLI) still work.
* Private keys are written to a temporary directory only for the duration of a signing container run, then
  deleted. Logs never contain keys, secrets or passphrases.
* **The signed fastboot gadget of a board is a master key to it**: rpi-fastbootd can open the board's LUKS
  container (`oem cryptopen`), read files (`oem upload-file`) and sign with its device key. Keep the
  per-board stage-2 files on the station.

What the irreversible operations burn (the page lists each one and asks for the serial first):

| Operation | When | What it does, forever |
| --- | --- | --- |
| `program_pubkey=1` (stage 1 `config.txt`) | secure scenario, board not yet locked | Burns the SHA-256 of this board's RSA public key into OTP. From then on the SoC only runs EEPROM and boot images signed with that key. Lose the key and the board is bricked for this station. |
| `program_jtag_lock=1` (stage 1) | secure scenario **and** `provisioning.jtag_lock` | Permanently disables VideoCore JTAG. |
| device key generation (stage 3: the gadget's export request / `oem fwcrypto init`) | secure scenario, blank key slot | The firmware generates the device-unique ECDSA P-256 key in OTP. It cannot be changed or erased; a copy goes to the station. |
| `erase:<disk>` (stage 3) | `erase_storage: true` | Wipes the SD card / eMMC / NVMe before IDP writes the partition table. |

The open scenario writes nothing to OTP.

More rules of the secure scenario:

* Stage 1 signs the EEPROM config with the board's RSA key (`SIGNED_BOOT=1`, `ENABLE_SELF_UPDATE=0` added to
  `boot_conf`) and adds `program_pubkey=1`. The verdict requires `SECURE_BOOT_PROVISION=success` and
  `CUSTOMER_KEY_HASH` equal to the stored hash.
* **Key-hash check before signing or burning.** The server recomputes `customer_key_hash` from the record's
  RSA key. If the stored hash differs, or the record has a hash but lost its PEMs, stage 1 is refused with 409
  ("the board record's customer_key_hash X does not match its RSA key … fix the record in storage first").
  Never edit `customer_key_hash` and the PEM columns in the sheet independently. `stage1.sh` gets the expected
  hash as `EXPECT_CKH` and dies if `public.pem` or the key embedded in `pieeprom.bin` hashes to anything else.
* **`boot_conf` rules.** Signed: `ENABLE_SELF_UPDATE=0` and `SIGNED_BOOT=1` count as present only when every
  assignment of the key is in `[all]` (or before the first section header) with exactly that value; otherwise
  every assignment is removed and the value is appended under a trailing `[all]`. Unsigned: any `SIGNED_BOOT`
  other than `0`, in any section, is removed with a note. Set `SIGNED_BOOT` only through the scenario.
* **OTP burnt but the stage-1 report lost.** Run `python -m otp_server modules mark-locked <serial>`: it records
  `otp_key_hash = customer_key_hash` and `secure_boot_provisioned = true`, so all later stages are served signed.
  It never generates a key. `modules mark-unlocked <serial>` undoes it. When a server is running both send
  the change through it (`POST /api/modules/{serial}/otp`).
* A board whose OTP is **locked to our key** always gets signed files: a counter-signed `bootcode5.bin`, a
  signed EEPROM, a `boot.sig` for the gadget, and a boot partition re-signed per board in stage 3.
* A board **locked to a different key** is refused (HTTP 409, "board OTP is locked to a different key").

## HTTP API

All JSON, same origin. Errors are `{"detail": "..."}`. Until the station is signed in to Google and the
settings sheet has been read, the module, stage and build endpoints answer **401** with what is missing. An
artifact that is not ready returns 409 `{"ready": false, "reason": "...", "job": Job|null}`. Interactive
docs are at `/api/docs`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | version, Google login + settings state, effective config, storage, Docker, Windows USB driver, artifact status, current jobs |
| GET | `/api/google/login` | redirect to Google's consent screen (Google redirects back to `/?state=…&code=…`) |
| POST | `/api/google/logout` | forget the Google token on this station (the spreadsheet id is kept) |
| GET | `/api/modules` | registry, newest first (public view, no secrets) |
| POST | `/api/modules/hello` | `{serial, chip?, board?, usb?, rom_stage?}` → get or create a board and its secrets |
| GET | `/api/modules/{serial}` | one board |
| POST | `/api/modules/{serial}/mode` | `{"mode": "open" \| "secure"}`: the board's scenario (switching resets it to stage 1) |
| GET | `/api/modules/{serial}/stage/{n}` | stage manifest (n = 1, 2, 3), or 409 while builds run |
| GET | `/api/modules/{serial}/stage/{n}/files/{name}` | a file listed in the last manifest issued for that board and stage (404 otherwise; 409 if it changed or disappeared since: restart the stage) |
| POST | `/api/modules/{serial}/stage/{n}/result` | report a stage result → `{module, verdict}` |
| POST | `/api/modules/{serial}/device-key` | `{key_der_b64, device_key_pem}`: the OTP device key exported by the gadget → `{module, device_key: {fingerprint, already, zero_words}}` |
| POST | `/api/modules/{serial}/facts` | `device_key_pem`, `duid`, `fastboot_vars`, `event` |
| POST | `/api/modules/{serial}/otp` | `{"action": "mark-locked" \| "mark-unlocked"}`: operator override used by the CLI |
| POST | `/api/fastboot/identify` | `{serialno, vars}` from the gadget → board |
| GET | `/api/builds` | status of `tools`, `gadget`, `image` (with both variants) |
| POST | `/api/builds/{target}` | `{force}` → start a build (returns the running job if one exists) |
| GET | `/api/jobs`, `/api/jobs/{id}` | jobs |
| GET | `/api/jobs/{id}/log` | `text/event-stream`: buffered lines, then live, then `event: done` |

Outside `/api`, only `/` (which also receives Google's OAuth redirect), `/css/*` and `/js/*` are served.

## CLI

```
python server.py [--host H] [--port N] [--browser EXE] [--no-browser] [--no-auto-build] [--work DIR]
python -m otp_server serve  ...                 # same as server.py
python -m otp_server login                      # sign in to Google from a terminal (opens the browser)
python -m otp_server build tools|gadget|image [--force]   # run one build, stream its log, exit with its result
python -m otp_server modules [--json]           # registry table / public JSON (no secrets)
python -m otp_server modules mark-locked <serial> [--yes]    # record that the board OTP holds our key hash
python -m otp_server modules mark-unlocked <serial> [--yes]  # undo mark-locked
python -m otp_server status                     # the /api/status document
python -m otp_server --version
```

Every command except `serve` and `status` reads the settings from the spreadsheet, so it needs the Google
login; without it the command exits with code 2 and says what is missing.

## Repository layout

```
server.py                  launcher
requirements.txt
google-oauth-client.json   the Desktop-app OAuth client (you add it)
otp_server/
  __main__.py              CLI; app.py (services, FastAPI app); api.py (routes)
  config.py                defaults, validation, merging (no config file)
  settings.py              the settings worksheet
  google_account.py        Google OAuth login, token, the station spreadsheet
  secrets_gen.py           RSA key, customer key hash, device secret, device key parsing, LUKS key
  modules.py               board registry logic, scenarios, device key, stage verdicts
  storage/                 base.py (record schema), gsheets.py (the modules worksheet)
  docker.py, jobs.py       Docker CLI runner; background jobs with logs and SSE
  artifacts/               tools image, stage 1, gadget + stage 2, droneos images + stage 3
  imagejson.py, sparse.py  rpi-image-gen image.json helpers; Android sparse validation
  winusb.py                Windows WinUSB driver-package check (read-only)
docker/
  tools.Dockerfile, tools-entrypoint.sh     otp-tools image ("otp-run <script>")
  scripts/stage1.sh, stage2-sign.sh, boot-resign.sh, image-collect.sh
  gadget.Dockerfile, gadget-entrypoint.sh   arm64 pi-gen-micro builder
  gadget-helpers/otp-keyexport/             pi-gen-micro helper package: OTP device key export
index.html, css/app.css
js/server.js               API client; flow.js provisioning state machine; app.js UI
js/rpiboot.js              rpiboot protocol (port of usbboot main.c); bootdir.js, tar.js, duid.js
js/fastboot.js             WebUSB fastboot client + IDP + device key export
tests/                     pytest suites; tests/web/ page self-test and end-to-end test (headless Chrome)
external/                  submodules
```

## Submodules

| Path | Upstream | Used for |
| --- | --- | --- |
| `external/usbboot` (+ nested `rpi-eeprom`) | raspberrypi/usbboot | `firmware/bootfiles.bin`, EEPROM images and recovery, `update-pieeprom.sh`, `rpi-eeprom-digest`, `rpi-sign-bootcode`, `rpi-make-boot-image` |
| `external/pi-gen-micro` | raspberrypi/pi-gen-micro | source of the fastboot gadget |
| `external/droneos` (+ nested `rpi-image-gen`) | zarcsis/droneos | the stage-3 image: `droneos.yaml`, `build.sh`, the builder `docker/Dockerfile` |

The droneos submodule pins the commit the image is built from: to build newer droneos work, commit and push
it in droneos, then move the pointer here (`git submodule update --remote external/droneos` for the tip of
the default branch, or `git -C external/droneos fetch` + `checkout <commit>`; then
`git submodule update --init --recursive external/droneos` for its nested rpi-image-gen) and commit
`external/droneos`. The image set's version is `git describe` of that checkout: once the pointer moves (or
the checkout gets uncommitted changes, `-dirty`), the published sets are `rebuild needed` and stage 3 waits
until the images are rebuilt — automatically with `builds.auto`, or with Build on the page /
`python -m otp_server build image`.

**rpi-fastbootd is deliberately not a submodule.** Its repository contains the systemd unit
`dev-usb\x2dffs-fastboot.mount`, a file name Windows cannot check out, and building it needs Raspberry Pi
OS libraries (librpifwcrypto, libblockdeviceid). pi-gen-micro vendors the official
`internal/packages/rpi-fastbootd_*_arm64.deb`, which is exactly what the gadget is built from.

Scripts stage a CR-stripped copy of every shell script inside the container, and never rely on git symlinks
(for example `usbboot/firmware/2712/*`) being materialised in a Windows checkout. The gadget build drops
pi-gen-micro's cached index of its local package repo before every build (that repo's `Release` file has no
hashes, so apt would otherwise never notice a new or changed helper package).

## Testing

```
python -m pip install -r requirements.txt
python -B -m pytest -q                        # server: config, settings, Google account, secrets, storage, modules, jobs, docker, artifacts, API, CLI, the key export script
python -B tests/web/run_selftest.py           # page: headless Chrome against a fake API (-v for every line)
python -B tests/web/run_e2e.py                # page + real server on the real artifacts + a mock board, both scenarios
```

The Google code is tested against fakes; there is no network access and it has not been run against real
Google yet. `OTP_DOCKER_TESTS=1` enables a smoke test against the real Docker engine. The page runners find
Chrome via `--chrome`, `$OTP_CHROME`, the default Windows path or `PATH`. The repository has no `.gitignore`
on purpose: run Python with `-B` (or `PYTHONDONTWRITEBYTECODE=1`) so no `__pycache__` directories appear.

## Troubleshooting

* **"No Google OAuth client".** Save the Desktop-app client JSON as `google-oauth-client.json` in the repository
  root (see Requirements) and reload the page.
* **Google sign-in fails or the login stops working after a week.** The OAuth app is still in *Testing*: then
  only its test users can sign in and Google expires their logins after 7 days. Publish it (*Audience →
  Publish app*); with the `drive.file` scope alone that needs no verification. "access_denied" means the
  account is not allowed (Testing) or the consent was cancelled.
* **"the station spreadsheet … of <account> is gone".** The account's spreadsheet was deleted, or another
  OAuth client created it (with the `drive.file` scope the station only sees its own files). Restore it from
  the Drive trash, or delete `<work>/google/spreadsheet.json` to let the server look in the account's Drive
  again and, if nothing is there, create a new one (the registry then starts empty). The server never
  replaces a remembered spreadsheet silently.
* **"invalid value in the settings sheet".** Fix the value in the `settings` worksheet; until then the server
  keeps the previous settings.
* **Docker badge red / builds fail with "docker: not found" or "cannot connect".** Start Docker Desktop (the
  server does it on Windows when `docker.start_desktop` is true), switch it to Linux containers, and check
  `docker info`. Set `docker.binary` if `docker` is not on `PATH`.
* **arm64 builds fail with `exec format error`.** The arm64 binfmt handler is missing. The server tries
  `docker run --rm --privileged tonistiigi/binfmt --install arm64` itself; run it by hand if that fails.
* **Chrome's chooser is empty / "Access denied" on Windows.** The device is not bound to WinUSB. Install
  `rpiboot_setup.exe` (see Requirements) and replug. If a libusb-win32/libusbK driver grabbed the device,
  rebind it, for example with Zadig.
* **Chrome asks again for every board.** WebUSB permissions are per device. The boot ROM, the second stage and
  the fastboot gadget are separate devices, so a new board needs the chooser for each.
* **"… is still being prepared" / HTTP 409 on a stage.** A build is still in progress. The page polls every 3 s
  and links the job log. A failed job shows its error; fix it and click Rebuild, or run
  `python -m otp_server build <target> --force` to see the whole log in the terminal.
* **Stage 3: "the OTP device key cannot be exported in this boot".** The key exists but was READ-locked before
  the helper ran (for example the gadget was booted without our helper). Run stage 2 again so the gadget boots
  afresh, then stage 3. "this fastboot gadget has no OTP key export helper" means an old gadget: rebuild it.
* **"board OTP is locked to a different key".** The board was locked with a key this registry does not hold.
  Nothing can be provisioned. Restore the registry row that holds its key.
* **HTTP 403 "Host … is not allowed" / "cross-site POST rejected".** Open the page at `http://127.0.0.1:<port>/`.
* **Port 8765 in use.** Another program holds it (exit code 2). Use `--port`.
* **The board does not show up in RPIBOOT.** Hold the power button while plugging USB-C, and use a different
  cable or port. Close `rpiboot.exe` and other tabs.

## References

* WebUSB: https://wicg.github.io/webusb/
* usbboot (rpiboot, secure-boot recovery, `rpi-eeprom` tools): https://github.com/raspberrypi/usbboot
* rpi-eeprom: https://github.com/raspberrypi/rpi-eeprom
* rpi-sb-provisioner (reference provisioning station): https://github.com/raspberrypi/rpi-sb-provisioner
* pi-gen-micro (fastboot gadget): https://github.com/raspberrypi/pi-gen-micro
* rpi-fastbootd: https://github.com/raspberrypi/rpi-fastbootd
* rpifwcrypto (`rpi-fw-crypto`): https://github.com/raspberrypi/utils/tree/master/rpifwcrypto
* rpi-image-gen (image build, IDP): https://github.com/raspberrypi/rpi-image-gen
* fastboot protocol: https://android.googlesource.com/platform/system/core/+/main/fastboot/README.md
* Android sparse format: https://android.googlesource.com/platform/system/core/+/main/libsparse/
* gspread: https://docs.gspread.org/
* Google OAuth for desktop apps: https://developers.google.com/identity/protocols/oauth2/native-app
