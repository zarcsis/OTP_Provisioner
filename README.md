# OTP_Provisioner

A demo provisioning station for Raspberry Pi 5 boards. A small Python server (FastAPI) generates and
stores the secrets of every board, builds all the files a board needs (in Docker), and serves a web
page. The page runs in Chrome or Edge and drives the board over **WebUSB**. It speaks the `rpiboot`
protocol to the BCM2712 boot ROM and `fastboot` to the provisioning gadget. The operator plugs a board
in and clicks **Connect board** and **Provision**. Chrome's device chooser and a typed-serial confirmation
before irreversible steps are the only other interactions.

Boards are identified by the 8-hex USB serial the boot ROM reports (for example `a7eb274c`).

| Stage | What the board does | Files come from | Registry stage after success |
| --- | --- | --- | --- |
| 1 · EEPROM & OTP | Boots `bootcode5.bin` (recovery) over rpiboot and flashes `pieeprom.bin` + `.sig`. It reports metadata (MAC, DUID, `CUSTOMER_KEY_HASH`, …) and reboots straight back into RPIBOOT (`set_reboot_order=0x3`, `recovery_reboot=1`). In secure-boot mode the EEPROM is signed and `program_pubkey=1` burns the key hash into OTP. | `external/usbboot/rpi-eeprom` firmware, packed by `docker/scripts/stage1.sh` | `eeprom` |
| 2 · Fastboot gadget | Boots `bootfiles.bin` + `boot.img` (pi-gen-micro "fastboot" ramdisk with rpi-fastbootd). The board re-enumerates as USB `18d1:4e40` with its 16-hex serial. | gadget built from `external/pi-gen-micro`, or the prebuilt image from `external/rpi-sb-provisioner` | `gadget` |
| 3 · Image | Page drives rpi-fastbootd: `oem fwcrypto init` → `getvar:public-key` → `erase` → IDP (`oem idpinit` / `idpwrite` / `idpgetblk` + `flash` of sparse pieces ≤ 256 MiB / `idpdone`) → `oem cryptsetpassword` → `reboot`. | droneos image (`../droneos`, rpi-image-gen, LUKS2 root `osroot_crypt`) built in Docker | `flashed` |

Status: the Python and page test suites pass. The server, the builds and the page have been tested
against mocks and real Docker. **Stage 3 and the self-built gadget have not been run on a real board yet.**

## Requirements

* **Chrome or Edge** (any Chromium browser with WebUSB). Firefox and Safari have no WebUSB.
* **Python 3.11+** with the packages from `requirements.txt`.
* **Docker** with arm64 emulation: Docker Desktop on Windows (Linux engine), or Docker Engine on Linux. The
  gadget and droneos builds run in `linux/arm64` containers. The server registers the arm64 binfmt handler
  when it is missing (see Troubleshooting). Both archive builds need internet access.
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
  rpi-eeprom, rpi-sb-provisioner, pi-gen-micro).
* **droneos** checked out next to this repo (`../droneos`, or set `paths.droneos`) with its own submodule:
  `git -C ../droneos submodule update --init`. Only stage 3 needs it.

## Quick start

```
git clone <this repo> OTP_Provisioner
cd OTP_Provisioner
git submodule update --init --recursive
python -m pip install -r requirements.txt
python server.py
```

`python server.py` prints the config file, the work directory and the storage backend. It serves
`http://127.0.0.1:8765/` and opens the page in Chrome (Edge if Chrome is missing, otherwise the default browser).
If an OTP_Provisioner is already running on that port, it just opens the page and exits.
Options: `--config PATH`, `--host H`, `--port N`, `--no-browser`, `--no-auto-build`.

With no config file everything uses the defaults: local JSON storage, unsigned EEPROM (no OTP change in
stage 1), and automatic builds. To change anything, copy `config.example.yaml` to `config.yaml`.

### What happens on first start

With `builds.auto: true` the server starts the missing builds in the background. The page works
meanwhile and its **Server builds** card shows each job with a live log:

1. **tools**: the `otp-tools:latest` image from `docker/tools.Dockerfile` (Debian trixie with openssl,
   pycryptodome, mtools and the Android sparse tools). It is used for all signing and packing. The
   image is rebuilt whenever `docker/tools.Dockerfile` or `docker/tools-entrypoint.sh` changes.
2. **gadget**: the pi-gen-micro fastboot ramdisk, built in an arm64 container (about 3 minutes cold). Until
   it exists, `source: auto` serves the prebuilt `fastboot-gadget-pi5-family.img` from rpi-sb-provisioner,
   so stage 2 is usable right away.
3. **image**: the droneos image. The builder image comes from `<droneos>/docker` and the build runs with
   `IGconf_image_pmap=crypt` (several minutes). The result is collected into an IDP set of sparse pieces
   ≤ `max_piece_size` with SHA-256 for each piece. Stage 3 answers "not ready" until this is done.

On Windows, if the Docker engine is not running, the server starts Docker Desktop and waits for it (up to 180 s).

Build rules worth knowing:

* **Rebuild triggers.** The gadget key is `<pi-gen-micro commit>-<hash of docker/gadget.Dockerfile +
  gadget-entrypoint.sh>-<targets>`, so editing either file makes the gadget "not built". An image set split
  with a larger `max_piece_size` than the current setting is reported as `rebuild needed: …` (status not
  ready, stage 3 409). The stage-1 identity includes the sha256 of the selected `pieeprom-*.bin` and
  `recovery.bin` and the content of `rpi-eeprom-config`, `rpi-eeprom-digest`, `rpi-sign-bootcode` and
  `update-pieeprom.sh`, so a firmware or usbboot submodule update rebuilds stage 1 (a quick build, about a
  minute) even when names and sizes stay the same. `builds.auto` rebuilds all of these by itself.
* **Forced rebuilds never replace the served build in place.** A forced gadget build goes to
  `<key>-r2`, `-r3`, …; the newest complete version is served and older ones are kept (they are never pruned,
  so disk use grows with forced rebuilds).
* **One heavy build at a time, across processes.** Gadget and image builds take `<work>/tmp/heavy.lock`.
  `python -m otp_server build …` started while the server builds waits ("waiting for another image/gadget
  build to finish …") and skips the build if the other process finished it meanwhile.
* **No-output watchdog.** A streamed `docker build`/`docker run` that prints nothing for 30 minutes is
  stopped: the container (always started as `--name otp-<id>`) is removed with `docker rm -f` and the job
  fails with "produced no output for N s and was stopped". The limit is `docker.idle_timeout` (default 1800 s;
  0 disables the watchdog).
* **Start-up sweep.** The server and the CLI remove leftover signing-key directories `<work>/tmp/keys-*`
  that no live process holds, and `*.old-*` directories left by replaced builds. A key directory that cannot
  be deleted is logged as a warning naming only the path.

All runtime state lives **outside the repo**, in the work directory. The default is
`%LOCALAPPDATA%\OTP_Provisioner` on Windows and `$XDG_DATA_HOME/otp-provisioner` or
`~/.local/share/otp-provisioner` elsewhere. Override it with `paths.work` or `OTP_WORK_DIR`.

```
<work>/config.yaml                     optional config (searched last)
<work>/registry/<serial>.json          local store: one record per board (contains secrets)
<work>/google/                         OAuth token caches; a good place for Google credential files
<work>/artifacts/stage1/<fp>/          shared unsigned stage-1 files
<work>/artifacts/stage2/config.txt
<work>/artifacts/gadget/<key>[-r<N>]/  built gadget + build-info.json (newest complete version served)
<work>/artifacts/image/<set>/          IDP set: image.json, sparse pieces, manifest.json
<work>/artifacts/image/current.json    which set stage 3 serves
<work>/modules/<serial>/stage{1,2,3}/<fp>/    per-board signed files (secure boot only)
<work>/jobs/<id>.log                   build logs
<work>/tmp/keys-<id>/ + keys-<id>.lock  short-lived key files for signing (deleted after use, swept at start)
<work>/tmp/heavy.lock                  cross-process lock for gadget/image builds
```

Docker volumes `otp-pgm-work` and `otp-droneos-work` keep the build trees and apt caches between runs.

## Operator procedure

1. Insert the target **SD card** into the board.
2. **Hold the power button**, connect **USB-C** to the station, release the button. The board enumerates
   as *BCM2712 Boot*. Use a port that can supply enough current.
3. Click **Connect board** and pick *BCM2712 Boot* in Chrome's chooser. The page registers the board with
   the server (`hello`). Its secrets are generated now if this serial has never been seen, and are reused otherwise.
4. Click **Provision**. Before any irreversible step (OTP writes, `oem fwcrypto init`, erase), the page shows
   what will happen and asks you to type the serial (`confirm_irreversible`).
   Stage 1 runs, the board reboots into RPIBOOT by itself, and stage 2 runs. If Chrome needs permission for
   the re-enumerated device, a **Select device** button appears.
5. When the gadget has booted, click **Connect fastboot gadget** and pick *Raspberry Pi …* in the chooser.
   Chrome's list updates while Linux boots. Stage 3 identifies the board, then flashes the image with a
   progress bar, and the board reboots into the new image.

The page skips stages that are already done. A board that already runs the gadget can be connected
directly for stage 3. If the cable is pulled, the page says which stage failed, and **Provision** resumes from there.
Only one program may claim the USB interface: close `rpiboot`, `fastboot` and other tabs of the page.

* **Long silences in stage 1 are normal.** recovery.bin can stay silent for longer than WinUSB's fixed ~5 s
  transfer timeout while it writes the EEPROM or OTP (Chrome reports that as `NetworkError`). The page's
  rpiboot file server retries every second for as long as the board is attached. It stops only when the board
  really left USB (disconnect event, device closed, or gone from `getDevices()`; the result is kept as
  interrupted with the metadata collected so far) or when an attached board asks for nothing for 180 s
  ("the board is still attached but has not asked for anything for N s").
* A failed rpiboot stage that never reached the board (for example a missing file) can be re-run on the
  same connected board without replugging it.
* Stage 3 compares the gadget's `getvar:serialno` with the board being provisioned before it contacts the
  server; a gadget of another board is refused with "the fastboot gadget belongs to board X, not Y".
* Step details: a successful stage 1 reads `EEPROM_UPDATE = … · N metadata fields, M files served`, a
  successful stage 2 reads "boot.img delivered; the board is booting the fastboot gadget". A stage 2 whose
  board leaves USB after `boot.img` is the expected hand-off and is no longer reported as "run was
  interrupted". Server notes appear as a muted list under the step.

The collapsed **Advanced (manual)** section keeps the old serverless tools: device list, rpiboot
runs from a local directory, and manual fastboot. It also works from `file://` without the server.
Before a run it checks the `config.txt` that will actually be served to the selected device's SoC
(the `<prefix>/config.txt` overlay, the `bootfiles.bin` member `<prefix>/config.txt`, then the top-level
`config.txt`), shows which file that is, and warns about other `config.txt` files that differ but are not
served. The exact bytes confirmed in the irreversible dialog are pinned and served even if the file changes
on disk afterwards.

## Secrets and storage

Generated per board at first contact and never regenerated:

| Field | Content |
| --- | --- |
| `rsa_private_pem` / `rsa_public_pem` | RSA-2048 boot-signing key (PKCS#8 / SPKI PEM) |
| `customer_key_hash` | `sha256(n as 256 bytes LE ‖ e as 8 bytes LE)`: the value the recovery burns with `program_pubkey` and reports as `CUSTOMER_KEY_HASH` |
| `device_secret` | 32 random bytes, hex; root of the LUKS recovery passphrase |

Learned later: `otp_key_hash` (what the board reports), `device_key_pem` (the OTP ECDSA public key from
`getvar:public-key`), `duid`, `mac`, `boardrev`, the full metadata, fastboot variables and an event log.

**LUKS recovery passphrase** (keyslot 1, added by `oem cryptsetpassword` when `recovery_passphrase: true`):

```
luks_passphrase = HMAC-SHA256(key = bytes.fromhex(device_secret), msg = "<mname>:<serial>").hexdigest()
                  # mname = the container's mapper name (osroot_crypt), serial = 8-hex board serial
```

Keyslot 0 is created by rpi-fastbootd itself. Its key is an HMAC computed by the firmware with the OTP device
key over the storage ID, and the image's initramfs unlocks the root with it at boot. The server never sees
that key. The recovery passphrase lets the server open the card offline.

The page and `/api/modules` show only a public view: which secrets exist, the hashes and the fingerprints. Private
keys and device secrets never go over the API. The only secret the page receives is the recovery passphrase in the
stage-3 manifest. The page passes it to `oem cryptsetpassword` and redacts it from the page log.

### Backends (`storage.backend`)

**`local`** (default): `<work>/registry/<serial>.json`, written atomically. Files are `0600` on POSIX. Back this
directory up. A board with `program_pubkey` burned can never run code again without its key.

**`gsheets`**: one worksheet, one row per board, with the header row created automatically.

1. In a Google Cloud project, enable **both** the *Google Sheets API* and the *Google Drive API*.
2. Service account (`auth: service_account`): IAM & Admin → Service accounts → create → Keys → Add key → JSON.
   Or OAuth (`auth: oauth`): configure the consent screen, add yourself as a test user, and create a
   *Desktop app* client JSON.
3. **Create the spreadsheet in your own Google account** and, for a service account, share it with the key's
   `client_email` as *Editor*. A service account has no Drive storage quota, so it cannot own the sheet itself.
4. Configure it:

   ```yaml
   storage:
     backend: gsheets
     gsheets:
       credentials: C:/Users/me/AppData/Local/OTP_Provisioner/google/service_account.json
       spreadsheet: https://docs.google.com/spreadsheets/d/<key>/edit   # or just <key>
   ```

**`gdrive`**: one `<serial>.json` file per board in a folder.

1. Enable the *Google Drive API*, and create a service account key or a Desktop OAuth client as above.
2. Where the folder lives depends on `auth`:
   * `auth: service_account`: the folder **must be in a Shared Drive** (Google Workspace), with the key's
     `client_email` as a member with *Content manager* or *Contributor* access. A service account has no
     Drive storage quota and cannot own files in a personal My Drive, even in a folder shared with it as
     Editor: every new board would fail with 403 `storageQuotaExceeded` (the error says so, and
     `login` warns when the folder is not in a Shared Drive).
   * `auth: oauth`: any folder in your own My Drive.
3. Set `storage.gdrive.folder_id` (the last part of the folder URL) and `storage.gdrive.credentials`.

**Login.** Run `python -m otp_server login` once on the station before starting the server. With
`auth: oauth` it opens the browser, waits up to 300 s, saves the token to `storage.<backend>.token` and
prints `OAuth login done, token saved to …: <location> is reachable, N module record(s)`. With
`auth: service_account` it only checks access (`service account <client_email>: … is reachable`). It exits 1
with `ERROR: <message>` on failure. **The server never opens a browser:** with a missing, unreadable or
rejected OAuth token the storage badge and every store call say "not logged in" / "the OAuth token … was
rejected" and point to `python -m otp_server login` (also the fix when a *Testing* OAuth app's token expires
after 7 days). A login done while the server runs takes effect without a restart: a rejected token makes the
store drop its client, and the next attempt (after the 10 s retry pause) reads the new token. Error advice
follows the auth mode: a rejected service-account key says to create a new JSON
key, and a local file permission error is reported as a file-system error, not a sharing problem.

Both Google backends connect lazily and cache records in memory to stay within the Sheets quota of 60 requests/min/user.
If Google cannot be reached, the server still starts: the storage badge turns red and the module
endpoints answer 503. Network failures (including while refreshing a token) are retried every 10 s and
never trigger a login. Every Sheets request has a 10 s connect / 60 s read timeout. Before overwriting a
row in place, Sheets reads that row's serial cell (one small extra request per write) and re-reads the sheet
if it no longer matches, so rows may be deleted, inserted or sorted by hand. **The sheet or folder holds
every board's private key and device secret: share it with nobody who should not have them.** The Google
libraries are only imported for these two backends.

## Security model and irreversible operations

* The server listens on `127.0.0.1` by default. WebUSB needs a secure context, and `http://127.0.0.1` qualifies.
  Anyone who can reach the port can fetch per-board signed files and recovery passphrases, so the server
  warns when you bind to another address. There is no authentication.
* **Host and Origin checks** (against DNS rebinding and cross-site requests). A request whose `Host` hostname
  is not `127.0.0.1`, `localhost`, `::1` or the configured `server.host` gets 403 with a JSON `detail`. When
  the server listens on `0.0.0.0` or `::`, any IP literal and the machine's own host name are accepted too;
  other DNS names are refused (there is no config key for extra names). Open the page via
  `http://127.0.0.1:<port>/` or the configured address. Any method other than GET/HEAD that carries an
  `Origin` (or, without one, a `Referer`) naming another host is refused with "cross-site POST rejected".
  Requests without either header (curl, scripts, the CLI) still work. For loopback names, `server.host` and
  the machine's host name ports are not compared; with a wildcard listen an IP-literal `Origin` must be this
  very server (same address and port as the `Host` header), so a site reached by IP cannot post.
* Private keys are written to a temporary directory only for the duration of a signing container run, then deleted.
  Logs never contain keys, secrets or passphrases.

What the irreversible operations burn (the page lists each one and asks for the serial first):

| Operation | When | What it does, forever |
| --- | --- | --- |
| `program_pubkey=1` (stage 1 `config.txt`) | `secure_boot: true` and the board is not yet locked | Burns the SHA-256 of this board's RSA public key into OTP. From then on the SoC only runs EEPROM and boot images signed with that key. Lose the key and the board is bricked for this station. |
| `program_jtag_lock=1` (stage 1) | `jtag_lock: true` **and** `secure_boot: true` | Permanently disables VideoCore JTAG. |
| `oem fwcrypto init` (stage 3) | **every** stage-3 run, including the default unsigned mode | Makes the firmware generate the device-unique ECDSA P-256 key in OTP and lock it (idempotent: "Key already provisioned" on later runs). The LUKS root is bound to it. It cannot be changed or erased, and the private half can never be read. |
| `erase:<disk>` (stage 3) | `erase_storage: true` | Wipes the SD card / eMMC / NVMe before IDP writes the partition table. |

### `secure_boot` mode

* `secure_boot: false` (default): stage 1 flashes an unsigned EEPROM and does not touch OTP. Stages 2 and 3 use
  unsigned files. Stage 3 still runs `oem fwcrypto init`.
* `secure_boot: true`: stage 1 signs the EEPROM config with the board's RSA key (`SIGNED_BOOT=1`,
  `ENABLE_SELF_UPDATE=0` added to `boot_conf`) and adds `program_pubkey=1`. The verdict requires
  `SECURE_BOOT_PROVISION=success` and `CUSTOMER_KEY_HASH` equal to the stored hash.
* **Key-hash check before signing or burning.** In signed mode the server recomputes `customer_key_hash` from
  the record's RSA key. If the stored hash differs, or the record has a hash but lost its PEMs (a freshly
  generated key would not match), stage 1 is refused with 409 ("the board record's customer_key_hash X does
  not match its RSA key … fix the record in storage first"), also when the files were already built. Never
  edit `customer_key_hash` and the PEM columns in Sheets/Drive independently. `stage1.sh` gets the expected
  hash as `EXPECT_CKH` (required in signed mode; add `-e EXPECT_CKH=<hash>` to a manual docker run) and dies if
  `public.pem` or the key embedded in `pieeprom.bin` hashes to anything else. A built stage-1 dir whose
  `build-info.json` names another key (or, unsigned, any key) is rebuilt.
* **`boot_conf` rules.** Signed mode: `ENABLE_SELF_UPDATE=0` and `SIGNED_BOOT=1` count as present only when
  every assignment of the key is in `[all]` (or before the first section header) with exactly that value;
  otherwise every assignment of the key in every section (for example a `[cm5]` or `[pi5]` override) is
  removed and the value is appended under a trailing `[all]`. Unsigned mode: any `SIGNED_BOOT` other than `0`,
  in any section, is removed; the stage-1 manifest carries a note and the job log a WARNING line, and
  `stage1.sh` itself refuses `MODE=unsigned` with `SIGNED_BOOT` set. Set `SIGNED_BOOT` only through
  `secure_boot`, never in `boot_conf`.
* **OTP burnt but the stage-1 report lost.** The record then does not know the board is locked. Run
  `python -m otp_server modules mark-locked <serial>`: it records `otp_key_hash = customer_key_hash` and
  `secure_boot_provisioned = true`, so all later stages are served signed. It never generates a key: it
  refuses a record without its private signing key, and one whose stored key hash does not match that key.
  `modules mark-unlocked <serial>` undoes it. Both print the current OTP state, ask you to type the serial
  (unless `--yes`), and add an `otp_override` event to the board. When a server is running they send the change
  through it (`POST /api/modules/{serial}/otp`), so the server's registry cache cannot overwrite it.
* A board whose OTP is **locked to our key** always gets signed files, whatever `secure_boot` says, because
  a locked board only runs signed code: a counter-signed `bootcode5.bin`, a signed EEPROM, a `boot.sig` for
  the gadget, and a boot partition re-signed per board in stage 3.
* A board **locked to a different key** is refused (HTTP 409, "board OTP is locked to a different key").
  This station cannot sign anything that board will run.

## Configuration

See [`config.example.yaml`](config.example.yaml). It lists every key with its default and a one-line comment.
Search order: `--config PATH` → `$OTP_CONFIG` → `<repo>/config.yaml` → `<work>/config.yaml`. Environment overrides
are `OTP_WORK_DIR`, `OTP_STORAGE` and `OTP_PORT`. Invalid values stop the server with a clear message (exit code 2).
Unknown keys only produce a warning. `GET /api/status` shows the effective configuration (paths, never secrets).

## HTTP API

All JSON, same origin. Errors are `{"detail": "..."}`. An artifact that is not ready returns
409 `{"ready": false, "reason": "...", "job": Job|null}`. Interactive docs are at `/api/docs`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | version, effective config, storage, Docker, Windows USB driver, artifact status, current jobs |
| GET | `/api/modules` | registry, newest first (public view, no secrets) |
| POST | `/api/modules/hello` | `{serial, chip?, board?, usb?, rom_stage?}` → get or create a board and its secrets |
| GET | `/api/modules/{serial}` | one board |
| GET | `/api/modules/{serial}/stage/{n}` | stage manifest (n = 1, 2, 3), or 409 while builds run |
| GET | `/api/modules/{serial}/stage/{n}/files/{name}` | a file listed in the last manifest issued for that board and stage (404 otherwise; 409 if it changed or disappeared since: restart the stage) |
| POST | `/api/modules/{serial}/stage/{n}/result` | report a stage result → `{module, verdict}` |
| POST | `/api/modules/{serial}/facts` | `device_key_pem`, `duid`, `fastboot_vars`, `event` |
| POST | `/api/modules/{serial}/otp` | `{"action": "mark-locked" \| "mark-unlocked"}`: operator override used by the CLI |
| POST | `/api/fastboot/identify` | `{serialno, vars}` from the gadget → board |
| GET | `/api/builds` | status of `tools`, `gadget`, `image` |
| POST | `/api/builds/{target}` | `{force}` → start a build (returns the running job if one exists) |
| GET | `/api/jobs`, `/api/jobs/{id}` | jobs |
| GET | `/api/jobs/{id}/log` | `text/event-stream`: buffered lines, then live, then `event: done` |

Outside `/api`, only `/`, `/css/*` and `/js/*` are served.

## CLI

```
python server.py [--config P] [--host H] [--port N] [--no-browser] [--no-auto-build]
python -m otp_server serve  ...                 # same as server.py
python -m otp_server build tools|gadget|image [--force]   # run one build, stream its log, exit with its result
python -m otp_server modules [--json]           # registry table / public JSON (no secrets)
python -m otp_server modules mark-locked <serial> [--yes]    # record that the board OTP holds our key hash
python -m otp_server modules mark-unlocked <serial> [--yes]  # undo mark-locked
python -m otp_server login                      # Google backends: OAuth login / service-account check
python -m otp_server status                     # the /api/status document
python -m otp_server --version
```

## Repository layout

```
server.py                  launcher
requirements.txt
config.example.yaml
otp_server/
  __main__.py              CLI; app.py (services, FastAPI app); api.py (routes)
  config.py                YAML config, defaults, validation
  secrets_gen.py           RSA key, customer key hash, device secret, LUKS passphrase
  modules.py               board registry logic and stage verdicts
  storage/                 local.py, gsheets.py, gdrive.py behind one ModuleStore protocol
  docker.py, jobs.py       Docker CLI runner; background jobs with logs and SSE
  artifacts/               tools image, stage 1, gadget + stage 2, droneos image + stage 3
  imagejson.py, sparse.py  rpi-image-gen image.json helpers; Android sparse validation
  winusb.py                Windows WinUSB driver-package check (read-only)
docker/
  tools.Dockerfile, tools-entrypoint.sh     otp-tools image ("otp-run <script>")
  scripts/stage1.sh, stage2-sign.sh, boot-resign.sh, image-collect.sh
  gadget.Dockerfile, gadget-entrypoint.sh   arm64 pi-gen-micro builder
index.html, css/app.css
js/server.js               API client; flow.js provisioning state machine; app.js UI
js/rpiboot.js              rpiboot protocol (port of usbboot main.c); bootdir.js, tar.js, duid.js
js/fastboot.js             WebUSB fastboot client + IDP
stage-dirs/                reference rpiboot directories (fastboot gadget, mass-storage gadget)
tests/                     pytest suites; tests/web/ page self-test (headless Chrome)
external/                  submodules
```

## Submodules

| Path | Upstream | Used for |
| --- | --- | --- |
| `external/usbboot` (+ nested `rpi-eeprom`) | raspberrypi/usbboot | `firmware/bootfiles.bin`, EEPROM images and recovery, `update-pieeprom.sh`, `rpi-eeprom-digest`, `rpi-sign-bootcode`, `rpi-make-boot-image` |
| `external/rpi-sb-provisioner` | raspberrypi/rpi-sb-provisioner | prebuilt `host-support/fastboot-gadget-pi5-family.img`; reference station |
| `external/pi-gen-micro` | raspberrypi/pi-gen-micro | source of the fastboot gadget |

**rpi-fastbootd is deliberately not a submodule.** Its repository contains the systemd unit
`dev-usb\x2dffs-fastboot.mount`, a file name Windows cannot check out, and building it needs Raspberry Pi
OS libraries (librpifwcrypto, libblockdeviceid). pi-gen-micro vendors the official
`internal/packages/rpi-fastbootd_*_arm64.deb`, which is exactly what the gadget is built from. It is not
in the Raspberry Pi apt archive either.

Scripts stage a CR-stripped copy of every shell script inside the container, and never rely on git symlinks
(for example `usbboot/firmware/2712/*`) being materialised in a Windows checkout.

## Testing

```
python -m pip install -r requirements.txt
python -B -m pytest -q                        # server: config, secrets, storage, modules, jobs, docker, artifacts, API, CLI
python tests/web/run_selftest.py              # page: headless Chrome, 248 assertions (-v for every line)
```

The Google backends are tested against the real gspread and googleapiclient request builders with fake
transports. There is no network access, and they have not been run against real Google yet. `OTP_DOCKER_TESTS=1` enables a
smoke test against the real Docker engine. The page runner finds Chrome via `--chrome`, `$OTP_CHROME`, the default
Windows path or `PATH`. `--screenshot out.png --state idle|demo|demo-fastboot|offline` renders the page with a
fake API, and `--serve` keeps it running for manual inspection. Set `PYTHONDONTWRITEBYTECODE=1` if you want no
`__pycache__` directories in the tree (the repo has no `.gitignore` on purpose).

## Troubleshooting

* **Docker badge red / builds fail with "docker: not found" or "cannot connect".** Start Docker Desktop (the
  server does it on Windows when `docker.start_desktop` is true), switch it to Linux containers, and check
  `docker info`. Set `docker.binary` if `docker` is not on `PATH`.
* **arm64 builds fail with `exec format error`.** The arm64 binfmt handler is missing. The server tries
  `docker run --rm --privileged tonistiigi/binfmt --install arm64` itself; run it by hand if that fails.
  Docker Desktop can lose the registration after a restart. On Linux, installing `qemu-user-static` / `binfmt-support` also works.
* **Chrome's chooser is empty / "Access denied" on Windows.** The device is not bound to WinUSB. Install
  `rpiboot_setup.exe` (see Requirements) and replug. Check the *USB driver* badge or `usb_driver` in
  `/api/status`. If a libusb-win32/libusbK driver grabbed the device, rebind it, for example with Zadig or
  `wdi-simple.exe -t 0 -v 0x0a5c -p 0x2712` (or `-v 0x18d1 -p 0x4e40`).
* **Chrome asks again for every board.** WebUSB permissions are per device. The boot ROM, the second stage and
  the fastboot gadget (different USB id and serial) are separate devices, so a new board needs the chooser for
  each. When the page cannot find the re-enumerated board, it shows **Select device**.
* **"… is still being prepared" / HTTP 409 on a stage.** A build (tools, gadget, image, or a per-board signing
  run) is still in progress. The page polls every 3 s and links the job log, so just wait. A failed job shows its error. Fix
  it and click Rebuild, or run `python -m otp_server build <target> --force` to see the whole log in the terminal.
  Starting a build that is already running returns the running job.
* **"board OTP is locked to a different key".** The board was locked with a key this registry does not hold (another
  station, or a lost registry). Nothing can be provisioned. Restore the registry record that holds its key.
* **Storage badge red / 503 from module endpoints.** Read the detail in `/api/status` (for example: the sheet is not
  shared with `client_email`, the OAuth token was rejected, or the credentials file is missing). For "not logged
  in" or a rejected OAuth token, run `python -m otp_server login`. On Drive, 403 `storageQuotaExceeded` means a
  service account is writing into a My Drive folder: use a Shared Drive or `auth: oauth`.
* **HTTP 403 "Host … is not allowed" / "cross-site POST rejected".** Open the page at `http://127.0.0.1:<port>/`
  (or the configured `server.host`), not through another DNS name or from another site.
* **Stage 1 refused: "customer_key_hash … does not match its RSA key".** The registry record is inconsistent.
  Restore the record (key and hash together) from a backup; do not burn anything until it matches.
* **Port 8765 in use.** Another program holds it (exit code 2). Use `--port`.
* **The board does not show up in RPIBOOT.** Hold the power button while plugging USB-C, and use a different cable or port.
  Close `rpiboot.exe` and other tabs.

## References

* WebUSB: https://wicg.github.io/webusb/
* usbboot (rpiboot, secure-boot recovery, `rpi-eeprom` tools): https://github.com/raspberrypi/usbboot
* rpi-eeprom: https://github.com/raspberrypi/rpi-eeprom
* rpi-sb-provisioner (reference provisioning station): https://github.com/raspberrypi/rpi-sb-provisioner
* pi-gen-micro (fastboot gadget): https://github.com/raspberrypi/pi-gen-micro
* rpi-fastbootd: https://github.com/raspberrypi/rpi-fastbootd
* rpi-image-gen (image build, IDP): https://github.com/raspberrypi/rpi-image-gen
* fastboot protocol: https://android.googlesource.com/platform/system/core/+/main/fastboot/README.md
* Android sparse format: https://android.googlesource.com/platform/system/core/+/main/libsparse/
* gspread authentication: https://docs.gspread.org/en/latest/oauth2.html
* Google Drive API v3: https://developers.google.com/workspace/drive/api/guides/about-sdk
