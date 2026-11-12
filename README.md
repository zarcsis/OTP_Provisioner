# OTP_Provisioner

A demo provisioning station for Raspberry Pi 5 boards (BCM2712: Pi 5, CM5, Pi 500) and Compute Module 4
modules (BCM2711; see "Compute Module 4"). A small Python server (FastAPI) keeps the secrets of every board,
builds all the files a board needs (in Docker), and serves a web page. The page runs in Chrome or Edge and
drives the board over **WebUSB**: it speaks the `rpiboot` protocol to the boot ROM and `fastboot` to the
provisioning gadget.

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
| Stage 3 · Image | Raspberry Pi OS Lite, clear (`IGconf_image_pmap=clear`), nothing written to OTP; the boot partition carries the board's first-boot files | the OTP device key is generated (if blank) and **exported to the server**; the **server builds the board's LUKS2 container** holding the root file system (`IGconf_image_pmap=crypt` image, keyslot 0 = the board's key) and the board writes that ciphertext raw, then proves its key opens it (`oem cryptcheck`, nothing is decrypted on the board); the boot partition carries the board's first-boot files and is re-signed per board, with `lock_device_private_key=1` in the signed `config.txt` (the running OS cannot read the OTP key) |

In every scenario a board goes through the same three stages:

| Stage | What the board does | Files come from | Registry stage after success |
| --- | --- | --- | --- |
| 1 · EEPROM & OTP | Boots `bootcode5.bin` (recovery; `bootcode4.bin` on a CM4) over rpiboot and flashes `pieeprom.bin` + `.sig`. It reports metadata (MAC, DUID, `CUSTOMER_KEY_HASH`, board type, …) and reboots straight back into RPIBOOT (`recovery_reboot=1`; a Pi 5 through `set_reboot_order=0x3`, a CM4 through its nRPIBOOT jumper). | `external/usbboot/rpi-eeprom` firmware (`firmware-2712` / `firmware-2711`), packed by `docker/scripts/stage1.sh` | `eeprom` |
| 2 · Fastboot gadget | Boots `bootfiles.bin` + `boot.img` (pi-gen-micro "fastboot" ramdisk with our build of rpi-fastbootd and our `otp-keyexport` helper). The board re-enumerates as USB `18d1:4e40` with its 16-hex serial. | gadget built from `external/pi-gen-micro` + `docker/gadget-helpers` + `docker/fastbootd` | `gadget` |
| 3 · Image | Page drives rpi-fastbootd: (secure) device key export → stage-3 manifest again (the server encrypts the root for the board) → `oem fwcrypto init` → `getvar:public-key` → `erase` → IDP (`oem idpinit` / `idpwrite` / `idpgetblk` + `flash` of sparse pieces ≤ 256 MiB / (secure) `oem cryptcheck` / `idpdone`) → `shutdown` (the board powers off). | the OS image: rpi-image-gen (`image/`) with the station's **OS image** settings, built in Docker in both variants; or an operator's own image uploaded on the page (see "Custom OS images") | `flashed` |

A board whose OTP is locked to its key can also be flashed **without the station**: its card gets an image
file the station assembles for that board and card (signed boot partition, encrypted root), written with
Raspberry Pi Imager (see "The image file for Raspberry Pi Imager").

Status: both scenarios have provisioned a real Pi 5 end to end (stages 1-3, board `ebbdf4fd`, 2026-10-06):
the open one with Wi-Fi, account and SSH set up at first boot, and the secure one with the signed boot
chain, the locked OTP, the exported device key, the station-built encrypted root (`oem cryptcheck` →
keyslot 0) and the power-off at the end. The notes on what the first secure run needed are in CLAUDE.md
("What went wrong"). The sandboxed apps ran from the station image on a second Pi 5 (board `2a03e58f`, open
scenario, 2026-10-28): the demo detector in its container, the provider counting its detections, the sandbox
probe 23 PASS / 0 FAIL (see "Checking a board" under "System packages and sandboxed apps"). Compute Module 4
support (2026-11-09) is checked without a module (the suites, real builds of every artifact, the end-to-end run on a
mock CM4); it has not been on a real module yet (see "Compute
Module 4" for what a first run must confirm).

## Requirements

* **Chrome or Edge** (any Chromium browser with WebUSB). Firefox and Safari have no WebUSB.
* **[uv](https://docs.astral.sh/uv/getting-started/installation/)** (Windows: `winget install --id=astral-sh.uv -e`,
  Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`). The first `uv run` brings the Python of
  `.python-version` (3.15, its newest patch release; the code needs 3.11+) and the packages pinned in `uv.lock`
  into `.venv`. The Python is uv's own build (`python-preference = "only-managed"`, kept in uv's directory, not in
  the repository): a system Python is neither needed nor used, and nothing is installed into one.
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
  gadget and image builds run in `linux/arm64` containers. The server registers the arm64 binfmt handler
  when it is missing (see Troubleshooting). The builds need internet access. **macOS** on Apple Silicon works too
  (first run 2026-11-10, with OrbStack): the engine is arm64 and runs the builds natively, without qemu, and the
  browser needs no driver. The work dir is `~/.local/share/otp-provisioner` (or `$XDG_DATA_HOME/otp-provisioner`).
* **USB driver on Windows:** Chrome can only open devices bound to WinUSB. Install the official
  `rpiboot_setup.exe` (from the [usbboot releases](https://github.com/raspberrypi/usbboot/releases)).
  It binds WinUSB to `0a5c:2712` (BCM2712 boot ROM), `0a5c:2711` (BCM2711 boot ROM, a Compute Module 4) and
  `18d1:4e40` (the fastboot gadget). `rpiboot.exe` itself is not needed. The page header shows whether the driver
  packages are present (the status detail says whether the CM4 one is).
* **Linux:** give your user access to the devices, for example `/etc/udev/rules.d/99-otp-provisioner.rules`:

  ```
  SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", TAG+="uaccess"
  SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2711", MODE="0660", TAG+="uaccess"
  SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e40", MODE="0660", TAG+="uaccess"
  ```

  then `sudo udevadm control --reload && sudo udevadm trigger`.
* **Submodules** of this repo: `git submodule update --init --recursive` (usbboot with its nested
  rpi-eeprom, pi-gen-micro, rpi-image-gen).

## Quick start

```
git clone <this repo> OTP_Provisioner
cd OTP_Provisioner
git submodule update --init --recursive
# put google-oauth-client.json (Desktop app OAuth client) into the repository root
uv run server.py
```

`uv run server.py` serves `http://127.0.0.1:8765/` and opens the page in Chrome (Edge if Chrome is missing,
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
2. **gadget**: the pi-gen-micro fastboot ramdisk plus our helper packages and our rpi-fastbootd, built in an
   arm64 container (about 3 minutes; the first build of the builder image also compiles rpi-fastbootd, about
   7 more). Stage 2 answers "not ready" until it exists — there is no prebuilt fallback, because only this
   gadget carries the device key export and the restricted rpi-fastbootd (see "The station's rpi-fastbootd").
   One gadget boots every family its targets name (`builds.gadget.targets`, default `pi5-family,cm4`).
3. **image**: the OS image in both variants, `clear` (open scenario) and `crypt` (secure scenario), for each
   board family in `builds.image.families` (default `pi5` and `cm4`: four images), about twelve minutes each (the
   first build in a new work volume takes longer). rpi-image-gen runs in the
   builder image from `image/docker` and builds Raspberry Pi OS Lite (see below); each
   result is collected into an IDP set of sparse pieces ≤ `max_piece_size` with SHA-256 for each piece.
   Stage 3 answers "not ready" until the variant the board needs is there. A station that never sees a CM4 can
   drop `cm4` from `builds.image.families` and save two builds.

On Windows, if the Docker engine is not running, the server starts Docker Desktop and waits for it (up to 180 s).

Build rules worth knowing:

* **Rebuild triggers.** The gadget key is `<pi-gen-micro commit>-<hash of docker/gadget.Dockerfile,
  gadget-entrypoint.sh and every file under docker/gadget-helpers and docker/fastbootd>-<targets>`, so editing
  any of them makes the gadget "not built". An image set is reported as `rebuild needed: …` (status not ready, stage 3 409)
  when it was built from another rpi-image-gen revision than the one checked out now (`git describe --tags
  --always --dirty` of `image/rpi-image-gen`), with another image name (`image.name`),
  `builds.image.overrides` or station image sources (`image/build.sh`, `image/docker/`, `image/layer/`), as
  another variant, or split with a larger `max_piece_size` than the current setting. The other `image.*`
  settings are not in the image (stage 3 writes them to each board), so saving them rebuilds nothing; a new
  image name starts the rebuild at once (with `builds.auto`), and a name saved while a build runs is picked
  up by the same job, which builds the stale variant again. The stage-1 identity includes the sha256 of the
  selected `pieeprom-*.bin` and `recovery.bin` and the content of `rpi-eeprom-config`, `rpi-eeprom-digest`,
  `rpi-sign-bootcode` and `update-pieeprom.sh`, so a firmware or usbboot submodule update rebuilds stage 1
  (a quick build, about a minute) even when names and sizes stay the same. `builds.auto` rebuilds all of these.
* **Forced rebuilds never replace the served build in place.** A forced gadget build goes to
  `<key>-r2`, `-r3`, …; the newest complete version is served and older ones are kept (they are never pruned,
  so disk use grows with forced rebuilds).
* **One heavy build at a time, across processes.** Gadget and image builds take `<work>/tmp/heavy.lock`.
  `uv run -m otp_server build …` started while the server builds waits ("waiting for another image/gadget
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
<work>/artifacts/image/current-clear.json, current-crypt.json   which set stage 3 serves per variant (Pi 5)
<work>/artifacts/image/current-cm4-clear.json, current-cm4-crypt.json   … and for the Compute Module 4
<work>/artifacts/image-json/           a custom set's image.json with another family's device class (a CM4's)
<work>/artifacts/custom/<id>/          an uploaded image: source.img, upload.json, its clear and crypt sets
                                       (<variant>-<fingerprint>/), current-<variant>.json, error-<variant>.json
<work>/modules/<serial>/stage{1,2}/<fp>/    per-board signed files (secure scenario only)
<work>/modules/<serial>/stage3/<fp>/   the board's boot partition (first-boot files; re-signed on secure boards)
<work>/modules/<serial>/luks/<fp>/     secure: the board's LUKS2 container (root.luks.sparse.N) + its image.json
<work>/jobs/<id>.log                   build logs
<work>/tmp/keys-<id>/ + keys-<id>.lock  short-lived key / first-boot files (deleted after use, swept at start)
<work>/tmp/heavy.lock                  cross-process lock for gadget/image builds
```

Docker volumes `otp-pgm-work` and `otp-image-work` keep the build trees and apt caches between runs
(`otp-droneos-work`, left by earlier versions, is no longer used: `docker volume rm otp-droneos-work`).

## The OS image

The image is **Raspberry Pi OS Lite** (trixie, arm64) built with rpi-image-gen, one for the Raspberry Pi 5 and
one for the Compute Module 4 (the same layers on another device layer and kernel; see "Compute Module 4"), and
it is the same for every board of a family. Like the official image it comes up with the first user `pi` locked, SSH
off and Wi-Fi off; what makes a board yours is written at stage 3 into **its own boot partition** as
cloud-init files, the way Raspberry Pi Imager customises Raspberry Pi OS. So the settings below apply to
every board flashed after they are saved, with no rebuild; boards provisioned earlier keep what they got.

The settings are in the **OS image** panel of the page and in the `image.*` rows of the `settings`
worksheet. Open and secure boards get the same settings.

| Field | Setting | On the board |
| --- | --- | --- |
| Hostname | `image.hostname` (`{family}-{serial}`) | host name and `/etc/hosts`; `{serial}` is the board's 8-hex serial, `{family}` its family (`pi5`, `cm4`); avahi announces `<name>.local` |
| Time zone (a list) | `image.timezone` (`Europe/Kyiv`) | `/etc/localtime`, `/etc/timezone` |
| Keyboard (a list) | `image.keyboard` (`us`) | `/etc/default/keyboard`: the console layout the password is typed with. Raspberry Pi OS itself defaults to `gb`, where Shift+2 gives `"` and Shift+' gives `@` |
| User, password | `image.user` (`pi`), `image.password_hash` | Raspberry Pi OS renames its first user `pi` to this name (userconf) and sets the password; it is in the `sudo` group and `sudo` asks for the password |
| SSH server, password login, authorized keys | `image.ssh` (off), `image.ssh_password_login` (on), `image.ssh_authorized_keys` | `ssh` enabled at first boot (an empty `ssh` file in the boot partition, plus the first-boot block), `~/.ssh/authorized_keys`; password login off = keys only |
| Wi-Fi network, password, country (a list), hidden | `image.wifi_ssid`, `image.wifi_password`, `image.wifi_country` (`UA`), `image.wifi_hidden` | a netplan network that NetworkManager runs (WPA-PSK as a PMK, DHCP), the regulatory domain; the Wi-Fi radio is switched on at first boot (`raspi-config nonint do_wifi_country`, in the first-boot block) |
| Image name | `image.name` (`rpios-trixie-arm64-lite`) | the name of the image sets; **the only setting that rebuilds the image** |

* **The first-boot files** (`otp_server/firstboot.py`) are Imager's `cloudinit-rpi` files: `user-data`
  (`#cloud-config`: host name, time zone, keyboard, the `user:` section, `ssh_pwauth`, `bootcmd`), `network-config`
  (netplan v2, only with a Wi-Fi network), `meta-data` (`instance-id: otp-<serial>-<hash>`) and, with SSH on,
  an empty `ssh` file (Raspberry Pi OS's `sshswitch.service` enables SSH when it finds it), plus
  Imager's kernel parameters in `cmdline.txt`: `cfg80211.ieee80211_regdom=<country>` and
  `ds=nocloud;i=<instance>`. On a secure board the boot partition holds the signed `boot.img`, so the
  parameters go into that `boot.img` (re-signed for the board anyway) and the three files next to it, where
  the OS reads them (`/boot/firmware`). They are plain files on a FAT partition on every board, so the
  account hash and the Wi-Fi PMK on the boot partition are readable to whoever has the SD card (the root
  file system of a secure board is encrypted; its boot partition is not).
* **A first boot cut short does no harm.** What Imager puts in `runcmd` (SSH on, password-less `sudo` for a
  key-only account, the Wi-Fi radio on) is one `bootcmd` block instead. `bootcmd` runs at the start of every
  boot (in the init-local stage here, before NetworkManager starts); the block does its work, `sync`s and only
  then writes its marker (`/var/lib/cloud/instance/otp-firstboot.done`), so it runs until it has completed
  once. cloud-init's own per-instance markers are not enough: a board unplugged during its first boot
  (2026-10-06, ebbdf4fd) kept them as empty files with their work lost, and cloud-init then marked its user
  scripts done on a boot that had no user-data, so `runcmd` never ran and the board came up without Wi-Fi
  and SSH. The station also ends stage 3 by powering the board off (below), so that first boot runs on the
  board's own power supply.
* **No account.** With no password and no SSH key there is no `user:` section: the first boot stops at the
  Raspberry Pi OS wizard on the board's console (screen and keyboard), as on an image nobody customised.
  The page warns about it. An account with SSH keys but no password gets password-less `sudo`.
* **Lists.** Time zone, Wi-Fi country and keyboard are picked from lists taken from the Debian trixie
  packages the image installs (`otp_server/image_choices.json`): the zones of `tzdata` (grouped by region,
  with the current UTC offset; legacy names such as `Europe/Kiev` live in `tzdata-legacy`, which the image
  does not have), the countries of `wireless-regdb` (`00` = world), named from `iso-codes`, and the layouts
  of `xkb-data`. The server accepts
  only values from these lists; `uv run -m otp_server.image_choices` regenerates the file (its docstring
  has the commands).
* **Passwords.** The account password is stored only as a SHA-512 crypt hash (`$6$…`, made by the server
  when you save it). The Wi-Fi password is stored as typed (8-63 characters, or a 64-digit hex key; empty =
  an open network) and written to the board as the PMK. Both passwords are write-only on the page: it
  shows whether one is set, **remove** clears it.
* **What the image is.** `image/layer` holds the station layers. `otp-rpios-packages` is the package set
  of an official Raspberry Pi OS Lite release, generated from the release's `.info` file by
  `python image/rpios_packages.py <url or path of the .info>`, without the kernels: the generator puts the
  kernel metapackages of each flavour into `otp-rpios-kernel-2712` (Pi 5) and `otp-rpios-kernel-v8` (CM4), and an
  image gets its family's. It also leaves out libcamera's soname package (`libcamera0.7` …): Raspberry Pi's archive
  moves libcamera between image releases (0.8 on 2026-11-04), the release's soname package then cannot be installed,
  and `libcamera-ipa` / `rpicam-apps` pull the current one. `otp-rpios-lite` puts it on rpi-image-gen's Debian and Raspberry Pi base and keeps the
  manual pages and documentation the official image has. `otp-rpios-setup` does what pi-gen configures
  beyond packages: `pi` locked with no login shell (cloud-init or the wizard set it up), SSH off and host
  keys made at first boot, Wi-Fi off until a country is set (`WirelessEnabled=false`), Bluetooth not
  blocked, classic interface names (`eth0`, `wlan0`), en_GB / gb / Europe/London, `raspberrypi`, pi-gen's
  shell and `PATH` tweaks, avahi, `/etc/machine-id` = `uninitialized`, the NoCloud templates in
  `/boot/firmware`, and no `apt`/`dpkg` leftovers of the build (recommends are installed again, as on
  Raspberry Pi OS). The differences from the official image: one kernel (the family's), `cryptsetup` added (the
  secure image), the boot partition layout and `config.txt` of rpi-image-gen's IDP image, **AppArmor on**
  (`apparmor=1 security=apparmor` in `cmdline.txt` from the fragment
  `layer/otp-rpios-setup.d/for/linux-base/cmdline.d/60-apparmor`, `apparmor.service` enabled: the Raspberry
  Pi kernel has AppArmor built in but selects no LSM by default, so Raspberry Pi OS ships the package with it
  off; `aa-status` on a board lists the loaded profiles), and on the
  **secure** (crypt) image `rpi-eeprom-update.service` is off (that bootloader is signed for the board,
  and only the station updates it), and the encrypted root grows to the whole card at the first boot: the
  initramfs script `otp-growpart` grows its partition **before** cryptroot opens the container (a card written
  from the Imager file is larger than the file), so the LUKS2 mapping opens at the partition's full size, and
  `otp-growroot.service` then grows the ext4 inside. `rpi-resize` is masked there. The mapping is never resized
  later: `cryptsetup resize` of a LUKS2 mapping whose key sits in the kernel keyring asks for the passphrase even
  when there is nothing to do, and after the unlock the initramfs locks the firmware HMAC the keyscript needs
  (`rpi-fw-crypto set-key-status 1 HMAC_LOCKED`, rpi-image-gen's `hwlock`; until the next boot).
* **How it is built.** The server writes `otp-image.yaml` (an rpi-image-gen config: the family's device layer,
  `rpi5` or `rpi-cm4`, the `image-rpios` layout, the image name, the station layers with the family's kernel layer
  and `luks2_cipher: aes-xts-plain64`) and mounts it read-only at `/cfg` for the build. `image/example.yaml` and
  `image/example-cm4.yaml` are that config for the default name (a test keeps them in sync).
* **Building by hand** (Linux with Docker): `image/build.sh --docker -c image/example.yaml` or your own
  config; `image/build.sh --help` lists the options. `IGconf_*=value` words after the options are passed to
  rpi-image-gen; `builds.image.overrides` does the same for the station.

## Custom OS images

Instead of the station's Raspberry Pi OS Lite, stage 3 can write **an image of your own**: in the **OS image**
panel, **Upload .img…** sends a raw disk image to the station (the same file you would flash with Raspberry Pi
Imager), the station prepares it, and the **Image** list chooses what stage 3 writes (`image.custom` = the
image's id; empty = the station image). Save applies it to the boards flashed from then on.

**What the station takes:** an uncompressed `.img` (unpack `.img.xz` / `.zip` first) with an MBR and exactly
two primary partitions, a FAT boot partition (0x0c, 0x0b, 0x0e or 0x06) and an ext4 root (0x83), with a
Raspberry Pi 5 kernel (`kernel_2712.img` or `kernel8.img`), `config.txt` and `cmdline.txt` in the boot
partition: what Raspberry Pi OS and pi-gen produce (bookworm or later). The same prepared image also serves a
Compute Module 4 when its boot partition has `kernel8.img` and the BCM2711 firmware (see "Compute Module 4"). The upload is checked as it arrives
(`otp_server/diskimage.py`: compressed files, GPT, partition count and types, file systems, a truncated upload)
and stored under the first 16 hex digits of its SHA-256; the same file uploaded twice is kept once. Uploads stay
on this station's disk (`<work>/artifacts/custom/`), only the choice is a setting.

**Preparation** (a job per image, `docker/scripts/custom-image.sh` in the tools image, `--privileged`), one set
per scenario:

* **open** (`clear`): the image as it is. The boot partition is copied whole; the root file system becomes a
  sparse image in which **only the blocks the ext4 allocation bitmaps mark free are left out**
  (`docker/scripts/ext4_sparse.py`; a block in use is always written, even when it is all zeros, because a free
  block may hold anything on the card and a used one may not). The image's own disk identifier, partition sizes
  and first-partition offset are kept, so `PARTUUID=` entries in its `fstab` and `cmdline.txt` keep working;
  nothing is grown (the image's own first-boot resizer, if it has one, does that). About a minute for a 6 GB image.
* **secure** (`crypt`): a copy of the image that **unlocks a LUKS2 root with the board's OTP key at every boot**,
  installed into the image itself (an arm64 chroot under QEMU, packages from the image's own apt sources, so the
  station needs internet access and the image's sources must offer `cryptsetup-initramfs` (Debian) and
  `rpifwcrypto` (archive.raspberrypi.com)): the keyscript `otp-hwkey` (the same derivation as rpi-image-gen's
  `hwkey`: `HMAC(OTP key, SD CID + "\n")` by `rpi-fw-crypto`, the CID read from sysfs because
  `block-device-id` is not packaged for bookworm, and handed over in a file under `/run` because bookworm's
  `rpi-fw-crypto` cannot read a pipe), an initramfs hook that adds `rpi-fw-crypto` and the
  dm-crypt / crypto modules, `/etc/crypttab` (`cryptroot UUID=<the set's LUKS UUID> none
  luks,initramfs,keyscript=…`), the root in `/etc/fstab` and in `cmdline.txt` on `/dev/mapper/cryptroot`
  (`init=…/firstboot` removed), `auto_initramfs=1` when `config.txt` loads no initramfs,
  `otp-growroot.service`, the initramfs scripts `otp-growpart` (grows the root partition before cryptroot opens
  it; its hook adds `sfdisk`, `blkid`, `partx`) and `otp-hwlock` (locks the firmware HMAC after the unlock,
  as the station image does), `rpi-eeprom-update.service` and `rpi-resize.service` masked; then
  `update-initramfs -u -k all` (with
  `MODULES=most` for that run only: `dep` would guess the modules of the build container). The result is
  checked (every initramfs on the boot partition has the keyscript, `rpi-fw-crypto`, the crypttab with that UUID
  and the modules) and the root file system must pass `e2fsck`. The files the image had in `/boot/firmware`
  stay there. About ten minutes. Stage 3 then encrypts the root for each board exactly like the station image's.

**At stage 3** the board gets the image's boot partition as it is when the image has no cloud-init (the station
cannot write the account, SSH, Wi-Fi and host name settings into such an image: it boots with the configuration
it was made with, and the page says so); an image with cloud-init gets the first-boot files like the station
image. On a board locked to our key the image's own boot partition gets `boot.img` (its files, without what a
Raspberry Pi 5 (or a CM4) never loads, and its `config.txt` with `lock_device_private_key=1` added), `boot.sig` and the
`config.txt` that makes the bootloader load it; everything else the image keeps there stays (`boot-slot.sh` with
`INPLACE=1`). Software in the image that reads the raw OTP key (`rpi-fw-crypto privkey`, `rpi-otp-private-key`)
gets an error on a secure board; `hmac` and `sign` work. `boot.img` must stay under the bootloader's
ramdisk limit (128 MiB).

Worth knowing about a secure board with any image: the bootloader boots the signed `boot.img`, so changes the
running system makes in `/boot/firmware` (`cmdline.txt`, `config.txt`, a new kernel or initramfs) have no
effect until the board is provisioned again.

The panel lists every uploaded image with its state per scenario and the job log; **Prepare again** forces a new
preparation, **Delete** removes the image and its sets (not the one stage 3 writes). A changed preparation
script or tools image marks the sets stale; with `builds.auto` the chosen image is prepared again (a failed
preparation is not retried by itself: fix the cause and click Prepare). Disk use: the upload plus about its
used size per set, plus each secure board's container.

## System packages and sandboxed apps

The station image can carry Debian packages of your own, of two kinds, chosen under **Applications** in the
**OS image** panel. Both are built into the image (a change rebuilds it); custom images (`image.custom`) do not
get them.

* A **system package** (`image.packages`) is trusted: rpi-image-gen installs it like the image's own packages
  (`packages:` with the `.deb` from the config dir; apt resolves its dependencies from the image's sources), its
  maintainer scripts run in the image build and its services run as whatever they ask for, root included. A
  system package may **offer permissions to apps**: a JSON file in `/usr/share/vn-apps/permissions/` says which
  D-Bus method calls each permission lets through.
* An **app** (`image.apps`) is any ordinary package: its own dependencies, systemd units, users, maintainer
  scripts. Nothing in it is restricted; it runs **sandboxed** instead, like an Android app: one container per app,
  isolated from the host and from every other app.

**Upload** with **Upload system package…** / **Upload app…** (an arm64 or `all` `.deb`; gzip, xz or, with Python
3.14+, zstd). The station reads its metadata only (`otp_server/debpkg.py`) and keeps it under the first 16 hex
digits of its SHA-256 in `<work>/artifacts/packages/`. Tick **in the image** to put it in. For an app, tick the
**permissions** it gets (those the system packages in the image offer; the ones the package asks for in an
optional `X-Sandbox-Permissions` control field are marked *requested*, nothing is granted by itself) and set its
limits (memory, CPUs, tasks); **Sandbox** shows the files the board will get for it. **Save** (in the header of
the OS image panel): the ticks are only a draft until then, although the row says *in the image* at once.
**Rebuild** under Server builds builds the *saved* settings and ignores the draft: ticking and then rebuilding
makes the same image again, without the packages (this happened on 2026-10-28, see "Checking a board"). Saving
a change of packages starts the rebuild by itself (`builds.auto`).

**An app is installed on the station, before the image is built** (a job per app, the `otp-app-builder` image,
`docker/apps.Dockerfile`; the image build prepares any app that is not prepared yet):

1. `app-vmkit.sh` (once): the installer VM's kernel and initramfs, Debian trixie's arm64 kernel with the modules a
   virtio disk with ext4 needs, and busybox (downloaded with apt, signatures checked).
2. `app-rootfs.sh` (privileged, network): Debian trixie arm64, minbase + systemd, plus the app's `Pre-Depends` and
   `Depends` from Debian (`apt-get satisfy`): only Debian's own maintainer scripts run here. The result is an
   ext4 disk image with the app's `.deb` in `/vn-install`.
3. `app-install.sh` (no network, no capabilities, `no-new-privileges`): `qemu-system-aarch64` (TCG, no KVM) boots
   that kit with two disks and nothing else; its `/init` (`app-vm-init`) runs `dpkg -i` in a chroot of the disk,
   so **the app's maintainer scripts run only inside this throwaway VM**, then writes the root file system as a
   tar archive to the second disk and powers off. About 20 s for the demo app.
4. `otp_server/rootfs_tar.py` reads that archive as untrusted and writes the prepared `rootfs.tar`: normalised
   names, no `..`, no member twice, nothing below a symbolic link, no device nodes, nothing below `dev/`,
   `proc/`, `sys/`, owners 0..65535 only, set-ID bits kept (they only switch between the app's own users),
   file capabilities rewritten as namespaced (v3) ones and every other extended attribute dropped.

**On the board** (layer `otp-apps`, files from `otp_server/sandbox.py`), app *N* (its slot, 1..64) gets:

* host UIDs/GIDs `0x100000 + N·65536` .. `+65535`: its container's 0..65535 (root included) are those, so
  nothing in it is root on the host. The base UID is the user `vnapp<N>`, member of `vnapps`;
* `/var/lib/vn-apps/vn-app-<package>/rootfs` (the parent `/var/lib/vn-apps` is `0711`, the app's directory `0700`
  for its base UID): its root file system, owners already moved into its range at image build time; it keeps
  its state there across boots;
* a rootful podman container (quadlet `/etc/containers/systemd/vn-app-<package>.container`, `Rootfs=`, systemd as
  init, so the package's units start as it enabled them): `Network=none`, its own AppArmor profile
  (`/etc/apparmor.d/vn-app-<package>`: podman's default plus mount and user namespaces for systemd, minus IP and
  packet sockets), CAP_SYS_ADMIN valid in its own user namespace only (systemd sandboxes the package's services),
  no devices (no `/dev/vcio`, so no firmware HMAC and no LUKS key), its own PID, IPC and mount namespaces,
  `MemoryMax`, `CPUQuota`, `TasksMax` in `vnapps.slice`;
* the system bus only through **its own xdg-dbus-proxy** (`vn-app-<package>-bus.service`, as `vnapp<N>`,
  `--filter` with one `--call=` rule per granted method), mounted at `/run/dbus` in the container: the app sees
  only the names it may call, owns none, and the services see the proxy's UID, i.e. the app's;
* an entry in `/etc/vn-apps/registry.json` (UID → app, version, permissions) for the trusted services to check
  every caller a second time.

The image also gets podman, crun, conmon, catatonit and xdg-dbus-proxy, and `cgroup_enable=memory` on the kernel
command line (the Raspberry Pi kernel disables the memory cgroup by default, the limits need it; the fragment
`layer/otp-apps.d/for/linux-base/cmdline.d/60-memcg`).

**What an app cannot do there, by design:** anything that needs the board's hardware, the network, the host's
configuration (udev, kernel modules, `cmdline.txt`), or another app. Its postinst sees an ordinary arm64 VM, not
the board: no serial number, no network; device-specific setup belongs in the service's start. While it is
installed, systemd does not run, so units are enabled but not started (as in any image build).

**The demo** (`examples/apps`, built with `uv run python -B examples/apps/build.py`: standard library only, the `.deb`
files land in `<temp>/otp-example-debs`):

* `vn-demo-provider` (system package): a synthetic camera, a bright blob moving over a gradient, 320×240 grey at
  30 Hz, in a sealed memfd ring (camhub's seqlock layout in miniature). D-Bus `io.github.DetectInt.Demo`:
  `GetFrameHandle() -> h` hands out a read-only descriptor (O_RDONLY, the memfd 0444, `F_SEAL_FUTURE_WRITE`),
  `ReportDetection(t frame, i x, i y, d score) -> b` scores a detection against the true position. It offers
  `demo.frames.read` and `demo.detections.report`, checks callers by UID against the registry and logs every
  app's detections and error.
* `vn-demo-detector` (app): finds the blob five times a second and reports it; a second unit checks once at
  start what its sandbox lets through (`podman exec vn-app-vn-demo-detector journalctl -u
  vn-demo-detector-probe`).

Upload both, put the provider and the detector in the image, grant the detector both permissions, save; the
image is rebuilt. On a board flashed from it: `journalctl -u vn-demo-provider` shows `vn-demo-detector (uid
1114112): 25 detections in 5 s, mean error 0.0 px`.

**Checking a build.** The settings sheet has `image.packages = <provider id>` and `image.apps = <detector id>
slot=1 grant=demo.detections.report,demo.frames.read`. The image job's log prints the generated `otp-image.yaml`:
it must have `apps: otp-apps` under `layer:`, an `otpapps:` block and the provider under `packages:`, followed by
`files next to it: apps/apps.list, apps/sandbox.tar`. The config dir of that job,
`<work>/artifacts/image/cfg/<job>-clear/`, holds `system/<provider>.deb`, `apps/vn-app-<package>.tar` (the app's
root file system, owners inside its slot's range), `apps/apps.list` and `apps/sandbox.tar` (the quadlet, the
bus proxy unit, the AppArmor profile, `registry.json`, sysusers and tmpfiles). The packages are part of the set's
digest, so a set with them has a new name: the demo's went from `trixie-arm64-clear-v2.9.0-94cf9a12` to
`…-98769f76`. The old name (or a `-r<N>` of it) means a set built without them.

**Checking a board** (over SSH; `sudo` for the lines that need root). What the demo board `2a03e58f` showed on
2026-10-28, which is what a good board shows:

| Check | Expected |
| --- | --- |
| `systemctl list-units --all 'vn*'`, `systemctl --failed` | `vn-demo-provider`, `vn-app-vn-demo-detector`, `vn-app-vn-demo-detector-bus` active (running), `vnapps.slice` active; nothing failed |
| `tr ' ' '\n' < /proc/cmdline \| grep cgroup`, `cat /sys/fs/cgroup/cgroup.controllers` | `cgroup_enable=memory` after the firmware's `cgroup_disable=memory`; `memory` among the controllers |
| `dpkg-query -W vn-demo-provider podman crun xdg-dbus-proxy` | all installed |
| `journalctl -u vn-demo-provider` | `registry: 1 app(s)`, `frame ring handed out read-only`, then every 5 s `25 detections in 5 s, mean error 0.0 px; … 0 for unknown frames, 0 over the rate limit` |
| `ps -eo uid,label,args \| awk '$1>=1114112 && $1<=1179647'` | the container's systemd and journald as UID 1114112, `detector.py` as another UID of the range, all `vn-app-vn-demo-detector (enforce)`; `xdg-dbus-proxy` as `vnapp1` |
| `cat /sys/fs/cgroup/vnapps.slice/vn-app-vn-demo-detector.service/{memory.max,cpu.max,pids.max}` | `268435456`, `100000 100000`, `512` (the defaults) |
| `sudo podman inspect vn-app-vn-demo-detector --format '{{.HostConfig.NetworkMode}} {{.HostConfig.IDMappings.UIDMap}} {{.AppArmorProfile}}'` | `none [0:1114112:65536] vn-app-vn-demo-detector` |
| `sudo podman exec vn-app-vn-demo-detector systemctl is-system-running` | `running` |
| `sudo podman exec vn-app-vn-demo-detector journalctl -u vn-demo-detector-probe -o cat` | `probe summary: 23 PASS, 2 INFO, 0 FAIL` (the INFO lines: tmpfs mounts and user namespaces are allowed inside its own namespaces) |
| `sudo aa-status` | the profile `vn-app-vn-demo-detector` in enforce mode, the container's processes under it |

As user `pi` (group `adm`) the journal, `ps` and the cgroup files can be read without `sudo`; `/run/vn-apps` and
`/var/lib/vn-apps` cannot be listed (`0711`), as intended. A board with no `vn*` units, no podman and no
`cgroup_enable=memory` was flashed from an image without the packages: check the build as above.

## The image file for Raspberry Pi Imager

A board whose OTP holds its key, whose OTP device key the station holds and whose SD card the station knows
(all three come from one secure stage 1-3 run) can be re-flashed without the station: the board card on the
page has **Image file for Raspberry Pi Imager**. Pick the source (the station image or a custom one), click
**Prepare**, then **Download**. The file is the board's signed boot partition (with the OTP key lock, as at
stage 3) and its root file system
encrypted with its OTP key for **that SD card** (keyslot 0 = `HMAC(OTP key, CID + "\n")`; on another card the
board cannot unlock it), with the partition table of the image set (its disk identifier, the first partition at
the set's alignment); the partitions are laid out as rpi-fastbootd lays out an IDP image. Write it with Raspberry
Pi Imager (*Choose OS → Use custom*, no OS customisation: the boot files are signed, the first-boot files come
from the station) to the board's card in a card reader. At the first boot the initramfs grows the root partition
to the whole card before it opens the container (`otp-growpart`), so the mapping opens at full size, and
`otp-growroot` grows the file system. The file is assembled from the sparse pieces as
it streams (`otp_server/diskimage.py`: nothing is written to disk; gaps read as zeros), so it is the size of the
partitions, mostly ciphertext. Only ciphertext, signed boot files and the first-boot files leave the station,
as in stage 3. The station images need this version's crypt layer for the growth (built after the change).

## Compute Module 4

The station provisions the **Compute Module 4** (BCM2711) next to the Raspberry Pi 5, in both scenarios and the
same three stages. The board's family comes from the boot ROM it reports (`chip` in the registry,
`otp_server/boards.py`); everything below follows from it.

**RPIBOOT mode.** On the CM4 IO Board fit jumper **J2** ("Fit jumper to disable eMMC Boot": nRPIBOOT), connect the
board's USB device port (micro-USB "USB slave") to the station and power the board from its own supply; on another
carrier, whatever pulls nRPIBOOT low and brings the CM4's USB 2.0 OTG port out. Carriers such as the Waveshare
CM4-NANO-B have a **BOOT switch** instead: on, it pulls nRPIBOOT low and routes the CM4's USB to the USB-C port, which
also powers the board; off, the module boots normally. The EEPROM must not be write-protected (EEPROM_nWP). Keep
nRPIBOOT low for all three stages: after stage 1 the module comes back in RPIBOOT because of it (the Pi 5 does it with
`set_reboot_order=0x3`, a BCM2712 feature the CM4 does not get). At the end of stage 3 the gadget shuts the module
down; a BCM2711 halts through a reset, so while nRPIBOOT is low it comes straight back as *BCM2711 Boot* (expected,
the page says so; `POWER_OFF_ON_HALT` does not change it). Remove the jumper (switch BOOT off) and power-cycle: the
module boots its new OS from eMMC (from the SD card on a CM4 Lite).

**Only the CM4.** The Pi 4 Model B, Pi 400 and CM4S have the same boot ROM. The board reports its type in stage 1
(`USER_BOARDREV`); anything but a CM4 (type `0x14`) fails that stage, and every stage is refused for it from then on
(the board card says why). A Pi 4 Model B has no RPIBOOT jumper and powers itself through the USB-C port the gadget
would need.

**Stage 1** uses `firmware-2711` (512 KiB EEPROM images) and serves `recovery.bin` as `bootcode4.bin`, unsigned,
whatever the board's OTP holds: the BCM2711 boot ROM checks only Raspberry Pi's signature (usbboot
`docs/secure-boot.md`, "Pi 4 vs Pi 5"). So nothing is counter-signed, the stage-1 manifest names no recovery
variant, and the page does not watch for a refused second stage. A secure stage 1 that broke off after
`program_pubkey=1` and the whole EEPROM image still makes the station assume the lock: the next run sends a signed
EEPROM without `program_pubkey=1`, and if the board then reports an empty OTP, that run fails and the one after it
burns the key hash.

**The secure scenario on a CM4 is weaker than on a Pi 5:**

* any bootloader signed by Raspberry Pi runs over rpiboot (no customer counter-signature); what stays enforced is the
  signed EEPROM config and `boot.img` verified with the key whose hash is in OTP. The bootloader's anti-rollback
  (`program_arb=1`, recovery.bin 2026-10-23 and later; on a BCM2711 kept in software) is not used by the station;
* `lock_device_private_key=1` is applied by `start4.elf` inside the signed `boot.img`, not by the EEPROM: `boot-slot.sh`
  refuses a CM4 boot partition (and a prebuilt `boot.img`) whose `start4*.elf` does not know the option (Raspberry Pi
  firmware older than 2025-08), since the OS could then read the OTP key;
* the BCM2711 has no AES instructions: rpi-image-gen would pick Adiantum for its LUKS2 container, but the station builds
  every container in `aes-xts-plain64` and sets that cipher in every image config. Left to itself the kernel then
  builds `xts(aes)` from the table-based `aes-arm64`, which is not constant-time (seen on a module); every station
  image, and every prepared custom crypt image, loads the bit-sliced `aes_neon_bs` in its initramfs
  (`scripts/init-top/otp-aes`, only on a CPU without the AES instructions) before cryptroot opens the root, so
  dm-crypt runs the constant-time `xts-aes-neonbs` (about 60-70 MiB/s, slower than a Pi 5);
* the kernel reports the Cortex-A72 vulnerable to Spectre v2 and speculative store bypass: those mitigations need EL3
  firmware, and the Raspberry Pi armstub of a BCM2711 has none (a Pi 5 boots through Arm Trusted Firmware). With
  `builds.image.cm4_tfa` the CM4 images boot through Debian's Arm Trusted Firmware (`arm-trusted-firmware`, platform
  rpi4: `bl31.bin`, `armstub=bl31.bin`, `enable_gic=1`, `enable_uart=1`, `device_tree_address=0x4000000` under
  `[cm4]`; layer `otp-tfa-rpi4`). TF-A edits the device tree in place and uses the 1 MiB after its start as scratch
  space (`fdt_open_into(dtb, dtb, 0x100000)`); without `device_tree_address` the firmware puts the device tree right
  below the initramfs, and TF-A overwrote the initramfs of the crypt image on a module (it booted the open image).
  Off by default until a module has booted the secure image with it (test plan phase 2b on the wiki).

**Stage 2** serves the same gadget: built for `pi5-family,cm4`, it carries the CM4's firmware (`start4cd.elf`,
`fixup4cd.dat`: pi-gen-micro's cut-down firmware for `gpu_mem=16`) and device trees; the kernel (`rpi-v8`) is the same.
`bootfiles.bin` has `2711/bootcode4.bin` as it is and gets `2711/pubkey.bin` next to `2712/pubkey.bin`.

**Stage 3** writes the CM4 image (`cm4-clear` / `cm4-crypt`): rpi-image-gen's `rpi-cm4` device layer with the v8
kernel (4 KiB pages, so ext4 with 4 KiB blocks) and `otp-rpios-kernel-v8`. Its storage is `mmcblk0` (the eMMC, or a
CM4 Lite's SD card); the root key is derived from that device's CID either way. rpi-fastbootd's `oem idpinit` checks
the image's device class against the board's model, so a CM4 gets an `image.json` that says `cm4`: the CM4 image's
own, or for a **custom image** a copy of the set's (`<work>/artifacts/image-json/`). A custom image serves a CM4 when
its boot partition has `kernel8.img`, `start4.elf` and `fixup4.dat` (Raspberry Pi OS images do; `boot-slot.sh` checks
it for every CM4 slot, also an unsigned one), signed in place with `PRUNE=cm4`.

**The image file for Raspberry Pi Imager** of a CM4 Lite goes to the SD card it had at stage 3, in a reader. A CM4
with eMMC cannot take it: the eMMC is only reachable over rpiboot's mass-storage gadget, whose `boot.img` is not
signed with the board's key, and a locked module boots only signed ones (usbboot's `secure-boot-msd` shows how one
could be signed per board; the station does not do it). Run stage 3 again instead.

**Checked without a module** (2026-11-09): the suites and the page self-test; the real `stage1.sh` for both families;
the gadget and all four images built; in the CM4 images a 4 KiB-block ext4, only the v8 kernel, `aes-xts-plain64`, an
initramfs with `dm-crypt`, `aes-neon-bs`, the `hwkey` keyscript and `rpi-fw-crypto`; the real `boot-slot.sh` on them (a
signed CM4 `boot.img` with `kernel8.img`, `initramfs8`, `start4.elf` and the key lock); the end-to-end runner on the real
artifacts with a mock CM4 (scenarios C and D).

**On a real CM4** (`8726622b`, CM4 Rev 1.1, 1 GB, 8 GB eMMC, Waveshare CM4-NANO-B; 2026-11-10/12, the station on
macOS; wiki: *Compute Module 4 test plan*): both scenarios passed. Open (phases 1-2): the first boot, the sandboxed
apps (probe `23 PASS, 2 INFO, 0 FAIL`). Secure (phases 3-4, at `04e4fba`): signed EEPROM and `program_pubkey`, the
signed gadget, the key export through the cut-down `start4cd.elf` (the module already held a key: origin
`existing`), the station-built LUKS2 root with `oem cryptcheck` keyslot 0, an unattended boot with the root
unlocked through the firmware HMAC, `privkey` refused, the root read through `xts-aes-neonbs` at 80 MB/s (raw eMMC
87 MB/s), `poweroff` holding. Phase 5: stage 3 again on the locked module (no second key export), the cable pulled
during stage 3, nRPIBOOT released too early, and an open run of a new Pi 5 (`d49c6c2e`) as the regression. Also
confirmed: the ROM's 8-hex USB serial, the WebUSB timings (the signed gadget's check takes 12.0 s on a CM4, inside
the 12 s pause plus Chrome's ~5 s), `erase` in about 3 s.

**Not confirmed on a real CM4 yet**: Arm Trusted Firmware on the secure image with `device_tree_address` (it booted
the open image, and broke the secure one before that setting); the Imager file's first boot (not possible on an eMMC
module; on an SD card it runs `otp-growpart`, which did its work on a locked Pi 5 on 2026-11-12).

## Operator procedure

1. Pick the scenario in the **Provision** panel: **Open** or **Secure** (the default comes from
   `provisioning.default_mode`; the page remembers your choice).
2. Insert the target **SD card** into the board (a Compute Module 4 with eMMC needs none).
3. **Raspberry Pi 5:** **hold the power button**, connect **USB-C** to the station, release the button. The board
   enumerates as *BCM2712 Boot*. Use a port that can supply enough current. **Compute Module 4:** see "Compute
   Module 4" (nRPIBOOT jumper, the carrier's USB device port); it enumerates as *BCM2711 Boot*.
4. Click **Connect board** and pick *BCM2712 Boot* (or *BCM2711 Boot*) in Chrome's chooser. The page registers the
   board with the server (`hello`). Its secrets are generated now if this serial has never been seen, and are
   reused otherwise.
5. Click **Provision**. The scenario is sent to the server first. Before any irreversible step (OTP writes,
   the device key generation, erase), the page shows what will happen and asks you to type the serial
   (`confirm_irreversible`). Stage 1 runs, the board reboots into RPIBOOT by itself, and stage 2 runs. If
   Chrome needs permission for the re-enumerated device, a **Select device** button appears.
6. When the gadget has booted, click **Connect fastboot gadget** and pick *Raspberry Pi …* in the chooser.
   Chrome's list updates while Linux boots. Stage 3 identifies the board, (secure) exports its device key,
   then flashes the image with a progress bar and **powers the board off** (`shutdown`).
7. Unplug the board and power it from its own supply (a CM4: remove its nRPIBOOT jumper first). Its first boot
   sets it up from the first-boot files (account, SSH, Wi-Fi, host name, time zone, keyboard). The board is not
   rebooted into the new system on the station's USB port on purpose: unplugging it during that first boot is
   what this avoids.

The page skips stages that are already done. Switching a provisioned board to the other scenario resets it
to stage 1: every stage is redone (the EEPROM, the gadget signing and the image all differ). A board whose
OTP holds a key hash only runs signed code, so it is always provisioned in the secure scenario (the Open
switch is disabled for it). A board that already runs the gadget can be connected directly for stage 3.
If the cable is pulled, the page says which stage failed, and **Provision** resumes from there. Only one
program may claim the USB interface: close `rpiboot`, `fastboot` and other tabs of the page.

* **Long silences in stages 1 and 2 are normal.** recovery.bin can stay silent for longer than WinUSB's fixed
  ~5 s transfer timeout while it writes the EEPROM or OTP, and so can the second stage while it checks a signed
  `boot.img` (9-13 s; Chrome reports a timeout as `NetworkError`). After `pieeprom.bin` and after any file of
  1 MiB or more the page therefore asks for nothing for 12 s (`busySettleMs`; a board that leaves USB cuts the
  pause short): rpiboot waits in one request for up to 20 s, and a request Chrome ended after 5 s while the board
  was busy left it out of step on a Pi 5 in the secure scenario (recovery.bin: one more answer, then silence for
  minutes, while rpiboot.exe went through on the same board and files 4 s after `pieeprom.bin`; after `boot.img`:
  a garbled last message). Like rpiboot, the page does not check its reply to the final Done (the gadget may
  already be starting). Otherwise the page's
  rpiboot file server retries every second for as long as the board is attached. It stops only when the board
  really left USB (disconnect event, device closed, or gone from `getDevices()`; the result is kept as
  interrupted with the metadata collected so far) or when an attached board asks for nothing for 180 s.
* A failed rpiboot stage that never reached the board (for example a missing file) can be re-run on the
  same connected board without replugging it.
* Stage 3 compares the gadget's `getvar:serialno` with the board being provisioned before it contacts the
  server; a gadget of another board is refused with "the fastboot gadget belongs to board X, not Y".

Nothing on the page works without the server: it holds the board secrets and builds every file (the
serverless "Advanced (manual)" section of earlier versions is gone).

## The secure scenario and the device key export

The BCM2712 (and the BCM2711 of a CM4) has one device-unique OTP key slot (`rpi-fw-crypto` key-id 1, ECDSA P-256). The crypt
image unlocks its LUKS root at every boot with `HMAC-SHA256(that key, the storage device id)` computed by the
firmware (initramfs keyscript `hwkey`). In the secure scenario the station keeps **a copy of that key**, so it
can derive the LUKS key of any card used in the board:

```
luks_key = hex( HMAC-SHA256(key = d as 32 big-endian bytes, msg = <cid of the card> + "\n") )   # secrets_gen.luks_key
```

**The root file system is encrypted on the station, not on the board**, so only ciphertext goes to the page
and over USB (the plain crypt image set never leaves the server):

* After the key export the page asks for the stage-3 manifest again. The server builds the board's LUKS2
  container with `docker/scripts/root-luks.sh` in the tools image: `cryptsetup luksFormat` on a file
  (aes-xts-plain64, 512-bit random volume key, sector size 4096, the label `OSROOT_CRYPT` and UUID of the
  image's provisioning map, low-cost argon2id since the passphrases are 256-bit secrets), keyslot 0 =
  `luks_key` of the card the gadget reports (`getvar mmc-cid`), keyslot 1 = the recovery passphrase with
  `provisioning.recovery_passphrase`; `docker/scripts/luks_encrypt.py` then encrypts the plain sparse pieces
  exactly as dm-crypt would (XTS tweak = the sector offset in 512-byte units; checked against dm-crypt),
  leaving never-written blocks out. About 1.5 minutes; `<work>/modules/<serial>/luks/<fp>/`, one per board.
* The board gets its own `image.json`: the `encrypted` block becomes a plain root partition with
  `expand-to-fit` (`imagejson.station_luks`), so `oem idpwrite` only writes the partition table and the
  container goes raw to `mmcblk0p2` (`root.luks.sparse`). The LUKS2 data segment is dynamic, so it covers
  the whole partition; the file system grows at first boot (`otp-growroot`).
* Before `idpdone` and the power-off the page runs `oem cryptcheck mmcblk0p2`: rpi-fastbootd derives the key from
  OTP itself and checks it against the container's keyslots without activating it (no `/dev/mapper` device, so
  nothing decrypted ever exists on the board), answering the keyslot it opened. It must be keyslot 0. A board
  that fails (the one link the station takes on trust: the firmware's HMAC key is the raw OTP key) fails stage
  3 and is not powered off (it stays in the gadget); the server does not accept a secure stage 3 without that check.
* The transfer is larger than the plain image (about 2.4 GB instead of 1.6 GB): zero-filled areas of the file
  system (journal, inode tables) are written as ciphertext.
* Still in the clear on the way to the board: the boot partition (kernel, initramfs; signed for the board) with
  the first-boot files, and the exported device key (the page relays it to the server). Whoever sees the
  device key and the CID can derive the LUKS key.
* **The running system cannot read the OTP key.** Every signed OS `boot.img` (stage 3 and the Imager file, the
  station image and custom images alike) ends its `config.txt` with `[all]` + `lock_device_private_key=1`
  (`boot-slot.sh`; the slot is refused unless it reports `key_locked`). The firmware then refuses the raw key to
  Linux (`rpi-fw-crypto privkey`, the `GET_CUSTOMER_PRIVATE_KEY` and user-OTP mailbox calls; EEPROM 2025-08-20
  and later), while `hmac`, `sign` and `pubkey` keep working, which is all the initramfs keyscript needs. That
  `config.txt` lives inside `boot.img`, so `boot.sig` covers it: taking the line out needs the board's RSA key.
  Without it any root process on a secure board could read the key and with it the LUKS key of any card. The
  fastboot gadget is not locked this way (on the first run its helper must read the key); it READ-locks the key
  at runtime instead (the helper after the export, rpi-fastbootd at start).

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
* **Where the key came from.** The page also says whether the gadget generated the key at the station's request in
  this run (`generated`). The first export records it as `facts.device_key_origin`: `station`, or `existing` when the
  key was in OTP before (not generated now, or already reported in an earlier run, an open one for instance). A
  module can come with a key: the first CM4 on hardware had one that nobody had generated on this station. An
  existing key is exported as it is (`genkey` never overwrites one), but its origin is unknown, and whoever generated
  it may hold a copy, so the board's encrypted root is only as secret as that copy: the page warns, the board card
  shows **Key origin**, and such a board should not ship.
* **The key leaves the board once.** When the station holds it, stage 3 no longer asks for it (no
  `key_export` in the manifest; the page checks `getvar:public-key` against the stored key and stops before
  erasing on a mismatch), and stage 2 serves the board **its own signed gadget**: `stage2-sign.sh` adds
  `otp_keyexport=off` to `cmdline.txt` inside `boot.img` before `boot.sig` is made, and the helper then never
  exports the key in that boot (status `disabled`). The flag is covered by the signature, so a client cannot
  take it out. Gadget files of the first run (the shared gadget and its `boot.sig`) stay valid for that board,
  so a client that kept them could still boot an exporting gadget; that client saw the key during the first
  run anyway.

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
the exported device key already lets the server derive the LUKS key): keyslot 1 of the container the station
builds, `HMAC-SHA256(key = bytes.fromhex(device_secret), msg = "<mname>:<serial>")`. It never goes to the page.

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
description) for every setting the sheet lacks and removes the rows of retired settings (`paths.droneos`,
`builds.image.config`); it changes a value only when the OS image panel on the page saves it. An empty value
means the default; switches are `true`/`false`, lists one item per line. The server re-reads the sheet while it runs
(at most every 15 s), so **changes need no restart**. A value it cannot use keeps the previous settings and
is shown on the page; unknown keys produce a warning. When Google is slow or not answering, the page's requests
do not wait for it longer than 2 s: the read goes on in the background, the last good settings stay in force,
and the storage line of the status says "waiting for Google Sheets to answer". Boards cannot be provisioned
meanwhile (every stage writes the board's record), but the page says why instead of staying at "Checking the
server…". Once, Google kept timing out on the station spreadsheet's cells (the API only; the spreadsheet opened in
the browser): download a copy first (File → Download → .xlsx: it is the only copy of the boards' keys), then type
a value into an empty cell in the browser and delete it again; that brought the API back within minutes.

| Key | Default | Meaning |
| --- | --- | --- |
| `provisioning.default_mode` | `open` | scenario the page preselects for a new board: `open` or `secure` |
| `provisioning.jtag_lock` | `false` | secure scenario: also burn `program_jtag_lock=1` (IRREVERSIBLE) |
| `provisioning.recovery_passphrase` | `false` | secure scenario: add a server-derived LUKS passphrase as keyslot 1 |
| `provisioning.confirm_irreversible` | `true` | the page asks the operator to type the serial before OTP writes / erase |
| `provisioning.erase_storage` | `true` | stage 3: erase the storage device before the image is written |
| `provisioning.firmware_channel` | `latest` | rpi-eeprom firmware channel for stage 1: `latest` or `default` |
| `provisioning.max_piece_size` | `268435456` | largest sparse piece sent to the board (bytes, rpi-fastbootd max-download-size) |
| `provisioning.boot_conf` | `[all]`, `BOOT_UART=1`, `POWER_OFF_ON_HALT=1`, `BOOT_ORDER=0xf2461` | EEPROM `boot.conf` written in stage 1 (multi-line) |
| `image.name` | `rpios-trixie-arm64-lite` | name of the OS image (part of the image set names; a new name rebuilds it). The other `image.*` settings are written to each board at stage 3 and rebuild nothing |
| `image.custom` | (none) | the custom image stage 3 writes instead of the station image: the id of an image uploaded on the page (empty = the station image) |
| `image.packages` | (none) | system packages built into the station image, one package id per line (see *System packages and sandboxed apps*); a change rebuilds the image |
| `image.apps` | (none) | sandboxed apps built into the station image, one per line: `<package id> slot=<1..64> [grant=<permission>,...] [memory=<MiB>] [cpus=<n>] [tasks=<n>]` (defaults 256 MiB, 1 CPU, 512 tasks); a change rebuilds the image |
| `image.hostname` | `{family}-{serial}` | host name of the boards; `{serial}` = the board's 8-hex serial, `{family}` = `pi5` or `cm4` (a sheet with the old default `pi5-{serial}` is read as the new one) |
| `image.timezone` | `Europe/Kyiv` | time zone of the image's tzdata (the page offers the list) |
| `image.keyboard` | `us` | keyboard layout of the boards' console (xkb `us`, `gb`, `ua`, …; the page offers the list) |
| `image.user` | `pi` | the boards' login account (Raspberry Pi OS renames its first user `pi` to it at first boot) |
| `image.password_hash` | (none) | crypt hash of the account password (set it on the page; empty = no password) |
| `image.ssh` | `false` | SSH server on the boards |
| `image.ssh_password_login` | `true` | SSH accepts the account password (`false` = keys only) |
| `image.ssh_authorized_keys` | (none) | SSH public keys of the account, one per line |
| `image.wifi_ssid` | (none) | Wi-Fi network the boards join (empty = no Wi-Fi profile) |
| `image.wifi_password` | (none) | Wi-Fi passphrase (8-63 characters or a 64-digit hex key; empty = open network) |
| `image.wifi_country` | `UA` | Wi-Fi country known to wireless-regdb, two letters (`00` = world; the page offers the list) |
| `image.wifi_hidden` | `false` | the Wi-Fi network does not broadcast its name |
| `builds.auto` | `true` | build what is missing (tools, gadget, the images of every family) once the station is signed in |
| `builds.tools.image_tag` | `otp-tools:latest` | Docker tag of the tools image |
| `builds.gadget.targets` | `pi5-family,cm4` | pi-gen-micro targets of the fastboot gadget, comma-separated (spaces are read as commas); stage 2 refuses a board whose family no target covers (`pi5-family`/`pi5`/`cm5`/`500` for a Pi 5, `cm4`/`pi4-family` for a CM4). A sheet that still says `pi5-family` (the old default) is read as the new one |
| `builds.gadget.image_tag` | `otp-gadget-builder:trixie` | Docker tag of the gadget builder image |
| `builds.gadget.volume` | `otp-pgm-work` | Docker volume with the gadget build tree |
| `builds.image.families` | `pi5`, `cm4` | board families the station builds its OS image for, one per line (`pi5` = Raspberry Pi 5 / CM5 / Pi 500, `cm4` = Compute Module 4); a clear and a crypt image each; stage 3 of a board whose family is not listed waits with a note naming this setting |
| `builds.image.overrides` | (none) | extra `IGconf_KEY=VALUE` overrides for rpi-image-gen, one per line (`IGconf_image_pmap` is set per scenario) |
| `builds.image.builder_tag` | `otp-image-builder:trixie` | Docker tag of the image builder (rpi-image-gen) |
| `builds.image.volume` | `otp-image-work` | Docker volume with the image build tree |
| `builds.image.keep_raw_image` | `false` | keep the raw `.img` next to the sparse pieces |
| `builds.image.cm4_tfa` | `false` | the Compute Module 4 images boot through Arm Trusted Firmware (Debian's `bl31.bin` for rpi4 as the armstub, the device tree at 64 MiB): the kernel gets the Spectre v2 / v4 workarounds the stock BCM2711 stub lacks. Experimental (booted the open image on a module; the secure image with `device_tree_address` not yet); switching it rebuilds the cm4 images |
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
* **The signed fastboot gadget cannot read the board back.** Whoever runs the page drives it, so its
  rpi-fastbootd is our build (see "The station's rpi-fastbootd"): no `oem cryptopen`, `mount`,
  `cryptsetpassword` or `fwcrypto` signing, `oem upload-file` / `download-file` only for the otp-keyexport
  files, no `getvar:private-key`, USB only. With it a client can erase or overwrite the card, and nothing more:
  the container needs the board's key to open, and the key leaves the board once (see above). Gadgets
  signed for a board before this build (stock rpi-fastbootd) stay valid for it, since a signature cannot be
  withdrawn; rebuild before boards go out, and keep the per-board stage-2 files on the station.

What the irreversible operations burn (the page lists each one and asks for the serial first):

| Operation | When | What it does, forever |
| --- | --- | --- |
| `program_pubkey=1` (stage 1 `config.txt`) | secure scenario, board not yet locked | Burns the SHA-256 of this board's RSA public key into OTP. From then on the SoC only runs EEPROM and boot images signed with that key. Lose the key and the board is bricked for this station. |
| `program_jtag_lock=1` (stage 1) | secure scenario **and** `provisioning.jtag_lock`, board not reported locked yet | Permanently disables VideoCore JTAG. |
| device key generation (stage 3: the gadget's export request / `oem fwcrypto init`) | secure scenario, blank key slot (a key already in OTP is exported as it is, nothing is generated) | The firmware generates the device-unique ECDSA P-256 key in OTP. It cannot be changed or erased; a copy goes to the station. |
| `erase:<disk>` (stage 3) | `erase_storage: true` | Wipes the SD card / eMMC / NVMe before IDP writes the partition table. |

The open scenario writes nothing to OTP.

More rules of the secure scenario:

* Stage 1 signs the EEPROM config with the board's RSA key (`SIGNED_BOOT=1`, `ENABLE_SELF_UPDATE=0` added to
  `boot_conf`) and adds `program_pubkey=1`. The verdict requires `SECURE_BOOT_PROVISION=success` and
  `CUSTOMER_KEY_HASH` equal to the stored hash.
* **JTAG lock.** With `provisioning.jtag_lock` the stage also sends `program_jtag_lock=1` (it only takes on a board
  whose OTP holds a key hash, so a later secure stage 1 of a locked board can still add it; it can never be taken
  back). The verdict then requires the board to report `JTAG_LOCKED=1`; a missing or `0` report fails the stage
  ("run stage 1 again"). Once a board has reported `JTAG_LOCKED=1` the record keeps it (`facts.jtag_locked`, the
  board card's **JTAG** line, an `otp` event) and stage 1 does not send `program_jtag_lock=1` to it again.
* **Key-hash check before signing or burning.** The server recomputes `customer_key_hash` from the record's
  RSA key. If the stored hash differs, or the record has a hash but lost its PEMs, stage 1 is refused with 409
  ("the board record's customer_key_hash X does not match its RSA key … fix the record in storage first").
  Never edit `customer_key_hash` and the PEM columns in the sheet independently. `stage1.sh` gets the expected
  hash as `EXPECT_CKH` and dies if `public.pem` or the key embedded in `pieeprom.bin` hashes to anything else.
* **`boot_conf` rules.** Signed: `ENABLE_SELF_UPDATE=0` and `SIGNED_BOOT=1` count as present only when every
  assignment of the key is in `[all]` (or before the first section header) with exactly that value; otherwise
  every assignment is removed and the value is appended under a trailing `[all]`. Unsigned: any `SIGNED_BOOT`
  other than `0`, in any section, is removed with a note. Set `SIGNED_BOOT` only through the scenario.
* **OTP burnt but the stage-1 report lost: the station works it out.** The BCM2712 boot ROM runs the plain
  `recovery.bin` only while the OTP holds no key hash, and the one counter-signed with our key only once it holds
  ours (usbboot `secure-boot-recovery5/README.md`); the wrong one it takes with status 0 and then keeps, silently.
  So the station keeps an assumption in the record (`facts.otp_lock`, shown on the page as "probably locked …";
  a CM4's boot ROM runs the plain second stage in both states, see "Compute Module 4"):
  * a secure stage 1 that broke off after the board got `program_pubkey=1` and the whole `pieeprom.bin`, with no
    `CUSTOMER_KEY_HASH` in its report, makes the next stage 1 assume the lock (counter-signed second stage, no
    second `program_pubkey`; the Open scenario is refused meanwhile);
  * the page notices a refused second stage: the ROM is still on USB 15 s after taking it (a second stage that
    runs makes it leave within a second or two). It reports which one was refused, the server flips the
    assumption, the stage card asks to unplug the board and plug it back in with the power button held, and
    stage 1 runs once more by itself with the other second stage;
  * the board's own report (`CUSTOMER_KEY_HASH`) replaces the assumption; stages 2 and 3 never run on an
    assumption. A board that refuses both second stages stops stage 1 with the reason (OTP locked to another
    key, or not really in RPIBOOT mode).

  This happened to ebbdf4fd on 2026-10-06. The manual override stays: `uv run -m otp_server modules mark-locked
  <serial>` records `otp_key_hash = customer_key_hash` and `secure_boot_provisioned = true`, so all later stages
  are served signed; it never generates a key. `modules mark-unlocked <serial>` undoes it. Both also clear the
  assumption. When a server is running both send the change through it (`POST /api/modules/{serial}/otp`).
* A board whose OTP is **locked to our key** always gets signed files: a counter-signed `bootcode5.bin` (with
  our public key as `pubkey.bin` next to it in `bootfiles.bin`: the bootloader of usbboot 2026-10-23 reads the
  key that verifies `boot.img` over rpiboot), a signed EEPROM, a `boot.sig` for the gadget, and a boot
  partition re-signed per board in stage 3, whose `boot.img` sets `lock_device_private_key=1` (see "The secure
  scenario and the device key export").
* A board **locked to a different key** is refused (HTTP 409, "board OTP is locked to a different key").

## HTTP API

All JSON, same origin. Errors are `{"detail": "..."}`. Until the station is signed in to Google and the
settings sheet has been read, the module, stage and build endpoints answer **401** with what is missing. An
artifact that is not ready returns 409 `{"ready": false, "reason": "...", "job": Job|null}`. Interactive
docs are at `/api/docs`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/status` | version, Google login + settings state, effective config, storage, Docker, Windows USB driver, artifact status, custom images, current jobs |
| GET | `/api/google/login` | redirect to Google's consent screen (Google redirects back to `/?state=…&code=…`) |
| POST | `/api/google/logout` | forget the Google token on this station (the spreadsheet id is kept) |
| GET | `/api/image` | the OS image settings `{settings, warnings, choices}`: no password or hash, only `password_set` / `wifi_password_set`; `choices` = the time zone and Wi-Fi country lists |
| POST | `/api/image` | save changed OS image fields (`custom`, `hostname`, `user`, `ssh`, …; `password` / `wifi_password`: `""` removes, a string sets) → the same view + `saved`; starts the rebuild (a new name) or the preparation (a new custom image) with `builds.auto` |
| GET | `/api/custom-images` | the uploaded images: id, name, size, OS, cloud-init, state per variant, job |
| PUT | `/api/custom-images?name=<file>` | upload an image: the raw `.img` as the body (`Content-Length` required) → `{image, new, job}`; 400 with the reason for a file the station cannot take |
| POST | `/api/custom-images/{id}/prepare` | `{force}` → prepare it (again) |
| DELETE | `/api/custom-images/{id}` | remove it and its sets (400 for the image stage 3 writes) |
| GET | `/api/packages` | system packages and apps on the station (also in `/api/status` as `packages`): metadata, permissions offered or requested, preparation state, job; the permissions the selected system packages offer, the next free slot, problems of the saved selection |
| PUT | `/api/packages?kind=system\|app&name=<file>` | upload a `.deb` as the body → `{package, new, job}` (an app is prepared right away); 400 with the reason for a file the station cannot take |
| POST | `/api/packages/{id}/prepare` | `{force}` → prepare an app (again) |
| GET | `/api/packages/{id}/sandbox` | the files of an app's sandbox as the image would get them now |
| DELETE | `/api/packages/{id}` | remove a package (400 while it is in `image.packages` / `image.apps`) |
| POST | `/api/modules/{serial}/imager-image` | `{"source": "" \| "<id>" \| null}`: prepare the board's image file for Raspberry Pi Imager → `{ready, name, size, url, partitions, mmc_cid, notes}`, or 409 while parts are built |
| GET | `/api/modules/{serial}/imager-image/{name}` | the prepared image file (streamed, `Content-Length`, attachment) |
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
uv run server.py [--host H] [--port N] [--browser EXE] [--no-browser] [--no-auto-build] [--work DIR]
uv run -m otp_server serve  ...                 # same as server.py
uv run -m otp_server login                      # sign in to Google from a terminal (opens the browser)
uv run -m otp_server build tools|gadget|image [--force]   # run one build, stream its log, exit with its result
uv run -m otp_server modules [--json]           # registry table / public JSON (no secrets)
uv run -m otp_server modules mark-locked <serial> [--yes]    # record that the board OTP holds our key hash
uv run -m otp_server modules mark-unlocked <serial> [--yes]  # undo mark-locked
uv run -m otp_server status                     # the /api/status document
uv run -m otp_server --version
```

Every command except `serve` and `status` reads the settings from the spreadsheet, so it needs the Google
login; without it the command exits with code 2 and says what is missing.

## Repository layout

```
server.py                  launcher
pyproject.toml, uv.lock    the dependencies and their locked versions (uv); .python-version picks the Python
google-oauth-client.json   the Desktop-app OAuth client (you add it)
otp_server/
  __main__.py              CLI; app.py (services, FastAPI app); api.py (routes)
  config.py                defaults, validation, merging (no config file)
  settings.py              the settings worksheet (read, complete with defaults, write)
  imageconfig.py           OS image settings -> rpi-image-gen config + secret files (+ image.apps lines)
  debpkg.py                metadata of an uploaded .deb (control fields, scripts, files), nothing unpacked
  sandbox.py               the files of every sandboxed app on the board (quadlet, proxy, AppArmor, users, registry)
  rootfs_tar.py            the check of an app's installed root file system and the shift of its owners
  image_choices.py/.json   time zones and Wi-Fi countries of the image (from Debian tzdata, wireless-regdb, iso-codes)
  passhash.py              SHA-512 crypt ($6$) for the account password
  google_account.py        Google OAuth login, token, the station spreadsheet
  secrets_gen.py           RSA key, customer key hash, device secret, device key parsing, LUKS key
  modules.py               board registry logic, scenarios, device key, stage verdicts
  boards.py                the board families (Raspberry Pi 5 / Compute Module 4) and what differs between them
  storage/                 base.py (record schema), gsheets.py (the modules worksheet)
  docker.py, jobs.py       Docker CLI runner; background jobs with logs and SSE
  artifacts/               tools image, stage 1, gadget + stage 2, OS images + stage 3, custom images (custom.py),
                           system packages and apps (packages.py: upload, the app's install in a VM)
  imagejson.py, sparse.py  rpi-image-gen image.json helpers (+ the custom image's); Android sparse validation and expansion
  diskimage.py             the checks of an uploaded .img; the disk image assembled from sparse pieces (Imager file)
  winusb.py                Windows WinUSB driver-package check (read-only)
docker/
  tools.Dockerfile, tools-entrypoint.sh     otp-tools image ("otp-run <script>")
  scripts/stage1.sh, stage2-sign.sh, boot-slot.sh, root-luks.sh (+ luks_encrypt.py), image-collect.sh
  scripts/custom-image.sh (+ ext4_sparse.py, custom-crypt/: otp-hwkey, the initramfs hooks and scripts
                            otp-cryptroot, otp-aes, otp-growpart, otp-hwlock, otp-growroot)
  gadget.Dockerfile, gadget-entrypoint.sh   arm64 pi-gen-micro builder (+ rpi-fastbootd build stage)
  apps.Dockerfile                           otp-app-builder: qemu-system-aarch64, mmdebstrap, mke2fs
  scripts/app-vmkit.sh, app-vm-init, app-rootfs.sh, app-install.sh   an app's root file system, installed in a VM
  gadget-helpers/otp-keyexport/             pi-gen-micro helper package: OTP device key export
  fastbootd/otp-station.patch               our changes to rpi-fastbootd (command allowlist, cryptcheck, USB only)
  fastbootd/station-test.sh, station_test.cpp  build-time self-test of the compiled daemon
image/
  build.sh                 rpi-image-gen front end (the station runs it with --in-container)
  docker/                  the builder image (Debian trixie + rpi-image-gen's dependencies)
  layer/                   station layers: otp-rpios-packages and otp-rpios-kernel-2712 / -v8 (generated), otp-rpios-lite,
                           otp-rpios-setup (+ otp-rpios-setup.d: kernel command line fragment, initramfs
                           otp-aes and otp-growpart),
                           otp-apps, otp-tfa-rpi4 (CM4, builds.image.cm4_tfa)
  rpios_packages.py        writes the package layers from a Raspberry Pi OS Lite release's .info file
  example.yaml             the config of the default OS image settings (example-cm4.yaml: the Compute Module 4's)
  rpi-image-gen/           submodule
index.html, css/app.css
js/server.js               API client; flow.js provisioning state machine; app.js UI
js/rpiboot.js              rpiboot protocol (port of usbboot main.c); bootdir.js, tar.js, duid.js
js/fastboot.js             WebUSB fastboot client + IDP + device key export
examples/apps/             the demo packages (vn-demo-provider, vn-demo-detector) and build.py
tests/                     pytest suites; tests/web/ page self-test and end-to-end test (headless Chrome)
external/                  submodules (usbboot, pi-gen-micro)
```

## Submodules

| Path | Upstream | Used for |
| --- | --- | --- |
| `external/usbboot` (+ nested `rpi-eeprom`) | raspberrypi/usbboot | `firmware/bootfiles.bin`, EEPROM images and recovery, `update-pieeprom.sh`, `rpi-eeprom-digest`, `rpi-sign-bootcode`, `rpi-make-boot-image` |
| `external/pi-gen-micro` | raspberrypi/pi-gen-micro | source of the fastboot gadget |
| `image/rpi-image-gen` | raspberrypi/rpi-image-gen (`v2.9.0`) | the image generator of stage 3 (mmdebstrap + genimage + IDP) |

The rpi-image-gen submodule pins the generator: to move to a newer release run
`git -C image/rpi-image-gen fetch --tags` and `git -C image/rpi-image-gen checkout <tag>`, then commit
`image/rpi-image-gen`. The image set's version is `git describe` of that checkout: once the pointer moves (or
the checkout gets uncommitted changes, `-dirty`), the published sets are `rebuild needed` and stage 3 waits
until the images are rebuilt — automatically with `builds.auto`, or with Build on the page /
`uv run -m otp_server build image`. The image build tooling (`image/build.sh`, `image/docker/`) came from the
droneos repository, which the station no longer uses.

**rpi-fastbootd is deliberately not a submodule.** Its repository contains the systemd unit
`dev-usb\x2dffs-fastboot.mount`, a file name Windows cannot check out, and building it needs Raspberry Pi
OS libraries (librpifwcrypto, libblockdeviceid). pi-gen-micro vendors the official
`internal/packages/rpi-fastbootd_*_arm64.deb`; the gadget builder image clones the same revision inside the
container instead (see below).

### The station's rpi-fastbootd

The signed gadget runs whatever the person at the page asks of it, and stock rpi-fastbootd can decrypt the
board's root (`oem cryptopen` with the key it derives from OTP), mount it and upload any file or block device.
So the gadget gets our build: `docker/gadget.Dockerfile` clones `raspberrypi/rpi-fastbootd` at
`FASTBOOTD_COMMIT` (the revision pi-gen-micro vendors, `adf29cb`), applies
`docker/fastbootd/otp-station.patch` and builds `rpi-fastbootd_<upstream version>+otp1_arm64.deb`;
`gadget-entrypoint.sh` puts it in place of the vendored deb in its staged pi-gen-micro copy, pins it
(priority 1001) and fails the build unless that exact version ended up in the gadget (`fastbootd_version` in
`build-info.json`). The patch:

* answers only `download`, `upload`, `getvar`, `shutdown`, `reboot`, `erase`, `flash` and `oem` (no
  `set_active`, `fetch`), and only these OEM commands: `idpinit`, `idpwrite`, `idpgetblk`, `idpdone`,
  `fwcrypto init`, `cryptcheck`, `upload-file` of `/run/otp-keyexport/{key.der,status}` and `download-file`
  of `/run/otp-keyexport/request` (upstream's `oem mac set` and `oem otp set`, which program OTP rows, are
  refused with the rest);
* adds `oem cryptcheck <partition>`: the LUKS key the board derives from OTP is checked against the
  container (`crypt_activate_by_passphrase` without a device name), answering `keyslot N`;
* makes `shutdown` power the board off (`systemctl poweroff`; upstream answered OKAY and only paused the
  daemon), which is how stage 3 ends;
* drops `getvar:private-key`;
* serves USB only: `-i usb+tcp` from the package's launcher is ignored (the TCP data plane flashes and
  erases for anyone on the board's network).

The builder image does not keep a deb that has not passed `docker/fastbootd/station-test.sh`: it links
`station_test.cpp` with the daemon's own objects (all but `main.cpp`) and drives the compiled dispatcher over a
scripted transport. Every upstream OEM command outside the list, the allowed ones with other arguments, other
file paths (`/etc/passwd`, `/dev/mmcblk0`, `..`), `getvar:private-key` and the dropped top-level commands
must be refused; the helper file exchange, IDP and `cryptcheck` must reach their handlers; and
`CryptCheckNative` must name keyslot 0 for the board key and keyslot 1 for the recovery key of a LUKS2 header
made there. `tests/test_artifacts.py` checks the patch against what `js/fastboot.js` sends, and the page
tests run against a gadget simulator that refuses everything else. What a client can still do with the gadget: erase or
overwrite the card (it could do that with the board in hand anyway), and generate the OTP key of a blank
slot (`fwcrypto init`, which stage 3 does in any case).

Scripts stage a CR-stripped copy of every shell script inside the container, and never rely on git symlinks
(for example `usbboot/firmware/2712/*`) being materialised in a Windows checkout. The gadget build drops
pi-gen-micro's cached index of its local package repo before every build (that repo's `Release` file has no
hashes, so apt would otherwise never notice a new or changed helper package).

## Testing

```
uv run --group dev python -B -m pytest -q     # server: config, settings, Google account, secrets, storage, modules, jobs, docker, artifacts, OS image config, password hash, API, CLI, the key export script
uv run python -B tests/web/run_selftest.py    # page: headless Chrome against a fake API (-v for every line)
uv run python -B tests/web/run_e2e.py         # page + real server on the real artifacts + a mock board, scenarios A-D
```

`run_e2e.py` runs scenarios A and B (a mock Pi 5, open and secure) and C and D (a mock CM4, when the cm4 images
exist); `--scenario A|B|C|D|both|cm4|all` picks them. Its server has only the default settings plus the station's
`image.name`: when the station image carries packages or apps, pass the sheet's values with `--set`
(`--set 'image.packages=["<id>"]' --set 'image.apps=["<line>"]'`), or every image set is "rebuild needed" for it.

The suites test the Google code against fakes (no network access); the station itself has run against real
Google (sign-in, spreadsheet, settings, registry). `OTP_DOCKER_TESTS=1` enables a smoke test against the real Docker engine. The page runners find
Chrome via `--chrome`, `$OTP_CHROME`, the default Windows path or `PATH`. The repository has no `.gitignore`
on purpose: run Python with `-B` (or `PYTHONDONTWRITEBYTECODE=1`) so no `__pycache__` directories appear.
`.venv` stays out of git through the `.gitignore` uv writes inside it. The `dev` group (pytest, httpx2, PyYAML) is
installed only for `--group dev`; a station's `uv run server.py` does not need it.

Some tests run the station's shell code on the host, and that code is written for Debian (GNU coreutils and sed,
bash 4 or later; `tests/hosttools.py` checks). On Windows put Git's Unix tools first (PowerShell:
`$env:PATH = "C:\Program Files\Git\usr\bin;$env:PATH"`): without them the `sh` tests and the kernel command line test
are skipped (WSL's `C:\Windows\System32\bash.exe` is never used). `C:\Program Files\Git\bin` is not the same: its
`sh.exe` puts Git's own tools before the test's stubs. On macOS the tests that need GNU `stat`/`sed` or bash 4 skip
with a hint; `brew install coreutils gnu-sed bash` with the gnubin directories first on `PATH` runs them. With
`usr\bin` first on Windows: 1296 passed, 3 skipped (2026-11-12). `run_e2e.py` uses the server's work dir (`OTP_WORK_DIR` or the
platform default) and exits with 2 when no scenario can run there.

## Troubleshooting

* **"The station was updated after this page was loaded".** The page's files changed under an open tab (a
  `git pull` and a server restart): the tab still runs the old page, which must not drive a board against the new
  server. Reload it (Ctrl+F5); until then Connect board and Provision stay disabled. On 2026-11-11 a tab opened
  before an update ran a whole secure stage 3 with the previous page.
* **The board left USB during stage 3** (cable pulled, power lost): the fastboot gadget ran from RAM and is gone.
  Put the board back into RPIBOOT mode, **Connect board**, **Run** stage 2, then **Connect fastboot gadget** and
  **Run** stage 3; the page says so instead of the raw WebUSB error. A board that was "Image written" before such a
  run goes back to "Fastboot gadget booted" (its storage may be erased or partly written), so **Provision** offers
  stages 2 and 3 again instead of calling it fully provisioned.
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
  `uv run -m otp_server build <target> --force` to see the whole log in the terminal.
* **Stage 3: "the OTP device key cannot be exported in this boot".** The key exists but was READ-locked before
  the helper ran (for example the gadget was booted without our helper). Run stage 2 again so the gadget boots
  afresh, then stage 3. "this fastboot gadget has no OTP key export helper" means an old gadget: rebuild it.
* **A custom image is refused at upload.** The message says why: unpack a compressed file first; GPT images,
  images with more or fewer than two partitions and roots that are not ext4 are not taken.
* **Preparing a custom image fails (secure set).** The job log shows the step. "the image's apt sources offer no
  rpifwcrypto": the image needs archive.raspberrypi.com (bookworm or later) in its apt sources. "no
  initramfs-tools": the image cannot unlock a root at boot. "cannot run the image's arm64 programs": register the
  arm64 binfmt handler (as for the builds). Network errors: the station needs internet access for the image's
  packages. The open set can still be used meanwhile.
* **A secure board with a custom image stops at the `(initramfs)` prompt.** The root was not unlocked. Sets
  prepared before 2026-10-12 had a keyscript that bookworm's `rpi-fw-crypto` fails without a message: the custom
  image shows "prepare it again", then provision the board again (or write a new Imager file). To unlock by hand
  in that shell and boot once (for a diagnosis; no `|` needed):

  ```sh
  cat /sys/block/mmcblk0/device/cid > /run/cid
  rpi-fw-crypto hmac --in /run/cid --key-id 1 --outform hex > /run/key
  cryptsetup open --key-file /run/key --keyfile-size 64 /dev/mmcblk0p2 cryptroot
  exit
  ```

  An error from `rpi-fw-crypto` means the OTP key is missing or the firmware refuses it; "No key available"
  from `cryptsetup` means the card or the board is not the one the set was made for.
* **The `(initramfs)` shell has the wrong keyboard layout.** It is the layout of the image (its
  `/etc/default/keyboard`; Raspberry Pi OS ships `gb`): `cryptsetup-initramfs` always copies it into the
  initramfs. On a US keyboard with `gb`, `|` is Right Alt + `` ` ``; `loadkeys` is there to change single keys
  (`echo 'keycode 43 = backslash bar' > /run/k.map`, then `loadkeys /run/k.map`). For another layout at every
  boot, set `XKBLAYOUT` in the image before uploading it.
* **"board OTP is locked to a different key".** The board was locked with a key this registry does not hold.
  Nothing can be provisioned. Restore the registry row that holds its key.
* **HTTP 403 "Host … is not allowed" / "cross-site POST rejected".** Open the page at `http://127.0.0.1:<port>/`.
* **Port 8765 in use.** Another program holds it (exit code 2). Use `--port`.
* **"No module named 'uvicorn'"** (or another package). The server was started by a Python outside uv
  (`python server.py`), which does not have the packages. Start it with `uv run server.py`.
* **`did not find executable at '…\uv\python\cpython-3.15.1-…\python.exe'`.** The `.venv` was made when
  `.python-version` named an exact patch release, and uv has since removed that release. Delete `.venv`; the next
  `uv run` makes it again on the newest 3.15 (it then follows uv's patch upgrades by itself).
* **A board flashed after adding packages has none of them** (no `vn*` units, no podman). The image it got was
  built without them: most often the ticks were not saved before a Rebuild. See "Checking a build" and "Checking a
  board" under "System packages and sandboxed apps"; save, wait for the rebuild, run stage 3 again.
* **`podman ps` on a freshly flashed board says the app has been up for an hour.** The board's clock jumped. A
  Pi 5 without an RTC battery starts at 1970 after a power cut; systemd-timesyncd moves the clock up to the
  timestamp of `/var/lib/systemd/timesync/clock` (on the first boot that is the image's build time, later the last
  time it was saved, at most a minute before the power went), and NTP corrects it once the network is up. A
  container started before that keeps the earlier start time; `ps -o etimes` shows the real age. Only the time
  stamps are wrong; the apps do not depend on wall-clock time.
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
