# OTP_Provisioner

A provisioning station for Raspberry Pi 5 modules that runs as a single web
page in Chrome. No build step, no framework, no native helper: the page talks
to the BCM2712 boot ROM over **WebUSB**, implementing the `rpiboot` protocol in
JavaScript, and to the provisioning agent over **fastboot** (also WebUSB).

It is the "station agent" of the *Reclus: secure boot and provisioning of
guidance modules on Raspberry Pi 5* design: it detects a module in rpiboot
mode, shows its serial, and drives the three provisioning stages with the
directories the server prepares for that module.

| Stage | What happens | Transport | Status |
| --- | --- | --- | --- |
| Detect | Module in ROM rpiboot mode (`0a5c:2712`), serial from the USB descriptor, ROM vs. second-stage detection | WebUSB | implemented |
| 1 · OTP & EEPROM | Send `bootcode5.bin` (recovery), serve `pieeprom.bin` / `pieeprom.sig` / `config.txt`, collect the metadata JSON (`CUSTOMER_KEY_HASH`, `SECURE_BOOT_PROVISION`, DUID, MAC) | rpiboot protocol | implemented, protocol-level tests, **not yet run on hardware** |
| 2 · Provisioning agent | Send the bootloader, serve `config.txt` / `boot.img` / `boot.sig` (the signed initramfs) | rpiboot protocol | same engine as stage 1 |
| 3 · Image | `stage image.json` → `oem idpinit` → `oem idpwrite` → `oem idpgetblk` / `flash` loop → `oem idpdone` (rpi-image-gen IDP) | fastboot | implemented against the protocol spec, **unverified**; no sparse-image splitting |

## Running

Open `index.html` in Chrome (or Edge / another Chromium browser). It works
from `file://`; WebUSB and the directory picker are available there.
Alternatively serve it over `http://localhost`:

```
python serve.py          # http://127.0.0.1:8765/
```

WebUSB requires a secure context: `file://`, `http://localhost` or `https://`.

### Operating-system access to the device

* **Windows.** Chrome can only open devices bound to the WinUSB driver. The
  official rpiboot installer (`rpiboot_setup.exe`) installs
  `rpiboot-winusb.inf`, which binds WinUSB to `0a5c:2763/2764/2711/2712`.
  Install it once; `rpiboot.exe` itself is not needed by the page. If the
  device shows up under a libusb-win32/libusbK driver instead, rebind it
  with the shipped tool: `wdi-simple.exe -t 0 -v 0x0a5c -p 0x2712`.
* **Linux.** Give your user access to the device, e.g.
  `/etc/udev/rules.d/99-rpiboot-webusb.rules`:

  ```
  SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2712", MODE="0660", GROUP="plugdev", TAG+="uaccess"
  SUBSYSTEM=="usb", ATTR{idVendor}=="0a5c", ATTR{idProduct}=="2711", MODE="0660", GROUP="plugdev", TAG+="uaccess"
  ```
* **macOS.** Works without drivers.

Only one program may claim the interface: close `rpiboot`, `rpi-sb-provisioner`
or another tab of this page before running a stage.

### Putting a Raspberry Pi 5 into rpiboot mode

No SD card, hold the power button, connect USB-C to the station, release the
button. The board enumerates as `BCM2712 Boot`. The station port must supply
enough current (Raspberry Pi recommends a 900 mA port or 5 V on the 40-pin
header for boards with peripherals).

## How the page works

`js/rpiboot.js` is a port of `usbboot/main.c`:

* The device advertises its stage in the device descriptor: `iSerialNumber`
  index 0 or 3 means boot ROM (send the second stage), anything else means
  the bootloader is running its file server. WebUSB allows the standard
  `GET_DESCRIPTOR` request, so the page reads the same byte rpiboot reads.
* Every host→device message is a vendor control transfer with the length
  (`wValue = len & 0xffff`, `wIndex = len >> 16`) followed by the bytes on
  the bulk OUT endpoint in 16 KiB pieces; device→host messages are vendor
  control IN transfers of the requested size.
* Second stage: a 24-byte `boot_message` (length + 20-byte signature, zero
  on BCM2711/2712) then `bootcode5.bin`; the ROM answers with a 4-byte status
  and re-enumerates. The page waits for the WebUSB `connect` event of the new
  enumeration (Chrome keeps the permission when the serial string is the
  same; otherwise click *Select device…* again) and continues.
* File server: 260-byte messages `{int32 command; char name[256]}` with
  `GetFileSize` (0), `ReadFile` (1), `Done` (2). Names starting with `*` are
  metadata `*KEY*VALUE`; `FACTORY_UUID` is C40-decoded (`js/duid.js`, port of
  `decode_duid.c`). The result is the same JSON `rpiboot -j` writes.
* File lookup follows `check_file()`: `..` is refused; with `bootfiles.bin`
  present, `<dir>/2712/<name>` overlays the tar entry `2712/<name>`
  (`js/tar.js`); otherwise `<dir>/2712/<name>` then `<dir>/<name>`.

`js/bootdir.js` reads the directory chosen with the File System Access API
(lazy, any size) or `<input webkitdirectory>`. `js/fastboot.js` is the
fastboot host (`getvar`, `download`, `flash`, `oem`, the IDP loop of
`rpi-image-gen/bin/idp.sh`). `js/registry.js` keeps the modules this browser
has seen (serial, chip, stage, last metadata) in `localStorage`; the real
station would report to the server instead.

### Safety rails

The rpiboot-side `config.txt` of the chosen directory is parsed and every
irreversible key (`program_pubkey`, `program_jtag_lock`,
`eeprom_write_protect`, `revoke_devkey`, `program_rpiboot_gpio`) is shown in
red; running such a directory requires typing the module serial in a
confirmation dialog. Stage 1 shows SHA-256 of every artifact and, if the
server's expected key hash is entered, compares it with `CUSTOMER_KEY_HASH`
from the metadata. Stage 3 asks for the same confirmation before
repartitioning.

## Demo without a signed toolchain

Stage 2 can be exercised with the stock `mass-storage-gadget64` directory of
the rpiboot installer (`C:\Program Files (x86)\Raspberry Pi\mass-storage-gadget64`
on Windows): the page sends `2712/bootcode5.bin` from `bootfiles.bin`, serves
`config.txt` and `boot.img`, and the module comes up as a USB mass-storage
device with its SD card. Stage 1 with `recovery5` (unsigned, no
`program_pubkey`) flashes the EEPROM and returns metadata without touching OTP.

## Testing stage 3 (fastboot)

`mass-storage-gadget64` has no fastboot: its initramfs only runs
`configure-gadgets` (ACM serial + mass storage, USB id `0a5c:0104`). The
fastboot gadget is a different ramdisk, built by the `fastboot` configuration
of [pi-gen-micro](https://github.com/raspberrypi/pi-gen-micro) with
[rpi-fastbootd](https://github.com/raspberrypi/rpi-fastbootd) inside. Two
ways to get it:

* **Prebuilt** (what rpi-sb-provisioner ships):
  `https://raw.githubusercontent.com/raspberrypi/rpi-sb-provisioner/main/host-support/fastboot-gadget-pi5-family.img`
  (27.6 MB FAT image = `boot.img`; `fastboot-gadget-pi4-family.img` for
  BCM2711). `stage-dirs/fastboot-gadget-pi5/` in this checkout is that file
  plus `bootfiles.bin` from the rpiboot installer and a `config.txt` with
  `boot_ramdisk=1`, exactly what `rpi-sb-bootstrap.sh` stages.
* **Build it**: on Debian/WSL2 with `mmdebstrap` and subuids,
  `pi-gen-micro-sysroot run fastboot cm5,pi5` → `out_image/boot.img`.

The gadget enumerates as USB `18d1:4e40` (Google VID, "Nexus 7 (Fastboot)"
PID), manufacturer "Raspberry Pi", product = the device-tree model, serial =
the full 64-bit board serial; fastbootd runs as `-i usb+tcp`, so the CLI can
also reach it on port 5554 over wired Ethernet. On Windows bind WinUSB to it
first (`wdi-simple.exe -t 0 -v 0x18d1 -p 0x4e40`, or the Google USB driver).

Test order, least to most destructive:

1. Stage 2 with `stage-dirs/fastboot-gadget-pi5/` on an unlocked Pi 5 (no
   `boot.sig` needed). The module reboots into the gadget.
2. Stage 3 → *Select fastboot device…* → `getvar:all`. Read-only; checks the
   WebUSB transport, endpoints and response parsing against the real daemon.
3. Stage 3 → *Choose image directory…* with an rpi-image-gen output that has
   `image.json` (an image layout with a provisioning map, e.g.
   `image/gpt/ab_userdata`), then *Provision (IDP)* on a scratch SD card.
   `stage image.json` + `oem idpinit` only validate; `oem idpwrite` repartitions.
   Sparse images above `max-download-size` are refused by this page.

Without a Pi, any Android phone in bootloader mode speaks the same protocol:
step 2 against it validates the client (never flash a phone from here).

## What a Chrome-only station cannot do

A browser cannot write to a raw disk, so the "agent exposes the SD card as a
USB disk and the station writes the image" path of the design is not
available here. Stage 3 therefore uses fastboot/IDP, where the module writes
its own storage. Sparse images larger than the gadget's
`max-download-size` would have to be split on the host (the `fastboot` CLI
does that); this page refuses them instead.

## Layout

```
index.html        the page
css/app.css
js/duid.js        C40 decoder for FACTORY_UUID (decode_duid.c)
js/tar.js         bootfiles.bin reader (bootfiles.c)
js/bootdir.js     boot directory + check_file() lookup order
js/rpiboot.js     rpiboot protocol over WebUSB (main.c)
js/fastboot.js    fastboot host + IDP loop
js/registry.js    localStorage module registry
js/app.js         UI
serve.py          optional stdlib static server
```

## References

* https://github.com/raspberrypi/usbboot — `main.c`, `bootfiles.c`, `decode_duid.c`, `secure-boot-recovery5/`
* https://github.com/raspberrypi/rpi-image-gen — IDP, `bin/idp.sh`
* https://github.com/raspberrypi/rpi-sb-provisioner — the reference Linux station
* https://wicg.github.io/webusb/ — WebUSB
* https://android.googlesource.com/platform/system/core/+/master/fastboot/README.md — fastboot protocol
