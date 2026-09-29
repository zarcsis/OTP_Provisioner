Stage-2 directory that boots the Raspberry Pi fastboot gadget (rpi-fastbootd) on a Pi 5 family board.

boot.img      = host-support/fastboot-gadget-pi5-family.img from github.com/raspberrypi/rpi-sb-provisioner (main, 2026-09):
                pi-gen-micro "fastboot" configuration, rpi-fastbootd 14.0.0, USB gadget 18d1:4e40 "Raspberry Pi" / <model>,
                serial = 64-bit board serial; fastbootd runs as "-i usb+tcp" (TCP port 5554 on wired Ethernet as well).
bootfiles.bin = second stage + firmware, copied from the rpiboot installer (mass-storage-gadget64/bootfiles.bin).
config.txt    = boot_ramdisk=1 (same as rpi-sb-provisioner host-support/boot_ramdisk_config.txt).

Unlocked board: no boot.sig needed. Locked board: sign boot.img with the module key (boot.sig) and counter-sign
2712/bootcode5.bin inside bootfiles.bin (mass-storage-gadget64/sign.sh shows the exact commands).

Windows: bind WinUSB to 18d1:4e40 before Chrome can open the gadget, e.g.
  "C:\Program Files (x86)\Raspberry Pi\redist\wdi-simple.exe" -t 0 -v 0x18d1 -p 0x4e40 -n "Raspberry Pi fastboot"
(or install the Google USB driver from Android platform-tools, which also binds WinUSB to Google VID devices).
