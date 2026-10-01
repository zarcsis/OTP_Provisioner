/*
 * rpiboot.js — the rpiboot USB protocol on top of WebUSB.
 *
 * A port of usbboot/main.c. The BCM2712 boot ROM (VID 0a5c, PID 2712)
 * enumerates as a vendor-class device with one bulk OUT endpoint. Everything
 * the host says starts with a vendor control transfer carrying the length
 * (wValue = len & 0xffff, wIndex = len >> 16) followed by the bytes on the
 * bulk endpoint; everything the device says is read with a vendor control
 * IN transfer of the requested size.
 *
 * Two stages, distinguished exactly like rpiboot does — by the string
 * descriptor index the device advertises for its serial number:
 *   iSerialNumber 0 or 3  → boot ROM: send the second-stage bootloader
 *                            (24-byte boot_message + the file);
 *   anything else         → second stage: run the file server until "Done".
 *
 * File server messages are 260 bytes: int32 command (0 GetFileSize,
 * 1 ReadFile, 2 Done) + 256-byte name. Names starting with '*' carry
 * metadata "*KEY*VALUE" (serial, MAC, key hash, ...).
 *
 * A failed file-server read is NOT proof that the board left: Chrome's WinUSB
 * backend gives every control transfer a fixed ~5 s timeout and reports it as
 * NetworkError, and recovery.bin goes quiet for longer than that while it
 * writes the EEPROM / OTP. Like usbboot's file_server (sleep(1); continue),
 * the read is retried while the device is still attached; the session ends
 * with DeviceGone only once the device is really gone (NotFoundError, closed,
 * a 'disconnect' event, or missing from navigator.usb.getDevices()), and with
 * an error when the board has not asked for anything for idleTimeoutMs.
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});

    const RPI_VID = 0x0a5c;
    const RPI_PIDS = [0x2763, 0x2764, 0x2711, 0x2712];
    const USB_FILTERS = RPI_PIDS.map((productId) => ({ vendorId: RPI_VID, productId }));
    const MAX_TRANSFER = 16 * 1024;        // LIBUSB_MAX_TRANSFER in main.c
    const FILE_MESSAGE_SIZE = 4 + 256;     // struct file_message
    const BOOT_MESSAGE_SIZE = 4 + 20;      // struct MESSAGE_S {int length; uint8 signature[20];}
    const COMMAND_NAMES = ['GetFileSize', 'ReadFile', 'Done'];

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const latin1 = new TextDecoder('latin1');

    function cstr(bytes, off, max) {
        let end = off;
        const lim = Math.min(bytes.length, off + max);
        while (end < lim && bytes[end] !== 0) end++;
        return latin1.decode(bytes.subarray(off, end));
    }

    function isGone(err) {
        // Chrome rejects pending transfers with NetworkError / NotFoundError / InvalidStateError when the device drops
        return !!err && (err.name === 'NetworkError' || err.name === 'NotFoundError' || err.name === 'InvalidStateError' || err.name === 'AbortError');
    }

    class DeviceGone extends Error {
        constructor(msg) { super(msg || 'device disconnected'); this.name = 'DeviceGone'; }
    }

    /**
     * Wraps a WebUSB USBDevice: open, claim the vendor interface, read the
     * device descriptor (for iSerialNumber) and the serial string.
     */
    class RpiDevice {
        constructor(usb) {
            this.usb = usb;
            this.chip = OTP.BootDir.chipForProductId(usb.productId);
            this.outEp = null;
            this.interfaceNumber = null;
            this.iSerial = null;   // string-descriptor index (0/3 = ROM)
            this.bcdDevice = null;
            this.serial = usb.serialNumber || '';
            this.opened = false;
            this.descriptorError = null;
            // usbboot gives every 16 KiB bulk write 5 s (libusb_bulk_transfer timeout) and then fails the file;
            // WebUSB has no transfer timeout, so a board that stops reading would hang the page forever.
            this.bulkStallMs = 10000;
            this.lastWrite = null; // {bytes, ms, chunks, slowestMs, slowestAt} of the last epWrite (shown in the log)
        }

        get isRaspberryPi() { return this.usb.vendorId === RPI_VID && !!this.chip; }
        get isRomStage() { return this.iSerial === 0 || this.iSerial === 3; }
        get stageName() {
            if (this.iSerial === null) return 'unknown';
            return this.isRomStage ? 'ROM (waiting for second stage)' : 'second stage (file server)';
        }

        async open() {
            const d = this.usb;
            if (!d.opened) await d.open();
            if (d.configuration === null) await d.selectConfiguration(1);
            const cfg = d.configuration;
            // main.c: one interface → interface 0 / OUT ep 1; two (2837 with MSD first) → interface 1 / OUT ep 3
            const ifaces = cfg.interfaces;
            const iface = ifaces.length === 1 ? ifaces[0] : ifaces[1];
            this.interfaceNumber = iface.interfaceNumber;
            const alt = iface.alternate || iface.alternates[0];
            const bulkOut = alt.endpoints.find((e) => e.direction === 'out' && e.type === 'bulk');
            this.outEp = bulkOut ? bulkOut.endpointNumber : (ifaces.length === 1 ? 1 : 3);
            await d.claimInterface(this.interfaceNumber);
            this.opened = true;
            await this.readDescriptor();
            return this;
        }

        /** GET_DESCRIPTOR(DEVICE): allowed by WebUSB for standard IN requests; byte 16 is iSerialNumber. */
        async readDescriptor() {
            try {
                const r = await this.usb.controlTransferIn({ requestType: 'standard', recipient: 'device', request: 0x06, value: 0x0100, index: 0 }, 18);
                if (r.status === 'ok' && r.data.byteLength >= 18) {
                    this.iSerial = r.data.getUint8(16);
                    this.bcdDevice = r.data.getUint16(12, true);
                    if (!this.serial && this.iSerial) this.serial = await this.readString(this.iSerial);
                }
            } catch (e) {
                this.descriptorError = e;
            }
        }

        async readString(index) {
            const r = await this.usb.controlTransferIn({ requestType: 'standard', recipient: 'device', request: 0x06, value: (0x03 << 8) | index, index: 0x0409 }, 255);
            if (r.status !== 'ok' || r.data.byteLength < 2) return '';
            const len = Math.min(r.data.getUint8(0), r.data.byteLength);
            const u16 = new Uint8Array(r.data.buffer, r.data.byteOffset + 2, len - 2);
            return new TextDecoder('utf-16le').decode(u16);
        }

        async close() {
            this.opened = false;
            try { if (this.interfaceNumber !== null && this.usb.opened) await this.usb.releaseInterface(this.interfaceNumber); } catch (e) { /* ignore */ }
            try { if (this.usb.opened) await this.usb.close(); } catch (e) { /* ignore */ }
        }

        // ---- protocol primitives -------------------------------------------------

        /** ep_write(): vendor control transfer with the length, then the bytes over bulk OUT in 16 KiB pieces. */
        async epWrite(data, onProgress) {
            const len = data ? data.byteLength : 0;
            const r = await this.usb.controlTransferOut({ requestType: 'vendor', recipient: 'device', request: 0, value: len & 0xffff, index: (len >>> 16) & 0xffff });
            if (r.status !== 'ok') throw new Error(`control transfer failed (${r.status}, len=${len})`);
            const t0 = Date.now();
            const stats = { bytes: 0, ms: 0, chunks: 0, slowestMs: 0, slowestAt: 0 };
            this.lastWrite = stats;
            let sent = 0;
            while (sent < len) {
                const chunk = data.subarray(sent, Math.min(sent + MAX_TRANSFER, len));
                const tc = Date.now();
                let timer = null;
                const stalled = new Promise((resolve) => {
                    timer = setTimeout(() => resolve({ stalled: true }), this.bulkStallMs);
                });
                const out = await Promise.race([this.usb.transferOut(this.outEp, chunk).then((res) => ({ res })), stalled]).finally(() => clearTimeout(timer));
                if (out.stalled) {
                    try { await this.close(); } catch (e2) { /* the pending transfer is abandoned */ }
                    const e = new Error(`the board stopped reading after ${sent} of ${len} bytes (no progress for ${Math.round(this.bulkStallMs / 1000)} s; `
                        + `${stats.chunks} pieces of 16 KiB went through in ${tc - t0} ms, the slowest took ${stats.slowestMs} ms). `
                        + 'Power-cycle the board into RPIBOOT mode and run the stage again.');
                    e.stalled = true;
                    throw e;
                }
                const res = out.res;
                if (res.status !== 'ok') throw new Error(`bulk transfer failed (${res.status}) after ${sent} bytes`);
                const took = Date.now() - tc;
                if (took > stats.slowestMs) { stats.slowestMs = took; stats.slowestAt = sent; }
                sent += res.bytesWritten;
                stats.chunks++;
                stats.bytes = sent;
                stats.ms = Date.now() - t0;
                if (onProgress) onProgress(sent, len);
            }
            return sent;
        }

        /** ep_read(): vendor control IN of `len` bytes. */
        async epRead(len) {
            const r = await this.usb.controlTransferIn({ requestType: 'vendor', recipient: 'device', request: 0, value: len & 0xffff, index: (len >>> 16) & 0xffff }, len);
            if (r.status !== 'ok') { const e = new Error(`control IN failed (${r.status})`); e.status = r.status; throw e; }
            return new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength);
        }
    }

    /**
     * One rpiboot run against one boot directory:
     *   session.step(device) → { kind: 'second-stage-sent' | 'file-server-done', ... }
     * The caller decides what to do when the device re-enumerates (the app
     * waits for the WebUSB connect event and calls step() again).
     * hooks: log, onProgress, onMetadata; usb (navigator.usb or a stand-in, used to tell a read timeout from a
     * disconnect; default navigator.usb), retryMs (1000, pause between failed reads), idleTimeoutMs (180000,
     * give up when the file server has had no request for that long while the board stays attached).
     * `handedOff` is true once the device of the current step has been handed control (the whole second stage
     * was written to the ROM, or the file server received a request): that USBDevice is about to go away.
     */
    class RpiBootSession {
        constructor(bootDir, hooks) {
            hooks = hooks || {};
            this.bootDir = bootDir;
            this.log = hooks.log || (() => {});
            this.onProgress = hooks.onProgress || (() => {});
            this.onMetadata = hooks.onMetadata || (() => {});
            this.usb = hooks.usb !== undefined ? hooks.usb : (typeof navigator !== 'undefined' && navigator.usb) || null;
            this.retryMs = hooks.retryMs || 1000;
            this.idleTimeoutMs = hooks.idleTimeoutMs || 180000;
            this.metadata = {};
            this.metadataOrder = [];
            this.filesServed = [];
            this.aborted = false;
            this.handedOff = false;
            this.device = null;
            this._wakers = new Set();
        }

        abort() {
            this.aborted = true;
            this._wake();
            if (this.device) this.device.close(); // rejects the pending control transfer
        }

        _wake() { for (const w of [...this._wakers]) w(); }

        /** sleep(ms) that abort() and a 'disconnect' of the current device cut short. */
        _pause(ms) {
            return new Promise((resolve) => {
                const done = () => { clearTimeout(t); this._wakers.delete(done); resolve(); };
                const t = setTimeout(done, ms);
                this._wakers.add(done);
            });
        }

        /** How a file went over bulk: the baseline to compare a stalled transfer against. */
        _logWrite(name, w) {
            if (!w || w.chunks < 2) return;
            const mbps = w.ms > 0 ? (w.bytes / 1048576) / (w.ms / 1000) : 0;
            this.log('debug', `Sent ${name}: ${w.bytes} bytes in ${w.ms} ms (${mbps ? mbps.toFixed(1) + ' MiB/s' : 'instant'}, ${w.chunks} pieces, `
                + `slowest ${w.slowestMs} ms at ${w.slowestAt})`);
        }

        /** Is the board behind `dev` still on the bus? (a failed transfer alone does not say so on Windows) */
        async _stillAttached(dev, unplugged) {
            if (unplugged() || !dev.usb.opened) return false;
            if (this.usb && this.usb.getDevices) {
                try {
                    if (!(await this.usb.getDevices()).includes(dev.usb)) return false;
                } catch (e) { /* cannot tell: rely on the other signals */ }
            }
            return true;
        }

        async step(rpiDevice) {
            this.device = rpiDevice;
            this.handedOff = false;
            if (!rpiDevice.chip) throw new Error(`Unknown Raspberry Pi product 0x${rpiDevice.usb.productId.toString(16)}`);
            if (!rpiDevice.opened) await rpiDevice.open();
            this.log('info', `Found ${rpiDevice.chip.name} (${rpiDevice.chip.board}) serial ${rpiDevice.serial || '?'} iSerialNumber=${rpiDevice.iSerial === null ? '?' : rpiDevice.iSerial}`);
            const u = rpiDevice.usb;
            if (typeof u.usbVersionMajor === 'number') this.log('debug', `USB ${u.usbVersionMajor}.${u.usbVersionMinor}${u.usbVersionSubminor || ''}, bcdDevice ${rpiDevice.bcdDevice === null ? '?' : rpiDevice.bcdDevice.toString(16).padStart(4, '0')}`);
            try {
                if (rpiDevice.iSerial === null) {
                    this.log('warn', 'Could not read the device descriptor; assuming boot ROM stage');
                    rpiDevice.iSerial = 3;
                }
                if (rpiDevice.isRomStage) return await this.secondStageBoot(rpiDevice);
                return await this.fileServer(rpiDevice);
            } finally {
                await rpiDevice.close();
                this.device = null;
            }
        }

        // second_stage_boot(): boot_message {length, signature[20]} + the file, then a 4-byte return code
        async secondStageBoot(dev) {
            const name = dev.chip.secondStage;
            const found = await this.bootDir.resolve(name, dev.chip);
            if (!found || found.denied) throw new Error(`Failed to open second stage bootloader (${name}) in "${this.bootDir.name}"`);
            const code = found.data;
            this.log('info', `Sending ${name} (${code.byteLength} bytes) from ${found.origin}`);
            const msg = new Uint8Array(BOOT_MESSAGE_SIZE);
            new DataView(msg.buffer).setInt32(0, code.byteLength, true);
            let n = await dev.epWrite(msg);
            if (n !== BOOT_MESSAGE_SIZE) throw new Error(`Failed to write correct length, returned ${n}`);
            n = await dev.epWrite(code, (sent, total) => this.onProgress(name, sent, total));
            this._logWrite(name, dev.lastWrite);
            if (n !== code.byteLength) throw new Error(`Failed to write second stage, sent ${n} of ${code.byteLength}`);
            this.handedOff = true; // the ROM runs the second stage now and re-enumerates
            await sleep(1000);
            let retcode = null;
            try {
                const rc = await dev.epRead(4);
                retcode = rc.byteLength >= 4 ? new DataView(rc.buffer, rc.byteOffset, 4).getInt32(0, true) : null;
            } catch (e) {
                if (!isGone(e)) throw e;
                this.log('info', 'Device re-enumerated before returning a status (normal)');
            }
            if (retcode === 0) this.log('ok', 'Second stage accepted (status 0); the device will re-enumerate');
            else if (retcode !== null) throw new Error(`Second stage rejected: status 0x${(retcode >>> 0).toString(16)}`);
            return { kind: 'second-stage-sent', iSerial: dev.iSerial, retcode };
        }

        // file_server(): answer GetFileSize / ReadFile / Done and collect "*KEY*VALUE" metadata
        async fileServer(dev) {
            this.log('info', 'Second stage boot server');
            let unplugged = false;
            const onDisconnect = (ev) => { if (ev && ev.device === dev.usb) { unplugged = true; this._wake(); } };
            const hub = this.usb && this.usb.addEventListener ? this.usb : null;
            if (hub) hub.addEventListener('disconnect', onDisconnect);
            try {
                return await this._fileServerLoop(dev, () => unplugged);
            } finally {
                if (hub && hub.removeEventListener) hub.removeEventListener('disconnect', onDisconnect);
            }
        }

        async _fileServerLoop(dev, unplugged) {
            let current = null; // {name, data, origin}
            let going = true;
            let metadataIndex = 0;
            let lastRequest = Date.now();
            let failures = 0;
            const gone = () => { this.log('warn', 'Device went away during the file server'); return new DeviceGone(); };
            while (going && !this.aborted) {
                let msg;
                try {
                    msg = await dev.epRead(FILE_MESSAGE_SIZE);
                } catch (e) {
                    if (this.aborted) break;
                    // usbboot: drop out only when the device went away; a timeout is retried (sleep(1); continue)
                    if ((e && e.name === 'NotFoundError') || !(await this._stillAttached(dev, unplugged))) throw gone();
                    const quiet = Date.now() - lastRequest;
                    const why = `${(e && e.name) || 'Error'}: ${(e && (e.status || e.message)) || e}`;
                    if (quiet >= this.idleTimeoutMs) {
                        throw new Error(`the board is still attached but has not asked for anything for ${Math.round(quiet / 1000)} s (last read: ${why})`);
                    }
                    failures++;
                    if (failures === 1) this.log('info', `Read failed (${why}); the board is still attached (busy writing the EEPROM / OTP?), retrying every ${Math.round(this.retryMs / 100) / 10} s`);
                    else this.log('debug', `Read failed again (${why}), ${Math.round(quiet / 1000)} s since the last request`);
                    await this._pause(this.retryMs);
                    if (this.aborted) break;
                    if (!(await this._stillAttached(dev, unplugged))) throw gone();
                    continue;
                }
                if (failures) {
                    this.log('info', `The board answered again after ${Math.round((Date.now() - lastRequest) / 1000)} s`);
                    failures = 0;
                }
                lastRequest = Date.now();
                if (msg.byteLength < 4) { await sleep(200); continue; }
                const command = new DataView(msg.buffer, msg.byteOffset, 4).getInt32(0, true);
                const fname = cstr(msg, 4, 256);
                this.log('debug', `← ${COMMAND_NAMES[command] || 'cmd ' + command}: ${fname || '(empty)'}`);

                this.handedOff = true; // the board runs the second stage and moves on from here
                if (fname.length === 0) { await dev.epWrite(null); break; }   // "Done can also just be null filename"

                if (fname[0] === '*' && command !== 2) {
                    this.addMetadata(fname.slice(1), metadataIndex++);
                    await dev.epWrite(null);
                    continue;
                }

                switch (command) {
                    case 0: { // GetFileSize
                        const found = await this.bootDir.resolve(fname, dev.chip);
                        if (found && found.denied) {
                            this.log('warn', `Denying request for ${fname}: ${found.reason}`);
                            current = null;
                            await dev.epWrite(null);
                        } else if (found) {
                            current = { name: fname, data: found.data, origin: found.origin };
                            this.log('info', `Loading: ${found.origin} (${found.data.byteLength} bytes)`);
                            const size = found.data.byteLength;
                            const r = await dev.usb.controlTransferOut({ requestType: 'vendor', recipient: 'device', request: 0, value: size & 0xffff, index: (size >>> 16) & 0xffff });
                            if (r.status !== 'ok') throw new Error(`GetFileSize reply failed (${r.status})`);
                        } else {
                            current = null;
                            this.log('warn', `Cannot open file ${fname}`);
                            await dev.epWrite(null);
                        }
                        break;
                    }
                    case 1: { // ReadFile
                        if (current) {
                            this.log('info', `File read: ${fname}`);
                            if (!current.data.byteLength) this.log('warn', `WARNING: ${fname} is empty`);
                            const total = current.data.byteLength;
                            const sent = await dev.epWrite(current.data, (s, t) => this.onProgress(fname, s, t));
                            this._logWrite(fname, dev.lastWrite);
                            this.filesServed.push({ name: fname, size: total, origin: current.origin });
                            current = null;
                            if (sent !== total) throw new Error('Failed to write complete file to USB device');
                        } else {
                            this.log('debug', `No file ${fname} found`);
                            await dev.epWrite(null);
                        }
                        break;
                    }
                    case 2: // Done
                        going = false;
                        break;
                    default:
                        throw new Error(`Unknown message ${command}`);
                }
            }
            if (this.aborted) throw new Error('aborted');
            this.log('ok', 'Second stage boot server done');
            return { kind: 'file-server-done', metadata: this.metadata, filesServed: this.filesServed };
        }

        // write_metadata_file(): "KEY*VALUE" tokens; FACTORY_UUID is C40-encoded
        addMetadata(str, index) {
            const tokens = str.split('*').filter((t) => t !== '');
            if (tokens.length < 2) return;
            const property = tokens[0];
            let value = tokens[1];
            if (property === 'FACTORY_UUID') {
                const decoded = OTP.duid.decodeC40(value);
                if (decoded === null) this.log('warn', 'Failed to decode a FACTORY_UUID: invalid input');
                else value = decoded;
            }
            this.metadata[property] = value;
            this.metadataOrder.push(property);
            this.log('meta', `${property} = ${value}`);
            this.onMetadata(property, value, this.metadata);
        }

        /** The <serial>.json rpiboot -j would write. */
        metadataJson(serial) {
            const obj = {};
            for (const k of this.metadataOrder) obj[k] = this.metadata[k];
            return { name: `${serial || 'unknown'}.json`, text: JSON.stringify(obj, null, '\t') + '\n' };
        }
    }

    /**
     * rpiboot's main loop across re-enumerations: while the board is in the ROM stage send the second stage
     * and wait for the next enumeration; then run the file server until "Done" (or until the board leaves USB,
     * which is normal when a ramdisk takes over: the result is then marked `interrupted`).
     *   waitNext(previousUsb) → Promise<USBDevice>  the next enumeration of the same board
     *   opts.maxHops (6), opts.onDevice(usb), opts.log(level, msg), opts.settleMs (1000)
     * Every enumeration is left alone for settleMs before it is opened: rpiboot finds the device, sleep(1)s, and only
     * then libusb_open()s it (main.c, open_device_with_vid). Opened right away (2 ms after the connect event), the
     * Pi 5 second stage stopped reading pieeprom.bin a few dozen milliseconds into the transfer, at a different
     * offset every run (144, 416, 480 KiB of 2 MiB; Windows, WinUSB), while rpiboot.exe went through on the same
     * board, port and cable; with the pause the page provisions that board end to end.
     * Returns {result, usb, serial}: result = {kind:'file-server-done', metadata, filesServed, interrupted?}.
     */
    async function runSession(session, usb, waitNext, opts) {
        opts = opts || {};
        const log = opts.log || session.log;
        let lastISerial = -1;
        let serial = usb.serialNumber || '';
        const settleMs = typeof opts.settleMs === 'number' ? opts.settleMs : 1000;
        for (let hop = 0; hop < (opts.maxHops || 6) && !session.aborted; hop++) {
            if (settleMs > 0) {
                await session._pause(settleMs);
                if (session.aborted) break;
            }
            const dev = new RpiDevice(usb);
            await dev.open();
            if (dev.serial) serial = dev.serial;
            if (dev.iSerial !== null && dev.iSerial === lastISerial) {
                // same enumeration as last time (rpiboot: last_serial) → keep waiting
                await dev.close();
                log('debug', 'Same enumeration as before; waiting for a new one');
                usb = await waitNext(usb);
                session.handedOff = false;
                if (opts.onDevice) opts.onDevice(usb);
                continue;
            }
            lastISerial = dev.iSerial;
            let r;
            try {
                r = await session.step(dev);
            } catch (e) {
                if (!(e instanceof DeviceGone)) throw e;
                log('warn', 'The board left USB before "Done"; keeping what was collected');
                r = { kind: 'file-server-done', metadata: session.metadata, filesServed: session.filesServed, interrupted: true };
            }
            if (r.kind === 'file-server-done') return { result: r, usb, serial };
            log('info', 'Waiting for the board to re-enumerate as the second stage…');
            usb = await waitNext(usb);
            session.handedOff = false; // nothing was handed to the new enumeration yet
            if (opts.onDevice) opts.onDevice(usb);
        }
        if (session.aborted) throw new Error('aborted');
        throw new Error('the board kept re-enumerating in the ROM stage; check the second-stage file');
    }

    OTP.rpiboot = { RPI_VID, RPI_PIDS, USB_FILTERS, RpiDevice, RpiBootSession, DeviceGone, isGone, sleep, runSession };
})();
