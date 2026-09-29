/*
 * fastboot.js — a minimal fastboot host on top of WebUSB.
 *
 * This is the transport for stage 3 (writing the image). Once the
 * provisioning agent (pi-gen-micro / rpi-fastbootd gadget) runs on the
 * module, the station drives it with the IDP sequence used by
 * rpi-image-gen/bin/idp.sh:
 *
 *   stage image.json → oem idpinit → oem idpwrite → loop { oem idpgetblk → flash <dev> <image> } → oem idpdone
 *
 * Protocol (AOSP fastboot/README.md): host sends an ASCII command in one
 * bulk packet; the device answers with one packet starting with OKAY, FAIL,
 * DATA or INFO/TEXT (INFO/TEXT may repeat before the final OKAY/FAIL).
 * "download:%08x" is answered with "DATA%08x", then the host sends the raw
 * bytes, then the device says OKAY. "flash:<name>" writes the downloaded
 * buffer.
 *
 * NOT VERIFIED ON HARDWARE YET. Images larger than max-download-size need
 * sparse-image splitting, which is not implemented here (the CLI does it).
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});

    const FILTERS = [{ classCode: 0xff, subclassCode: 0x42, protocolCode: 0x03 }];
    const RESPONSE_SIZE = 256;
    const DATA_CHUNK = 1024 * 1024;
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    class FastbootError extends Error {
        constructor(msg, response) { super(msg); this.name = 'FastbootError'; this.response = response; }
    }

    class FastbootClient {
        constructor(usb) {
            this.usb = usb;
            this.inEp = null;
            this.outEp = null;
            this.interfaceNumber = null;
            this.maxDownloadSize = null;
            this.log = () => {};
        }

        static get FILTERS() { return FILTERS; }

        async open() {
            const d = this.usb;
            if (!d.opened) await d.open();
            if (d.configuration === null) await d.selectConfiguration(1);
            let found = null;
            for (const iface of d.configuration.interfaces) {
                for (const alt of iface.alternates) {
                    if (alt.interfaceClass === 0xff && alt.interfaceSubclass === 0x42 && alt.interfaceProtocol === 0x03) {
                        found = { iface, alt };
                        break;
                    }
                }
                if (found) break;
            }
            if (!found) throw new FastbootError('no fastboot interface (class ff/42/03) on this device');
            this.interfaceNumber = found.iface.interfaceNumber;
            await d.claimInterface(this.interfaceNumber);
            if (found.alt.alternateSetting !== 0) await d.selectAlternateInterface(this.interfaceNumber, found.alt.alternateSetting);
            const bulkIn = found.alt.endpoints.find((e) => e.direction === 'in' && e.type === 'bulk');
            const bulkOut = found.alt.endpoints.find((e) => e.direction === 'out' && e.type === 'bulk');
            if (!bulkIn || !bulkOut) throw new FastbootError('fastboot interface without bulk endpoints');
            this.inEp = bulkIn.endpointNumber;
            this.outEp = bulkOut.endpointNumber;
            return this;
        }

        async close() {
            try { if (this.interfaceNumber !== null && this.usb.opened) await this.usb.releaseInterface(this.interfaceNumber); } catch (e) { /* ignore */ }
            try { if (this.usb.opened) await this.usb.close(); } catch (e) { /* ignore */ }
        }

        async _readPacket() {
            const r = await this.usb.transferIn(this.inEp, RESPONSE_SIZE);
            if (r.status !== 'ok') throw new FastbootError(`bulk IN failed (${r.status})`);
            return dec.decode(new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength));
        }

        /** Read INFO/TEXT lines until OKAY / FAIL / DATA. */
        async readResponse() {
            const infos = [];
            for (;;) {
                const pkt = await this._readPacket();
                const status = pkt.slice(0, 4);
                const message = pkt.slice(4);
                if (status === 'INFO' || status === 'TEXT') {
                    infos.push(message);
                    this.log('info', status === 'INFO' ? `(bootloader) ${message}` : message);
                    continue;
                }
                if (status === 'OKAY') return { status, message, infos };
                if (status === 'FAIL') throw new FastbootError(`FAIL ${message}`, { status, message, infos });
                if (status === 'DATA') return { status, message, infos, dataSize: parseInt(message.slice(0, 8), 16) };
                throw new FastbootError(`unexpected response "${pkt}"`);
            }
        }

        async command(cmd) {
            this.log('debug', `→ ${cmd}`);
            const r = await this.usb.transferOut(this.outEp, enc.encode(cmd));
            if (r.status !== 'ok') throw new FastbootError(`bulk OUT failed (${r.status})`);
            return this.readResponse();
        }

        async getvar(name) {
            const r = await this.command(`getvar:${name}`);
            return r.message;
        }

        /** getvar:all returns one INFO line per variable ("name: value"). */
        async getvarAll() {
            const r = await this.command('getvar:all');
            const vars = {};
            for (const line of r.infos) {
                const i = line.indexOf(':');
                if (i > 0) vars[line.slice(0, i).trim()] = line.slice(i + 1).trim();
            }
            return vars;
        }

        async ensureMaxDownloadSize() {
            if (this.maxDownloadSize) return this.maxDownloadSize;
            const v = await this.getvar('max-download-size');
            this.maxDownloadSize = parseInt(v, v.startsWith('0x') ? 16 : 10) || 0;
            return this.maxDownloadSize;
        }

        /** download:%08x + the bytes. Equivalent of "fastboot stage <file>" when not followed by flash. */
        async download(bytes, onProgress) {
            const size = bytes.byteLength;
            const max = await this.ensureMaxDownloadSize();
            if (max && size > max) throw new FastbootError(`image is ${size} bytes but max-download-size is ${max}; sparse splitting is not implemented`);
            const r = await this.command(`download:${size.toString(16).padStart(8, '0')}`);
            if (r.status !== 'DATA') throw new FastbootError(`expected DATA, got ${r.status}`);
            if (r.dataSize !== size) throw new FastbootError(`device accepts ${r.dataSize} bytes, wanted ${size}`);
            let sent = 0;
            while (sent < size) {
                const chunk = bytes.subarray(sent, Math.min(sent + DATA_CHUNK, size));
                const w = await this.usb.transferOut(this.outEp, chunk);
                if (w.status !== 'ok') throw new FastbootError(`bulk OUT failed (${w.status}) after ${sent} bytes`);
                sent += w.bytesWritten;
                if (onProgress) onProgress(sent, size);
            }
            return this.readResponse();
        }

        async flash(partition, bytes, onProgress) {
            await this.download(bytes, onProgress);
            return this.command(`flash:${partition}`);
        }

        async oem(cmd) { return this.command(`oem ${cmd}`); }
        async reboot() { return this.command('reboot'); }
        async continueBoot() { return this.command('continue'); }

        /**
         * The IDP flow of rpi-image-gen/bin/idp.sh.
         * readImage(name) → Uint8Array of a sparse image next to image.json.
         */
        async provisionIdp(imageJsonBytes, readImage, onProgress) {
            this.log('info', 'Staging description..');
            await this.download(imageJsonBytes, onProgress);
            this.log('info', 'Checking if provisioning is possible..');
            await this.oem('idpinit');
            this.log('info', 'Initiating provisioning..');
            await this.oem('idpwrite');
            for (;;) {
                const r = await this.oem('idpgetblk');
                const pairs = r.infos.map((l) => l.match(/^([^:]+):(.+)$/)).filter(Boolean);
                if (!pairs.length) break;
                for (const m of pairs) {
                    const dev = m[1].trim();
                    const image = m[2].trim();
                    const bytes = await readImage(image);
                    if (!bytes) throw new FastbootError(`image "${image}" not found next to image.json`);
                    this.log('info', `Writing ${image} (${bytes.byteLength} bytes) to ${dev}`);
                    await this.flash(dev, bytes, (s, t) => onProgress && onProgress(s, t, image));
                }
            }
            this.log('info', 'Complete');
            await this.oem('idpdone');
        }
    }

    OTP.fastboot = { FastbootClient, FastbootError, FILTERS };
})();
