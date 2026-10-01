/*
 * fastboot.js — a fastboot host on top of WebUSB.
 *
 * This is the transport for stage 3 (writing the image). Once the fastboot
 * gadget (pi-gen-micro "fastboot" ramdisk with rpi-fastbootd) runs on the
 * board, the station drives it with the IDP sequence of rpi-sb-provisioner
 * (rpi-idp-provisioner.sh) / rpi-image-gen bin/idp.sh:
 *
 *   oem fwcrypto init → getvar:public-key → erase:<disk> (+3 s) →
 *   download image.json → oem idpinit → oem idpwrite →
 *   loop { oem idpgetblk → download + flash:<dev> for every piece } →
 *   oem cryptsetpassword <container> <passphrase> → oem idpdone → reboot
 *
 * Wire protocol (AOSP fastboot, unmodified in rpi-fastbootd): the host sends
 * one ASCII command (at most 256 bytes — the daemon reads 256), the device
 * answers with 256-byte packets starting with INFO/TEXT (repeatable), then
 * OKAY / FAIL / DATA. "download:%08x" is answered with "DATA%08x", then the
 * raw bytes, then OKAY. The daemon reads the data phase as chained 64 KiB
 * FunctionFS reads, so every transferOut of a data phase except the last
 * must be a multiple of 64 KiB (a short packet mid-stream desynchronises it).
 *
 * The device identifies as USB 18d1:4e40 (manufacturer "Raspberry Pi",
 * serial = 16-hex board serial) with a vendor interface ff/42/03.
 *
 * Secure scenario: before any of the above, exportDeviceKey() fetches the board's OTP device key from
 * our gadget helper (otp-keyexport) with "oem upload-file" + "upload" ("upload" answers DATA%08x, then
 * the device sends the bytes, then OKAY), so the server can keep it.
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});

    const FASTBOOT_VID = 0x18d1;
    const FASTBOOT_PID = 0x4e40;
    const FILTERS = [
        { vendorId: FASTBOOT_VID, productId: FASTBOOT_PID },
        { classCode: 0xff, subclassCode: 0x42, protocolCode: 0x03 },
    ];
    const RESPONSE_SIZE = 256;
    const MAX_COMMAND = 256;             // rpi-fastbootd reads at most FB_RESPONSE_SZ bytes per command
    const DATA_ALIGN = 64 * 1024;        // io_uring read size on the device
    const DATA_CHUNK = 16 * DATA_ALIGN;  // 1 MiB per transferOut, a multiple of 64 KiB
    const MAX_IDP_BLOCKS = 64;           // safety net against a device that never says "done"
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    class FastbootError extends Error {
        constructor(msg, response) { super(msg); this.name = 'FastbootError'; this.response = response; }
    }

    /** Strip NULs and surrounding whitespace (device-tree strings carry a trailing NUL). */
    function clean(s) { return String(s || '').replace(/\0/g, '').trim(); }

    function isFastbootDevice(usb) {
        if (!usb) return false;
        if (usb.vendorId === FASTBOOT_VID && usb.productId === FASTBOOT_PID) return true;
        const cfgs = usb.configurations || (usb.configuration ? [usb.configuration] : []);
        for (const c of cfgs) {
            for (const iface of c.interfaces || []) {
                for (const alt of iface.alternates || []) {
                    if (alt.interfaceClass === 0xff && alt.interfaceSubclass === 0x42 && alt.interfaceProtocol === 0x03) return true;
                }
            }
        }
        return false;
    }

    class FastbootClient {
        constructor(usb) {
            this.usb = usb;
            this.inEp = null;
            this.outEp = null;
            this.interfaceNumber = null;
            this.maxDownloadSize = null;
            this.eraseSettleMs = 3000;   // rpi-sb-provisioner sleeps 3 s after erase so udev settles
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
                const message = pkt.slice(4).replace(/\0+$/, '');
                if (status === 'INFO' || status === 'TEXT') {
                    infos.push(message);
                    this.log('info', status === 'INFO' ? `(bootloader) ${message}` : message);
                    continue;
                }
                if (status === 'OKAY') return { status, message, infos };
                if (status === 'FAIL') throw new FastbootError(`FAIL ${message}`, { status, message, infos });
                if (status === 'DATA') return { status, message, infos, dataSize: parseInt(message.slice(0, 8), 16) };
                throw new FastbootError(`unexpected response "${pkt.slice(0, 64)}"`);
            }
        }

        /**
         * Send one command and read its response.
         * `logAs` replaces the command text in the log (used to keep passphrases out of it).
         */
        async command(cmd, logAs) {
            const bytes = enc.encode(cmd);
            if (bytes.byteLength > MAX_COMMAND) {
                throw new FastbootError(`command is ${bytes.byteLength} bytes; rpi-fastbootd reads at most ${MAX_COMMAND}: ${(logAs || cmd).slice(0, 48)}…`);
            }
            if (/[\x00-\x1f\x7f]/.test(cmd)) throw new FastbootError('command contains a control character');
            this.log('debug', `→ ${logAs || cmd}`);
            const r = await this.usb.transferOut(this.outEp, bytes);
            if (r.status !== 'ok') throw new FastbootError(`bulk OUT failed (${r.status})`);
            return this.readResponse();
        }

        async getvar(name) {
            const r = await this.command(`getvar:${name}`);
            return r.message;
        }

        /** getvar as text: INFO lines + the OKAY payload joined with newlines, NULs and outer whitespace removed. */
        async getvarText(name) {
            const r = await this.command(`getvar:${name}`);
            return clean([...r.infos.map(clean), clean(r.message)].filter((s) => s !== '').join('\n'));
        }

        /** getvar:all returns one INFO line per variable ("name: value"). */
        async getvarAll() {
            const r = await this.command('getvar:all');
            const vars = {};
            for (const line of r.infos) {
                const i = line.indexOf(':');
                if (i > 0) vars[line.slice(0, i).trim()] = clean(line.slice(i + 1));
            }
            return vars;
        }

        /** Read several variables, skipping the ones the daemon does not know. */
        async getvars(names) {
            const out = {};
            for (const n of names) {
                try { out[n] = await this.getvarText(n); } catch (e) { if (!(e instanceof FastbootError)) throw e; }
            }
            return out;
        }

        async ensureMaxDownloadSize() {
            if (this.maxDownloadSize) return this.maxDownloadSize;
            const v = clean(await this.getvar('max-download-size'));
            this.maxDownloadSize = parseInt(v, /^0x/i.test(v) ? 16 : 10) || 0;
            return this.maxDownloadSize;
        }

        /** download:%08x + the bytes (the "stage" of the fastboot CLI). Rejects payloads above max-download-size. */
        async download(bytes, onProgress) {
            const size = bytes.byteLength;
            if (!size) throw new FastbootError('refusing to download an empty payload');
            const max = await this.ensureMaxDownloadSize();
            if (max && size > max) throw new FastbootError(`payload is ${size} bytes but max-download-size is ${max}; it must be split into sparse pieces on the server`);
            const r = await this.command(`download:${size.toString(16).padStart(8, '0')}`);
            if (r.status !== 'DATA') throw new FastbootError(`expected DATA, got ${r.status}`);
            if (r.dataSize !== size) throw new FastbootError(`device accepts ${r.dataSize} bytes, wanted ${size}`);
            let sent = 0;
            while (sent < size) {
                const chunk = bytes.subarray(sent, Math.min(sent + DATA_CHUNK, size));
                const w = await this.usb.transferOut(this.outEp, chunk);
                if (w.status !== 'ok') throw new FastbootError(`bulk OUT failed (${w.status}) after ${sent} bytes`);
                if (w.bytesWritten !== chunk.byteLength) throw new FastbootError(`short bulk write (${w.bytesWritten} of ${chunk.byteLength}) after ${sent} bytes`);
                sent += w.bytesWritten;
                if (onProgress) onProgress(sent, size);
            }
            return this.readResponse();
        }

        async flash(partition, bytes, onProgress) {
            await this.download(bytes, onProgress);
            return this.command(`flash:${partition}`);
        }

        /**
         * "upload": the device sends what the last "oem upload-file" staged — DATA%08x, the bytes, OKAY.
         * Every read asks for exactly the bytes still due, so the OKAY packet is never swallowed.
         */
        async upload() {
            const r = await this.command('upload');
            if (r.status !== 'DATA') throw new FastbootError(`expected DATA, got ${r.status}`);
            const size = r.dataSize;
            const out = new Uint8Array(size);
            let got = 0;
            while (got < size) {
                const t = await this.usb.transferIn(this.inEp, Math.min(DATA_CHUNK, size - got));
                if (t.status !== 'ok') throw new FastbootError(`bulk IN failed (${t.status}) after ${got} bytes`);
                const chunk = new Uint8Array(t.data.buffer, t.data.byteOffset, t.data.byteLength);
                if (got + chunk.byteLength > size) throw new FastbootError(`the device sent more than the ${size} bytes it announced`);
                out.set(chunk, got);
                got += chunk.byteLength;
            }
            await this.readResponse();
            return out;
        }

        /** The bytes of a file on the gadget ("oem upload-file <path>" + "upload"); null when it does not exist or is empty. */
        async uploadFile(path) {
            if (!path || /\s/.test(path)) throw new FastbootError(`invalid path "${path}"`);
            try {
                await this.oem(`upload-file ${path}`);
            } catch (e) {
                if (e instanceof FastbootError && /ERRNO|opening file|size ?zero/i.test(e.message)) return null;
                throw e;
            }
            return this.upload();
        }

        /** Write bytes to a file on the gadget ("download" + "oem download-file <path>"). */
        async downloadFile(path, bytes) {
            if (!path || /\s/.test(path)) throw new FastbootError(`invalid path "${path}"`);
            await this.download(bytes);
            return this.oem(`download-file ${path}`);
        }

        /**
         * Hand the board's OTP device private key to the station (secure scenario), through the gadget's
         * otp-keyexport helper (paths from the stage-3 manifest's key_export: {key, status, request}).
         * The helper exports an existing key at gadget boot, before rpi-fastbootd READ-locks it; a blank
         * slot is generated on request (IRREVERSIBLE, the same OTP write as "oem fwcrypto init").
         * Returns {der, generated}. The key bytes are never logged.
         */
        async exportDeviceKey(keyExport, opts) {
            const ke = keyExport || {};
            const o = Object.assign({ timeoutMs: 30000, pollMs: 500, log: null }, opts || {});
            const say = o.log || this.log;
            const statusText = async () => {
                const b = await this.uploadFile(ke.status);
                return b ? clean(dec.decode(b)) : '';
            };
            let der = await this.uploadFile(ke.key);
            let generated = false;
            if (!der) {
                const st = await statusText();
                if (!st) throw new FastbootError('this fastboot gadget has no OTP key export helper (otp-keyexport): rebuild the gadget on the server');
                if (/^locked/.test(st)) throw new FastbootError(`the OTP device key cannot be exported in this boot (${st}); run stage 2 again to reboot the gadget`);
                if (/^error/.test(st)) throw new FastbootError(`the gadget could not read the OTP device key: ${st}`);
                generated = /^blank/.test(st);
                say('info', generated ? 'OTP key slot is empty: the gadget generates the device key (OTP write) and exports it…'
                    : `asking the gadget to export the device key (${st})…`);
                await this.downloadFile(ke.request, enc.encode('export\n'));
                const deadline = Date.now() + o.timeoutMs;
                for (;;) {
                    await sleep(o.pollMs);
                    der = await this.uploadFile(ke.key);
                    if (der) break;
                    const s2 = await statusText();
                    if (/^(locked|error)/.test(s2)) throw new FastbootError(`the OTP device key export failed: ${s2}`);
                    if (Date.now() > deadline) throw new FastbootError(`the gadget did not export the device key within ${Math.round(o.timeoutMs / 1000)} s (${s2 || 'no status'})`);
                }
            }
            say('ok', `OTP device key exported by the gadget (${der.byteLength} bytes${generated ? ', generated now' : ''})`);
            return { der, generated };
        }

        async oem(cmd) { return this.command(`oem ${cmd}`); }
        async reboot() { return this.command('reboot'); }

        /**
         * oem fwcrypto init: creates the device ECDSA key in OTP (IRREVERSIBLE, idempotent).
         * Returns {message, created}: created=false when the key already existed.
         */
        async fwcryptoInit() {
            const r = await this.oem('fwcrypto init');
            const message = clean(r.message);
            return { message, created: /provisioned and lock/i.test(message) };
        }

        /** getvar:public-key → PEM of the OTP device key, or null when the daemon does not return one. */
        async publicKey() {
            let text;
            try { text = await this.getvarText('public-key'); } catch (e) { if (e instanceof FastbootError) return null; throw e; }
            const m = text.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/);
            return m ? m[0] + '\n' : null;
        }

        /** erase:<dev>, then wait so udev settles (idpinit otherwise may see "storage device not ready"). */
        async erase(dev) {
            const r = await this.command(`erase:${dev}`);
            if (this.eraseSettleMs > 0) await sleep(this.eraseSettleMs);
            return r;
        }

        /**
         * oem idpgetblk → {dev, simage} from the INFO "<dev>:<simage>" line, or null when the device answers
         * only "OKAYIDP:done" (the list is exhausted). The OKAY payload itself is never parsed.
         */
        async idpGetBlk() {
            const r = await this.oem('idpgetblk');
            for (const raw of r.infos) {
                const m = clean(raw).match(/^([A-Za-z0-9_./-]+):([^\s:/]+)$/);
                if (m) return { dev: m[1], simage: m[2] };
            }
            return null;
        }

        /** oem cryptsetpassword <dev> <pass>: adds the passphrase as LUKS keyslot 1. The passphrase never reaches the log. */
        async cryptSetPassword(dev, pass) {
            if (!dev || /\s/.test(dev)) throw new FastbootError(`invalid container device "${dev}"`);
            if (!pass || /\s/.test(pass)) throw new FastbootError('the passphrase must be a single token without spaces');
            return this.command(`oem cryptsetpassword ${dev} ${pass}`, `oem cryptsetpassword ${dev} <redacted>`);
        }

        async _idpDoneQuietly() {
            try { await this.oem('idpdone'); } catch (e) { this.log('warn', `oem idpdone after failure: ${e.message || e}`); }
        }

        /**
         * The IDP provisioning of stage 3.
         * opts:
         *   imageJson       Uint8Array (image.json)
         *   parts           {simage: [piece, ...]} with piece {name, size?, url?, bytes?}
         *   readPiece       async (piece) → Uint8Array (default: piece.bytes)
         *   storageDevice   disk to erase (default "mmcblk0")
         *   erase           erase the disk first (default true)
         *   fwcryptoInit    run "oem fwcrypto init" + read the public key first (default true)
         *   crypt           [{dev, mname, passphrase}] → oem cryptsetpassword before idpdone
         *   reboot          send "reboot" at the end (default true)
         *   totalBytes      for the progress callback (default: sum of piece sizes)
         *   onProgress      ({sent, total, piece, dev, phase}) → void
         *   onDeviceKey     async (pem) → void, called as soon as the public key is known
         *   log             (level, msg) → void
         * Returns {flashed: [{dev, simage, pieces, bytes}], crypt: [{dev, mname}], device_key_pem, fwcrypto}.
         */
        async idpProvision(opts) {
            const o = Object.assign({ storageDevice: 'mmcblk0', erase: true, fwcryptoInit: true, crypt: [], reboot: true, parts: {} }, opts || {});
            const log = o.log || this.log;
            const say = (level, msg) => log(level, msg);
            if (!o.imageJson || !o.imageJson.byteLength) throw new FastbootError('image.json is missing');
            const readPiece = o.readPiece || (async (p) => { if (!p.bytes) throw new FastbootError(`no data for ${p.name}`); return p.bytes; });
            const total = o.totalBytes || Object.values(o.parts).flat().reduce((a, p) => a + (p.size || (p.bytes ? p.bytes.byteLength : 0)), 0);
            const result = { flashed: [], crypt: [], device_key_pem: null, fwcrypto: null };
            let done = 0;
            const progress = (extra) => { if (o.onProgress) o.onProgress(Object.assign({ sent: done, total }, extra)); };

            if (o.fwcryptoInit) {
                say('info', 'oem fwcrypto init (device key in OTP)…');
                const fc = await this.fwcryptoInit();
                result.fwcrypto = fc.message;
                say('ok', `fwcrypto: ${fc.message || 'OKAY'}`);
                result.device_key_pem = await this.publicKey();
                if (result.device_key_pem) {
                    say('info', 'Device public key received');
                    if (o.onDeviceKey) await o.onDeviceKey(result.device_key_pem);
                } else say('warn', 'getvar:public-key returned no PEM');
            }
            await this.ensureMaxDownloadSize();

            const stageAndInit = async () => {
                if (o.erase) {
                    say('info', `erase:${o.storageDevice}…`);
                    progress({ phase: 'erase' });
                    await this.erase(o.storageDevice);
                }
                say('info', `Staging image.json (${o.imageJson.byteLength} bytes)`);
                await this.download(o.imageJson);
                const r = await this.oem('idpinit');
                say('ok', `idpinit: ${clean(r.message)}`);
            };
            try {
                await stageAndInit();
            } catch (e) {
                if (!(e instanceof FastbootError) || !/already initiali[sz]ed/i.test(e.message)) throw e;
                say('warn', 'IDP already initialised on the device (earlier run): oem idpdone and retry');
                await this.oem('idpdone');
                await stageAndInit();
            }

            try {
                say('info', 'oem idpwrite (partition table; LUKS containers for an encrypted image)…');
                progress({ phase: 'idpwrite' });
                const w = await this.oem('idpwrite');
                say('ok', `idpwrite: ${clean(w.message)}`);
                const seen = new Set();
                for (let i = 0; ; i++) {
                    if (i >= MAX_IDP_BLOCKS) throw new FastbootError(`oem idpgetblk did not finish after ${MAX_IDP_BLOCKS} blocks`);
                    const blk = await this.idpGetBlk();
                    if (!blk) break;
                    const key = `${blk.dev}:${blk.simage}`;
                    if (seen.has(key)) throw new FastbootError(`oem idpgetblk repeated ${key}`);
                    seen.add(key);
                    const pieces = o.parts[blk.simage];
                    if (!pieces || !pieces.length) throw new FastbootError(`the device asks for "${blk.simage}" but the image set has no such file`);
                    let bytes = 0;
                    for (let k = 0; k < pieces.length; k++) {
                        const piece = pieces[k];
                        const label = pieces.length > 1 ? `${piece.name} (${k + 1}/${pieces.length})` : piece.name;
                        say('info', `Writing ${label} → ${blk.dev}`);
                        progress({ phase: 'fetch', piece: piece.name, dev: blk.dev });
                        const data = await readPiece(piece, (s, t) => progress({ phase: 'fetch', piece: piece.name, dev: blk.dev, fetched: s, fetchTotal: t }));
                        if (piece.size && data.byteLength !== piece.size) throw new FastbootError(`${piece.name}: got ${data.byteLength} bytes, manifest says ${piece.size}`);
                        const base = done;
                        await this.download(data, (s) => { done = base + s; progress({ phase: 'download', piece: piece.name, dev: blk.dev }); });
                        const f = await this.command(`flash:${blk.dev}`);
                        say('ok', `flash:${blk.dev} ← ${label}: ${clean(f.message) || 'OKAY'}`);
                        done = base + data.byteLength;
                        bytes += data.byteLength;
                    }
                    result.flashed.push({ dev: blk.dev, simage: blk.simage, pieces: pieces.map((p) => p.name), bytes });
                }
                for (const c of o.crypt || []) {
                    say('info', `oem cryptsetpassword ${c.dev} <recovery passphrase> (LUKS keyslot 1)`);
                    progress({ phase: 'crypt' });
                    const r = await this.cryptSetPassword(c.dev, c.passphrase);
                    say('ok', `${c.dev}: ${clean(r.message) || 'OKAY'}`);
                    result.crypt.push({ dev: c.dev, mname: c.mname || '' });
                }
            } catch (e) {
                await this._idpDoneQuietly();
                throw e;
            }
            const d = await this.oem('idpdone');
            say('ok', `idpdone: ${clean(d.message)}`);
            if (o.reboot) {
                try { await this.reboot(); say('ok', 'reboot sent'); } catch (e) { say('warn', `reboot: ${e.message || e}`); }
            }
            progress({ phase: 'done' });
            return result;
        }

        /**
         * Manual mode (Advanced panel): IDP from a local rpi-image-gen output directory.
         * readImage(name) → Uint8Array of a sparse image next to image.json. No splitting: a sparse file above
         * max-download-size is refused.
         */
        async provisionIdp(imageJsonBytes, readImage, onProgress, extra) {
            const json = JSON.parse(dec.decode(imageJsonBytes));
            const pi = (json.layout && json.layout.partitionimages) || {};
            const parts = {};
            for (const v of Object.values(pi)) if (v && v.simage) parts[v.simage] = [{ name: v.simage }];
            return this.idpProvision(Object.assign({
                imageJson: imageJsonBytes,
                parts,
                readPiece: async (p) => { const b = await readImage(p.name); if (!b) throw new FastbootError(`image "${p.name}" not found next to image.json`); return b; },
                erase: false,
                fwcryptoInit: false,
                reboot: false,
                totalBytes: 0,
                onProgress: onProgress ? (p) => onProgress(p.sent, p.total, p.piece) : null,
            }, extra || {}));
        }
    }

    OTP.fastboot = { FastbootClient, FastbootError, FILTERS, FASTBOOT_VID, FASTBOOT_PID, DATA_ALIGN, DATA_CHUNK, MAX_COMMAND, isFastbootDevice, clean };
})();
