/*
 * mocks.js — test doubles for the WebUSB page self-test (loaded before selftest.js).
 *
 *   MockHub       a navigator.usb replacement: getDevices / requestDevice / connect + disconnect events,
 *                 permissions keyed like Chrome's (vendor:product:serial).
 *   romDevice     BCM2712 boot ROM (iSerialNumber 3): accepts the second stage, answers status 0.
 *   fsDevice      second-stage file server (iSerialNumber 1) replaying a script of 260-byte messages.
 *   FastbootSim   an rpi-fastbootd simulator (getvar, download/DATA, flash, erase, oem idp*, fwcrypto,
 *                 cryptsetpassword, reboot) that records every command and every data-phase transfer size.
 *   MockBoard     glues them into one Raspberry Pi 5: ROM → recovery → ROM → gadget bootloader → fastboot.
 *   FakeApi       an in-memory OTP.api with stage manifests, 409 build waits and call recording.
 */
(function () {
    'use strict';
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const T = (window.TestMocks = {});
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    T.sleep = sleep;

    function gone(msg) { return new DOMException(msg || 'The device was disconnected.', 'NetworkError'); }
    T.gone = gone;
    /** What Chrome's WinUSB backend reports when a control transfer hits its fixed ~5 s timeout (device still attached). */
    function transferTimeout() { return new DOMException('A transfer error has occurred.', 'NetworkError'); }
    T.transferTimeout = transferTimeout;

    function checksum(bytes, seed) {
        let h = seed === undefined ? 0x811c9dc5 : seed;
        for (let i = 0; i < bytes.length; i++) { h ^= bytes[i]; h = Math.imul(h, 0x01000193) >>> 0; }
        return h >>> 0;
    }
    T.checksum = checksum;

    /** Deterministic pseudo-random bytes. */
    function bytesOf(n, seed) {
        const out = new Uint8Array(n);
        let x = (seed || 1) >>> 0;
        for (let i = 0; i < n; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; out[i] = x & 0xff; }
        return out;
    }
    T.bytesOf = bytesOf;

    // ------------------------------------------------------------------ hub

    class MockHub {
        constructor() {
            this.devices = [];
            this.permitted = new Set();
            this.listeners = { connect: [], disconnect: [] };
            this.requests = [];
        }
        static key(d) { return `${d.vendorId}:${d.productId}:${d.serialNumber || ''}`; }
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
        removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
        _emit(type, device) { for (const fn of this.listeners[type] || []) { try { fn({ device }); } catch (e) { console.error(e); } } }
        async getDevices() { return this.devices.filter((d) => this.permitted.has(MockHub.key(d))); }
        static matches(filters, d) {
            return (filters || []).some((f) => {
                if (f.vendorId !== undefined && f.vendorId !== d.vendorId) return false;
                if (f.productId !== undefined && f.productId !== d.productId) return false;
                if (f.classCode !== undefined) {
                    const alts = d.configurations.flatMap((c) => c.interfaces.flatMap((i) => i.alternates || [i.alternate]));
                    if (!alts.some((a) => a && a.interfaceClass === f.classCode && (f.subclassCode === undefined || a.interfaceSubclass === f.subclassCode) && (f.protocolCode === undefined || a.interfaceProtocol === f.protocolCode))) return false;
                }
                return true;
            });
        }
        /** Chrome's chooser: the newest matching device is "picked". */
        async requestDevice({ filters }) {
            this.requests.push(filters);
            const cands = this.devices.filter((d) => MockHub.matches(filters, d));
            if (!cands.length) throw new DOMException('No device selected.', 'NotFoundError');
            const d = cands[cands.length - 1];
            this.permitted.add(MockHub.key(d));
            return d;
        }
        plug(d) {
            d.attached = true;
            this.devices.push(d);
            if (this.permitted.has(MockHub.key(d))) this._emit('connect', d);
        }
        unplug(d) {
            if (!this.devices.includes(d)) return;
            d.attached = false;
            d.opened = false; // Chrome closes a USBDevice that left the bus
            this.devices = this.devices.filter((x) => x !== d);
            if (this.permitted.has(MockHub.key(d))) this._emit('disconnect', d);
        }
        has(kind) {
            return this.devices.some((d) => (kind === 'fastboot' ? d.vendorId === 0x18d1 : d.vendorId === 0x0a5c));
        }
    }
    T.MockHub = MockHub;

    // ------------------------------------------------------------------ rpiboot devices

    function rpiBase({ iSerial, serial, productName }) {
        return {
            vendorId: 0x0a5c, productId: 0x2712, serialNumber: serial, productName: productName || 'BCM2712 Boot', manufacturerName: 'Broadcom',
            opened: false, configuration: null, attached: true,
            configurations: [{ configurationValue: 1, interfaces: [{ interfaceNumber: 0, alternate: { alternateSetting: 0, interfaceClass: 0xff, interfaceSubclass: 0, interfaceProtocol: 0, endpoints: [{ direction: 'out', type: 'bulk', endpointNumber: 1 }, { direction: 'in', type: 'bulk', endpointNumber: 2 }] }, alternates: [{ alternateSetting: 0, interfaceClass: 0xff, interfaceSubclass: 0, interfaceProtocol: 0, endpoints: [] }] }] }],
            events: [], bulk: [], iSerial,
            async open() { if (!this.attached) throw gone('open: device gone'); this.opened = true; },
            async close() { this.opened = false; },
            async selectConfiguration() { this.configuration = this.configurations[0]; },
            async claimInterface() { if (!this.attached) throw gone(); },
            async releaseInterface() {},
            _descriptor() {
                const d = new Uint8Array(18); d[0] = 18; d[1] = 1; d[8] = 0x5c; d[9] = 0x0a; d[10] = 0x12; d[11] = 0x27; d[12] = 0x01; d[13] = 0x01; d[16] = iSerial; d[17] = 1;
                return { status: 'ok', data: new DataView(d.buffer) };
            },
            async controlTransferOut(setup) {
                if (!this.attached) throw gone();
                this.events.push({ t: 'ctrl', len: setup.value | (setup.index << 16) });
                return { status: 'ok', bytesWritten: 0 };
            },
            async transferOut(ep, data) {
                if (!this.attached) throw gone();
                this.events.push({ t: 'bulk', ep, len: data.byteLength });
                this.bulk.push(new Uint8Array(data));
                return { status: 'ok', bytesWritten: data.byteLength };
            },
        };
    }

    /** Boot ROM: after the 4-byte status read it calls onBooted() (the board re-enumerates). */
    function romDevice({ serial, retcode, onBooted }) {
        const d = rpiBase({ iSerial: 3, serial });
        d.kind = 'rom';
        d.controlTransferIn = async function (setup, length) {
            if (!this.attached) throw gone();
            if (setup.requestType === 'standard' && setup.request === 6 && setup.value === 0x0100) return this._descriptor();
            if (setup.requestType === 'vendor') {
                const want = setup.value | (setup.index << 16);
                this.events.push({ t: 'read', len: want });
                if (want === 4) {
                    const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, retcode || 0, true);
                    if (onBooted) setTimeout(onBooted, 5);
                    return { status: 'ok', data: new DataView(b.buffer) };
                }
            }
            throw new Error('ROM: unexpected controlTransferIn ' + JSON.stringify(setup));
        };
        return d;
    }
    T.romDevice = romDevice;

    /**
     * Second-stage file server: script = [{cmd, name, after?}] replayed on 260-byte vendor reads. `after` runs
     * once the message has been handed to the host. An exhausted script behaves like a board that left USB
     * (the device detaches and is closed; onEnd runs once, e.g. to unplug it from a hub).
     * timeouts = {scriptIndex: n}: the read of that message first fails n times with a WinUSB-style NetworkError
     * while the device stays attached (recovery.bin busy writing the EEPROM); onTimeout(device, count) after each.
     */
    function fsDevice({ serial, script, onEnd, timeouts, onTimeout }) {
        const d = rpiBase({ iSerial: 1, serial });
        d.kind = 'fs';
        d.readIndex = 0;
        d.timeoutsLeft = Object.assign({}, timeouts || {});
        d.timeoutCount = 0;
        d.controlTransferIn = async function (setup, length) {
            if (!this.attached) throw gone();
            if (setup.requestType === 'standard' && setup.request === 6 && setup.value === 0x0100) return this._descriptor();
            if (setup.requestType === 'standard' && setup.request === 6) {
                const s = 'serial';
                const b = new Uint8Array(2 + s.length * 2); b[0] = b.length; b[1] = 3;
                for (let i = 0; i < s.length; i++) b[2 + 2 * i] = s.charCodeAt(i);
                return { status: 'ok', data: new DataView(b.buffer) };
            }
            if (setup.requestType === 'vendor') {
                const want = setup.value | (setup.index << 16);
                if (this.timeoutsLeft[this.readIndex] > 0) {
                    this.timeoutsLeft[this.readIndex]--;
                    this.timeoutCount++;
                    this.events.push({ t: 'timeout', len: want });
                    if (onTimeout) onTimeout(this, this.timeoutCount);
                    throw transferTimeout();
                }
                this.events.push({ t: 'read', len: want });
                const m = script[this.readIndex++];
                if (!m) {
                    this.attached = false;
                    this.opened = false;
                    if (onEnd && !this._ended) { this._ended = true; setTimeout(onEnd, 5); }
                    throw gone('file server: board left USB');
                }
                const b = new Uint8Array(260); new DataView(b.buffer).setInt32(0, m.cmd, true); b.set(enc.encode(m.name), 4);
                if (m.after) setTimeout(m.after, 5);
                return { status: 'ok', data: new DataView(b.buffer) };
            }
            throw new Error('FS: unexpected controlTransferIn ' + JSON.stringify(setup));
        };
        return d;
    }
    T.fsDevice = fsDevice;

    // ------------------------------------------------------------------ fastboot simulator

    const PEM = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexampleexampleexampleexampleexa\nmpleexampleexampleexampleexampleexampleexampleexampleexampleex==\n-----END PUBLIC KEY-----';
    T.PEM = PEM;

    class FastbootSim {
        constructor(opts) {
            this.o = Object.assign({
                serial64: '10000000a7eb274c',
                maxDownload: 0x10000000,
                blocks: ['mmcblk0p1:boot.sparse', 'mapper/osroot_crypt:root.sparse'],
                staleIdp: false,
                failFlash: null,        // dev name → FAIL on flash
                goneOnFlash: null,      // dev name → the board disappears while flashing
                keyProvisioned: false,
                noiseInfo: true,
                onReboot: null,
            }, opts || {});
            this.vendorId = 0x18d1; this.productId = 0x4e40;
            this.serialNumber = this.o.serial64;
            this.productName = 'Raspberry Pi 5 Model B Rev 1.0';
            this.manufacturerName = 'Raspberry Pi';
            this.opened = false; this.configuration = null; this.attached = true;
            this.configurations = [{ configurationValue: 1, interfaces: [{ interfaceNumber: 0, alternates: [{ alternateSetting: 0, interfaceClass: 0xff, interfaceSubclass: 0x42, interfaceProtocol: 0x03, endpoints: [{ direction: 'out', type: 'bulk', endpointNumber: 1 }, { direction: 'in', type: 'bulk', endpointNumber: 1 }] }] }] }];
            this.commands = [];
            this.responses = [];
            this.downloads = [];      // [{size, chunks: [sizes], checksum}]
            this.flashes = [];        // [{dev, size, checksum}]
            this.passwords = [];      // [{dev, pass}]
            this.erased = [];
            this.buffer = null;
            this.dataRemaining = 0;
            this.cur = null;
            this.idp = this.o.staleIdp ? 'error' : null;
            this.cursor = 0;
            this.keyProvisioned = this.o.keyProvisioned;
            this.maxCommandSeen = 0;
        }
        async open() { if (!this.attached) throw gone(); this.opened = true; }
        async close() { this.opened = false; }
        async selectConfiguration() { this.configuration = this.configurations[0]; }
        async claimInterface() {}
        async releaseInterface() {}
        async selectAlternateInterface() {}

        async transferOut(ep, data) {
            if (!this.attached) throw gone();
            const u = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
            if (this.dataRemaining > 0) {
                if (this.goneNow) { this.attached = false; throw gone('unplugged during download'); }
                this.cur.chunks.push(u.byteLength);
                this.buffer.set(u, this.cur.got);
                this.cur.got += u.byteLength;
                this.dataRemaining -= u.byteLength;
                if (this.dataRemaining < 0) throw new Error('sim: host sent more data than announced');
                if (this.dataRemaining === 0) { this.cur.checksum = checksum(this.buffer); this.downloads.push(this.cur); this.responses.push('OKAY'); }
                return { status: 'ok', bytesWritten: u.byteLength };
            }
            const cmd = dec.decode(u);
            this.maxCommandSeen = Math.max(this.maxCommandSeen, u.byteLength);
            this.commands.push(cmd.startsWith('oem cryptsetpassword ') ? cmd.split(' ').slice(0, 3).join(' ') + ' <pass>' : cmd);
            if (u.byteLength > 256) { this.responses.push('FAILcommand too long'); return { status: 'ok', bytesWritten: u.byteLength }; }
            this.handle(cmd);
            return { status: 'ok', bytesWritten: u.byteLength };
        }
        async transferIn(ep, len) {
            if (!this.attached) throw gone();
            const s = this.responses.shift();
            if (s === undefined) throw new Error('sim: no response pending');
            const b = enc.encode(s);
            if (b.byteLength > 256) throw new Error('sim: response longer than 256 bytes');
            return { status: 'ok', data: new DataView(b.buffer) };
        }
        ok(msg) { this.responses.push('OKAY' + (msg || '')); }
        fail(msg) { this.responses.push('FAIL' + msg); }
        info(msg) { this.responses.push('INFO' + msg); }

        handle(cmd) {
            if (cmd.startsWith('getvar:')) {
                const name = cmd.slice(7);
                const vars = {
                    serialno: this.o.serial64 + '\0',
                    'max-download-size': '0x' + this.o.maxDownload.toString(16).toUpperCase(),
                    product: 'Raspberry Pi 5 Model B Rev 1.0\0',
                    'version-bootloader': '2026/06/03',
                    'version-fastbootd': '14.0.0~git20260902.cca05b2',
                    secure: 'no', 'secure-otp': 'not present', 'secure-devkey': 'present',
                    'mmc-cid': '1b534d4542345154c0a1b2c301a4',
                    'mac-ethernet': '2c:cf:67:70:76:f3',
                    'rpi-duid': '001000911006186073',
                    'otp-lock-status': 'ok',
                    'block-devices': 'mmcblk0',
                };
                if (name === 'public-key') { if (this.keyProvisioned) this.ok(PEM); else this.fail('Key not provisioned'); return; }
                if (name in vars) { this.ok(vars[name]); return; }
                this.fail('Unknown variable');
                return;
            }
            if (cmd.startsWith('download:')) {
                const hex = cmd.slice(9);
                if (hex.length !== 8) { this.fail('Invalid size (length of size != 8)'); return; }
                const size = parseInt(hex, 16);
                if (!size) { this.fail('Invalid size (0)'); return; }
                if (size > this.o.maxDownload) { this.fail('Invalid size'); return; }
                this.buffer = new Uint8Array(size);
                this.dataRemaining = size;
                this.cur = { size, chunks: [], got: 0, checksum: null };
                this.responses.push('DATA' + hex);
                return;
            }
            if (cmd.startsWith('erase:')) { this.erased.push(cmd.slice(6)); this.ok('Erasing succeeded'); return; }
            if (cmd.startsWith('flash:')) {
                const dev = cmd.slice(6);
                if (this.o.goneOnFlash === dev) { this.attached = false; return; } // no response: transferIn will reject
                if (this.o.failFlash === dev) { this.fail(`payload ${this.buffer ? this.buffer.byteLength : 0}B exceeds partition size`); return; }
                if (!this.buffer) { this.fail('No data'); return; }
                this.flashes.push({ dev, size: this.buffer.byteLength, checksum: checksum(this.buffer) });
                this.ok('Flashing succeeded');
                return;
            }
            if (cmd === 'reboot') { this.ok('Rebooting'); if (this.o.onReboot) setTimeout(this.o.onReboot, 5); return; }
            if (cmd.startsWith('oem ')) return this.oem(cmd.slice(4).split(' '));
            this.fail(`Unrecognized command ${cmd.split(':')[0]}`);
        }

        oem(args) {
            const c = args[0];
            if (c === 'fwcrypto' && args[1] === 'init') {
                if (this.keyProvisioned) this.ok('Key already provisioned');
                else { this.keyProvisioned = true; this.ok('Key provisioned and LOCKed'); }
                return;
            }
            if (c === 'idpinit') {
                if (!this.buffer) { this.fail('IDP:No data. Check description was staged'); return; }
                if (this.idp) { this.fail('IDP:already initialised'); return; }
                let j;
                try { j = JSON.parse(dec.decode(this.buffer)); } catch (e) { this.fail('IDP:invalid description: not JSON'); return; }
                if (!j.IGversion) { this.fail('IDP:invalid description: IGversion'); return; }
                this.idp = 'init';
                this.cursor = 0;
                this.ok('IDP:ready');
                return;
            }
            if (c === 'idpwrite') { if (this.idp !== 'init') { this.fail('IDP:not initialised'); return; } this.idp = 'partitioned'; this.ok('IDP:ok'); return; }
            if (c === 'idpgetblk') {
                if (!this.idp) { this.fail('IDP:not initialised'); return; }
                if (this.idp !== 'partitioned') { this.fail('IDP:not partitioned (state 1)'); return; }
                if (this.o.noiseInfo && this.cursor === 0) this.info('IDP: next block');
                if (this.cursor < this.o.blocks.length) this.info(this.o.blocks[this.cursor++]);
                this.ok('IDP:done');
                return;
            }
            if (c === 'idpdone') { if (!this.idp) { this.ok('IDP:not initialised'); return; } this.idp = null; this.ok('IDP:done'); return; }
            if (c === 'cryptsetpassword') {
                if (this.idp !== 'partitioned') { this.fail('no open container'); return; }
                this.passwords.push({ dev: args[1], pass: args[2] });
                this.ok('User passphrase set successfully');
                return;
            }
            this.fail('Unknown OEM command.');
        }
    }
    T.FastbootSim = FastbootSim;

    // ------------------------------------------------------------------ the whole board

    /**
     * One Raspberry Pi 5 going through the three stages.
     * stage-1 recovery script: config.txt, pieeprom.sig, pieeprom.bin, metadata, Done → reboot into the ROM.
     * stage-2 bootloader script: config.txt, boot.sig (absent), boot.img, then it leaves USB → fastboot gadget.
     * The second stage enumerates with an empty serial string, so Chrome needs a new permission the first time.
     */
    class MockBoard {
        constructor(hub, opts) {
            this.hub = hub;
            this.o = Object.assign({ serial: 'a7eb274c', keyHash: 'ab'.repeat(32), fsSerial: '', fastboot: {}, stage1Timeouts: null }, opts || {});
            this.boots = 0;
            this.history = [];
            this.fb = null;
        }
        _replace(oldDev, newDev, delay) {
            setTimeout(() => {
                if (oldDev) this.hub.unplug(oldDev);
                setTimeout(() => { this.history.push(newDev.kind); this.hub.plug(newDev); }, 5);
            }, delay || 5);
        }
        powerOnRom() {
            const rom = romDevice({ serial: this.o.serial, onBooted: () => this._secondStage(rom) });
            this.history.push('rom');
            this.hub.plug(rom);
            return rom;
        }
        _secondStage(rom) {
            this.boots++;
            const serial = this.o.fsSerial;
            let fs;
            if (this.boots === 1) {
                fs = fsDevice({
                    serial,
                    script: [
                        { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
                        { cmd: 0, name: 'pieeprom.sig' }, { cmd: 1, name: 'pieeprom.sig' },
                        { cmd: 0, name: 'pieeprom.bin' }, { cmd: 1, name: 'pieeprom.bin' },
                        { cmd: 0, name: '*USER_SERIAL_NUM*' + this.o.serial },
                        { cmd: 0, name: '*MAC_ADDR*2c:cf:67:70:76:f3' },
                        { cmd: 0, name: '*CUSTOMER_KEY_HASH*' + this.o.keyHash },
                        { cmd: 0, name: '*SECURE_BOOT_PROVISION*success' },
                        { cmd: 0, name: '*EEPROM_UPDATE*success' },
                        { cmd: 2, name: 'done', after: () => this._reboot(fs) },
                    ],
                    timeouts: this.o.stage1Timeouts,
                });
            } else {
                fs = fsDevice({
                    serial,
                    script: [
                        { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
                        { cmd: 0, name: 'boot.sig' }, { cmd: 1, name: 'boot.sig' },
                        { cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' },
                    ],
                    onEnd: () => this._gadget(fs),
                });
            }
            this._replace(rom, fs, 5);
        }
        _reboot(fs) {
            const rom = romDevice({ serial: this.o.serial, onBooted: () => this._secondStage(rom) });
            this._replace(fs, rom, 10);
        }
        _gadget(fs) {
            this.fb = new FastbootSim(Object.assign({ serial64: '10000000' + this.o.serial }, this.o.fastboot));
            this.fb.kind = 'fastboot';
            this._replace(fs, this.fb, 30);
        }
    }
    T.MockBoard = MockBoard;

    // ------------------------------------------------------------------ fake API

    const STAGES = ['new', 'eeprom', 'gadget', 'flashed'];
    const LABELS = { new: 'New', eeprom: 'EEPROM flashed', gadget: 'Fastboot gadget booted', flashed: 'Image written' };

    /**
     * In-memory OTP.api. manifests: {1: m | fn(callNo), 2: ..., 3: ...}; files: Map url → Uint8Array.
     * Every call is recorded in `calls` as [name, ...args].
     */
    class FakeApi {
        constructor({ manifests, files, confirm }) {
            this.available = true;
            this.lastStatus = { version: 'fake', config: { provisioning: { confirm_irreversible: confirm !== false } } };
            this.manifests = manifests;
            this.files = files;
            this.calls = [];
            this.stageCalls = { 1: 0, 2: 0, 3: 0 };
            this.modules = new Map();
            this.fetched = [];
        }
        _mod(serial) {
            let m = this.modules.get(serial);
            if (!m) {
                m = { serial, stage: 'new', stage_label: LABELS.new, chip: '', board: '', duid: '', mac: '', created: 'now', updated: 'now',
                    secrets: { rsa_key: true, customer_key_hash: 'ab'.repeat(32), device_secret: true, rsa_key_fingerprint: 'cd'.repeat(32) },
                    otp: { customer_key_hash: '', locked: false, locked_to_our_key: false, secure_boot_provisioned: false, device_key: false, device_key_fingerprint: '' },
                    metadata: {}, facts: {}, events: [] };
                this.modules.set(serial, m);
                return [m, true];
            }
            return [m, false];
        }
        _advance(m, stage) {
            if (STAGES.indexOf(stage) > STAGES.indexOf(m.stage)) { m.stage = stage; m.stage_label = LABELS[stage]; }
        }
        _copy(m) { return JSON.parse(JSON.stringify(m)); }
        async hello(body) {
            this.calls.push(['hello', body]);
            const [m, created] = this._mod(body.serial);
            m.chip = body.chip; m.board = body.board;
            m.events.push({ t: 'now', kind: 'hello', note: '' });
            return { module: this._copy(m), created };
        }
        async identify(body) {
            this.calls.push(['identify', body]);
            const serial = String(body.serialno).replace(/\0/g, '').trim().slice(-8);
            const [m, created] = this._mod(serial);
            m.duid = body.serialno;
            m.facts.fastboot = body.vars;
            this._advance(m, 'gadget');
            return { module: this._copy(m), created };
        }
        async stage(serial, n) {
            this.calls.push(['stage', serial, n]);
            const k = ++this.stageCalls[n];
            const v = this.manifests[n];
            return typeof v === 'function' ? v(k) : v;
        }
        async result(serial, n, body) {
            this.calls.push(['result', serial, n, body]);
            const [m] = this._mod(serial);
            const notes = [];
            let ok = !!body.ok;
            if (body.interrupted) notes.push('run was interrupted'); // otp_server/modules.py record_result
            if (n === 1) {
                Object.assign(m.metadata, body.metadata || {});
                if ((body.metadata || {}).EEPROM_UPDATE !== 'success') { ok = false; notes.push('no EEPROM_UPDATE in metadata'); }
                if (body.expect && body.expect.secure_boot_provision && (body.metadata || {}).CUSTOMER_KEY_HASH !== body.expect.customer_key_hash) { ok = false; notes.push('CUSTOMER_KEY_HASH mismatch'); }
                if (ok) { this._advance(m, 'eeprom'); notes.push('EEPROM_UPDATE = success'); m.otp.locked = true; m.otp.locked_to_our_key = true; }
            } else if (n === 2) {
                if (!(body.files_served || []).some((f) => f.name === 'boot.img')) { ok = false; notes.push('boot.img was not served'); }
                if (ok) this._advance(m, 'gadget');
            } else if (n === 3) {
                if (ok) this._advance(m, 'flashed');
            }
            m.events.push({ t: 'now', kind: 'stage' + n, note: ok ? 'ok' : 'failed: ' + (body.error || notes.join('; ')) });
            return { module: this._copy(m), verdict: { ok, notes } };
        }
        async facts(serial, body) {
            this.calls.push(['facts', serial, body]);
            const [m] = this._mod(serial);
            if (body.device_key_pem) { m.device_key_pem = body.device_key_pem; m.otp.device_key = true; m.otp.device_key_fingerprint = 'ee'.repeat(32); }
            return { module: this._copy(m) };
        }
        async fetchBytes(url, onProgress) {
            this.fetched.push(url);
            const b = this.files.get(url);
            if (!b) { const e = new Error(`HTTP 404 ${url}`); e.name = 'ApiError'; e.status = 404; e.detail = 'not found'; throw e; }
            if (onProgress) onProgress(b.byteLength, b.byteLength);
            return b.slice();
        }
        names() { return this.calls.map((c) => c[0] + (c[0] === 'stage' || c[0] === 'result' ? c[2] : '')); }
    }
    T.FakeApi = FakeApi;

    /** Fake EventSource for OTP.createApi tests. */
    class FakeEventSource {
        constructor(url) { this.url = url; this.readyState = 1; this.listeners = {}; FakeEventSource.last = this; }
        addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
        close() { this.readyState = 2; this.closed = true; }
        emit(data) { if (this.onmessage) this.onmessage({ data }); }
        emitEvent(t, data) { for (const fn of this.listeners[t] || []) fn({ data }); }
    }
    T.FakeEventSource = FakeEventSource;
})();
