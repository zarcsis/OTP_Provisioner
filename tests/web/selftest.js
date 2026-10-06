/*
 * selftest.js — runs inside index.html (served by tests/web/run_selftest.py) in headless Chrome and POSTs the
 * results to /__result. window.__FIX = {bootfiles, config}: URLs of real rpiboot fixtures in the repo.
 */
(async function () {
    const out = document.getElementById('test-out');
    const results = [];
    let failed = 0;
    let section = '';
    function report(name, ok, detail) {
        results.push(`${ok ? 'PASS' : 'FAIL'} ${section ? '[' + section + '] ' : ''}${name}${!ok && detail ? ' — ' + detail : ''}`);
        if (!ok) failed++;
    }
    function assert(cond, name, detail) { report(name, !!cond, cond ? '' : detail); }
    /**
     * A known product bug (reported, not fixed here): XFAIL while it holds, XPASS once it is fixed (then turn it
     * into an assert). Neither counts as a failure.
     */
    function xfail(cond, name, bug) {
        results.push(`${cond ? 'XPASS' : 'XFAIL'} ${section ? '[' + section + '] ' : ''}${name} — ${cond ? 'fixed? make this a normal assertion' : 'known bug: ' + bug}`);
    }
    function eq(a, b, name) { const ok = a === b; report(name, ok, ok ? '' : `got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`); }
    function deq(a, b, name) { const sa = JSON.stringify(a); const sb = JSON.stringify(b); report(name, sa === sb, sa === sb ? '' : `got ${sa}, want ${sb}`); }
    async function throwsLike(fn, re, name) {
        let err = null;
        try { await fn(); } catch (e) { err = e; }
        report(name, !!err && re.test(String(err && err.message)), err ? `error: ${err.message}` : 'no error thrown');
        return err;
    }
    async function until(cond, ms, what) {
        const t0 = Date.now();
        while (!cond()) {
            if (Date.now() - t0 > (ms || 5000)) throw new Error(`timeout waiting for ${what || 'condition'}`);
            await new Promise((r) => setTimeout(r, 10));
        }
    }
    window.addEventListener('error', (e) => { results.push('WINDOW ERROR: ' + e.message + ' @ ' + e.filename + ':' + e.lineno); failed++; });
    window.addEventListener('unhandledrejection', (e) => { results.push('UNHANDLED REJECTION: ' + ((e.reason && e.reason.stack) || e.reason)); failed++; });

    const OTP = window.OTP;
    const T = window.TestMocks;
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    const sha = (b) => OTP.BootDir.sha256Hex(b);
    const t0 = Date.now();

    try {
        const bootfiles = new Uint8Array(await (await fetch(window.__FIX.bootfiles)).arrayBuffer());
        const msdConfig = new Uint8Array(await (await fetch(window.__FIX.config)).arrayBuffer());
        results.push(`  fixtures: ${window.__FIX.bootfiles} (${bootfiles.byteLength} B), ${window.__FIX.config} (${msdConfig.byteLength} B)`);

        // ================================================================ T1 tar
        section = 'tar';
        const entries = OTP.tar.list(bootfiles);
        const names = entries.map((e) => e.name);
        assert(names.includes('2712/bootcode5.bin'), 'lists 2712/bootcode5.bin', names.join(','));
        assert(names.includes('2711/bootcode4.bin'), 'lists 2711/bootcode4.bin', names.join(','));
        const bc5 = OTP.tar.find(bootfiles, '2712/BOOTCODE5.BIN');
        assert(bc5 && bc5.byteLength === entries.find((e) => e.name === '2712/bootcode5.bin').size, 'find is case-insensitive and sizes match');
        eq(OTP.tar.find(bootfiles, '2712/nope.bin'), null, 'find missing → null');

        // ================================================================ T2 DUID
        section = 'duid';
        const duid = '001000911006186073';
        const encoded = OTP.duid.encodeC40(duid);
        eq(OTP.duid.decodeC40(encoded), duid, 'round trip (' + encoded + ')');
        eq(OTP.duid.decodeC40('XYZ'), '', 'non-hex word → strtoul 0 → empty');
        eq(OTP.duid.decodeC40('ABC123XYZ'), null, 'leading hex digits parsed like strtoul, invalid C40 → null');
        eq(OTP.duid.decodeC40('0'), '', 'zero word stops');
        eq(OTP.duid.decodeC40('10000'), null, 'zero low half → invalid (C semantics)');

        // ================================================================ T3 BootDir (local entries)
        section = 'bootdir';
        const chip = OTP.CHIPS[0x2712];
        const mk = (name, bytes) => new File([bytes], name);
        const stage2 = OTP.BootDir.fromEntries('msd', [
            { path: 'bootfiles.bin', file: mk('bootfiles.bin', bootfiles) },
            { path: 'config.txt', file: mk('config.txt', msdConfig) },
            { path: 'boot.img', file: mk('boot.img', new Uint8Array(70000).fill(7)) },
        ]);
        let r = await stage2.resolve('bootcode5.bin', chip);
        eq(r && r.origin, 'bootfiles.bin:2712/bootcode5.bin', 'resolve second stage from tar');
        eq(r && r.data.byteLength, bc5.byteLength, 'second stage bytes from tar');
        r = await stage2.resolve('config.txt', chip);
        eq(r && r.origin, 'msd/config.txt', 'resolve top-level config.txt');
        r = await stage2.resolve('../etc/passwd', chip);
        assert(r && r.denied, 'resolve denies ..');
        eq(await stage2.resolve('missing.txt', chip), null, 'resolve missing → null');
        eq((await stage2.validate()).length, 0, 'validate: tar directory ok');
        const cfg = await stage2.configTxt();
        eq(cfg.keys.boot_ramdisk, '1', 'config.txt boot_ramdisk=1');
        eq(cfg.keys.uart_2ndstage, '1', 'config.txt uart_2ndstage=1');
        const overlayDir = OTP.BootDir.fromEntries('ov', [
            { path: 'bootfiles.bin', file: mk('bootfiles.bin', bootfiles) },
            { path: '2712/config.txt', file: mk('config.txt', enc.encode('x=1\n')) },
        ]);
        r = await overlayDir.resolve('config.txt', chip);
        eq(r && r.origin, 'ov/2712/config.txt (bootfiles.bin overlay)', 'overlay <dir>/2712/config.txt wins over the tar');
        const stage1 = OTP.BootDir.fromEntries('sb', [
            { path: 'bootcode5.bin', file: mk('bootcode5.bin', new Uint8Array(1000).fill(1)) },
            { path: 'pieeprom.bin', file: mk('pieeprom.bin', new Uint8Array(2048).fill(2)) },
            { path: 'pieeprom.sig', file: mk('pieeprom.sig', enc.encode('deadbeef\nts: 1\n')) },
            { path: 'config.txt', file: mk('config.txt', enc.encode('uart_2ndstage=1\n#program_pubkey=1\nprogram_pubkey=1\n# program_jtag_lock=1\nrecovery_reboot=0\n')) },
        ]);
        eq((await stage1.validate()).length, 0, 'validate: bootcode5.bin directory ok');
        const c1 = await stage1.configTxt();
        eq(c1.keys.program_pubkey, '1', 'stage1 config program_pubkey=1 (commented copy ignored)');
        eq(c1.keys.program_jtag_lock, undefined, 'stage1 config commented program_jtag_lock ignored');
        const empty = OTP.BootDir.fromEntries('e', [{ path: 'readme.txt', file: mk('readme.txt', enc.encode('x')) }]);
        eq((await empty.validate()).length, 1, 'validate: no bootcode → problem');
        eq(await sha(enc.encode('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256 helper');

        // ================================================================ T4 rpiboot session with mock devices
        section = 'rpiboot';
        const logLines = [];
        const hooks = { log: (l, m) => logLines.push(l + ': ' + m) };
        const rom = T.romDevice({ serial: 'a7eb274c' });
        const romDev = new OTP.rpiboot.RpiDevice(rom);
        const s = new OTP.rpiboot.RpiBootSession(stage2, hooks);
        let step = await s.step(romDev);
        eq(step.kind, 'second-stage-sent', 'ROM: step kind');
        eq(romDev.iSerial, 3, 'ROM: iSerialNumber read from descriptor');
        assert(romDev.isRomStage, 'ROM: stage detection');
        eq(romDev.outEp, 1, 'ROM: bulk OUT endpoint 1');
        eq(rom.events[0].t + rom.events[0].len, 'ctrl24', 'ROM: boot_message control transfer (24)');
        eq(rom.events[1].t + rom.events[1].len, 'bulk24', 'ROM: boot_message bulk (24)');
        eq(new DataView(rom.bulk[0].buffer).getInt32(0, true), bc5.byteLength, 'ROM: boot_message.length = bootcode5 size');
        eq(rom.events[2].t + rom.events[2].len, 'ctrl' + bc5.byteLength, 'ROM: bootcode control transfer with size');
        eq(rom.bulk.slice(1).reduce((a, b) => a + b.byteLength, 0), bc5.byteLength, 'ROM: bootcode bytes sent in full');
        assert(rom.bulk.slice(1).every((b) => b.byteLength <= 16384), 'ROM: chunks ≤ 16 KiB');
        eq(rom.events[rom.events.length - 1].t + rom.events[rom.events.length - 1].len, 'read4', 'ROM: 4-byte status read');
        eq(rom.opened, false, 'ROM: device closed after step');

        const fs = T.fsDevice({ serial: 'a7eb274c', script: [
            { cmd: 0, name: '*USER_SERIAL_NUM*a7eb274c' },
            { cmd: 0, name: '*MAC_ADDR*2c:cf:67:70:76:f3' },
            { cmd: 0, name: '*FACTORY_UUID*' + encoded },
            { cmd: 0, name: '*BROKEN' },
            { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
            { cmd: 0, name: 'missing.txt' }, { cmd: 1, name: 'missing.txt' },
            { cmd: 0, name: '../x' },
            { cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' },
            { cmd: 2, name: 'done' },
        ] });
        const fsDev = new OTP.rpiboot.RpiDevice(fs);
        step = await s.step(fsDev);
        eq(step.kind, 'file-server-done', 'FS: step kind');
        assert(!fsDev.isRomStage, 'FS: iSerial 1 → second stage');
        eq(step.metadata.USER_SERIAL_NUM, 'a7eb274c', 'FS: metadata serial');
        eq(step.metadata.MAC_ADDR, '2c:cf:67:70:76:f3', 'FS: metadata MAC');
        eq(step.metadata.FACTORY_UUID, duid, 'FS: FACTORY_UUID decoded');
        eq(Object.keys(step.metadata).length, 3, 'FS: broken metadata ignored');
        eq(step.filesServed.map((f) => f.name).join(','), 'config.txt,boot.img', 'FS: files served');
        const ev = fs.events.map((e) => e.t + e.len).join(' ');
        assert(ev.includes('read260 ctrl0 read260 ctrl0 read260 ctrl0 read260 ctrl0'), 'FS: metadata answered with zero-length ep_write', ev);
        assert(ev.includes('read260 ctrl' + msdConfig.byteLength + ' read260 ctrl' + msdConfig.byteLength + ' bulk' + msdConfig.byteLength), 'FS: GetFileSize + ReadFile config.txt', ev);
        assert(ev.includes('bulk16384'), 'FS: boot.img chunked at 16 KiB', ev);
        eq(fs.bulk.reduce((a, b) => a + b.byteLength, 0), msdConfig.byteLength + 70000, 'FS: total bulk bytes = config.txt + boot.img');
        const json = s.metadataJson('a7eb274c');
        eq(json.name, 'a7eb274c.json', 'FS: metadata file name');
        assert(json.text.startsWith('{\n\t"USER_SERIAL_NUM": "a7eb274c",'), 'FS: metadata JSON shape', json.text);
        assert(logLines.some((l) => l.startsWith('warn: Denying request for ../x')), 'FS: traversal logged');

        const drop = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: '*X*1' }] });
        const s2 = new OTP.rpiboot.RpiBootSession(stage2, hooks);
        let gone = null;
        try { await s2.step(new OTP.rpiboot.RpiDevice(drop)); } catch (e) { gone = e; }
        assert(gone instanceof OTP.rpiboot.DeviceGone, 'FS: NetworkError → DeviceGone', String(gone));
        eq(s2.metadata.X, '1', 'FS: metadata kept after drop');

        // #0 Windows: WinUSB fails a control transfer after ~5 s with NetworkError while recovery.bin writes the EEPROM
        {
            const hub = new T.MockHub();
            const fsT = T.fsDevice({ serial: 'a7eb274c', script: [
                { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
                { cmd: 0, name: '*EEPROM_UPDATE*success' },
                { cmd: 0, name: '*SECURE_BOOT_PROVISION*success' },
                { cmd: 2, name: 'done' },
            ], timeouts: { 2: 3 } });
            hub.permitted.add(T.MockHub.key(fsT));
            hub.plug(fsT);
            const lines = [];
            const sess = new OTP.rpiboot.RpiBootSession(stage2, { log: (l, m) => lines.push(l + ': ' + m), usb: hub, retryMs: 20 });
            let res = null;
            let err = null;
            try { res = await sess.step(new OTP.rpiboot.RpiDevice(fsT)); } catch (e) { err = e; }
            eq(err && String(err), null, 'FS timeouts: NetworkError on an attached board is not a disconnect');
            eq(fsT.timeoutCount, 3, 'FS timeouts: three failed control IN reads');
            eq(res && res.kind, 'file-server-done', 'FS timeouts: the file server reaches "Done"');
            eq(res && res.metadata.EEPROM_UPDATE + ':' + res.metadata.SECURE_BOOT_PROVISION, 'success:success', 'FS timeouts: the metadata after the quiet period is collected');
            assert(lines.some((l) => /still attached/.test(l)) && lines.some((l) => /answered again/.test(l)), 'FS timeouts: retry logged', lines.join(' | '));
        }
        {
            // the board really disappears while the file server waits between retries: the disconnect event ends it
            const hub = new T.MockHub();
            const fsG = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: '*X*1' }, { cmd: 2, name: 'done' }], timeouts: { 1: 1000 },
                onTimeout: (d, k) => { if (k === 1) setTimeout(() => hub.unplug(d), 30); } });
            hub.permitted.add(T.MockHub.key(fsG));
            hub.plug(fsG);
            const sess = new OTP.rpiboot.RpiBootSession(stage2, { log: () => {}, usb: hub, retryMs: 5000 });
            const tg = Date.now();
            let err = null;
            try { await sess.step(new OTP.rpiboot.RpiDevice(fsG)); } catch (e) { err = e; }
            assert(err instanceof OTP.rpiboot.DeviceGone, 'FS unplug: a board that left during the retry wait → DeviceGone', String(err));
            assert(Date.now() - tg < 2500, 'FS unplug: the disconnect event cuts the 5 s retry wait short', `${Date.now() - tg} ms`);
            eq(sess.metadata.X, '1', 'FS unplug: metadata kept');
            const r = await OTP.rpiboot.runSession(new OTP.rpiboot.RpiBootSession(stage2, { log: () => {}, usb: hub }),
                T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: '*Y*2' }] }), async () => { throw new Error('no wait expected'); });
            eq(r.result.interrupted + ':' + r.result.metadata.Y, 'true:2', 'runSession: board gone → interrupted result with the metadata');
        }
        {
            // attached but silent for longer than the overall deadline → a clear error, not "device gone"
            const hub = new T.MockHub();
            const fsS = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: '*Z*3' }, { cmd: 2, name: 'done' }], timeouts: { 1: 50 } }); // ~1 s of timeouts, deadline 0.2 s
            hub.permitted.add(T.MockHub.key(fsS));
            hub.plug(fsS);
            const sess = new OTP.rpiboot.RpiBootSession(stage2, { log: () => {}, usb: hub, retryMs: 20, idleTimeoutMs: 200 });
            const err = await throwsLike(() => sess.step(new OTP.rpiboot.RpiDevice(fsS)), /has not asked for anything/, 'FS deadline: an attached board that stays silent → error');
            assert(!(err instanceof OTP.rpiboot.DeviceGone), 'FS deadline: not reported as a disconnect');
            eq(sess.metadata.Z, '3', 'FS deadline: metadata kept');
        }
        {
            // abort while the file server waits between retries
            const hub = new T.MockHub();
            let sess = null;
            const fsA = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 2, name: 'done' }], timeouts: { 0: 100000 },
                onTimeout: (d, k) => { if (k === 1) setTimeout(() => sess.abort(), 20); } });
            hub.permitted.add(T.MockHub.key(fsA));
            hub.plug(fsA);
            sess = new OTP.rpiboot.RpiBootSession(stage2, { log: () => {}, usb: hub, retryMs: 5000 });
            const ta = Date.now();
            await throwsLike(() => sess.step(new OTP.rpiboot.RpiDevice(fsA)), /aborted/, 'FS abort: abort() during the retry wait');
            assert(Date.now() - ta < 2500, 'FS abort: returns without waiting out the retry pause', `${Date.now() - ta} ms`);
        }

        const s3 = new OTP.rpiboot.RpiBootSession(empty, hooks);
        await throwsLike(() => s3.step(new OTP.rpiboot.RpiDevice(T.romDevice({ serial: 'x' }))), /Failed to open second stage/, 'ROM: missing bootcode5.bin → error');

        // runSession: ROM → re-enumeration → file server (the shared hop loop)
        {
            const romA = T.romDevice({ serial: 'a7eb274c' });
            const fsB = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' }] });
            const sess = new OTP.rpiboot.RpiBootSession(stage2, hooks);
            const waits = [];
            const res = await OTP.rpiboot.runSession(sess, romA, async (prev) => { waits.push(prev); return fsB; });
            eq(waits.length === 1 && waits[0] === romA, true, 'runSession: waited once for the re-enumeration of the ROM device');
            eq(res.result.kind + ':' + !!res.result.interrupted, 'file-server-done:true', 'runSession: board leaving USB → interrupted result');
            eq(res.usb, fsB, 'runSession: returns the last device');
        }

        // ep_write: one 16 KiB piece at a time (usbboot's ep_write), a stall watchdog, timing stats for the log
        {
            const bulkUsb = (opts) => ({
                vendorId: 0x0a5c, productId: 0x2712, serialNumber: 'a7eb274c', opened: true, closed: false,
                ctrl: [], pieces: [], inflight: 0, maxInflight: 0,
                async controlTransferOut(setup) { this.ctrl.push(setup.value | (setup.index << 16)); return { status: 'ok' }; },
                transferOut(ep, data) {
                    const i = this.pieces.length;
                    this.pieces.push(new Uint8Array(data));
                    this.inflight++;
                    this.maxInflight = Math.max(this.maxInflight, this.inflight);
                    return opts.piece(i, data).then((r) => { this.inflight--; return r; });
                },
                async releaseInterface() {},
                async close() { this.closed = true; this.opened = false; },
            });
            const later = (ms, v) => new Promise((r) => setTimeout(() => r(v), ms));
            const payload = new Uint8Array(16384 * 20 + 1000);
            for (let i = 0; i < payload.length; i++) payload[i] = (i * 7 + (i >> 9)) & 0xff;

            const okUsb = bulkUsb({ piece: (i, data) => later(i % 3, { status: 'ok', bytesWritten: data.byteLength }) });
            const okDev = new OTP.rpiboot.RpiDevice(okUsb);
            okDev.outEp = 1;
            const prog = [];
            const n = await okDev.epWrite(payload, (s, t) => prog.push([s, t]));
            eq(n, payload.byteLength, 'ep_write: every byte reported sent');
            eq(okUsb.ctrl.join(','), String(payload.byteLength), 'ep_write: one length announcement first');
            eq(okUsb.pieces.length, 21, 'ep_write: 16 KiB pieces');
            assert(okUsb.pieces.every((p) => p.byteLength <= 16384), 'ep_write: no piece above 16 KiB');
            const joined = new Uint8Array(payload.byteLength);
            let off = 0;
            for (const p of okUsb.pieces) { joined.set(p, off); off += p.byteLength; }
            assert(joined.every((b, i) => b === payload[i]), 'ep_write: pieces in order, bytes intact');
            eq(okUsb.maxInflight, 1, 'ep_write: one piece in flight at a time, as usbboot does');
            deq(prog[prog.length - 1], [payload.byteLength, payload.byteLength], 'ep_write: progress reaches the total');
            eq(okDev.lastWrite.chunks + ':' + okDev.lastWrite.bytes, '21:' + payload.byteLength, 'ep_write: stats count the pieces and bytes');

            const partUsb = bulkUsb({ piece: (i, data) => later(0, { status: 'ok', bytesWritten: i === 2 ? 100 : data.byteLength }) });
            const part = new OTP.rpiboot.RpiDevice(partUsb);
            part.outEp = 1;
            eq(await part.epWrite(payload), payload.byteLength, 'ep_write: a partial write continues from where it stopped (usbboot: buf += sent)');
            eq(partUsb.pieces[3][0], payload[32768 + 100], 'ep_write: the piece after a partial write starts at the first unsent byte');

            const stuckUsb = bulkUsb({ piece: (i, data) => (i === 3 ? new Promise(() => {}) : later(0, { status: 'ok', bytesWritten: data.byteLength })) });
            const stuck = new OTP.rpiboot.RpiDevice(stuckUsb);
            stuck.outEp = 1;
            stuck.bulkStallMs = 60;
            const se = await throwsLike(() => stuck.epWrite(payload), /stopped reading after 49152 of 328680 bytes .*3 pieces of 16 KiB/, 'ep_write: a piece that never completes → stall error at the last completed byte');
            assert(se && se.stalled === true, 'ep_write: stall error is marked', String(se));
            assert(stuckUsb.closed, 'ep_write: a stall closes the device (Chrome then fails the pending transfer)');

            const goneErr = await (async () => {
                const d = new OTP.rpiboot.RpiDevice(bulkUsb({ piece: (i, data) => (i === 4 ? later(1).then(() => { throw new DOMException('device gone', 'NetworkError'); }) : later(0, { status: 'ok', bytesWritten: data.byteLength })) }));
                d.outEp = 1;
                try { await d.epWrite(payload); } catch (e) { return e; }
                return null;
            })();
            eq(goneErr && goneErr.name, 'NetworkError', 'ep_write: a failing transfer\'s own error is thrown');
            await later(20);
        }

        // runSession leaves every enumeration alone for a second before opening it (rpiboot: sleep(1) before libusb_open)
        {
            const romA = T.romDevice({ serial: 'a7eb274c' });
            const fsB = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' }] });
            const opened = [];
            const tS = Date.now();
            let tWait = 0;
            for (const d of [romA, fsB]) { const o = d.open.bind(d); d.open = async () => { opened.push(Date.now() - tS); return o(); }; }
            const sess = new OTP.rpiboot.RpiBootSession(stage2, { log: () => {} });
            await OTP.rpiboot.runSession(sess, romA, async () => { tWait = Date.now() - tS; return fsB; });
            assert(opened.length >= 2 && opened[0] >= 950, 'settle: the first device is opened after ~1 s', JSON.stringify(opened));
            assert(opened.length >= 2 && opened[opened.length - 1] - tWait >= 950, 'settle: the re-enumerated device is opened ~1 s after it appeared', JSON.stringify({ opened, tWait }));

            const romC = T.romDevice({ serial: 'a7eb274c' });
            const sessC = new OTP.rpiboot.RpiBootSession(stage2, { log: () => {} });
            let openedC = false;
            const oc = romC.open.bind(romC);
            romC.open = async () => { openedC = true; return oc(); };
            setTimeout(() => sessC.abort(), 50);
            const tA = Date.now();
            await throwsLike(() => OTP.rpiboot.runSession(sessC, romC, async () => fsB), /aborted/, 'settle: abort during the pause → aborted');
            assert(!openedC && Date.now() - tA < 600, 'settle: abort cuts the pause short and nothing is opened', `${Date.now() - tA} ms, opened=${openedC}`);
        }

        // ================================================================ T5 app manual panels
        section = 'app-manual';
        const app = OTP.app;
        assert(app && app.panels.length === 2, 'two boot panels');
        eq(OTP.registry, undefined, 'registry.js (localStorage) is gone');
        const p2 = app.panels[1];
        await p2.loadDir(stage2);
        const rows = [...p2.filesTable.querySelectorAll('tbody tr')];
        eq(rows.length, 4, 'stage 2 expected-file rows');
        eq(rows[0].querySelector('td.status').textContent, '✓', 'bootcode5.bin found (tar)');
        eq(rows[3].querySelector('td.status').textContent, 'optional, absent', 'boot.sig optional');
        assert(p2.otherFiles.textContent.includes('2712/bootcode5.bin'), 'tar contents listed');
        assert(rows[0].lastChild.textContent.length === 64, 'sha256 column filled');
        eq(p2.irreversible.length, 0, 'stage 2 msd config has no irreversible keys');
        const p1 = app.panels[0];
        await p1.loadDir(stage1);
        eq(p1.irreversible.map((f) => f.key).join(','), 'program_pubkey', 'stage 1 irreversible keys detected');
        assert(p1.otpRequested, 'otpRequested');
        assert(p1.flagsBox.textContent.includes('IRREVERSIBLE'), 'irreversible flag rendered');
        let v = p1.verdict({ metadata: { EEPROM_UPDATE: 'success', SECURE_BOOT_PROVISION: 'success', CUSTOMER_KEY_HASH: 'AB' }, filesServed: [] });
        assert(v.ok, 'stage 1 verdict ok', v.notes.join('|'));
        p1.keyHashInput.value = 'ab';
        v = p1.verdict({ metadata: { EEPROM_UPDATE: 'success', SECURE_BOOT_PROVISION: 'success', CUSTOMER_KEY_HASH: 'AB' }, filesServed: [] });
        assert(v.ok && v.notes.some((n) => /matches/.test(n)), 'key hash match (case-insensitive)', v.notes.join('|'));
        p1.keyHashInput.value = 'cd';
        v = p1.verdict({ metadata: { EEPROM_UPDATE: 'success', SECURE_BOOT_PROVISION: 'success', CUSTOMER_KEY_HASH: 'AB' }, filesServed: [] });
        assert(!v.ok, 'key hash mismatch → not ok');
        p1.keyHashInput.value = '';
        v = p1.verdict({ metadata: { EEPROM_UPDATE: 'success' }, filesServed: [] });
        assert(!v.ok && v.notes.some((n) => /SECURE_BOOT_PROVISION = missing/.test(n)), 'OTP requested but not confirmed → not ok', v.notes.join('|'));
        v = p2.verdict({ metadata: {}, filesServed: [{ name: 'boot.img' }], interrupted: true });
        assert(v.ok && v.notes.length === 2, 'stage 2 verdict ok with interruption note');
        eq(p1.btnRun.disabled, true, 'run disabled without a device');

        // #14: the irreversible-key check reads the config.txt the file server will serve (BootDir.resolve)
        function makeTar(members) {
            const parts = [];
            for (const [name, data] of Object.entries(members)) {
                const h = new Uint8Array(512);
                h.set(enc.encode(name), 0);
                h.set(enc.encode(data.byteLength.toString(8).padStart(11, '0') + '\0'), 124);
                h[156] = 0x30;
                h.set(enc.encode('ustar\0'), 257);
                const body = new Uint8Array(Math.ceil(data.byteLength / 512) * 512);
                body.set(data);
                parts.push(h, body);
            }
            parts.push(new Uint8Array(1024));
            const out = new Uint8Array(parts.reduce((a, b) => a + b.byteLength, 0));
            let o = 0;
            for (const b of parts) { out.set(b, o); o += b.byteLength; }
            return out;
        }
        const stage1Files = () => [
            { path: 'bootcode5.bin', file: mk('bootcode5.bin', new Uint8Array(1000).fill(1)) },
            { path: 'pieeprom.bin', file: mk('pieeprom.bin', new Uint8Array(2048).fill(2)) },
            { path: 'pieeprom.sig', file: mk('pieeprom.sig', enc.encode('deadbeef\nts: 1\n')) },
            { path: 'config.txt', file: mk('config.txt', enc.encode('uart_2ndstage=1\nrecovery_reboot=1\n')) },
        ];
        {
            const ov = OTP.BootDir.fromEntries('ov1', [...stage1Files(),
                { path: 'bootfiles.bin', file: mk('bootfiles.bin', bootfiles) },
                { path: '2712/config.txt', file: mk('config.txt', enc.encode('program_pubkey=1\nprogram_jtag_lock=1\n')) }]);
            await p1.loadDir(ov);
            eq(p1.irreversible.map((f) => f.key).join(','), 'program_pubkey,program_jtag_lock', 'manual: the 2712/config.txt overlay (what is served) is checked, not the top-level file');
            assert(p1.otpRequested, 'manual: overlay program_pubkey → OTP requested');
            assert(p1.flagsBox.textContent.includes('ov1/2712/config.txt'), 'manual: the served config.txt is named', p1.flagsBox.textContent);
            assert(/ov1\/config\.txt differs and is NOT served/.test(p1.flagsBox.textContent), 'manual: the shadowed top-level config.txt is flagged', p1.flagsBox.textContent);
        }
        {
            const tarDir = OTP.BootDir.fromEntries('tm1', [...stage1Files(),
                { path: 'bootfiles.bin', file: mk('bootfiles.bin', makeTar({ '2712/bootcode5.bin': new Uint8Array(900).fill(5), '2712/config.txt': enc.encode('program_pubkey=1\n') })) }]);
            await p1.loadDir(tarDir);
            eq(p1.irreversible.map((f) => f.key).join(','), 'program_pubkey', 'manual: the bootfiles.bin member 2712/config.txt is checked');
            const prep = await p1.prepareRun(chip);
            eq(prep.cfg && prep.cfg.origin, 'bootfiles.bin:2712/config.txt', 'manual: prepareRun resolves the same config.txt as the file server');
        }
        {
            // the bytes that were checked are the bytes the board receives, even if the file changes after the check
            const disk = {
                'bootcode5.bin': new Uint8Array(1000).fill(1),
                'config.txt': enc.encode('uart_2ndstage=1\n'),
                '2712/config.txt': enc.encode('program_pubkey=1\n'),
            };
            const md = new OTP.BootDir('mut1', async (rel) => (disk[rel] ? disk[rel].slice() : null));
            await p1.loadDir(md);
            const prep = await p1.prepareRun(chip);
            eq(prep.flags.map((f) => f.key).join(','), 'program_pubkey', 'manual: prepareRun flags from the served file');
            disk['2712/config.txt'] = enc.encode('program_jtag_lock=1\nrevoke_devkey=1\n');
            md._cache.clear();
            const fsC = T.fsDevice({ serial: 'a7eb274c', script: [{ cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' }, { cmd: 2, name: 'done' }] });
            const sc = new OTP.rpiboot.RpiBootSession(md, { log: () => {} });
            await sc.step(new OTP.rpiboot.RpiDevice(fsC));
            eq(dec.decode(fsC.bulk.length ? fsC.bulk[0] : new Uint8Array(0)), 'program_pubkey=1\n', 'manual: the file server sends the confirmed config.txt bytes (pinned)');
            const p2711 = await p1.prepareRun(OTP.CHIPS[0x2711]);
            eq(p2711.cfg && p2711.cfg.origin, 'mut1/config.txt', 'manual: prepareRun follows the selected device\'s chip');
            eq(p1.irreversible.length, 0, 'manual: flags re-derived for that chip');
        }

        // ================================================================ T6 fastboot basics (scripted replies)
        section = 'fastboot';
        function mockFb(replies) {
            return {
                vendorId: 0x1d6b, productId: 0x0104, serialNumber: 'fb1', opened: false, configuration: null, sent: [],
                configurations: [{ configurationValue: 1, interfaces: [{ interfaceNumber: 0, alternates: [{ alternateSetting: 0, interfaceClass: 0xff, interfaceSubclass: 0x42, interfaceProtocol: 0x03, endpoints: [{ direction: 'in', type: 'bulk', endpointNumber: 1 }, { direction: 'out', type: 'bulk', endpointNumber: 2 }] }] }] }],
                async open() { this.opened = true; }, async close() { this.opened = false; }, async selectConfiguration() { this.configuration = this.configurations[0]; },
                async claimInterface() {}, async releaseInterface() {},
                async transferOut(ep, data) { const u = new Uint8Array(data.buffer, data.byteOffset, data.byteLength); const text = u.every((b) => b >= 0x20 && b < 0x7f); this.sent.push(text ? dec.decode(u) : '<' + u.byteLength + ' bytes>'); return { status: 'ok', bytesWritten: u.byteLength }; },
                async transferIn() { const x = replies.shift(); if (x === undefined) throw new Error('no reply'); return { status: 'ok', data: new DataView(enc.encode(x).buffer) }; },
            };
        }
        const fbu = mockFb(['INFOversion: 0.4', 'INFOmax-download-size: 0x1000', 'OKAY', 'OKAY0x1000', 'DATA00000010', 'OKAY', 'INFOwriting', 'OKAY', 'FAILnope']);
        const fbc = new OTP.fastboot.FastbootClient(fbu);
        await fbc.open();
        eq(fbc.inEp + ':' + fbc.outEp, '1:2', 'endpoints');
        const vars = await fbc.getvarAll();
        eq(vars['max-download-size'], '0x1000', 'getvar:all parsed');
        await fbc.flash('mmcblk0', new Uint8Array(16));
        eq(fbu.sent.join('|'), 'getvar:all|getvar:max-download-size|download:00000010|<16 bytes>|flash:mmcblk0', 'flash command sequence');
        const fbErr = await throwsLike(() => fbc.command('oem nope'), /FAIL nope/, 'FAIL → FastbootError');
        eq(fbErr && fbErr.name, 'FastbootError', 'error class');
        const big = new OTP.fastboot.FastbootClient(mockFb(['OKAY0x10']));
        await big.open();
        await throwsLike(() => big.download(new Uint8Array(32)), /max-download-size/, 'oversize download refused');
        deq(OTP.fastboot.FILTERS, [{ vendorId: 0x18d1, productId: 0x4e40 }, { classCode: 0xff, subclassCode: 0x42, protocolCode: 0x03 }], 'USB filters: 18d1:4e40 + class ff/42/03');

        // ================================================================ T7 FastbootClient IDP against the rpi-fastbootd simulator
        section = 'idp';
        // the station's layout: the boot partition plus the root as a LUKS2 container the station built, written raw
        const imageJsonObj = { IGversion: '2.0.0', IGmeta: { IGconf_device_class: 'pi5', IGconf_device_storage_type: 'sd' }, layout: { partitionimages: { boot: { simage: 'boot.sparse' }, root: { simage: 'root.luks.sparse' } } } };
        const imageJson = enc.encode(JSON.stringify(imageJsonObj));
        const bootPiece = T.bytesOf(300000, 11);
        const root0 = T.bytesOf(2 * 1048576 + 123, 12);
        const root1 = T.bytesOf(3 * 65536, 13);
        const idpParts = () => ({
            'boot.sparse': [{ name: 'boot.sparse', size: bootPiece.byteLength, bytes: bootPiece }],
            'root.luks.sparse': [{ name: 'root.luks.sparse.0', size: root0.byteLength, bytes: root0 }, { name: 'root.luks.sparse.1', size: root1.byteLength, bytes: root1 }],
        });
        {
            const sim = new T.FastbootSim({ staleIdp: true });
            const c = new OTP.fastboot.FastbootClient(sim);
            c.eraseSettleMs = 30;
            await c.open();
            eq(await c.getvarText('serialno'), '10000000a7eb274c', 'getvarText strips the trailing NUL');
            sim.commands.length = 0;
            const logs = [];
            const keys = [];
            const prog = [];
            const tErase = Date.now();
            const res = await c.idpProvision({
                imageJson, parts: idpParts(),
                onDeviceKey: async (p) => keys.push(p), onProgress: (p) => prog.push(p), log: (l, m) => logs.push(`${l}: ${m}`),
            });
            const norm = sim.commands.map((x) => (x.startsWith('download:') ? 'download' : x));
            deq(norm, ['oem fwcrypto init', 'getvar:public-key', 'getvar:max-download-size',
                'erase:mmcblk0', 'download', 'oem idpinit', 'oem idpdone',
                'erase:mmcblk0', 'download', 'oem idpinit', 'oem idpwrite',
                'oem idpgetblk', 'download', 'flash:mmcblk0p1',
                'oem idpgetblk', 'download', 'flash:mmcblk0p2', 'download', 'flash:mmcblk0p2',
                'oem idpgetblk', 'oem idpdone', 'reboot'], 'full IDP command sequence (fwcrypto, erase, idpinit retry, multi-piece flash, reboot)');
            assert(Date.now() - tErase >= 60, 'erase waits eraseSettleMs after each erase');
            eq(sim.erased.join(','), 'mmcblk0,mmcblk0', 'erase:mmcblk0 before each idpinit attempt');
            deq(sim.flashes.map((f) => [f.dev, f.size, f.checksum]), [
                ['mmcblk0p1', bootPiece.byteLength, T.checksum(bootPiece)],
                ['mmcblk0p2', root0.byteLength, T.checksum(root0)],
                ['mmcblk0p2', root1.byteLength, T.checksum(root1)]], 'pieces flashed in order, byte-exact');
            const dl = sim.downloads;
            assert(dl.length === 5, 'five data phases (2× image.json + 3 pieces)', String(dl.length));
            const aligned = dl.every((d) => d.chunks.slice(0, -1).every((n) => n % 65536 === 0));
            assert(aligned, 'every data-phase transferOut except the last is a multiple of 64 KiB', JSON.stringify(dl.map((d) => d.chunks)));
            assert(dl.some((d) => d.chunks.length >= 3), 'a >2 MiB piece is sent in several chunks', JSON.stringify(dl.map((d) => d.chunks)));
            assert(dl.every((d) => d.chunks.reduce((a, b) => a + b, 0) === d.size), 'data phases carry exactly the announced size');
            assert(keys.length === 1 && keys[0].includes('BEGIN PUBLIC KEY') && keys[0].includes('END PUBLIC KEY'), 'device public key PEM reported');
            eq(res.flashed.map((f) => `${f.dev}:${f.simage}:${f.pieces.length}`).join(' '), 'mmcblk0p1:boot.sparse:1 mmcblk0p2:root.luks.sparse:2', 'result.flashed');
            deq(res.verified, [], 'result.verified: nothing to check without verifyKey');
            const last = prog[prog.length - 1];
            eq(last.phase + ':' + (last.sent === last.total) + ':' + last.total, `done:true:${bootPiece.byteLength + root0.byteLength + root1.byteLength}`, 'progress ends at total bytes');
            assert(sim.maxCommandSeen <= 256, 'no command above 256 bytes');
            eq(sim.idp, null, 'IDP closed with idpdone');
        }
        for (const outcome of ['ok', 'fails', 'slot1']) {
            // station-built LUKS container: the board writes it raw to mmcblk0p2, then checks that its own key opens
            // keyslot 0 (oem cryptcheck: nothing is opened on the board)
            const sim = new T.FastbootSim({ blocks: ['mmcblk0p1:boot.sparse', 'mmcblk0p2:root.luks.sparse'],
                cryptCheckFails: outcome === 'fails', cryptCheckSlot: outcome === 'slot1' ? 1 : 0 });
            const c = new OTP.fastboot.FastbootClient(sim);
            await c.open();
            sim.commands.length = 0;
            const parts = { 'boot.sparse': idpParts()['boot.sparse'], 'root.luks.sparse': [{ name: 'root.luks.sparse.0', size: root1.byteLength, bytes: root1 }] };
            const run = () => c.idpProvision({ imageJson, parts, erase: false, powerOff: true, verifyKey: [{ dev: 'mmcblk0p2', label: 'OSROOT_CRYPT' }] });
            if (outcome === 'ok') {
                const res = await run();
                deq(sim.commands.slice(-4), ['oem idpgetblk', 'oem cryptcheck mmcblk0p2', 'oem idpdone', 'shutdown'],
                    'verifyKey: oem cryptcheck after the last block, before idpdone; powerOff: "shutdown" instead of "reboot"');
                eq(sim.poweredOff, true, 'powerOff: the gadget powered the board off');
                deq(sim.flashes.map((f) => f.dev), ['mmcblk0p1', 'mmcblk0p2'], 'the container is written raw to the partition, no mapper');
                deq(res.verified, [{ dev: 'mmcblk0p2', keyslot: 0 }], 'result.verified: keyslot 0');
            } else if (outcome === 'fails') {
                await throwsLike(run, /OTP device key does not open mmcblk0p2 \(OSROOT_CRYPT\).*stays in the fastboot gadget/, 'a container the board cannot open fails the run');
                deq(sim.commands.slice(-2), ['oem cryptcheck mmcblk0p2', 'oem idpdone'], '… with idpdone and without reboot');
            } else {
                await throwsLike(run, /opens keyslot 1 of mmcblk0p2 \(OSROOT_CRYPT\), not keyslot 0.*stays in the fastboot gadget/, 'the board key must open keyslot 0, not another slot');
                deq(sim.commands.slice(-2), ['oem cryptcheck mmcblk0p2', 'oem idpdone'], '… with idpdone and without reboot');
            }
        }
        {
            const sim = new T.FastbootSim({ blocks: ['mmcblk0p1:boot.sparse'] });
            const c = new OTP.fastboot.FastbootClient(sim);
            await c.open();
            sim.idp = 'partitioned';
            deq(await c.idpGetBlk(), { dev: 'mmcblk0p1', simage: 'boot.sparse' }, 'idpGetBlk parses INFO <dev>:<simage> (noise INFO ignored)');
            eq(await c.idpGetBlk(), null, 'idpGetBlk → null on a bare "OKAYIDP:done"');
            const n = sim.commands.length;
            await throwsLike(() => c.command('oem ' + 'x'.repeat(253)), /at most 256/, 'command length guard (257 bytes)');
            eq(sim.commands.length, n, 'an over-long command is never sent');
            await throwsLike(() => c.command('oem ' + 'x'.repeat(252)), /Unknown OEM command/, 'a 256-byte command is sent');
            eq(sim.maxCommandSeen, 256, 'device received exactly 256 bytes');
            const nc = sim.commands.length;
            await throwsLike(() => c.cryptCheck('mapper/osroot_crypt'), /invalid partition/, 'cryptCheck: a bare partition name only');
            await throwsLike(() => c.cryptCheck('../sda'), /invalid partition/, 'cryptCheck: no paths');
            eq(sim.commands.length, nc, '… and nothing is sent for them');
            const fc = await c.fwcryptoInit();
            eq(fc.message + ':' + fc.created, 'Key provisioned and LOCKed:true', 'fwcryptoInit: new key');
            const fc2 = await c.fwcryptoInit();
            eq(fc2.message + ':' + fc2.created, 'Key already provisioned:false', 'fwcryptoInit: idempotent');
        }
        {
            const sim = new T.FastbootSim({ failFlash: 'mmcblk0p2', keyProvisioned: true });
            const c = new OTP.fastboot.FastbootClient(sim);
            c.eraseSettleMs = 0;
            await c.open();
            await throwsLike(() => c.idpProvision({ imageJson, parts: idpParts(), log: () => {} }), /exceeds partition/, 'flash FAIL → error');
            deq(sim.commands.slice(-2), ['flash:mmcblk0p2', 'oem idpdone'], 'flash failure → oem idpdone, no reboot');
        }
        {
            const sim = new T.FastbootSim({ maxDownload: 0x100000, keyProvisioned: true });
            const c = new OTP.fastboot.FastbootClient(sim);
            c.eraseSettleMs = 0;
            await c.open();
            await throwsLike(() => c.idpProvision({ imageJson, parts: idpParts(), log: () => {} }), /max-download-size/, 'piece above max-download-size refused');
            eq(sim.commands[sim.commands.length - 1], 'oem idpdone', '… and the IDP is closed');
        }
        {
            const sim = new T.FastbootSim({ keyProvisioned: true });
            const c = new OTP.fastboot.FastbootClient(sim);
            c.eraseSettleMs = 0;
            await c.open();
            const parts = idpParts();
            delete parts['root.luks.sparse'];
            await throwsLike(() => c.idpProvision({ imageJson, parts, log: () => {} }), /no such file/, 'unknown simage requested → error');
            eq(sim.commands[sim.commands.length - 1], 'oem idpdone', '… and the IDP is closed');
        }

        // ================================================================ T7b upload / upload-file / download-file
        section = 'upload';
        {
            // the station rpi-fastbootd exchanges only the otp-keyexport files (here under /run/x)
            const sim = new T.FastbootSim({ keyExport: false, keyExportDir: '/run/x' });
            const c = new OTP.fastboot.FastbootClient(sim);
            await c.open();
            eq(await c.uploadFile('/run/x/status'), null, 'uploadFile: a missing file ("Error opening file, ERRNO: 2") → null');
            deq(sim.commands, ['oem upload-file /run/x/status'], '… after "oem upload-file" alone (no upload)');
            sim.files.set('/run/x/status', new Uint8Array(0));
            eq(await c.uploadFile('/run/x/status'), null, 'uploadFile: an empty file ("Filesize zero") → null');
            const small = T.bytesOf(200, 51);
            sim.files.set('/run/x/key.der', small);
            const gotSmall = await c.uploadFile('/run/x/key.der');
            eq(gotSmall && `${gotSmall.byteLength}:${T.checksum(gotSmall)}`, `200:${T.checksum(small)}`, 'uploadFile: 200 bytes back byte-exact');
            deq(sim.commands.slice(-2), ['oem upload-file /run/x/key.der', 'upload'], 'uploadFile: oem upload-file <path>, then upload');
            deq(sim.uploads[0] && [sim.uploads[0].asked, sim.uploads[0].sent], [[200], [200]], 'upload: one transfer asking for exactly the 200 announced bytes');
            const big = T.bytesOf(1300, 52);
            sim.files.set('/run/x/key.der', big);
            const gotBig = await c.uploadFile('/run/x/key.der');
            eq(gotBig && `${gotBig.byteLength}:${T.checksum(gotBig)}`, `1300:${T.checksum(big)}`, 'uploadFile: 1300 bytes (more than one 512-byte transfer) reassembled byte-exact');
            deq(sim.uploads[1] && sim.uploads[1].sent, [512, 512, 276], 'upload: the device sends the data phase as 512 + 512 + 276');
            deq(sim.uploads[1] && sim.uploads[1].asked, [1300, 788, 276], 'upload: every transferIn asks for exactly the bytes still due');
            eq(sim.responses.length, 0, 'upload: the final OKAY was read (nothing pending)');
            const r = await c.downloadFile('/run/x/request', enc.encode('export\n'));
            eq(r && r.status, 'OKAY', 'downloadFile: OKAY');
            deq(sim.commands.slice(-2), ['download:00000007', 'oem download-file /run/x/request'], 'downloadFile: download:%08x + data, then oem download-file <path>');
            eq(sim.files.get('/run/x/request') && dec.decode(sim.files.get('/run/x/request')), 'export\n', 'downloadFile: the gadget file holds the bytes');
            deq(sim.downloads[sim.downloads.length - 1].chunks, [7], 'downloadFile: one 7-byte data phase');
            const n = sim.commands.length;
            await throwsLike(() => c.uploadFile('/run/x/a b'), /invalid path/, 'uploadFile: a path with whitespace is refused');
            await throwsLike(() => c.downloadFile('', enc.encode('x')), /invalid path/, 'downloadFile: an empty path is refused');
            eq(sim.commands.length, n, '… and nothing is sent for them');
            // anything else on the board cannot be read or written through the station gadget
            sim.files.set('/etc/shadow', enc.encode('root:*:'));
            await throwsLike(() => c.uploadFile('/etc/shadow'), /Unknown OEM command/, 'uploadFile: a path outside the key export helper is refused');
            await throwsLike(() => c.uploadFile('/dev/mmcblk0p2'), /Unknown OEM command/, 'uploadFile: a block device is refused');
            await throwsLike(() => c.downloadFile('/run/x/key.der', enc.encode('x')), /Unknown OEM command/, 'downloadFile: only the request file');
            await throwsLike(() => c.command('oem cryptopen mmcblk0p2 x'), /Unknown OEM command/, 'oem cryptopen is refused');
            await throwsLike(() => c.command('oem mount /dev/mmcblk0p2 /mnt'), /Unknown OEM command/, 'oem mount is refused');
        }
        {
            // more than 1 MiB: the reads are capped at 1 MiB (DATA_CHUNK), the rest is asked for exactly
            const sim = new T.FastbootSim({ keyExport: false, keyExportDir: '/run/x', uploadChunk: 4 << 20 });
            const c = new OTP.fastboot.FastbootClient(sim);
            await c.open();
            const huge = T.bytesOf((1 << 20) + 4103, 53);
            sim.files.set('/run/x/key.der', huge);
            const got = await c.uploadFile('/run/x/key.der');
            eq(got && `${got.byteLength}:${T.checksum(got)}`, `${huge.byteLength}:${T.checksum(huge)}`, 'upload of 1 MiB + 4103 bytes byte-exact');
            deq(sim.uploads[0] && sim.uploads[0].asked, [1 << 20, 4103], 'upload: transferIn lengths capped at 1 MiB, then the remainder');
            const fresh = new T.FastbootSim({ keyExport: false });
            const c2 = new OTP.fastboot.FastbootClient(fresh);
            await c2.open();
            await throwsLike(() => c2.upload(), /FAIL No data/, 'upload with nothing staged → FAIL');
            const old = new T.FastbootSim({ keyExport: false, keyExportDir: '/run/x', fileCommands: false });
            const c3 = new OTP.fastboot.FastbootClient(old);
            await c3.open();
            await throwsLike(() => c3.uploadFile('/run/x/key.der'), /Unknown OEM command/, 'uploadFile: a gadget without "oem upload-file" is an error, not a missing file');
        }

        // ================================================================ T7c exportDeviceKey (gadget otp-keyexport helper)
        section = 'keyexport';
        const KX = { dir: '/run/otp-keyexport', key: '/run/otp-keyexport/key.der', status: '/run/otp-keyexport/status', request: '/run/otp-keyexport/request' };
        const KEY_A = await T.makeDeviceKey();
        const KEY_B = await T.makeDeviceKey();
        const openFb = async (opts) => { const sim = new T.FastbootSim(opts); const c = new OTP.fastboot.FastbootClient(sim); await c.open(); return { sim, c }; };
        {
            // the OTP already holds a key: the helper exported it at gadget boot, before rpi-fastbootd READ-locked it
            const { sim, c } = await openFb({ deviceKey: KEY_A });
            eq(sim.keyStatus(), 'exported key.der', 'existing key: the boot run of the helper exported it');
            const logs = [];
            const r = await c.exportDeviceKey(KX, { log: (l, m) => logs.push(`${l}: ${m}`), pollMs: 10 });
            eq(r.generated, false, 'existing key: generated=false');
            eq(T.hex(r.der), T.hex(KEY_A.der), 'existing key: key.der = the OTP key (PKCS#8 DER)');
            deq(sim.commands, [`oem upload-file ${KX.key}`, 'upload'], 'existing key: only key.der is fetched, nothing is requested');
            eq(sim.keyRequests + sim.fileWrites.length, 0, 'existing key: nothing written to the gadget');
            assert(!logs.some((l) => l.includes(T.b64(KEY_A.der).slice(10, 40))), 'existing key: the key bytes are never logged', logs.join(' | '));
            eq(await c.publicKey(), KEY_A.pem, 'existing key: getvar:public-key is the same key');
        }
        {
            // blank slot: request → the helper generates the key (OTP write) → poll until key.der appears
            const { sim, c } = await openFb({ keyGenDelayMs: 80 });
            eq(sim.keyStatus().split(' ')[0], 'blank', 'blank slot: the helper reports "blank" at boot');
            const logs = [];
            const r = await c.exportDeviceKey(KX, { log: (l, m) => logs.push(`${l}: ${m}`), pollMs: 20, timeoutMs: 5000 });
            eq(r.generated, true, 'blank slot: generated=true');
            eq(sim.keyGenerated && T.hex(r.der) === T.hex(sim.deviceKey.der), true, 'blank slot: the key generated on request is the one exported');
            deq(sim.commands.filter((x) => !x.startsWith('getvar:')).slice(0, 5), [`oem upload-file ${KX.key}`, `oem upload-file ${KX.status}`, 'upload', 'download:00000007', `oem download-file ${KX.request}`],
                'blank slot: key.der missing → status read → "export\\n" written to the request file');
            deq(sim.fileWrites, [{ path: KX.request, size: 7 }], 'blank slot: exactly one request ("export\\n", 7 bytes)');
            eq(sim.keyRequests, 1, 'blank slot: the helper ran its request mode once');
            const polls = sim.commands.slice(sim.commands.indexOf(`oem download-file ${KX.request}`) + 1).filter((x) => x === `oem upload-file ${KX.key}`).length;
            assert(polls >= 2, 'blank slot: key.der polled until it appeared', `${polls} polls: ${sim.commands.slice(sim.commands.indexOf(`oem download-file ${KX.request}`) + 1).join(' | ')}`);
            deq(sim.commands.slice(-2), [`oem upload-file ${KX.key}`, 'upload'], 'blank slot: ends with the upload of key.der');
            assert(logs.some((l) => /OTP key slot is empty: the gadget generates the device key/.test(l)), 'blank slot: the OTP write is announced in the log', logs.join(' | '));
            const pem = await c.publicKey();
            eq(T.hex(await T.spkiOfPkcs8(r.der)), T.hex(T.pemDer(pem, 'PUBLIC KEY')), 'blank slot: the exported private key belongs to getvar:public-key');
            const fc = await c.fwcryptoInit();
            eq(`${fc.message}:${fc.created}`, 'Key already provisioned:false', 'blank slot: afterwards "oem fwcrypto init" answers "Key already provisioned"');
        }
        {
            const { sim, c } = await openFb({ deviceKey: KEY_A, readLocked: true });
            eq(sim.keyStatus().split(' ')[0], 'locked', 'READ-locked key: the helper says "locked"');
            await throwsLike(() => c.exportDeviceKey(KX, { pollMs: 10 }), /cannot be exported in this boot .*run stage 2 again/, 'READ-locked key: error (reboot the gadget: run stage 2 again)');
            eq(sim.fileWrites.length, 0, 'READ-locked key: no request written');
        }
        {
            const { sim, c } = await openFb({ keyExport: false, deviceKey: KEY_A });
            await throwsLike(() => c.exportDeviceKey(KX, { pollMs: 10 }), /no OTP key export helper/, 'no helper in the gadget: error (rebuild the gadget)');
            eq(sim.fileWrites.length, 0, 'no helper: no request written');
        }
        {
            const { sim, c } = await openFb({ keyGenDelayMs: 60000 });
            const tt = Date.now();
            await throwsLike(() => c.exportDeviceKey(KX, { pollMs: 20, timeoutMs: 200 }), /did not export the device key within 0 s \(busy generating/, 'timeout: error with the last status');
            assert(Date.now() - tt < 3000, 'timeout: honoured', `${Date.now() - tt} ms`);
            eq(sim.keyRequests, 1, 'timeout: the request was sent once');
        }
        {
            const { c } = await openFb({ keyGenError: 'mailbox: -5' });
            await throwsLike(() => c.exportDeviceKey(KX, { pollMs: 10, timeoutMs: 5000 }), /export failed: error genkey: mailbox: -5/, 'genkey fails while polling → error');
        }
        {
            const { sim, c } = await openFb({ bootStatus: 'error no firmware mailbox device (/dev/vcio_crypto, /dev/vcio)' });
            await throwsLike(() => c.exportDeviceKey(KX, { pollMs: 10 }), /could not read the OTP device key: error no firmware mailbox/, 'helper error at boot → error');
            eq(sim.fileWrites.length, 0, 'helper error at boot: no request written');
        }

        // ================================================================ T8 server.js + BootDir.fromManifest
        section = 'api';
        {
            const calls = [];
            const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
            const blob = T.bytesOf(200000, 21);
            const stub = async (url, init) => {
                const method = (init && init.method) || 'GET';
                calls.push(`${method} ${url}${init && init.body ? ' ' + init.body : ''}`);
                if (url === '/api/status') return json(200, { version: '0.2.0', config: { provisioning: { confirm_irreversible: true } } });
                if (url === '/api/modules/a7eb274c/stage/2') return json(409, { ready: false, reason: 'gadget build running', job: { id: 'j1', status: 'running' } });
                if (url === '/api/modules/a7eb274c/stage/1') return json(200, { stage: 1, kind: 'rpiboot', files: [] });
                if (url === '/api/modules/zz') return json(404, { detail: 'unknown module zz' });
                if (url === '/api/modules/hello') return json(200, { module: { serial: 'a7eb274c' }, created: true });
                if (url === '/api/builds/gadget') return json(200, { job: { id: 'j2', status: 'queued' } });
                if (url === '/f.bin') return new Response(blob, { status: 200, headers: { 'Content-Length': String(blob.byteLength) } });
                return json(404, { detail: 'Not Found' });
            };
            const a = OTP.createApi({ fetch: stub, EventSource: T.FakeEventSource });
            const st = await a.probe();
            eq(a.available && st.version, '0.2.0', 'probe → available');
            const nr = await a.stage('a7eb274c', 2);
            eq(nr.ready + ':' + nr.reason + ':' + nr.job.id, 'false:gadget build running:j1', 'stage(): 409 resolves {ready:false, reason, job}');
            eq((await a.stage('a7eb274c', 1)).ready, true, 'stage(): 200 → ready manifest');
            const e404 = await throwsLike(() => a.module('zz'), /unknown module zz/, 'module(): 404 → ApiError with detail');
            eq(e404 && e404.status, 404, 'ApiError.status');
            await a.hello({ serial: 'a7eb274c', chip: 'BCM2712' });
            assert(calls.includes('POST /api/modules/hello {"serial":"a7eb274c","chip":"BCM2712"}'), 'hello POSTs JSON', calls.join(' | '));
            await a.startBuild('gadget', true);
            assert(calls.includes('POST /api/builds/gadget {"force":true}'), 'startBuild body {force}', calls.join(' | '));
            const prog = [];
            const got = await a.fetchBytes('/f.bin', (x, t) => prog.push([x, t]));
            eq(got.byteLength === blob.byteLength && T.checksum(got) === T.checksum(blob), true, 'fetchBytes streams the whole body');
            eq(prog.length > 0 && prog[prog.length - 1][0] === blob.byteLength && prog[prog.length - 1][1] === blob.byteLength, true, 'fetchBytes progress reaches Content-Length');
            const lines = [];
            let doneInfo = null;
            a.jobLog('j1', (l) => lines.push(l), (d) => { doneInfo = d; });
            const es = T.FakeEventSource.last;
            eq(es.url, '/api/jobs/j1/log', 'jobLog opens the SSE URL');
            es.emit('{"line":"==> step 1"}');
            es.emit('{"line":"done here"}');
            es.emitEvent('done', '{"status":"succeeded","rc":0}');
            deq(lines, ['==> step 1', 'done here'], 'jobLog lines');
            eq(doneInfo && doneInfo.status + ':' + doneInfo.rc + ':' + es.closed, 'succeeded:0:true', 'jobLog done → onDone + close');
            const dead = OTP.createApi({ fetch: async () => { throw new TypeError('Failed to fetch'); } });
            eq(await dead.probe(), null, 'probe with no server → null');
            eq(dead.available, false, 'available=false with no server');
            eq(OTP.api && typeof OTP.api.stage, 'function', 'OTP.api default instance');
        }
        section = 'manifest';
        {
            const f = {
                'bootfiles.bin': bootfiles,
                'config.txt': enc.encode('boot_ramdisk=1\nuart_2ndstage=1\n'),
                'boot.img': T.bytesOf(50000, 31),
            };
            const manifest = { stage: 2, kind: 'rpiboot', mode: 'unsigned', files: [] };
            for (const [name, b] of Object.entries(f)) manifest.files.push({ name, size: b.byteLength, sha256: await sha(b), url: `/api/modules/a7eb274c/stage/2/files/${name}` });
            const fetched = [];
            const fetchBytes = async (url, p) => { fetched.push(url); const b = f[url.split('/').pop()]; if (p) p(b.byteLength, b.byteLength); return b.slice(); };
            const bd = OTP.BootDir.fromManifest(manifest, { fetchBytes });
            eq(bd.name, 'server stage 2 (unsigned)', 'display name');
            let x = await bd.resolve('bootcode5.bin', chip);
            eq(x && x.origin, 'bootfiles.bin:2712/bootcode5.bin', 'second stage from the served bootfiles.bin');
            x = await bd.resolve('config.txt', chip);
            eq(x && dec.decode(x.data), 'boot_ramdisk=1\nuart_2ndstage=1\n', 'config.txt from the manifest');
            x = await bd.resolve('boot.img', chip);
            eq(x && x.data.byteLength, 50000, 'boot.img from the manifest');
            await bd.resolve('boot.img', chip);
            await bd.resolve('config.txt', chip);
            eq(fetched.filter((u) => u.endsWith('/boot.img')).length, 1, 'each file is fetched once');
            eq(await bd.resolve('boot.sig', chip), null, 'a name outside the manifest → null, no fetch');
            eq(fetched.some((u) => u.endsWith('boot.sig')), false, '… nothing fetched for it');
            eq((await bd.validate()).length, 0, 'validate: bootfiles.bin present');
            eq((await bd.listTop()).map((e) => e.name).join(','), 'bootfiles.bin,config.txt,boot.img', 'listTop from the manifest');
            const bad = OTP.BootDir.fromManifest({ stage: 1, files: [{ name: 'config.txt', size: 3, sha256: '00'.repeat(32), url: '/x/config.txt' }] }, { fetchBytes: async () => enc.encode('abc') });
            await throwsLike(() => bad.resolve('config.txt', chip), /SHA-256 mismatch/, 'sha256 mismatch → error');
            const short = OTP.BootDir.fromManifest({ stage: 1, files: [{ name: 'config.txt', size: 5, url: '/x/config.txt' }] }, { fetchBytes: async () => enc.encode('abc') });
            await throwsLike(() => short.resolve('config.txt', chip), /manifest says 5/, 'size mismatch → error');
        }

        // ================================================================ T9 Flow: full run ROM → gadget → fastboot
        section = 'flow';
        eq(OTP.Flow.normalizeSerial('10000000A7EB274C\0'), 'a7eb274c', 'normalizeSerial: 16 hex → last 8');
        eq(OTP.Flow.normalizeSerial(' a7eb274c '), 'a7eb274c', 'normalizeSerial: 8 hex trimmed');
        eq(OTP.Flow.normalizeSerial('Broadcom'), '', 'normalizeSerial: "Broadcom" → unusable');

        const KEYHASH = 'ab'.repeat(32);
        async function buildServerFiles() {
            const files = new Map();
            const add = async (stageNo, name, bytes, dir) => {
                const url = `/api/modules/a7eb274c/stage/${stageNo}/files/${dir ? dir + '/' : ''}${name}`;
                files.set(url, bytes);
                return { name, size: bytes.byteLength, sha256: await sha(bytes), url, origin: 'test' };
            };
            // open scenario: unsigned EEPROM, nothing for OTP
            const m1open = {
                stage: 1, kind: 'rpiboot', title: 'EEPROM & OTP', ready: true, mode: 'unsigned',
                files: [await add(1, 'bootcode5.bin', T.bytesOf(1000, 44), 'open'), await add(1, 'pieeprom.bin', T.bytesOf(4096, 45), 'open'),
                    await add(1, 'pieeprom.sig', enc.encode('11\nts: 1\n'), 'open'),
                    await add(1, 'config.txt', enc.encode('uart_2ndstage=1\nset_reboot_order=0x3\nrecovery_reboot=1\n'), 'open')],
                irreversible: [], expect: { secure_boot_provision: false, customer_key_hash: null }, notes: ['unsigned EEPROM update; OTP is not changed in this stage'],
            };
            const m1 = {
                stage: 1, kind: 'rpiboot', title: 'EEPROM & OTP', ready: true, mode: 'signed',
                files: [await add(1, 'bootcode5.bin', T.bytesOf(1000, 41)), await add(1, 'pieeprom.bin', T.bytesOf(4096, 42)),
                    await add(1, 'pieeprom.sig', enc.encode('00\nts: 1\nrsa2048: ' + 'aa'.repeat(256) + '\n')),
                    await add(1, 'config.txt', enc.encode('uart_2ndstage=1\nset_reboot_order=0x3\nrecovery_reboot=1\nprogram_pubkey=1\n'))],
                irreversible: [{ key: 'program_pubkey', value: '1', why: 'burns the key hash into OTP' }],
                expect: { secure_boot_provision: true, customer_key_hash: KEYHASH }, notes: [],
            };
            const m2 = {
                stage: 2, kind: 'rpiboot', title: 'Fastboot gadget', ready: true, mode: 'unsigned',
                files: [await add(2, 'bootfiles.bin', bootfiles), await add(2, 'boot.img', T.bytesOf(70000, 43)), await add(2, 'config.txt', enc.encode('boot_ramdisk=1\nuart_2ndstage=1\n'))],
                irreversible: [], expect: { secure_boot_provision: false, customer_key_hash: null }, notes: [],
            };
            const ij = await add(3, 'image.json', imageJson);
            const pb = await add(3, 'boot.sparse', bootPiece);
            const r0 = await add(3, 'root.luks.sparse.0', root0);
            const r1 = await add(3, 'root.luks.sparse.1', root1);
            const c0 = await add(3, 'root.sparse.0', root0);
            const c1 = await add(3, 'root.sparse.1', root1);
            // secure scenario: the root as the board's LUKS2 container, built on the station (ciphertext only)
            const m3 = {
                stage: 3, kind: 'fastboot-idp', title: 'Image', ready: true, mode: 'unsigned', scenario: 'secure',
                image: { name: 'deb13-arm64-min', version: 'v1-test', set: 'set1', variant: 'crypt', encrypted: true },
                storage_device: 'mmcblk0', image_json: ij,
                parts: { 'boot.sparse': [pb], 'root.luks.sparse': [r0, r1] },
                total_bytes: bootPiece.byteLength + root0.byteLength + root1.byteLength, max_piece_size: 268435456,
                fwcrypto_init: true, key_export: Object.assign({}, KX), erase: true,
                verify_key: [{ dev: 'mmcblk0p2', label: 'OSROOT_CRYPT' }],
                irreversible: [{ key: 'oem fwcrypto init', value: '', why: 'device key in OTP' }, { key: 'erase', value: 'mmcblk0', why: 'wipes the card' }],
                notes: ['the OTP device key is exported to the station before the storage is erased'],
            };
            // open scenario: clear image, no OTP key, nothing exported
            const m3open = Object.assign({}, m3, {
                scenario: 'open', image: { name: 'deb13-arm64-min', version: 'v1-test', set: 'set1-clear', variant: 'clear', encrypted: false },
                parts: { 'boot.sparse': [pb], 'root.sparse': [c0, c1] },
                fwcrypto_init: false, key_export: null, verify_key: [],
                irreversible: [{ key: 'erase', value: 'mmcblk0', why: 'wipes the card' }],
                notes: ['open scenario: clear image, OTP is not touched'],
            });
            return { files, m1, m2, m3, m1open, m3open };
        }
        const FLOW_OPTS = { reenumTimeoutMs: 20000, fastbootTimeoutMs: 20000, pollMs: 25, needDeviceAfterMs: 150, buildPollMs: 60, eraseSettleMs: 10, fileServerRetryMs: 20, rpibootSettleMs: 20 };
        function makeFlow(api, hub, ev, extraOpts) {
            let flow = null;
            flow = new OTP.Flow({
                api, usb: hub, options: Object.assign({}, FLOW_OPTS, extraOpts || {}),
                hooks: {
                    onStage: (n, st, d) => ev.stages.push(`${n}:${st}`),
                    onNeed: (kind) => {
                        ev.need.push(kind);
                        if (!kind || ev.noAutoPick) return;
                        (async () => {
                            await until(() => (kind === 'fastboot' ? hub.has('fastboot') : hub.devices.some((d) => d.kind === 'fs')), 15000, 'device for ' + kind);
                            if (kind === 'fastboot') await flow.connectFastboot(); else await flow.selectDevice();
                        })().catch((e) => ev.errors.push(e.message));
                    },
                    onConfirm: async (req) => { ev.confirms.push(req); return ev.confirmAnswer !== false; },
                    onLog: (l, m) => ev.logs.push(`${l}: ${m}`),
                    onBuildWait: (n) => ev.buildWaits.push(n),
                    onModule: (m) => ev.modules.push(m.stage),
                    onProgress: (n, p) => { ev.progress[n] = p; },
                },
            });
            return flow;
        }
        const newEv = () => ({ stages: [], need: [], confirms: [], logs: [], buildWaits: [], modules: [], progress: {}, errors: [] });

        {
            const { files, m1, m2, m3 } = await buildServerFiles();
            const job = { id: 'job3', target: 'image', title: 'Build OS images (clear + crypt)', status: 'running' };
            const api = new T.FakeApi({ files, manifests: { 1: m1, 2: m2, 3: (k) => (k <= 2 ? { ready: false, reason: 'the OS image is being built', job } : m3) } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub, { serial: 'a7eb274c', keyHash: KEYHASH, stage1Timeouts: { 6: 3 }, fastboot: { keyGenDelayMs: 30 } });
            board.powerOnRom();
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { scenario: 'secure' });
            const m = await flow.connectBoard();
            eq(m && m.serial, 'a7eb274c', 'connectBoard → hello → module');
            deq(api.calls[0][1], { serial: 'a7eb274c', chip: 'BCM2712', board: 'Pi 5 / CM5 / Pi 500', usb: { vendor_id: 0x0a5c, product_id: 0x2712, product_name: 'BCM2712 Boot', manufacturer: 'Broadcom', serial_number: 'a7eb274c' }, rom_stage: 'rom' }, 'hello body');
            eq(`${m && m.mode}:${m && m.mode_chosen}`, 'open:', 'a new record: the server default scenario, none chosen yet');
            eq(flow.scenarioChanges(), false, 'a new board: picking "secure" is not a scenario change (no progress yet)');
            deq(flow.plan(), [1, 2, 3], 'plan for a new board: 1, 2, 3');
            const tRun = Date.now();
            const ok = await flow.provision();
            results.push(`  flow run took ${Date.now() - tRun} ms; board history: ${board.history.join(' → ')}`);
            eq(ok, true, 'provision() succeeded');
            if (!ok) results.push('  flow log:\n    ' + ev.logs.slice(-25).join('\n    '));
            eq(flow.module && flow.module.stage, 'flashed', 'server record ends at "flashed"');
            eq([1, 2, 3].map((n) => flow.stages[n].state).join(','), 'done,done,done', 'all three stages done');
            deq(board.history, ['rom', 'fs', 'rom', 'fs', 'fastboot'], 'board went ROM → recovery → ROM → bootloader → fastboot gadget');
            const res = api.calls.filter((c) => c[0] === 'result');
            eq(res.map((c) => c[2]).join(','), '1,2,3', 'results posted for stages 1, 2, 3 in order');
            const b1 = res[0] && res[0][3];
            eq(b1 && b1.ok && b1.metadata.EEPROM_UPDATE, 'success', 'stage 1 result: metadata from the recovery');
            eq(b1 && b1.files_served.map((x) => x.name).join(','), 'config.txt,pieeprom.sig,pieeprom.bin', 'stage 1 result: files_served');
            eq(b1 && b1.expect.secure_boot_provision && b1.expect.customer_key_hash, KEYHASH, 'stage 1 result: expect from the manifest');
            eq(b1 && b1.metadata.CUSTOMER_KEY_HASH, KEYHASH, 'stage 1: CUSTOMER_KEY_HASH reported');
            const b2 = res[1] && res[1][3];
            eq(b2 && b2.files_served.map((x) => x.name).join(',') + ':' + b2.interrupted, 'config.txt,boot.img:true', 'stage 2 result: boot.img served, board left USB');
            eq(flow.stages[2].detail, 'boot.img delivered; the board is booting the fastboot gadget', 'stage 2 detail: the hand-off is presented as expected, not as an interruption');
            const n2 = (flow.stages[2].verdict && flow.stages[2].verdict.notes) || [];
            assert(!n2.includes('run was interrupted') && n2.some((t) => /expected: the fastboot gadget took over/.test(t)), 'stage 2 notes: the generic "interrupted" note is explained', JSON.stringify(n2));
            assert(/EEPROM_UPDATE = success/.test(flow.stages[1].detail), 'stage 1 detail: a summary, not the raw notes', flow.stages[1].detail);
            assert(ev.logs.some((l) => /still attached/.test(l)), 'stage 1: WinUSB control-IN timeouts during the EEPROM write were retried', ev.logs.filter((l) => /Read failed|went away/.test(l)).join(' | '));
            const b3 = res[2] && res[2][3];
            eq(b3 && b3.ok && b3.details.flashed.length, 2, 'stage 3 result: two simages flashed');
            deq(b3 && b3.details.verified, [{ dev: 'mmcblk0p2', keyslot: 0 }], 'stage 3 result: the board key opens keyslot 0 of its container');
            eq(b3 && 'crypt' in b3.details, false, 'stage 3 result: no passphrase field at all');
            assert(b3 && /BEGIN PUBLIC KEY/.test(b3.details.device_key_pem), 'stage 3 result: device key');
            const facts = api.calls.find((c) => c[0] === 'facts');
            eq(facts && facts[2].duid + ':' + /BEGIN PUBLIC KEY/.test(facts[2].device_key_pem), '10000000a7eb274c:true', 'facts posted: device_key_pem + duid');
            const idc = api.calls.find((c) => c[0] === 'identify');
            eq(idc && idc[1].serialno, '10000000a7eb274c', 'identify: 16-hex serialno without NUL');
            eq(idc && idc[1].vars.product, 'Raspberry Pi 5 Model B Rev 1.0', 'identify: vars (product)');
            assert(idc && OTP.Flow.FASTBOOT_VARS.every((k) => k in idc[1].vars), 'identify: every whitelisted getvar', JSON.stringify(idc && idc[1].vars));
            const names = api.names();
            assert(names.indexOf('identify') < names.indexOf('deviceKey') && names.indexOf('deviceKey') < names.indexOf('facts') && names.indexOf('facts') < names.indexOf('result3'),
                'order: identify → deviceKey → facts → result3', names.join(' '));
            // scenario: chosen on the server before anything else
            deq(api.calls[1], ['setMode', 'a7eb274c', 'secure'], 'secure: api.setMode(serial, "secure") right after hello');
            assert(names.indexOf('setMode') < names.findIndex((x) => /^stage\d$/.test(x)), 'secure: the scenario is sent before the first stage manifest is fetched', names.join(' '));
            eq(names.filter((x) => x === 'setMode').length, 1, 'secure: setMode called once');
            eq(flow.module && `${flow.module.mode}:${flow.module.mode_chosen}:${flow.module.mode_locked}`, 'secure:secure:true', 'secure: the record ends secure, chosen and locked');
            // stage 3: the OTP device key is exported BEFORE anything is erased, then posted to the server
            const fbs = board.fb;
            const cmds = fbs ? fbs.commands : [];
            const iReq = cmds.indexOf(`oem download-file ${KX.request}`);
            const iKey = cmds.lastIndexOf(`oem upload-file ${KX.key}`);
            const iFw = cmds.indexOf('oem fwcrypto init');
            const iErase = cmds.indexOf('erase:mmcblk0');
            assert(iReq > 0 && iKey > iReq && cmds[iKey + 1] === 'upload', 'secure: blank OTP slot → request → key.der uploaded', cmds.slice(0, Math.max(iFw, 0) + 1).join(' | '));
            assert(iKey >= 0 && iKey < iFw && iFw < iErase, 'secure: key export → oem fwcrypto init → erase (the key is out before anything is erased)', `export ${iKey}, fwcrypto ${iFw}, erase ${iErase}`);
            eq(fbs && fbs.keyGenerated, true, 'secure: the gadget generated the device key on request');
            const dk = api.calls.find((c) => c[0] === 'deviceKey');
            eq(dk && dk[1], 'a7eb274c', 'secure: deviceKey posted for the board');
            eq(dk && fbs && T.hex(T.unb64(dk[2].key_der_b64)) === T.hex(fbs.deviceKey.der), true, 'secure: key_der_b64 = the gadget\'s key.der');
            eq(dk && fbs && dk[2].device_key_pem.trim() === fbs.deviceKey.pem.trim(), true, 'secure: device_key_pem = getvar:public-key');
            eq(flow.module && flow.module.otp.device_key_exported, true, 'secure: the server record says the key was exported');
            assert(ev.logs.includes('info: Board a7eb274c: secure scenario'), 'secure: the first scenario choice of a new board is logged plainly', ev.logs.filter((l) => /scenario/.test(l)).join(' | '));
            eq(ev.logs.some((l) => /every stage is redone/.test(l)), false, 'secure: … and does not claim "every stage is redone" (nothing was reset)');
            eq(api.gated, 2, 'secure: the early manifests of stages 2 and 3 are refused (409) until stage 1 has burnt our key hash');
            assert(ev.logs.some((l) => /OTP device key stored on the server/.test(l)), 'secure: "stored on the server" logged');
            assert(ev.logs.some((l) => /fwcrypto: Key already provisioned/.test(l)), 'secure: oem fwcrypto init found the exported key ("Key already provisioned")', ev.logs.filter((l) => /fwcrypto/.test(l)).join(' | '));
            assert(fbs && !ev.logs.some((l) => l.includes(T.b64(fbs.deviceKey.der).slice(8, 40))), 'secure: the private key never appears in the log');
            assert(names.indexOf('deviceKey') < names.indexOf('result3'), 'secure: deviceKey before result3');
            eq(ev.confirms.length, 2, 'two confirmations: stage 1 up front, stage 3 once its manifest is ready');
            eq(ev.confirms[0] && ev.confirms[0].token, 'a7eb274c', 'confirmation token = serial');
            eq(ev.confirms[0] && ev.confirms[0].flags.map((f) => f.key).join('|'), 'stage 1: program_pubkey', 'first confirmation: program_pubkey');
            eq(ev.confirms[1] && ev.confirms[1].flags.map((f) => f.key).join('|'), 'stage 3: oem fwcrypto init|stage 3: erase', 'second confirmation: fwcrypto init + erase');
            assert(ev.stages.includes('3:waiting') && ev.buildWaits.includes(3), '409 with a running job → stage 3 waits and polls', ev.stages.join(' '));
            assert(ev.need.includes('rpiboot'), 'second stage without permission → "Select device" requested');
            assert(ev.need.includes('fastboot'), 'fastboot gadget → "Connect fastboot gadget" requested');
            eq(ev.need[ev.need.length - 1], null, 'need cleared at the end');
            eq(ev.errors.length, 0, 'no errors in the device pickers');
            const sim = board.fb;
            deq(sim && sim.flashes.map((f) => [f.dev, f.checksum]), [['mmcblk0p1', T.checksum(bootPiece)], ['mmcblk0p2', T.checksum(root0)], ['mmcblk0p2', T.checksum(root1)]], 'the gadget received the server pieces byte-exact');
            deq(sim && sim.cryptChecks, [{ dev: 'mmcblk0p2', keyslot: 0 }], 'the board checked its key against the container (oem cryptcheck)');
            assert(sim && sim.downloads.every((d) => d.chunks.slice(0, -1).every((n) => n % 65536 === 0)), 'flow: 64 KiB-aligned data phases');
            assert(sim && !sim.commands.some((c) => /^oem (cryptopen|cryptsetpassword|mount)\b/.test(c)), 'flow: nothing opens or reads the container on the board');
            eq(sim && sim.commands[sim.commands.length - 1], 'shutdown', 'the gadget powers the board off at the end (no reboot into the new system on the station\'s USB power)');
            eq(sim && sim.commands.includes('reboot'), false, '… and never reboots it');
            assert(/powered off: unplug it/.test(flow.stages[3].detail), 'stage 3 detail tells the operator to move the board to its own supply', flow.stages[3].detail);
            const p3 = ev.progress[3];
            eq(p3 && p3.sent === p3.total && p3.total === m3.total_bytes, true, 'stage 3 progress reached total_bytes');
            deq(flow.plan(), [], 'plan after provisioning: nothing left');
            eq(await flow.provision(), true, 'provision() on a flashed board is a no-op');
            eq(api.calls.filter((c) => c[0] === 'setMode').length, 1, 'the no-op run sends no setMode (mode_chosen already "secure")');
        }

        // the open scenario: unsigned EEPROM, clear image, nothing written to OTP, no key export, no fwcrypto init
        section = 'flow-open';
        {
            const { files, m1open, m2, m3open } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: m1open, 2: m2, 3: m3open } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub, { serial: 'a7eb274c', program: false, fastboot: { blocks: ['mmcblk0p1:boot.sparse', 'mmcblk0p2:root.sparse'] } });
            board.powerOnRom();
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { scenario: 'open' });
            await flow.connectBoard();
            const ok = await flow.provision();
            eq(ok, true, 'open: provision() succeeded');
            if (!ok) results.push('  open flow log:\n    ' + ev.logs.slice(-20).join('\n    '));
            deq(api.calls[1], ['setMode', 'a7eb274c', 'open'], 'open: the scenario is sent first (none was chosen for the board yet)');
            eq(flow.module && `${flow.module.stage}:${flow.module.mode}:${flow.module.mode_locked}:${flow.module.otp.locked}`, 'flashed:open:false:false', 'open: flashed, OTP not locked');
            const cmds = board.fb ? board.fb.commands : [];
            deq(cmds.filter((c) => /^oem (upload-file|download-file|fwcrypto)|^upload$/.test(c)), [], 'open: no key export and no oem fwcrypto init on the gadget');
            eq(board.fb && board.fb.keyProvisioned, false, 'open: the OTP key slot stays empty');
            eq(api.calls.some((c) => c[0] === 'deviceKey' || c[0] === 'facts'), false, 'open: no device key posted (the board has none)');
            deq(board.fb && board.fb.flashes.map((f) => f.dev), ['mmcblk0p1', 'mmcblk0p2', 'mmcblk0p2'], 'open: clear image flashed to the plain partitions');
            eq(board.fb && board.fb.cryptChecks.length, 0, 'open: no oem cryptcheck (nothing encrypted)');
            eq(board.fb && board.fb.commands[board.fb.commands.length - 1], 'shutdown', 'open: the board is powered off at the end too');
            eq(ev.confirms.length, 1, 'open: one confirmation');
            eq(ev.confirms[0] && ev.confirms[0].flags.map((f) => f.key).join('|'), 'stage 3: erase', 'open: the only irreversible step is the erase');
            const b1 = api.calls.find((c) => c[0] === 'result' && c[2] === 1);
            eq(b1 && `${b1[3].expect.secure_boot_provision}:${b1[3].metadata.SECURE_BOOT_PROVISION}`, 'false:undefined', 'open: stage 1 expects no OTP programming');
            const r3 = api.calls.find((c) => c[0] === 'result' && c[2] === 3);
            eq(r3 && `${r3[3].ok}:${r3[3].details.device_key_pem}`, 'true:null', 'open: stage-3 result without a device key');
        }

        // ================================================================ T10 Flow: failure paths
        section = 'flow-errors';
        {
            const { files, m2, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: { ready: false, reason: 'board OTP is locked to a different key (CUSTOMER_KEY_HASH 1234…)', job: null }, 2: m2, 3: m3 } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub);
            const rom = board.powerOnRom();
            const ev = newEv();
            const flow = makeFlow(api, hub, ev);
            await flow.connectBoard();
            const ok = await flow.provision([1]);
            eq(ok, false, '409 without a job → stage fails');
            eq(flow.stages[1].state, 'failed', 'stage 1 failed');
            assert(/locked to a different key/.test(flow.stages[1].detail), 'the server reason is shown', flow.stages[1].detail);
            eq(rom.events.length, 0, 'no rpiboot traffic when the server refuses the stage');
            eq(api.calls.some((c) => c[0] === 'result'), false, 'no result posted');
        }
        {
            const { files, m1, m2, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: m1, 2: m2, 3: m3 } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub);
            const rom = board.powerOnRom();
            const ev = newEv();
            ev.confirmAnswer = false;
            const flow = makeFlow(api, hub, ev);
            await flow.connectBoard();
            eq(await flow.provision(), false, 'confirmation cancelled → provision() false');
            eq(ev.confirms.length, 1, 'asked once');
            eq(rom.events.length + api.calls.filter((c) => c[0] === 'result').length, 0, 'nothing written, nothing posted');
            eq(flow.running, false, 'flow idle again');
        }
        {
            const { files, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: null, 2: null, 3: m3 } });
            const hub = new T.MockHub();
            const sim = new T.FastbootSim({ goneOnFlash: 'mmcblk0p2', deviceKey: KEY_A });
            hub.plug(sim);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev);
            const m = await flow.connectBoard();
            eq(m && m.serial + ':' + m.stage, 'a7eb274c:gadget', 'connect directly to a fastboot gadget → identify');
            deq(flow.plan(), [3], 'plan for a board already in the gadget: stage 3');
            const ok = await flow.provision();
            eq(ok, false, 'board unplugged while flashing → stage 3 fails');
            assert(/disconnected/.test(flow.stages[3].detail), 'clear "disconnected" message', flow.stages[3].detail);
            const r3 = api.calls.find((c) => c[0] === 'result');
            eq(r3 && r3[2] + ':' + r3[3].ok, '3:false', 'failed stage-3 result posted');
            assert(r3 && r3[3].details.flashed.length === 0 && /BEGIN PUBLIC KEY/.test(r3[3].details.device_key_pem || ''), 'partial details (device key) kept in the failure report');
            deq(flow.plan(), [3], 'resume: stage 3 is still pending');
        }
        {
            const { files, m1 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: m1 } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub);
            board.powerOnRom();
            const ev = newEv();
            ev.noAutoPick = true; // nobody clicks "Select device": abort while waiting
            const flow = makeFlow(api, hub, ev);
            await flow.connectBoard();
            const p = flow.provision([1]);
            await until(() => ev.need.includes('rpiboot'), 8000, 'need rpiboot');
            flow.abort();
            eq(await p, false, 'abort while waiting for a device → provision() false');
            eq(flow.stages[1].detail, 'aborted by the operator', 'aborted stage message');
        }

        {
            // #1: a stage that fails before anything reached the board leaves the same ROM device usable for a retry
            const { files, m1 } = await buildServerFiles();
            const broken = Object.assign({}, m1, { files: m1.files.filter((f) => f.name !== 'bootcode5.bin') });
            const api = new T.FakeApi({ files, manifests: { 1: broken } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub, { keyHash: KEYHASH });
            const rom = board.powerOnRom();
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { reenumTimeoutMs: 3000 });
            await flow.connectBoard();
            eq(await flow.provision([1]), false, 'retry: stage 1 fails without the second-stage file');
            assert(/Failed to open second stage/.test(flow.stages[1].detail), 'retry: the missing file is reported', flow.stages[1].detail);
            eq(rom.events.length, 0, 'retry: nothing was sent to the ROM');
            eq(flow.deviceStale, false, 'retry: the untouched ROM device is not marked stale');
            api.manifests[1] = m1;
            const ok = await flow.provision([1]);
            eq(ok, true, 'retry: the second attempt reuses the still-connected ROM device');
            if (!ok) results.push('  retry log:\n    ' + ev.logs.slice(-12).join('\n    '));
            eq(flow.deviceStale, true, 'retry: after the hand-off the device is stale');
        }
        {
            // #2: a fastboot gadget of another board (unusable USB iSerial) is refused before identify()
            const { files, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: null, 2: null, 3: m3 } });
            const hub = new T.MockHub();
            const mine = new T.FastbootSim({ serial64: '10000000a7eb274c', deviceKey: KEY_A });
            hub.plug(mine);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev);
            await flow.connectBoard();
            eq(flow.serial, 'a7eb274c', 'foreign gadget: connected to board a7eb274c');
            hub.unplug(mine);
            const other = new T.FastbootSim({ serial64: '10000000deadbeef', deviceKey: KEY_B });
            other.serialNumber = 'RPI-GADGET'; // no usable USB serial: only getvar:serialno tells the boards apart
            hub.plug(other);
            const before = api.calls.filter((c) => c[0] === 'identify').length;
            eq(await flow.provision([3]), false, 'foreign gadget: stage 3 fails');
            assert(/belongs to board deadbeef, not a7eb274c/.test(flow.stages[3].detail), 'foreign gadget: clear message', flow.stages[3].detail);
            eq(api.calls.filter((c) => c[0] === 'identify').length, before, 'foreign gadget: identify() was not called for it');
            eq(api.modules.has('deadbeef'), false, 'foreign gadget: no server record created for it');
            eq(flow.serial, 'a7eb274c', 'foreign gadget: the run stays on board a7eb274c');
            eq(other.flashes.length + other.erased.length + other.commands.filter((c) => c.startsWith('oem')).length, 0, 'foreign gadget: nothing written to it');
            eq(ev.confirms.map((c) => c.token).join(','), 'a7eb274c', 'foreign gadget: only the up-front confirmation for board a7eb274c');
            // retry with the refused gadget still attached: the run must not pick it again, it must wait for
            // and use the gadget of board a7eb274c once that is plugged back in
            eq(flow.device, null, 'foreign gadget: the refused gadget is dropped as the current device');
            setTimeout(() => hub.plug(mine), 50);
            const retried = await flow.provision([3]);
            eq(retried, true, 'foreign gadget: the retry provisions the right gadget', flow.stages[3].detail);
            eq(other.flashes.length + other.erased.length, 0, 'foreign gadget: still nothing written to the refused gadget');
            assert(mine.flashes.length > 0, 'foreign gadget: the right gadget was flashed on retry');
        }
        {
            // #2: confirmations are keyed by board serial
            const api = new T.FakeApi({ files: new Map(), manifests: {} });
            const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: FLOW_OPTS, hooks: {} });
            flow.serial = 'a7eb274c';
            const a = flow._irreversibleOf(1, { irreversible: [{ key: 'program_pubkey', value: '1' }] });
            flow.serial = 'deadbeef';
            const b = flow._irreversibleOf(1, { irreversible: [{ key: 'program_pubkey', value: '1' }] });
            assert(a[0].id !== b[0].id && a[0].id.startsWith('a7eb274c|'), 'confirmation ids carry the board serial', a[0].id + ' / ' + b[0].id);
        }

        // ================================================================ T10b Flow: scenario (Open / Secure) handling
        section = 'flow-scenario';
        {
            const refused = { ready: false, reason: 'stop here (test)', job: null };
            /** A flow on a seeded module (no USB): scenario `want`, every stage manifest refused. */
            const scenarioFlow = (fields, want, apiOpts) => {
                const api = new T.FakeApi(Object.assign({ files: new Map(), manifests: { 1: refused, 2: refused, 3: refused } }, apiOpts || {}));
                const m = api.seed('a7eb274c', fields);
                const ev = newEv();
                const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: Object.assign({}, FLOW_OPTS, { scenario: want }), hooks: { onLog: (l, x) => ev.logs.push(`${l}: ${x}`), onConfirm: async () => true } });
                flow.module = JSON.parse(JSON.stringify(m));
                flow.serial = m.serial;
                return { api, flow, ev };
            };
            let pick = 'secure';
            const fnFlow = new OTP.Flow({ api: new T.FakeApi({ files: new Map(), manifests: {} }), usb: new T.MockHub(), options: { scenario: () => pick } });
            eq(fnFlow.scenario(), 'secure', 'scenario option as a function (the page radios)');
            pick = 'open';
            eq(fnFlow.scenario(), 'open', '… read on every call');
            pick = 'weird';
            eq(fnFlow.scenario(), '', 'unknown scenario → ""');
            deq(fnFlow.plan(), [], 'plan without a module: nothing');

            // plan() / scenarioChanges(): module.mode is the scenario the stages so far ran in
            const planOf = (fields, want) => { const { flow } = scenarioFlow(fields, want); return `${flow.scenarioChanges()}:${flow.plan().join('')}`; };
            eq(planOf({ stage: 'new' }, 'secure'), 'false:123', 'new board, secure picked: no change, plan 1,2,3');
            eq(planOf({ stage: 'eeprom', mode: 'open', mode_chosen: 'open' }, 'open'), 'false:23', 'eeprom done, same scenario: plan 2,3');
            eq(planOf({ stage: 'eeprom', mode: 'open', mode_chosen: 'open' }, 'secure'), 'true:123', 'eeprom done in open, secure picked: every stage redone (1,2,3)');
            eq(planOf({ stage: 'flashed', mode: 'open', mode_chosen: 'open' }, 'open'), 'false:', 'flashed, same scenario: nothing to do');
            eq(planOf({ stage: 'flashed', mode: 'open', mode_chosen: 'open' }, 'secure'), 'true:123', 'flashed in open, secure picked: plan 1,2,3');
            eq(planOf({ stage: 'flashed', mode: 'open', mode_chosen: '' }, 'secure'), 'true:123', 'flashed with the server default (open), secure picked: plan 1,2,3');
            eq(planOf({ stage: 'flashed', mode: 'open', mode_chosen: '' }, 'open'), 'false:', 'flashed with the server default, the same scenario picked: nothing to do');
            eq(planOf({ stage: 'gadget', mode: 'secure', mode_chosen: 'secure', mode_locked: true }, 'secure'), 'false:23', 'locked board in secure: no change');
            eq(planOf({ stage: 'eeprom', mode: 'open', mode_chosen: 'open' }, ''), 'false:23', 'no scenario picked: never a change');
        }
        {
            // setMode is called before any stage, with the picked scenario
            const refused = { ready: false, reason: 'stop here (test)', job: null };
            const api = new T.FakeApi({ files: new Map(), manifests: { 1: refused } });
            const m = api.seed('a7eb274c', { stage: 'new' });
            const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: Object.assign({}, FLOW_OPTS, { scenario: 'secure' }), hooks: {} });
            flow.module = JSON.parse(JSON.stringify(m));
            flow.serial = 'a7eb274c';
            eq(await flow.provision([1]), false, 'setMode: the run itself stops at the refused stage 1');
            deq(api.calls[0], ['setMode', 'a7eb274c', 'secure'], 'setMode: first call of the run, with the picked scenario');
            eq(api.names().slice(1).every((x) => x === 'stage1'), true, 'setMode: only then the stage manifests', api.names().join(' '));
            eq(`${flow.module.mode}:${flow.module.mode_chosen}`, 'secure:secure', 'setMode: the flow takes the module the server returned');
        }
        {
            // not called again when the board already has that scenario
            const refused = { ready: false, reason: 'stop here (test)', job: null };
            const api = new T.FakeApi({ files: new Map(), manifests: { 1: refused } });
            const m = api.seed('a7eb274c', { stage: 'new', mode: 'secure', mode_chosen: 'secure' });
            const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: Object.assign({}, FLOW_OPTS, { scenario: 'secure' }), hooks: {} });
            flow.module = JSON.parse(JSON.stringify(m));
            flow.serial = 'a7eb274c';
            await flow.provision([1]);
            eq(api.calls.some((c) => c[0] === 'setMode'), false, 'mode_chosen already "secure": no setMode');
        }
        {
            // the server default is not a choice: it is sent once (and resets nothing when it is the same)
            const api = new T.FakeApi({ files: new Map(), manifests: {} });
            const m = api.seed('a7eb274c', { stage: 'flashed', mode: 'open', mode_chosen: '' });
            const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: Object.assign({}, FLOW_OPTS, { scenario: 'open' }), hooks: {} });
            flow.module = JSON.parse(JSON.stringify(m));
            flow.serial = 'a7eb274c';
            eq(await flow.provision(), true, 'default scenario confirmed on a flashed board: nothing to run');
            deq(api.calls.map((c) => c.join(' ')), ['setMode a7eb274c open'], '… setMode records the choice, no stage is fetched');
            eq(flow.module.stage, 'flashed', '… and the board stays flashed');
        }
        {
            // a board whose OTP holds a key hash can only be provisioned in the secure scenario
            const api = new T.FakeApi({ files: new Map(), manifests: {} });
            const m = api.seed('a7eb274c', { stage: 'gadget', mode: 'secure', mode_chosen: 'secure', mode_locked: true, otp: { locked: true, locked_to_our_key: true, secure_boot_provisioned: true } });
            const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: Object.assign({}, FLOW_OPTS, { scenario: 'open' }), hooks: {} });
            flow.module = JSON.parse(JSON.stringify(m));
            flow.serial = 'a7eb274c';
            await throwsLike(() => flow.provision(), /only the secure scenario is possible/, 'open on a mode_locked board → refused before anything runs');
            eq(api.calls.length, 0, 'mode_locked: no setMode, no stage call');
            eq(flow.running, false, 'mode_locked: the flow is idle');
            await throwsLike(() => api.setMode('a7eb274c', 'open'), /only the secure scenario/, 'FakeApi mirrors the server: setMode open on a locked board → 400');
        }
        {
            // switching scenario on a board with progress: the server resets the stage, the run plans 1, 2, 3
            const refused = { ready: false, reason: 'stop here (test)', job: null };
            const api = new T.FakeApi({ files: new Map(), manifests: { 1: refused, 2: refused, 3: refused } });
            const m = api.seed('a7eb274c', { stage: 'flashed', mode: 'open', mode_chosen: 'open' });
            const ev = newEv();
            const flow = new OTP.Flow({ api, usb: new T.MockHub(), options: Object.assign({}, FLOW_OPTS, { scenario: 'secure' }), hooks: { onLog: (l, x) => ev.logs.push(`${l}: ${x}`) } });
            flow.module = JSON.parse(JSON.stringify(m));
            flow.serial = 'a7eb274c';
            deq(flow.plan(), [1, 2, 3], 'switch open → secure on a flashed board: plan 1, 2, 3');
            eq(await flow.provision(), false, 'switch: the run starts (and stops at the refused stage 1)');
            deq(api.names(), ['setMode', 'stage1', 'stage2', 'stage3', 'stage1'], 'switch: setMode, the three manifests for the confirmation, then stage 1');
            eq(`${flow.module.stage}:${flow.module.mode}`, 'new:secure', 'switch: the server reset the record to "new"');
            assert(ev.logs.includes('info: Board a7eb274c: secure scenario (every stage is redone, starting with stage 1)'), 'switch: the reset is logged', ev.logs.join(' | '));
        }
        {
            // the same switch while the board is connected as a fastboot gadget: the run starts over in RPIBOOT mode
            const { files, m1 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: m1, 2: null, 3: null } });
            const m = api.seed('a7eb274c', { stage: 'gadget', mode: 'open', mode_chosen: 'open' });
            const hub = new T.MockHub();
            const gadget = new T.FastbootSim({ serial64: '10000000a7eb274c' });
            hub.permitted.add(T.MockHub.key(gadget));
            hub.plug(gadget);
            const ev = newEv();
            ev.noAutoPick = true;   // nobody plugs the board in RPIBOOT mode: abort while the run waits for it
            const flow = makeFlow(api, hub, ev, { scenario: 'secure' });
            flow.module = JSON.parse(JSON.stringify(m));
            flow.serial = 'a7eb274c';
            flow.device = gadget;
            flow.deviceKind = 'fastboot';
            deq(flow.plan(), [1, 2, 3], 'switch on a gadget: the page announces stages 1, 2, 3');
            await flow._applyScenario();
            eq(flow.module.stage, 'new', 'switch on a gadget: the server reset the record');
            deq(flow.plan(), [1, 2, 3], 'switch on a gadget: after the reset the run still plans 1, 2, 3 (not stage 3 alone)');
            api.seed('a7eb274c', { stage: 'gadget', mode: 'open', mode_chosen: 'open' });   // back to before the switch
            flow.module = JSON.parse(JSON.stringify(m));   // provision() applies the switch itself
            api.calls.length = 0;
            const run = flow.provision();
            await until(() => ev.need.includes('rpiboot'), 8000, 'the run to ask for the board in RPIBOOT mode');
            eq(flow.stages[1].state, 'waiting', 'switch on a gadget: stage 1 waits for the board in RPIBOOT mode');
            assert(/RPIBOOT/.test(flow.stages[1].detail), 'switch on a gadget: … and says so', flow.stages[1].detail);
            flow.abort();
            eq(await run, false, 'switch on a gadget: aborted while waiting');
            deq(api.names(), ['setMode', 'stage1', 'stage2', 'stage3', 'stage1'], 'switch on a gadget: setMode, the manifests, then stage 1 (stages 2 and 3 refused: secure, OTP not locked yet)');
            eq(api.gated, 2, 'switch on a gadget: the server refuses stages 2 and 3 of the not-yet-locked secure board');
            deq(gadget.commands, [], 'switch on a gadget: nothing was sent to the gadget (no stage 3 on its own)');
            eq(ev.confirms.length, 1, 'switch on a gadget: one confirmation (stage 1) before waiting');
            eq(ev.confirms[0] && ev.confirms[0].flags.map((f) => f.key).join('|'), 'stage 1: program_pubkey', '… for program_pubkey');
            assert(ev.logs.includes('info: Board a7eb274c: secure scenario (every stage is redone, starting with stage 1)'), 'switch on a gadget: the reset is logged', ev.logs.filter((l) => /scenario/.test(l)).join(' | '));
        }
        {
            // a secure board whose OTP does not hold our key hash (stage 1 never confirmed): stage 3 alone is refused
            const { files, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: null, 2: null, 3: m3 } });
            api.seed('a7eb274c', { stage: 'gadget', mode_chosen: 'secure' });
            const hub = new T.MockHub();
            const sim = new T.FastbootSim({ deviceKey: KEY_A });
            hub.plug(sim);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { scenario: 'secure' });
            await flow.connectBoard();
            deq(flow.plan(), [3], 'secure gadget, OTP not locked: the page plans stage 3');
            eq(await flow.provision(), false, 'secure gadget, OTP not locked: stage 3 fails');
            assert(/OTP does not hold this board's key hash yet: run stage 1 first/.test(flow.stages[3].detail), 'secure gadget, OTP not locked: the server\'s reason is shown', flow.stages[3].detail);
            deq(sim.commands.filter((c) => !c.startsWith('getvar:')), [], 'secure gadget, OTP not locked: nothing exported, erased or written');
            eq(api.calls.some((c) => c[0] === 'deviceKey'), false, 'secure gadget, OTP not locked: no device key posted');
        }

        // ================================================================ T10c secure stage 3 on a gadget: existing key, failures
        section = 'stage3-secure';
        {
            // the board's OTP already holds a key (exported at gadget boot); the server reports zero OTP words
            const { files, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: null, 2: null, 3: m3 }, zeroWords: 2 });
            api.seed('a7eb274c', { stage: 'gadget', mode: 'secure', mode_chosen: 'secure', mode_locked: true, otp: { locked: true, locked_to_our_key: true, secure_boot_provisioned: true } });
            const hub = new T.MockHub();
            const sim = new T.FastbootSim({ deviceKey: KEY_A });
            hub.plug(sim);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { scenario: 'secure' });
            await flow.connectBoard();
            deq(flow.plan(), [3], 'existing key: a gadget of a secure board plans stage 3');
            eq(await flow.provision(), true, 'existing key: stage 3 succeeded');
            const cmds = sim.commands;
            const first = cmds.findIndex((c) => !c.startsWith('getvar:'));
            deq(cmds.slice(first, first + 2), [`oem upload-file ${KX.key}`, 'upload'], 'existing key: the first state-touching commands fetch key.der');
            eq(cmds.indexOf(`oem download-file ${KX.request}`), -1, 'existing key: no request (nothing generated)');
            assert(cmds.lastIndexOf('upload') < cmds.indexOf('erase:mmcblk0'), 'existing key: exported before the erase', cmds.join(' | '));
            const dk = api.calls.find((c) => c[0] === 'deviceKey');
            eq(dk && T.hex(T.unb64(dk[2].key_der_b64)), T.hex(KEY_A.der), 'existing key: posted to the server');
            assert(ev.logs.some((l) => /^warn: 2 of the 8 OTP words of the device key are zero/.test(l)), 'existing key: zero_words > 0 → warning', ev.logs.filter((l) => /OTP/.test(l)).join(' | '));
            eq(api.calls.some((c) => c[0] === 'setMode'), false, 'existing key: the scenario was already chosen');
        }
        {
            // the key is READ-locked in this boot: stage 3 fails before anything is erased
            const { files, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: null, 2: null, 3: m3 } });
            api.seed('a7eb274c', { stage: 'gadget', mode: 'secure', mode_chosen: 'secure', mode_locked: true, otp: { locked: true, locked_to_our_key: true, secure_boot_provisioned: true } });
            const hub = new T.MockHub();
            const sim = new T.FastbootSim({ deviceKey: KEY_A, readLocked: true });
            hub.plug(sim);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { scenario: 'secure' });
            await flow.connectBoard();
            eq(await flow.provision(), false, 'locked key: stage 3 fails');
            assert(/run stage 2 again/.test(flow.stages[3].detail), 'locked key: the operator is told to boot the gadget again', flow.stages[3].detail);
            eq(sim.erased.length + sim.flashes.length, 0, 'locked key: nothing erased or flashed');
            eq(sim.commands.includes('oem fwcrypto init'), false, 'locked key: no oem fwcrypto init');
            eq(api.calls.some((c) => c[0] === 'deviceKey'), false, 'locked key: nothing posted as a device key');
            const r3 = api.calls.find((c) => c[0] === 'result');
            eq(r3 && `${r3[2]}:${r3[3].ok}`, '3:false', 'locked key: the failure is reported to the server');
        }
        {
            // the server refuses the exported key (it does not match getvar:public-key): nothing is erased
            const { files, m3 } = await buildServerFiles();
            const api = new T.FakeApi({ files, manifests: { 1: null, 2: null, 3: m3 } });
            api.seed('a7eb274c', { stage: 'gadget', mode: 'secure', mode_chosen: 'secure', mode_locked: true, otp: { locked: true, locked_to_our_key: true, secure_boot_provisioned: true } });
            const hub = new T.MockHub();
            const sim = new T.FastbootSim({ deviceKey: KEY_A });
            sim.files.set(KX.key, KEY_B.der.slice());   // key.der of another key than the OTP one
            hub.plug(sim);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev, { scenario: 'secure' });
            await flow.connectBoard();
            eq(await flow.provision(), false, 'mismatching key: stage 3 fails');
            assert(/server: the exported device key does not match/.test(flow.stages[3].detail), 'mismatching key: the server\'s reason is shown', flow.stages[3].detail);
            eq(sim.erased.length + sim.flashes.length, 0, 'mismatching key: nothing erased or flashed');
        }

        // ================================================================ T11 page wiring with the runner's fake API
        section = 'page';
        await OTP.app.ready;
        // app = OTP.app (declared in T5)
        const gate = document.getElementById('google-gate');
        // ?google_error=... (what /api/google/login appends when the sign-in failed): shown, removed from the URL
        eq(app.srv.googleError, window.__FIX.googleError, 'google_error from the URL is picked up');
        eq(location.search, '', 'google_error is removed from the URL');
        assert(!gate.classList.contains('hidden') && gate.textContent.includes('Google sign-in: ' + window.__FIX.googleError), 'google_error is shown in the gate', gate.textContent);
        eq(document.body.classList.contains('gated'), false, 'google_error alone does not gate the page (still signed in)');
        const dismiss = [...gate.querySelectorAll('button')].find((b) => b.textContent === 'Dismiss');
        assert(dismiss, 'google_error: a Dismiss button');
        if (dismiss) dismiss.click();
        eq(gate.classList.contains('hidden'), true, 'Dismiss hides the gate');
        const badges = document.getElementById('server-badges').textContent;
        assert(/Server .*✓/.test(badges), 'server badge online (runner fake API)', badges);
        assert(/Storage: gsheets ✓/.test(badges), 'storage badge: Google Sheets', badges);
        const sheetLink = [...document.querySelectorAll('#server-badges a.badge')].find((a) => /Sheets ↗/.test(a.textContent));
        assert(sheetLink && /^https:\/\/docs\.google\.com\/spreadsheets\/d\//.test(sheetLink.getAttribute('href')), 'header: link to the station spreadsheet', sheetLink && sheetLink.outerHTML);
        assert([...document.querySelectorAll('#server-badges button')].some((b) => b.textContent === 'Sign out'), 'header: Sign out button');
        eq(document.querySelectorAll('#builds .build-row').length, 3, 'three build rows');
        assert(document.querySelectorAll('#registry-table tbody tr.clickable').length >= 1, 'registry rows from /api/modules');
        eq(document.querySelectorAll('#steps .step').length, 3, 'three step rows');
        eq(document.getElementById('btn-provision').disabled, true, 'Provision disabled until a board is connected');
        eq(document.getElementById('btn-connect').disabled, !navigator.usb, 'Connect board enabled when WebUSB exists');
        document.querySelector('#registry-table tbody tr.clickable').click();
        assert(document.querySelector('#board-detail .serial-big'), 'clicking a registry row shows the record in the Board card');
        const rowOf = (serial) => [...document.querySelectorAll('#registry-table tbody tr.clickable')].find((tr) => tr.firstChild.textContent === serial);
        if (rowOf('5e21c09a')) rowOf('5e21c09a').click();
        let card = document.getElementById('board-detail').textContent;
        assert(card.includes('Scenariosecure · OTP locked: secure only'), 'board card: the scenario of a locked board', card);
        assert(card.includes('private key on the server'), 'board card: the exported device key', card);
        if (rowOf('0c4f88d1')) rowOf('0c4f88d1').click();
        card = document.getElementById('board-detail').textContent;
        assert(card.includes('Scenarioopen (default)'), 'board card: a board without a choice shows the default scenario', card);
        assert(!document.documentElement.innerHTML.includes('stage-dirs'), 'no hint mentions the deleted stage-dirs/ folder');
        OTP.app.setStep(2, 'failed', 'test failure', { verdict: { ok: false, notes: ['note A'] } });
        eq(OTP.app.steps[2].root.className + '|' + OTP.app.steps[2].notes.textContent, 'step state-failed|note A', 'step rendering');
        OTP.app.setStep(2, 'idle', '');

        // ================================================================ T12 Google gate (fake /api/status variants)
        section = 'page-google';
        const fakeStatus = async (obj) => { await fetch('/__fake/status', { method: 'POST', body: JSON.stringify(obj) }); return app.refreshStatus(); };
        const fakeReset = async () => { await fetch('/__fake/reset', { method: 'POST' }); return app.refreshStatus(); };
        const counts = async () => (await fetch('/__fake/counts')).json();
        const provBtn = document.getElementById('btn-provision');
        const connBtn = document.getElementById('btn-connect');
        const hintEl = document.getElementById('provision-hint');
        const gated = () => document.body.classList.contains('gated');
        const fakeBoard = (fields) => Object.assign({ serial: 'a7eb274c', stage: 'eeprom', stage_label: 'EEPROM flashed', mode: 'open', mode_chosen: 'open', mode_locked: false, secrets: {}, otp: {}, metadata: {}, facts: {}, events: [] }, fields || {});
        app.flow.module = fakeBoard();
        app.flow.serial = 'a7eb274c';
        app.renderScenario();
        eq(provBtn.disabled, false, 'signed in + a board: Provision enabled');
        {
            await fakeStatus({ google: { client: false, signed_in: false, spreadsheet_id: '', spreadsheet_url: '' }, google_ready: false, settings: { ok: false, error: 'not signed in to Google' } });
            assert(!gate.classList.contains('hidden') && gate.classList.contains('err'), 'no OAuth client: the gate is shown as an error');
            assert(/No Google OAuth client/.test(gate.textContent) && gate.textContent.includes('C:/station/OTP_Provisioner/google-oauth-client.json'), 'no OAuth client: says where the client JSON goes', gate.textContent);
            eq(gate.querySelector('a[href="/api/google/login"]'), null, 'no OAuth client: no sign-in link');
            eq(gated(), true, 'no OAuth client: body.gated');
            eq(`${connBtn.disabled}:${provBtn.disabled}`, 'true:true', 'no OAuth client: Connect board and Provision disabled');
            eq(hintEl.textContent, 'sign in to Google first', 'gated: the provision hint');
            eq([...document.querySelectorAll('#server-badges a.badge')].some((a) => /Sheets ↗/.test(a.textContent)), false, 'not signed in: no spreadsheet link in the header');
        }
        {
            await fakeStatus({ google: { client: true } });
            const link = gate.querySelector('a[href="/api/google/login"]');
            eq(link && link.textContent, 'Sign in with Google', 'not signed in: "Sign in with Google" → /api/google/login');
            eq(gate.classList.contains('err'), false, 'not signed in: not shown as an error');
            eq(gated(), true, 'not signed in: body.gated');
            eq(`${connBtn.disabled}:${provBtn.disabled}`, 'true:true', 'not signed in: Connect board and Provision disabled');
            await throwsLike(() => OTP.api.modules(), /sign in to Google first.*HTTP 401/, 'not signed in: module endpoints answer 401 with the reason');
        }
        {
            await fakeStatus({ google: { signed_in: true, spreadsheet_id: 'x1', spreadsheet_url: 'https://docs.google.com/spreadsheets/d/x1/edit' },
                settings: { error: 'the settings worksheet cannot be read: HTTP 403 (insufficient permissions)' } });
            assert(gate.textContent.includes('Google Sheets is not usable: the settings worksheet cannot be read: HTTP 403'), 'signed in, not ready: the sheet error is shown', gate.textContent);
            const again = gate.querySelector('a[href="/api/google/login"]');
            eq(again && again.textContent, 'Sign in again', 'signed in, not ready: "Sign in again"');
            assert([...gate.querySelectorAll('button')].some((b) => b.textContent === 'Sign out'), 'signed in, not ready: "Sign out" in the gate');
            eq(gate.classList.contains('err'), true, 'signed in, not ready: shown as an error');
            eq(gated(), true, 'signed in, not ready: body.gated');
            eq(provBtn.disabled, true, 'signed in, not ready: Provision disabled even with a board');
        }
        {
            const before = (await counts())['GET modules'] || 0;
            await fakeStatus({ google_ready: true, settings: { ok: true, error: '' } });
            eq(gate.classList.contains('hidden'), true, 'ready: no gate');
            eq(gated(), false, 'ready: body not gated');
            eq(`${connBtn.disabled}:${provBtn.disabled}`, `${!navigator.usb}:false`, 'ready: Connect board and Provision enabled again');
            let after = before;
            for (let i = 0; i < 100 && after <= before; i++) { await T.sleep(20); after = (await counts())['GET modules'] || 0; }
            assert(after > before, 'signing in reloads the registry (GET /api/modules)', `${before} → ${after}`);
            const link = [...document.querySelectorAll('#server-badges a.badge')].find((a) => /Sheets ↗/.test(a.textContent));
            eq(link && link.getAttribute('href'), 'https://docs.google.com/spreadsheets/d/x1/edit', 'ready: the header links the spreadsheet_url');
            eq(link && link.textContent, 'Google: operator@example.com · Sheets ↗', 'ready: the header names the signed-in account');
            const out = [...document.querySelectorAll('#server-badges button')].find((b) => b.textContent === 'Sign out');
            assert(out, 'ready: Sign out in the header');
            const posts = (await counts())['POST google/*'] || 0;
            if (out) out.click();
            await until(() => gated(), 3000, 'Sign out to gate the page');
            eq(((await counts())['POST google/*'] || 0) - posts, 1, 'Sign out → POST /api/google/logout');
            eq(gate.querySelector('a[href="/api/google/login"]') && gate.querySelector('a[href="/api/google/login"]').textContent, 'Sign in with Google', 'after Sign out: the sign-in link');
        }
        await fakeReset();
        eq(gated(), false, 'fake API reset: signed in again');

        // ================================================================ T13 scenario radios
        section = 'page-scenario';
        {
            const R = Object.fromEntries([...document.querySelectorAll('#scenario input[name=scenario]')].map((r) => [r.value, r]));
            deq(Object.keys(R).sort(), ['open', 'secure'], 'two scenario radios: open, secure');
            const modeText = () => document.getElementById('provision-mode').textContent;
            app.flow.module = null;
            app.flow.serial = '';
            app.srv.scenario = '';
            localStorage.removeItem('otp.scenario');
            app.renderScenario();
            eq(`${R.open.checked}:${R.secure.checked}`, 'true:false', 'no choice yet: provisioning.default_mode from /api/status (open)');
            assert(/^Open: /.test(modeText()), 'the open scenario is described', modeText());
            await fakeStatus({ config: { provisioning: { default_mode: 'secure' } } });
            eq(`${R.open.checked}:${R.secure.checked}`, 'false:true', 'default_mode secure → secure preselected');
            assert(/^Secure: .*LUKS/.test(modeText()), 'the secure scenario is described', modeText());
            eq(app.flow.scenario(), 'secure', 'the page\'s Flow reads the selected scenario');
            R.open.click();
            eq(localStorage.getItem('otp.scenario'), 'open', 'the operator\'s choice is remembered (localStorage otp.scenario)');
            eq(`${app.currentScenario()}:${R.open.checked}:${app.flow.scenario()}`, 'open:true:open', 'the choice wins over the default');
            await app.refreshStatus();
            eq(R.open.checked, true, 'the choice survives a status refresh');
            app.flow.module = fakeBoard({ mode: 'secure', mode_chosen: 'secure', mode_locked: true, otp: { locked: true, locked_to_our_key: true } });
            app.flow.serial = 'a7eb274c';
            app.renderScenario();
            eq(`${R.secure.checked}:${R.open.disabled}:${R.secure.disabled}`, 'true:true:false', 'mode_locked board: secure forced, open disabled');
            assert(/OTP is locked: secure only/.test(modeText()), 'mode_locked board: explained', modeText());
            eq(app.flow.scenario(), 'secure', 'mode_locked board: the Flow gets secure');
            R.open.click();
            eq(R.secure.checked, true, 'mode_locked board: open cannot be picked');
            eq(localStorage.getItem('otp.scenario'), 'open', 'mode_locked board: the remembered choice is kept');
            app.flow.module = fakeBoard({ stage: 'flashed', stage_label: 'Image written' });
            app.renderScenario();
            eq(`${R.open.disabled}:${R.open.checked}`, 'false:true', 'an open board: open selectable again (the remembered choice)');
            assert(/is fully provisioned \(open scenario\)/.test(hintEl.textContent), 'flashed in the picked scenario: nothing to do', hintEl.textContent);
            eq(provBtn.disabled, true, 'flashed in the picked scenario: Provision disabled');
            R.secure.click();
            assert(/stages 1 → 2 → 3 · secure scenario \(switching: every stage is redone\)/.test(hintEl.textContent), 'switching the scenario of a flashed board: the hint says every stage is redone', hintEl.textContent);
            eq(provBtn.disabled, false, 'switching: Provision enabled');
            eq(localStorage.getItem('otp.scenario'), 'secure', 'switching: remembered');
        }
        app.flow.module = null;
        app.flow.serial = '';
        app.srv.scenario = '';
        localStorage.removeItem('otp.scenario');
        await fakeReset();
        app.renderScenario();
        app.renderBoard();

        // ================================================================ T14 server.js scenario / device-key calls against the fake API
        section = 'api-scenario';
        {
            const a = OTP.api;
            const r1 = await a.setMode('0c4f88d1', 'secure');
            eq(`${r1.module.mode}:${r1.module.mode_chosen}:${r1.module.stage}`, 'secure:secure:new', 'setMode → POST /api/modules/{serial}/mode; a board with progress is reset to "new"');
            for (const n of [2, 3]) {
                const g = await a.stage('0c4f88d1', n);
                eq(`${g.ready}:${g.job}:${/OTP does not hold this board's key hash yet: run stage 1 first/.test(g.reason)}`, 'false:null:true',
                    `stage ${n} of a secure board whose OTP is not locked yet → 409 "run stage 1 first"`);
            }
            const s3 = await a.stage('5e21c09a', 3);
            eq(`${s3.ready}:${s3.scenario}:${s3.mode}:${s3.fwcrypto_init}:${s3.image.variant}`, 'true:secure:signed:true:crypt', 'stage 3 of a locked secure board: signed, fwcrypto init, crypt image');
            deq(s3.key_export, KX, 'stage 3 of a secure board names the gadget\'s key export paths');
            const o3 = await a.stage('a7eb274c', 3);
            eq(`${o3.scenario}:${o3.key_export}:${o3.fwcrypto_init}:${o3.image.variant}`, 'open:null:false:clear', 'stage 3 of an open board: no key export, no fwcrypto init, clear image');
            eq((await a.stage('0c4f88d1', 1)).irreversible.map((f) => f.key).join(','), 'program_pubkey', 'stage 1 of a secure board: program_pubkey');
            eq((await a.stage('a7eb274c', 1)).irreversible.length, 0, 'stage 1 of an open board: nothing irreversible');
            await throwsLike(() => a.setMode('5e21c09a', 'open'), /only the secure scenario is possible.*HTTP 400/, 'setMode open on a locked board → ApiError 400');
            await throwsLike(() => a.setMode('a7eb274c', 'closed'), /mode must be one of open, secure/, 'setMode with an unknown scenario → 400');
            const dk = await a.deviceKey('0c4f88d1', { key_der_b64: T.b64(KEY_A.der), device_key_pem: KEY_A.pem });
            eq(dk.device_key.fingerprint, await T.pemFingerprint(KEY_A.pem), 'deviceKey → POST /api/modules/{serial}/device-key; fingerprint = SHA-256 of the SPKI');
            eq(`${dk.device_key.already}:${dk.device_key.zero_words}:${dk.module.otp.device_key_exported}`, 'false:0:true', 'deviceKey: stored, the module says device_key_exported');
            eq((await a.deviceKey('0c4f88d1', { key_der_b64: T.b64(KEY_A.der), device_key_pem: KEY_A.pem })).device_key.already, true, 'deviceKey: the same key again → already');
            await throwsLike(() => a.deviceKey('0c4f88d1', { key_der_b64: '%%%', device_key_pem: KEY_A.pem }), /not valid base64/, 'deviceKey: bad base64 → 400');
            await fakeReset();
        }

        // ================================================================ T15 OS image panel (image.* settings)
        section = 'page-image';
        {
            const form = document.getElementById('image-form');
            const f = (n) => form.elements.namedItem(n);
            const save = document.getElementById('btn-image-save');
            const revert = document.getElementById('btn-image-revert');
            const status = document.getElementById('image-status');
            const warn = () => [...document.querySelectorAll('#image-warnings li')].map((li) => li.textContent);
            await fakeReset();
            app.img.loaded = null;
            await app.loadImageSettings();
            eq(f('hostname').value, 'pi5', 'loaded from GET /api/image');
            eq(`${f('user').value}:${f('timezone').value}:${f('wifi_country').value}:${f('name').value}`,
                'pi:Europe/Kyiv:UA:deb13-arm64-min', 'the other fields');
            eq(`${f('ssh').checked}:${f('ssh_password_login').checked}`, 'false:true', 'SSH off, password login on');
            eq(`${f('ssh_password_login').disabled}:${f('ssh_authorized_keys').disabled}`, 'true:true', 'SSH off: its options are disabled');
            eq(`${save.disabled}:${revert.disabled}`, 'true:true', 'nothing changed: Save and Revert disabled');
            eq(f('password').placeholder, 'none', 'no password: the placeholder says so');
            eq(form.querySelector('button[data-remove="password"]').disabled, true, 'no password: "remove" is disabled');
            deq(warn(), ["no password and no SSH key: the board's first boot stops at the Raspberry Pi OS wizard on its console (screen and keyboard), which asks for a user name and password"],
                'server warnings are listed');

            // time zone and Wi-Fi country are lists (the image's tzdata and wireless-regdb, from the server)
            const tzSel = f('timezone');
            const ccSel = f('wifi_country');
            eq(`${tzSel.tagName}:${ccSel.tagName}`, 'SELECT:SELECT', 'time zone and country are lists');
            eq(tzSel.options.length, 313, 'time zone list: the 312 canonical zones of zone1970.tab + UTC');
            eq(tzSel.options[0].value + '|' + tzSel.options[0].textContent, 'UTC|UTC', 'UTC comes first, outside the regions');
            deq([...tzSel.querySelectorAll('optgroup')].map((g) => g.label),
                ['Africa', 'America', 'Antarctica', 'Asia', 'Atlantic', 'Australia', 'Europe', 'Indian', 'Pacific'], 'zones are grouped by region');
            const kyiv = [...tzSel.options].find((o) => o.value === 'Europe/Kyiv');
            assert(kyiv && /^Kyiv \(UTC\+0[23]:00\)$/.test(kyiv.textContent) && kyiv.parentElement.label === 'Europe',
                'an option shows the city and its current UTC offset', kyiv && kyiv.textContent);
            const ba = [...tzSel.options].find((o) => o.value === 'America/Argentina/Buenos_Aires');
            eq(ba && ba.textContent.replace(/ \(.*\)$/, ''), 'Argentina/Buenos Aires', 'deeper names keep their path, underscores become spaces');
            eq(tzSel.value, 'Europe/Kyiv', 'the saved time zone is selected');
            eq([...tzSel.options].some((o) => o.value === 'Europe/Kiev'), false, 'legacy names (tzdata-legacy) are not offered');
            const kbSel = f('keyboard');
            eq(`${kbSel.tagName}:${kbSel.options.length}:${kbSel.value}`, 'SELECT:99:us', 'keyboard: a list of the xkb-data layouts, the saved one selected');
            eq([...kbSel.options].find((o) => o.value === 'gb').textContent, 'English (UK) (gb)', 'a layout shows its name and code');
            eq(ccSel.options.length, 182, 'country list: every country of wireless-regdb');
            eq(ccSel.options[0].value + '|' + ccSel.options[0].textContent, '00|World (most restrictive) (00)', 'the world domain comes first');
            const names = [...ccSel.options].slice(1).map((o) => o.textContent);
            deq(names, names.slice().sort((a, b) => a.localeCompare(b)), 'the countries are sorted by name');
            assert(names.includes('Ukraine (UA)') && names.includes('Poland (PL)'), 'options read "Name (code)"');
            eq(ccSel.value, 'UA', 'the saved country is selected');
            // a value typed into the sheet by hand that the list lacks stays visible and selected
            app.img.loaded = Object.assign({}, app.img.loaded, { timezone: 'Etc/GMT-3' });
            const loadedBefore = app.img.loaded;
            document.getElementById('btn-image-revert').disabled = false;
            document.getElementById('btn-image-revert').click();
            const extra = tzSel.querySelector('option[data-extra]');
            assert(extra && extra.value === 'Etc/GMT-3' && tzSel.value === 'Etc/GMT-3' && /not in the list/.test(extra.textContent),
                'a value outside the list is kept as an extra option', extra && extra.textContent);
            eq(save.disabled, true, 'that is no change');
            app.img.loaded = Object.assign({}, loadedBefore, { timezone: 'Europe/Kyiv' });
            document.getElementById('btn-image-revert').disabled = false;
            document.getElementById('btn-image-revert').click();
            eq(`${tzSel.querySelectorAll('option[data-extra]').length}:${tzSel.value}`, '0:Europe/Kyiv', 'the extra option goes away again');

            const sent = [];
            const realSave = OTP.api.saveImageSettings;
            OTP.api.saveImageSettings = (body) => { sent.push(JSON.parse(JSON.stringify(body))); return realSave.call(OTP.api, body); };
            const type = (name, value) => { f(name).value = value; f(name).dispatchEvent(new Event('input', { bubbles: true })); };
            const tick = (name, on) => { f(name).checked = on; f(name).dispatchEvent(new Event('change', { bubbles: true })); };
            try {
                type('hostname', 'Drone-7');
                eq(`${save.disabled}:${revert.disabled}`, 'false:false', 'an edit enables Save and Revert');
                revert.click();
                eq(`${f('hostname').value}:${save.disabled}`, 'pi5:true', 'Revert restores the loaded values');

                type('hostname', 'Drone-7');
                type('password', 'pw 1$');
                tick('ssh', true);
                eq(f('ssh_authorized_keys').disabled, false, 'SSH on: the keys are editable');
                type('ssh_authorized_keys', 'ssh-ed25519 AAAA key1\n\n  ssh-ed25519 BBBB key2  ');
                type('wifi_ssid', 'Field Net');
                type('wifi_password', 'password1');
                type('wifi_country', 'PL');
                type('timezone', 'Europe/Warsaw');
                save.click();
                await until(() => sent.length === 1 && !app.img.saving, 3000, 'save 1');
                deq(sent[0], { hostname: 'Drone-7', timezone: 'Europe/Warsaw', wifi_ssid: 'Field Net', wifi_country: 'PL', ssh: true,
                    ssh_authorized_keys: ['ssh-ed25519 AAAA key1', 'ssh-ed25519 BBBB key2'], password: 'pw 1$', wifi_password: 'password1' },
                    'Save sends only what changed (picked list values, keys one per line, passwords as typed)');
                eq(`${tzSel.value}:${ccSel.value}`, 'Europe/Warsaw:PL', 'after the save the lists show the saved values');
                await until(() => /^Saved: /.test(status.textContent), 3000, 'saved message');
                assert(/hostname/.test(status.textContent) && /flashed from now on/.test(status.textContent)
                    && /\(no rebuild\)/.test(status.textContent) && !status.classList.contains('bad'),
                    'the status names what was saved: board settings apply at stage 3, no rebuild', status.textContent);
                eq(f('hostname').value, 'drone-7', 'the form shows the server\'s normalised value');
                eq(`${f('password').value}|${f('wifi_password').value}`, '|', 'the password fields are emptied after a save');
                eq(f('password').placeholder, 'set: type to change', 'a saved password: placeholder');
                eq(f('wifi_password').placeholder, 'saved: type to change', 'a saved Wi-Fi password: placeholder');
                eq(save.disabled, true, 'saved: nothing left to save');
                deq(warn(), [], 'no warnings once a password is set');

                const rmWifi = form.querySelector('button[data-remove="wifi_password"]');
                eq(rmWifi.disabled, false, 'a saved Wi-Fi password can be removed');
                rmWifi.click();
                eq(`${rmWifi.textContent}:${save.disabled}`, 'keep:false', 'remove: the button offers "keep", Save is enabled');
                eq(f('wifi_password').placeholder, 'will be removed (open network)', 'remove: the placeholder says what happens');
                rmWifi.click();
                eq(`${rmWifi.textContent}:${save.disabled}`, 'remove:true', 'keep: no change any more');
                rmWifi.click();
                save.click();
                await until(() => sent.length === 2 && !app.img.saving, 3000, 'save 2');
                deq(sent[1], { wifi_password: '' }, 'removing the Wi-Fi password sends ""');
                await until(() => app.img.loaded && app.img.loaded.wifi_password_set === false, 3000, 'reloaded');
                assert(warn().some((w) => /the board joins it as an open network/.test(w)), 'warning: an open network', warn().join(' | '));

                type('wifi_password', 'password2');
                eq(rmWifi.disabled, true, 'nothing saved to remove: "remove" is disabled again');

                const showPw = form.querySelector('button[data-show="password"]');
                showPw.click();
                eq(`${f('password').type}:${showPw.textContent}`, 'text:hide', 'show: the password is visible');
                showPw.click();
                eq(`${f('password').type}:${showPw.textContent}`, 'password:show', 'hide: masked again');
                type('wifi_password', '');

                type('hostname', 'bad_host');
                save.click();
                await until(() => sent.length === 3 && !app.img.saving, 3000, 'save 3');
                assert(/^Not saved: .*image\.hostname/.test(status.textContent) && status.classList.contains('bad'),
                    'a rejected save is shown as an error', status.textContent);
                eq(f('hostname').value, 'bad_host', 'the rejected edit stays in the form');
                type('hostname', 'drone-7');
                eq(save.disabled, true, 'back to the saved value: nothing to save');
            } finally {
                OTP.api.saveImageSettings = realSave;
            }

            await fakeStatus({ google_ready: false, google: { signed_in: false } });
            eq(`${f('hostname').disabled}:${save.disabled}`, 'true:true', 'signed out: the form is disabled');
            eq(app.img.loaded, null, 'signed out: the loaded settings are dropped (the next account has its own)');
            await fakeReset();
            await until(() => !f('hostname').disabled, 3000, 'reloaded after the sign-in');
            eq(f('hostname').value, 'pi5', 'signed in again: the settings are loaded afresh');

            // a failed load is shown and stays shown
            const realGet = OTP.api.imageSettings;
            OTP.api.imageSettings = async () => { throw Object.assign(new Error('boom'), { detail: 'settings sheet unreachable' }); };
            try {
                app.img.loaded = null;
                await app.loadImageSettings();
                app.renderImagePanel();
                assert(/^Image settings: settings sheet unreachable/.test(status.textContent) && status.classList.contains('bad'),
                    'a failed load is reported (and not wiped by the next render)', status.textContent);
            } finally {
                OTP.api.imageSettings = realGet;
            }
            await app.loadImageSettings();
            eq(status.textContent, '', 'a successful load clears the error');
        }
    } catch (e) {
        results.push('EXCEPTION: ' + ((e && e.stack) || e));
        failed++;
    }
    const passed = results.filter((x) => x.startsWith('PASS')).length;
    results.push(`SUMMARY ${failed === 0 ? 'ALL PASS' : failed + ' FAILED'} (${passed} passed, ${Date.now() - t0} ms)`);
    const appLog = document.getElementById('log') ? document.getElementById('log').textContent : '';
    out.textContent = results.join('\n');
    try { await fetch('/__result', { method: 'POST', body: results.join('\n') + '\n--- app log ---\n' + appLog }); } catch (e) { /* not served by the runner */ }
})();
