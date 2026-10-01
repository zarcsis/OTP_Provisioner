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
        const PASS = 'f0'.repeat(32);
        const imageJsonObj = { IGversion: '2.0.0', IGmeta: { IGconf_device_class: 'pi5', IGconf_device_storage_type: 'sd' }, layout: { partitionimages: { boot: { simage: 'boot.sparse' }, root: { simage: 'root.sparse' } } } };
        const imageJson = enc.encode(JSON.stringify(imageJsonObj));
        const bootPiece = T.bytesOf(300000, 11);
        const root0 = T.bytesOf(2 * 1048576 + 123, 12);
        const root1 = T.bytesOf(3 * 65536, 13);
        const idpParts = () => ({
            'boot.sparse': [{ name: 'boot.sparse', size: bootPiece.byteLength, bytes: bootPiece }],
            'root.sparse': [{ name: 'root.sparse.0', size: root0.byteLength, bytes: root0 }, { name: 'root.sparse.1', size: root1.byteLength, bytes: root1 }],
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
                crypt: [{ dev: 'mmcblk0p2', mname: 'osroot_crypt', passphrase: PASS }],
                onDeviceKey: async (p) => keys.push(p), onProgress: (p) => prog.push(p), log: (l, m) => logs.push(`${l}: ${m}`),
            });
            const norm = sim.commands.map((x) => (x.startsWith('download:') ? 'download' : x));
            deq(norm, ['oem fwcrypto init', 'getvar:public-key', 'getvar:max-download-size',
                'erase:mmcblk0', 'download', 'oem idpinit', 'oem idpdone',
                'erase:mmcblk0', 'download', 'oem idpinit', 'oem idpwrite',
                'oem idpgetblk', 'download', 'flash:mmcblk0p1',
                'oem idpgetblk', 'download', 'flash:mapper/osroot_crypt', 'download', 'flash:mapper/osroot_crypt',
                'oem idpgetblk', 'oem cryptsetpassword mmcblk0p2 <pass>', 'oem idpdone', 'reboot'], 'full IDP command sequence (fwcrypto, erase, idpinit retry, multi-piece flash, cryptsetpassword, reboot)');
            assert(Date.now() - tErase >= 60, 'erase waits eraseSettleMs after each erase');
            eq(sim.erased.join(','), 'mmcblk0,mmcblk0', 'erase:mmcblk0 before each idpinit attempt');
            deq(sim.flashes.map((f) => [f.dev, f.size, f.checksum]), [
                ['mmcblk0p1', bootPiece.byteLength, T.checksum(bootPiece)],
                ['mapper/osroot_crypt', root0.byteLength, T.checksum(root0)],
                ['mapper/osroot_crypt', root1.byteLength, T.checksum(root1)]], 'pieces flashed in order, byte-exact');
            const dl = sim.downloads;
            assert(dl.length === 5, 'five data phases (2× image.json + 3 pieces)', String(dl.length));
            const aligned = dl.every((d) => d.chunks.slice(0, -1).every((n) => n % 65536 === 0));
            assert(aligned, 'every data-phase transferOut except the last is a multiple of 64 KiB', JSON.stringify(dl.map((d) => d.chunks)));
            assert(dl.some((d) => d.chunks.length >= 3), 'a >2 MiB piece is sent in several chunks', JSON.stringify(dl.map((d) => d.chunks)));
            assert(dl.every((d) => d.chunks.reduce((a, b) => a + b, 0) === d.size), 'data phases carry exactly the announced size');
            eq(sim.passwords.length === 1 && sim.passwords[0].dev === 'mmcblk0p2' && sim.passwords[0].pass === PASS, true, 'cryptsetpassword reached the device with the passphrase');
            assert(!logs.some((l) => l.includes(PASS)), 'the passphrase never appears in the log');
            assert(keys.length === 1 && keys[0].includes('BEGIN PUBLIC KEY') && keys[0].includes('END PUBLIC KEY'), 'device public key PEM reported');
            eq(res.flashed.map((f) => `${f.dev}:${f.simage}:${f.pieces.length}`).join(' '), 'mmcblk0p1:boot.sparse:1 mapper/osroot_crypt:root.sparse:2', 'result.flashed');
            eq(res.crypt[0].dev + ':' + res.crypt[0].mname, 'mmcblk0p2:osroot_crypt', 'result.crypt');
            const last = prog[prog.length - 1];
            eq(last.phase + ':' + (last.sent === last.total) + ':' + last.total, `done:true:${bootPiece.byteLength + root0.byteLength + root1.byteLength}`, 'progress ends at total bytes');
            assert(sim.maxCommandSeen <= 256, 'no command above 256 bytes');
            eq(sim.idp, null, 'IDP closed with idpdone');
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
            await throwsLike(() => c.cryptSetPassword('mmcblk0p2', 'two words'), /without spaces/, 'passphrase with a space refused');
            const fc = await c.fwcryptoInit();
            eq(fc.message + ':' + fc.created, 'Key provisioned and LOCKed:true', 'fwcryptoInit: new key');
            const fc2 = await c.fwcryptoInit();
            eq(fc2.message + ':' + fc2.created, 'Key already provisioned:false', 'fwcryptoInit: idempotent');
        }
        {
            const sim = new T.FastbootSim({ failFlash: 'mapper/osroot_crypt', keyProvisioned: true });
            const c = new OTP.fastboot.FastbootClient(sim);
            c.eraseSettleMs = 0;
            await c.open();
            await throwsLike(() => c.idpProvision({ imageJson, parts: idpParts(), log: () => {} }), /exceeds partition/, 'flash FAIL → error');
            deq(sim.commands.slice(-2), ['flash:mapper/osroot_crypt', 'oem idpdone'], 'flash failure → oem idpdone, no reboot');
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
            delete parts['root.sparse'];
            await throwsLike(() => c.idpProvision({ imageJson, parts, log: () => {} }), /no such file/, 'unknown simage requested → error');
            eq(sim.commands[sim.commands.length - 1], 'oem idpdone', '… and the IDP is closed');
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
            const add = async (stageNo, name, bytes) => {
                const url = `/api/modules/a7eb274c/stage/${stageNo}/files/${name}`;
                files.set(url, bytes);
                return { name, size: bytes.byteLength, sha256: await sha(bytes), url, origin: 'test' };
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
            const r0 = await add(3, 'root.sparse.0', root0);
            const r1 = await add(3, 'root.sparse.1', root1);
            const m3 = {
                stage: 3, kind: 'fastboot-idp', title: 'Image', ready: true, mode: 'unsigned',
                image: { name: 'deb13-arm64-min', version: 'v1-test', set: 'set1', encrypted: true },
                storage_device: 'mmcblk0', image_json: ij,
                parts: { 'boot.sparse': [pb], 'root.sparse': [r0, r1] },
                total_bytes: bootPiece.byteLength + root0.byteLength + root1.byteLength, max_piece_size: 268435456,
                fwcrypto_init: true, erase: true,
                crypt: [{ dev: 'mmcblk0p2', mname: 'osroot_crypt', label: 'OSROOT_CRYPT', passphrase: PASS }],
                irreversible: [{ key: 'oem fwcrypto init', value: '', why: 'device key in OTP' }, { key: 'erase', value: 'mmcblk0', why: 'wipes the card' }],
                notes: [],
            };
            return { files, m1, m2, m3 };
        }
        const FLOW_OPTS = { reenumTimeoutMs: 20000, fastbootTimeoutMs: 20000, pollMs: 25, needDeviceAfterMs: 150, buildPollMs: 60, eraseSettleMs: 10, fileServerRetryMs: 20 };
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
            const job = { id: 'job3', target: 'image', title: 'Build droneos image', status: 'running' };
            const api = new T.FakeApi({ files, manifests: { 1: m1, 2: m2, 3: (k) => (k <= 2 ? { ready: false, reason: 'the droneos image is being built', job } : m3) } });
            const hub = new T.MockHub();
            const board = new T.MockBoard(hub, { serial: 'a7eb274c', keyHash: KEYHASH, stage1Timeouts: { 6: 3 } });
            board.powerOnRom();
            const ev = newEv();
            const flow = makeFlow(api, hub, ev);
            const m = await flow.connectBoard();
            eq(m && m.serial, 'a7eb274c', 'connectBoard → hello → module');
            deq(api.calls[0][1], { serial: 'a7eb274c', chip: 'BCM2712', board: 'Pi 5 / CM5 / Pi 500', usb: { vendor_id: 0x0a5c, product_id: 0x2712, product_name: 'BCM2712 Boot', manufacturer: 'Broadcom', serial_number: 'a7eb274c' }, rom_stage: 'rom' }, 'hello body');
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
            eq(b3 && b3.details.crypt[0].dev, 'mmcblk0p2', 'stage 3 result: crypt container');
            assert(b3 && /BEGIN PUBLIC KEY/.test(b3.details.device_key_pem), 'stage 3 result: device key');
            const facts = api.calls.find((c) => c[0] === 'facts');
            eq(facts && facts[2].duid + ':' + /BEGIN PUBLIC KEY/.test(facts[2].device_key_pem), '10000000a7eb274c:true', 'facts posted: device_key_pem + duid');
            const idc = api.calls.find((c) => c[0] === 'identify');
            eq(idc && idc[1].serialno, '10000000a7eb274c', 'identify: 16-hex serialno without NUL');
            eq(idc && idc[1].vars.product, 'Raspberry Pi 5 Model B Rev 1.0', 'identify: vars (product)');
            assert(idc && OTP.Flow.FASTBOOT_VARS.every((k) => k in idc[1].vars), 'identify: every whitelisted getvar', JSON.stringify(idc && idc[1].vars));
            const names = api.names();
            assert(names.indexOf('identify') < names.indexOf('facts') && names.indexOf('facts') < names.indexOf('result3'), 'order: identify → facts → result3', names.join(' '));
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
            deq(sim && sim.flashes.map((f) => [f.dev, f.checksum]), [['mmcblk0p1', T.checksum(bootPiece)], ['mapper/osroot_crypt', T.checksum(root0)], ['mapper/osroot_crypt', T.checksum(root1)]], 'the gadget received the server pieces byte-exact');
            eq(sim && sim.passwords[0] && sim.passwords[0].pass, PASS, 'recovery passphrase set on mmcblk0p2');
            assert(sim && sim.downloads.every((d) => d.chunks.slice(0, -1).every((n) => n % 65536 === 0)), 'flow: 64 KiB-aligned data phases');
            assert(!ev.logs.some((l) => l.includes(PASS)), 'flow: passphrase not in the log');
            eq(sim && sim.commands[sim.commands.length - 1], 'reboot', 'gadget rebooted at the end');
            const p3 = ev.progress[3];
            eq(p3 && p3.sent === p3.total && p3.total === m3.total_bytes, true, 'stage 3 progress reached total_bytes');
            deq(flow.plan(), [], 'plan after provisioning: nothing left');
            eq(await flow.provision(), true, 'provision() on a flashed board is a no-op');
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
            const sim = new T.FastbootSim({ goneOnFlash: 'mapper/osroot_crypt', keyProvisioned: true });
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
            const mine = new T.FastbootSim({ serial64: '10000000a7eb274c', keyProvisioned: true });
            hub.plug(mine);
            const ev = newEv();
            const flow = makeFlow(api, hub, ev);
            await flow.connectBoard();
            eq(flow.serial, 'a7eb274c', 'foreign gadget: connected to board a7eb274c');
            hub.unplug(mine);
            const other = new T.FastbootSim({ serial64: '10000000deadbeef', keyProvisioned: true });
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

        // ================================================================ T11 page wiring with the runner's fake API
        section = 'page';
        await OTP.app.ready;
        const badges = document.getElementById('server-badges').textContent;
        assert(/Server .*✓/.test(badges), 'server badge online (runner fake API)', badges);
        assert(/Storage: local/.test(badges), 'storage badge', badges);
        eq(document.querySelectorAll('#builds .build-row').length, 3, 'three build rows');
        assert(document.querySelectorAll('#registry-table tbody tr.clickable').length >= 1, 'registry rows from /api/modules');
        eq(document.querySelectorAll('#steps .step').length, 3, 'three step rows');
        eq(document.getElementById('btn-provision').disabled, true, 'Provision disabled until a board is connected');
        eq(document.getElementById('btn-connect').disabled, !navigator.usb, 'Connect board enabled when WebUSB exists');
        document.querySelector('#registry-table tbody tr.clickable').click();
        assert(document.querySelector('#board-detail .serial-big'), 'clicking a registry row shows the record in the Board card');
        OTP.app.setStep(2, 'failed', 'test failure', { verdict: { ok: false, notes: ['note A'] } });
        eq(OTP.app.steps[2].root.className + '|' + OTP.app.steps[2].notes.textContent, 'step state-failed|note A', 'step rendering');
        OTP.app.setStep(2, 'idle', '');
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
