/*
 * e2e.js — end-to-end operator run against the REAL server (driven by tests/web/run_e2e.py).
 *
 * Loaded by the runner's proxy BEFORE the page's own scripts (after tests/web/mocks.js), so navigator.usb is a
 * TestMocks.MockHub by the time js/app.js builds its OTP.Flow. window.__E2E = {scenario, serial, devicePem,
 * timeoutMs} comes from the runner. The script plugs a mock Raspberry Pi 5 into the hub and clicks through the
 * real UI like an operator (Connect board → Provision → typed-serial confirmation → Select device /
 * Connect fastboot gadget), records every byte the board received, and POSTs a JSON report to /__e2e_result.
 * All assertions are made by the runner (Python), which also knows the server files and the registry.
 */
(function () {
    'use strict';
    const T = window.TestMocks;
    const CFG = window.__E2E || {};
    const hub = new T.MockHub();
    Object.defineProperty(navigator, 'usb', { value: hub, configurable: true });

    const report = { scenario: CFG.scenario, serial: CFG.serial, errors: [], timeline: [], dialogs: [], clicks: [], stages: {} };
    const t0 = Date.now();
    const mark = (what) => report.timeline.push(`${((Date.now() - t0) / 1000).toFixed(1)}s ${what}`);
    window.addEventListener('error', (e) => report.errors.push(`window error: ${e.message} @ ${e.filename}:${e.lineno}`));
    window.addEventListener('unhandledrejection', (e) => report.errors.push(`unhandled rejection: ${(e.reason && e.reason.stack) || e.reason}`));

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    async function sha(bytes) {
        const d = await crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
    }
    function concat(chunks) {
        const n = chunks.reduce((a, c) => a + c.byteLength, 0);
        const out = new Uint8Array(n);
        let o = 0;
        for (const c of chunks) { out.set(c, o); o += c.byteLength; }
        return out;
    }

    // ------------------------------------------------------------------ the board (records what it received)

    /** One Pi 5: ROM → recovery (stage 1) → ROM → bootloader (stage 2) → fastboot gadget (stage 3). */
    class E2EBoard {
        constructor(opts) {
            this.o = Object.assign({ serial: 'e2e5a7c1', keyHash: '0'.repeat(64), secureBoot: false, blocks: [], fastboot: {} }, opts);
            this.boots = 0;
            this.history = [];
            this.roms = [];          // [{boot, bytes: Uint8Array}] second stage sent to each ROM enumeration
            this.fileServers = [];   // [{boot, files: {name: [chunks]}, asked: [names]}]
            this.fb = null;
        }
        _replace(oldDev, newDev, delay) {
            setTimeout(() => {
                if (oldDev) hub.unplug(oldDev);
                setTimeout(() => { this.history.push(newDev.kind); mark(`board: ${newDev.kind} enumerated`); hub.plug(newDev); }, 5);
            }, delay || 5);
        }
        _rom() {
            const rom = T.romDevice({ serial: this.o.serial, onBooted: () => this._secondStage(rom) });
            this.roms.push({ boot: this.boots + 1, dev: rom });
            return rom;
        }
        powerOnRom() {
            const rom = this._rom();
            this.history.push('rom');
            hub.plug(rom);
            mark('board: ROM plugged');
            return rom;
        }
        _metadata() {
            const md = [
                ['USER_SERIAL_NUM', this.o.serial],
                ['MAC_ADDR', '2c:cf:67:e2:e5:01'],
                ['USER_BOARDREV', 'd04170'],
                ['CUSTOMER_KEY_HASH', this.o.keyHash],
            ];
            if (this.o.secureBoot) md.push(['SECURE_BOOT_PROVISION', 'success']);
            md.push(['EEPROM_UPDATE', 'success']);
            return md.map(([k, v]) => ({ cmd: 0, name: `*${k}*${v}` }));
        }
        _fs(script, rec, onEnd) {
            const fs = T.fsDevice({ serial: '', script, onEnd });
            const origIn = fs.controlTransferIn;
            fs.controlTransferIn = async function (setup, len) {
                const idx = this.readIndex;
                const r = await origIn.call(this, setup, len);
                if (setup.requestType === 'vendor') {
                    const m = script[idx];
                    this._cur = m && m.cmd === 1 ? m.name : null;
                    if (m && m.cmd === 0 && m.name[0] !== '*') rec.asked.push(m.name);
                    if (this._cur) rec.files[this._cur] = [];
                }
                return r;
            };
            const origOut = fs.transferOut;
            fs.transferOut = async function (ep, data) {
                const r = await origOut.call(this, ep, data);
                if (this._cur) rec.files[this._cur].push(new Uint8Array(data));
                return r;
            };
            return fs;
        }
        _secondStage(rom) {
            this.boots++;
            const rec = { boot: this.boots, files: {}, asked: [] };
            this.fileServers.push(rec);
            let fs;
            if (this.boots === 1) {
                const script = [
                    { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
                    { cmd: 0, name: 'pieeprom.sig' }, { cmd: 1, name: 'pieeprom.sig' },
                    { cmd: 0, name: 'pieeprom.bin' }, { cmd: 1, name: 'pieeprom.bin' },
                    ...this._metadata(),
                    { cmd: 2, name: 'done', after: () => this._reboot(fs) },
                ];
                fs = this._fs(script, rec);
            } else {
                const script = [
                    { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
                    { cmd: 0, name: 'boot.sig' }, { cmd: 1, name: 'boot.sig' },
                    { cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' },
                ];
                fs = this._fs(script, rec, () => this._gadget(fs));
            }
            this._replace(rom, fs, 5);
        }
        _reboot(fs) { this._replace(fs, this._rom(), 10); }
        _gadget(fs) {
            const sim = new T.FastbootSim(Object.assign({ serial64: '10000000' + this.o.serial, maxDownload: 0x10000000, blocks: this.o.blocks }, this.o.fastboot));
            sim.kind = 'fastboot';
            // a real device key (the mocks' placeholder PEM does not parse)
            const origHandle = sim.handle.bind(sim);
            sim.handle = (cmd) => {
                if (cmd === 'getvar:public-key' && sim.keyProvisioned && CFG.devicePem) { sim.ok(CFG.devicePem.trim()); return; }
                return origHandle(cmd);
            };
            // SHA-256 of every completed download
            const origOut = sim.transferOut.bind(sim);
            sim.transferOut = async (ep, data) => {
                const n = sim.downloads.length;
                const r = await origOut(ep, data);
                if (sim.downloads.length > n) sim.downloads[n].sha256 = await sha(sim.buffer);
                return r;
            };
            // keep the passphrase out of the recorded command list but remember it for the runner
            this.fb = sim;
            this._replace(fs, sim, 300);
        }
        async summary() {
            const roms = [];
            for (const r of this.roms) {
                const bulk = r.dev.bulk;
                if (!bulk.length) { roms.push({ boot: r.boot, sent: false }); continue; }
                const body = concat(bulk.slice(1));
                roms.push({ boot: r.boot, sent: true, header_len: bulk[0].byteLength, header_size_field: new DataView(bulk[0].buffer).getInt32(0, true), size: body.byteLength, sha256: await sha(body) });
            }
            const fss = [];
            for (const f of this.fileServers) {
                const files = {};
                for (const [name, chunks] of Object.entries(f.files)) {
                    const b = concat(chunks);
                    files[name] = { size: b.byteLength, sha256: b.byteLength ? await sha(b) : null };
                }
                fss.push({ boot: f.boot, asked: f.asked, files });
            }
            const fb = this.fb;
            return {
                history: this.history,
                roms,
                fileServers: fss,
                fastboot: fb ? {
                    commands: fb.commands,
                    downloads: fb.downloads.map((d) => ({ size: d.size, chunks: d.chunks, sha256: d.sha256 || null })),
                    flashes: fb.flashes.map((f) => ({ dev: f.dev, size: f.size })),
                    erased: fb.erased,
                    passwords: fb.passwords.map((p) => ({ dev: p.dev, pass: p.pass })),
                    keyProvisioned: fb.keyProvisioned,
                    maxCommandSeen: fb.maxCommandSeen,
                    idp: fb.idp,
                } : null,
            };
        }
    }

    // ------------------------------------------------------------------ operator

    const $ = (s) => document.querySelector(s);
    const visible = (el) => !!el && !el.classList.contains('hidden') && !el.disabled;
    function click(sel, why) {
        const b = $(sel);
        report.clicks.push(`${((Date.now() - t0) / 1000).toFixed(1)}s ${sel}${why ? ' (' + why + ')' : ''}`);
        b.click();
    }
    async function until(cond, ms, what) {
        const start = Date.now();
        for (;;) {
            const v = await cond();
            if (v) return v;
            if (Date.now() - start > ms) throw new Error(`timeout (${Math.round(ms / 1000)} s) waiting for ${what}`);
            await sleep(100);
        }
    }
    async function getJson(url) {
        const r = await fetch(url, { cache: 'no-store', headers: { 'X-E2E-Harness': '1' } });
        const text = await r.text();
        let body = null;
        try { body = JSON.parse(text); } catch (e) { body = text; }
        return { status: r.status, body };
    }

    function answerDialog() {
        const dlg = $('#confirm-dialog');
        if (!dlg || !dlg.open) return false;
        const token = $('#confirm-serial').textContent;
        const flags = [...document.querySelectorAll('#confirm-flags li')].map((li) => li.textContent);
        const okBefore = $('#confirm-ok').disabled;
        const input = $('#confirm-input');
        input.value = token;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const okAfter = $('#confirm-ok').disabled;
        report.dialogs.push({ what: $('#confirm-what').textContent, token, flags, okDisabledBeforeTyping: okBefore, okDisabledAfterTyping: okAfter });
        mark(`confirm dialog: ${flags.length} item(s), typed "${token}"`);
        click('#confirm-ok', 'typed serial');
        return true;
    }

    async function run() {
        const app = window.OTP && window.OTP.app;
        if (!app) throw new Error('OTP.app is missing: the page did not initialise');
        await app.ready;
        mark('page ready');
        report.apiAvailable = window.OTP.api.available;
        if (!report.apiAvailable) throw new Error('the page says the server is offline');
        const verbose = $('#chk-verbose');
        if (!verbose.checked) verbose.click();   // render debug lines too, so the log check sees everything

        const board = new E2EBoard({ serial: CFG.serial, secureBoot: !!CFG.secureBoot });
        window.__E2E_BOARD = board;
        board.powerOnRom();
        await sleep(50);
        report.connectEnabled = !$('#btn-connect').disabled;
        click('#btn-connect', 'Connect board');
        const flow = app.flow;
        await until(() => (flow.module && flow.module.serial === CFG.serial) || $('#board-status').textContent, 30000, 'the board record');
        if (!flow.module) throw new Error(`Connect board failed: ${$('#board-status').textContent}`);
        mark(`board connected: record ${flow.module.serial} stage ${flow.module.stage}`);
        report.moduleAfterHello = flow.module;
        report.boardCardSerial = ($('#board-detail .serial-big') || {}).textContent || '';

        // the board's OTP facts: scenario B reports our key hash as burnt (read from the registry by the runner)
        if (CFG.secureBoot) {
            const kh = await getJson(`/__e2e__/keyhash?serial=${CFG.serial}`);
            if (kh.status !== 200 || !/^[0-9a-f]{64}$/.test(kh.body.customer_key_hash || '')) throw new Error(`keyhash: ${JSON.stringify(kh)}`);
            board.o.keyHash = kh.body.customer_key_hash;
            report.registryKeyHash = kh.body.customer_key_hash;
        }
        // the image's real block list (INFO <dev>:<simage>) from the stage-3 manifest
        const m3 = await getJson(`/api/modules/${CFG.serial}/stage/3`);
        if (m3.status !== 200) throw new Error(`stage 3 manifest before the run: HTTP ${m3.status} ${JSON.stringify(m3.body).slice(0, 300)}`);
        const simages = Object.keys(m3.body.parts || {});
        const crypt = m3.body.crypt || [];
        const mapper = crypt.length ? `mapper/${crypt[0].mname}` : `${m3.body.storage_device}p2`;
        board.o.blocks = simages.map((s, i) => (i === 0 ? `${m3.body.storage_device}p1:${s}` : `${mapper}:${s}`));
        report.blocks = board.o.blocks;
        mark(`blocks: ${board.o.blocks.join(', ')}`);

        await until(() => !$('#btn-provision').disabled, 10000, 'Provision to be enabled');
        report.provisionHint = $('#provision-hint').textContent;
        report.provisionMode = $('#provision-mode').textContent;
        click('#btn-provision', 'Provision');
        await until(() => flow.running, 10000, 'the run to start');
        mark('provisioning started');

        const deadline = Date.now() + (CFG.timeoutMs || 1800000);
        let lastSel = 0;
        let lastFb = 0;
        const seenStates = { 1: [], 2: [], 3: [] };
        while (flow.running) {
            if (Date.now() > deadline) { flow.abort(); throw new Error('the run did not finish in time'); }
            for (const n of [1, 2, 3]) {
                const st = flow.stages[n].state;
                const arr = seenStates[n];
                if (arr[arr.length - 1] !== st) { arr.push(st); mark(`stage ${n}: ${st} ${flow.stages[n].detail || ''}`.trim()); }
            }
            answerDialog();
            if (visible($('#btn-select-device')) && Date.now() - lastSel > 2000) { lastSel = Date.now(); click('#btn-select-device', 'page asks for the re-enumerated board'); }
            if (visible($('#btn-connect-fastboot')) && hub.has('fastboot') && Date.now() - lastFb > 2000) { lastFb = Date.now(); click('#btn-connect-fastboot', 'gadget enumerated'); }
            await sleep(100);
        }
        mark('provisioning finished');
        await sleep(300);
        report.seenStates = seenStates;
        for (const n of [1, 2, 3]) {
            const s = app.steps[n];
            report.stages[n] = { flowState: flow.stages[n].state, flowDetail: flow.stages[n].detail, uiClass: s.root.className, uiState: s.stateLabel.textContent, uiIcon: s.icon.textContent, uiDetail: s.detail.textContent, notes: [...s.notes.querySelectorAll('li')].map((li) => li.textContent) };
        }
        report.finalModuleFlow = flow.module;
        report.hubRequests = hub.requests.length;
    }

    async function finish() {
        try { report.board = window.__E2E_BOARD ? await window.__E2E_BOARD.summary() : null; } catch (e) { report.errors.push('board summary: ' + (e.stack || e)); }
        report.pageLog = ($('#log') || {}).textContent || '';
        report.jobLog = ($('#job-log') || {}).textContent || '';
        report.boardCard = ($('#board-detail') || {}).textContent || '';
        report.bodyText = document.body.innerText.slice(0, 20000);
        report.elapsedMs = Date.now() - t0;
        try {
            await fetch('/__e2e_result', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(report) });
        } catch (e) { console.error('cannot post the result', e); }
    }

    window.addEventListener('load', () => {
        run().catch((e) => { report.errors.push('run: ' + (e && (e.stack || e.message) || e)); mark('run failed: ' + (e && e.message)); }).finally(finish);
    });
})();
