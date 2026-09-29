/*
 * app.js — the station UI.
 *
 * Left column: devices Chrome has been allowed to see, the selected module,
 * the registry. Right column: the three provisioning stages of the Reclus
 * design (OTP & EEPROM, provisioning agent, image) and the log.
 * Stages 1 and 2 are the same rpiboot run with different directories;
 * stage 3 is fastboot.
 */
(function () {
    'use strict';
    const OTP = window.OTP;
    const { RPI_VID, USB_FILTERS, RpiDevice, RpiBootSession, DeviceGone, sleep } = OTP.rpiboot;
    const { BootDir, CHIPS, IRREVERSIBLE_KEYS } = OTP;
    const registry = OTP.registry;

    // ---------- tiny DOM helpers ----------
    const $ = (sel, root) => (root || document).querySelector(sel);
    function el(tag, attrs, ...children) {
        const n = document.createElement(tag);
        if (attrs) {
            for (const [k, v] of Object.entries(attrs)) {
                if (v === undefined || v === null || v === false) continue;
                if (k === 'class') n.className = v;
                else if (k === 'text') n.textContent = v;
                else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
                else n.setAttribute(k, v === true ? '' : v);
            }
        }
        for (const c of children.flat()) {
            if (c === undefined || c === null || c === false) continue;
            n.append(c.nodeType ? c : document.createTextNode(String(c)));
        }
        return n;
    }
    const hex4 = (n) => n.toString(16).padStart(4, '0');
    const fmtBytes = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KiB' : (n / 1048576).toFixed(1) + ' MiB');
    function downloadText(name, text, type) {
        const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: type || 'application/json' })), download: name });
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }

    // ---------- log ----------
    const logEl = $('#log');
    const logEntries = [];
    let verbose = localStorage.getItem('otp.verbose') === '1';
    function appendLogLine(entry) {
        logEl.append(el('div', { class: 'log-' + entry.level, text: entry.line }));
        logEl.scrollTop = logEl.scrollHeight;
    }
    function log(level, msg) {
        const entry = { level, line: `${new Date().toISOString().slice(11, 23)} ${level.toUpperCase().padEnd(5)} ${msg}` };
        logEntries.push(entry);
        if (logEntries.length > 5000) logEntries.shift();
        if (level === 'debug' && !verbose) return;
        appendLogLine(entry);
    }
    function rerenderLog() {
        logEl.replaceChildren();
        for (const e of logEntries) if (e.level !== 'debug' || verbose) appendLogLine(e);
    }
    $('#chk-verbose').checked = verbose;
    $('#chk-verbose').addEventListener('change', (e) => { verbose = e.target.checked; localStorage.setItem('otp.verbose', verbose ? '1' : '0'); rerenderLog(); });
    $('#btn-log-copy').addEventListener('click', () => navigator.clipboard.writeText(logEntries.map((e) => e.line).join('\n')));
    $('#btn-log-save').addEventListener('click', () => downloadText(`otp-provisioner-${new Date().toISOString().replace(/[:.]/g, '-')}.log`, logEntries.map((e) => e.line).join('\n') + '\n', 'text/plain'));
    $('#btn-log-clear').addEventListener('click', () => { logEntries.length = 0; rerenderLog(); });

    // ---------- capabilities ----------
    function renderCaps() {
        const badge = (label, ok, title) => el('span', { class: 'badge ' + (ok ? 'ok' : 'err'), title }, label + (ok ? ' ✓' : ' ✗'));
        const win = /Win/.test(navigator.platform);
        $('#caps').replaceChildren(
            badge('WebUSB', !!navigator.usb, 'navigator.usb: Chrome / Edge / Opera'),
            badge('Directory picker', !!window.showDirectoryPicker, 'File System Access API (falls back to <input webkitdirectory>)'),
            badge('Secure context', window.isSecureContext, 'WebUSB needs https://, http://localhost or file://'),
            el('span', { class: 'badge', title: win
                ? 'The rpiboot installer binds WinUSB (rpiboot-winusb.inf) to 0a5c:2763/2764/2711/2712; without it Chrome cannot open the device.'
                : 'The browser must be allowed to open 0a5c:* — see the udev rule in README.md.' },
            win ? 'Windows · WinUSB driver required' : 'Linux/macOS · udev access required'),
        );
        if (!navigator.usb) log('error', 'WebUSB is not available in this browser. Use Chrome, Edge or another Chromium browser.');
    }

    // ---------- devices ----------
    const state = { devices: new Map(), selectedKey: null, session: null, waiter: null, busy: false };
    const keyOf = (usb) => `${hex4(usb.vendorId)}:${hex4(usb.productId)}:${usb.serialNumber || ''}`;
    const isRpi = (usb) => usb.vendorId === RPI_VID && !!CHIPS[usb.productId];

    function upsertDevice(usb, connected) {
        const key = keyOf(usb);
        let rec = state.devices.get(key);
        if (!rec) { rec = { key, probe: null }; state.devices.set(key, rec); }
        rec.usb = usb;
        rec.connected = connected;
        return rec;
    }

    async function refreshDevices() {
        if (!navigator.usb) return;
        const list = await navigator.usb.getDevices();
        const seen = new Set();
        for (const usb of list) {
            if (!isRpi(usb)) continue;
            seen.add(keyOf(usb));
            upsertDevice(usb, true);
        }
        for (const [key, rec] of state.devices) if (!seen.has(key)) rec.connected = false;
        if ((!state.selectedKey || !state.devices.get(state.selectedKey)) && seen.size) state.selectedKey = [...seen][0];
        renderDevices();
        renderDetail();
    }

    async function pickDevice() {
        if (!navigator.usb) return;
        try {
            const usb = await navigator.usb.requestDevice({ filters: USB_FILTERS });
            const rec = upsertDevice(usb, true);
            log('info', `Granted: ${CHIPS[usb.productId].name} ${usb.serialNumber || '(no serial)'} ${usb.productName || ''}`);
            if (state.waiter) { state.waiter.offer(usb); renderDevices(); return; }
            await selectDevice(rec.key);
        } catch (e) {
            if (e.name !== 'NotFoundError') log('error', `requestDevice: ${e.message || e}`);
        }
    }

    async function probe(rec) {
        if (!rec || !rec.connected || state.session || state.busy) return;
        state.busy = true;
        const dev = new RpiDevice(rec.usb);
        try {
            await dev.open();
            rec.probe = { iSerial: dev.iSerial, serial: dev.serial, stage: dev.stageName, rom: dev.isRomStage, bcdDevice: dev.bcdDevice, error: dev.descriptorError ? String(dev.descriptorError.message || dev.descriptorError) : null };
            log('info', `${dev.chip.name} ${dev.serial || '(no serial)'}: ${dev.stageName} (iSerialNumber=${dev.iSerial})`);
            if (dev.serial) registry.upsert(dev.serial, { chip: dev.chip.name, board: dev.chip.board, usbId: `${hex4(rec.usb.vendorId)}:${hex4(rec.usb.productId)}` });
        } catch (e) {
            rec.probe = { error: e.message || String(e) };
            log('error', `Probe failed: ${e.message || e}${/claim|access|busy/i.test(String(e.message)) ? ' — is rpiboot.exe or another tab holding the device?' : ''}`);
        } finally {
            await dev.close();
            state.busy = false;
        }
        renderDevices();
        renderDetail();
        renderRegistry();
    }

    async function selectDevice(key) {
        state.selectedKey = key;
        renderDevices();
        renderDetail();
        const rec = state.devices.get(key);
        if (rec && rec.connected && $('#chk-autoprobe').checked) await probe(rec);
    }

    function renderDevices() {
        const ul = $('#device-list');
        ul.replaceChildren();
        const recs = [...state.devices.values()].sort((a, b) => Number(b.connected) - Number(a.connected));
        if (!recs.length) {
            ul.append(el('li', { class: 'empty' }, 'No authorized Raspberry Pi devices yet. Put the module in rpiboot mode and click "Select device…".'));
            return;
        }
        for (const rec of recs) {
            const chip = CHIPS[rec.usb.productId];
            ul.append(el('li', { class: (rec.key === state.selectedKey ? 'selected ' : '') + (rec.connected ? '' : 'offline'), onclick: () => selectDevice(rec.key) },
                el('span', { class: 'title' }, `${chip.name} · ${chip.board}`),
                el('span', { class: 'serial' }, rec.usb.serialNumber || '(no serial)'),
                el('span', { class: 'state' }, [rec.connected ? 'connected' : 'disconnected', rec.usb.productName || `${hex4(rec.usb.vendorId)}:${hex4(rec.usb.productId)}`, rec.probe && rec.probe.stage].filter(Boolean).join(' · '))));
        }
    }

    function renderDetail() {
        const box = $('#device-detail');
        const rec = state.devices.get(state.selectedKey);
        if (!rec) { box.replaceChildren(el('p', { class: 'muted' }, 'No module selected.')); return; }
        const chip = CHIPS[rec.usb.productId];
        const p = rec.probe || {};
        const serial = rec.usb.serialNumber || p.serial || '';
        const reg = serial ? registry.get(serial) : null;
        box.replaceChildren(
            el('div', { class: 'serial-big' }, serial || '—'),
            el('div', { class: 'row' },
                el('button', { class: 'small', onclick: () => navigator.clipboard.writeText(serial), disabled: !serial }, 'Copy serial'),
                el('button', { class: 'small', onclick: () => probe(rec), disabled: !rec.connected }, 'Probe stage')),
            el('p', { class: 'hint' }, 'The USB serial is the lower 32 bits of the board serial. The full serial, MAC addresses and the DUID (FACTORY_UUID) arrive in the metadata as soon as a bootloader runs (stage 1).'),
            el('dl', { class: 'kv' },
                el('dt', {}, 'SoC'), el('dd', {}, `${chip.name} (${chip.board})`),
                el('dt', {}, 'USB'), el('dd', {}, [`${hex4(rec.usb.vendorId)}:${hex4(rec.usb.productId)}`, rec.usb.manufacturerName, rec.usb.productName].filter(Boolean).join(' ')),
                el('dt', {}, 'State'), el('dd', {}, rec.connected ? 'connected' : 'disconnected'),
                el('dt', {}, 'Stage'), el('dd', {}, p.stage ? `${p.stage} (iSerialNumber=${p.iSerial})` : p.error ? `probe failed: ${p.error}` : 'not probed'),
                el('dt', {}, 'bcdDevice'), el('dd', {}, p.bcdDevice != null ? hex4(p.bcdDevice) : '—'),
                el('dt', {}, 'Registry'), el('dd', {}, reg ? `${registry.STAGES[reg.stage]} · first seen ${reg.firstSeen.slice(0, 19).replace('T', ' ')}` : 'not registered'),
                reg && reg.metadata && reg.metadata.MAC_ADDR ? [el('dt', {}, 'MAC'), el('dd', {}, reg.metadata.MAC_ADDR)] : null,
                reg && reg.metadata && reg.metadata.FACTORY_UUID ? [el('dt', {}, 'DUID'), el('dd', {}, reg.metadata.FACTORY_UUID)] : null,
                reg && reg.metadata && reg.metadata.CUSTOMER_KEY_HASH ? [el('dt', {}, 'Key hash'), el('dd', {}, reg.metadata.CUSTOMER_KEY_HASH)] : null,
            ));
    }

    /** Resolve with the next Raspberry Pi device of the same product that is not `previous` (connect event, manual pick or polling). */
    function waitForDevice({ previous, productId, timeoutMs }) {
        return new Promise((resolve, reject) => {
            let done = false;
            const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); if (state.waiter === waiter) state.waiter = null; fn(v); };
            const timer = setTimeout(() => finish(reject, new Error(`timed out after ${timeoutMs / 1000} s waiting for the module to re-enumerate`)), timeoutMs);
            const waiter = {
                offer(usb) { if (isRpi(usb) && usb.productId === productId && usb !== previous) finish(resolve, usb); },
                cancel() { finish(reject, new Error('aborted')); },
            };
            state.waiter = waiter;
            (async () => {
                while (!done) {
                    try { for (const u of await navigator.usb.getDevices()) waiter.offer(u); } catch (e) { /* ignore */ }
                    await sleep(1000);
                }
            })();
        });
    }

    function abortRun() {
        if (state.session) state.session.abort();
        if (state.waiter) state.waiter.cancel();
    }

    /**
     * rpiboot's main loop: while the device is in the ROM stage send the
     * second stage and wait for it to re-enumerate; then run the file server.
     */
    async function runBootDir(panel) {
        const rec = state.devices.get(state.selectedKey);
        if (!rec) return log('error', 'Select a module first');
        if (!rec.connected) return log('error', 'The selected module is not connected');
        if (state.session) return log('error', 'Another run is in progress');
        const session = new RpiBootSession(panel.dir, {
            log,
            onProgress: (name, s, t) => panel.progress(name, s, t),
            onMetadata: (k, v) => panel.metadataLine(k, v),
        });
        state.session = session;
        panel.setRunning(true);
        let usb = rec.usb;
        let lastISerial = -1;
        let result = null;
        let serial = rec.usb.serialNumber || '';
        log('info', `=== ${panel.title}: "${panel.dir.name}" → ${CHIPS[usb.productId].name} ${serial} ===`);
        try {
            for (let hop = 0; hop < 6 && !session.aborted; hop++) {
                const dev = new RpiDevice(usb);
                await dev.open();
                if (dev.serial) serial = dev.serial;
                if (dev.iSerial !== null && dev.iSerial === lastISerial) {
                    // same enumeration as last time (rpiboot: last_serial) → keep waiting
                    await dev.close();
                    log('debug', 'Same enumeration as before; waiting for a new one');
                    usb = await waitForDevice({ previous: usb, productId: usb.productId, timeoutMs: 60000 });
                    continue;
                }
                lastISerial = dev.iSerial;
                let r;
                try {
                    r = await session.step(dev);
                } catch (e) {
                    if (!(e instanceof DeviceGone)) throw e;
                    log('warn', 'The module left USB before "Done"; keeping what was collected');
                    r = { kind: 'file-server-done', metadata: session.metadata, filesServed: session.filesServed, interrupted: true };
                }
                if (r.kind === 'file-server-done') { result = r; break; }
                log('info', 'Waiting for the module to re-enumerate as the second stage…');
                usb = await waitForDevice({ previous: usb, productId: usb.productId, timeoutMs: 60000 });
                upsertDevice(usb, true);
                renderDevices();
            }
            if (!result && !session.aborted) throw new Error('the module kept re-enumerating in the ROM stage; check the second-stage file');
        } catch (e) {
            log('error', `${panel.title} failed: ${e.message || e}`);
            panel.showError(e);
        } finally {
            state.session = null;
            if (state.waiter) state.waiter.cancel();
            panel.setRunning(false);
        }
        if (!result) return;
        const meta = result.metadata;
        const key = serial || meta.USER_SERIAL_NUM || meta.SERIAL_NUMBER || '';
        log('ok', `${panel.title} finished: ${Object.keys(meta).length} metadata fields, ${result.filesServed.length} files served`);
        const verdict = panel.verdict(result);
        if (key) {
            registry.upsert(key, { chip: CHIPS[rec.usb.productId].name, metadata: meta, stage: verdict.ok ? panel.stageDone : undefined });
            registry.addEvent(key, panel.stageDone, `${verdict.ok ? 'ok' : 'check'}: ${panel.dir.name}; files: ${result.filesServed.map((f) => f.name).join(', ') || 'none'}`);
        }
        panel.showResult(result, verdict, session.metadataJson(key));
        renderRegistry();
        renderDetail();
    }

    // ---------- confirmation for irreversible steps ----------
    function confirmIrreversible({ what, flags, token, okLabel }) {
        return new Promise((resolve) => {
            const dlg = $('#confirm-dialog');
            $('#confirm-what').textContent = what;
            $('#confirm-flags').replaceChildren(...flags.map((f) => el('li', {}, el('code', {}, f.key + (f.value !== undefined ? '=' + f.value : '')), ' — ' + f.why)));
            $('#confirm-serial').textContent = token;
            const input = $('#confirm-input');
            const ok = $('#confirm-ok');
            ok.textContent = okLabel || 'Proceed';
            input.value = '';
            ok.disabled = true;
            const onInput = () => { ok.disabled = input.value.trim().toLowerCase() !== token.toLowerCase(); };
            input.addEventListener('input', onInput);
            const cleanup = (v) => { input.removeEventListener('input', onInput); dlg.close(); resolve(v); };
            ok.onclick = () => cleanup(true);
            $('#confirm-cancel').onclick = () => cleanup(false);
            dlg.oncancel = (e) => { e.preventDefault(); cleanup(false); };
            dlg.showModal();
            input.focus();
        });
    }

    // ---------- a stage that runs a boot directory ----------
    const HASHED_FILES = ['bootcode5.bin', 'bootcode4.bin', 'bootcode.bin', 'recovery.bin', 'pieeprom.bin', 'pieeprom.sig', 'boot.img', 'boot.sig', 'bootfiles.bin', 'config.txt'];

    class BootRunPanel {
        constructor(root, cfg) {
            this.root = root;
            this.cfg = cfg;
            this.title = cfg.title;
            this.stageDone = cfg.stageDone;
            this.dir = null;
            this.chip = CHIPS[0x2712];
            this.irreversible = [];
            this.otpRequested = false;
            this.render();
        }

        render() {
            const r = this.root;
            r.replaceChildren(
                el('h2', {}, this.title),
                el('p', { class: 'blurb' }, ...this.cfg.blurb),
                el('div', { class: 'row' },
                    this.btnChoose = el('button', { class: 'primary', onclick: () => this.chooseDir() }, 'Choose boot directory…'),
                    this.dirLabel = el('span', { class: 'muted' }, this.cfg.dirHint),
                    this.fileInput = el('input', { type: 'file', webkitdirectory: true, class: 'hidden', onchange: (e) => e.target.files.length && this.loadDir(BootDir.fromFileList(e.target.files)) })),
                this.dirBox = el('div', { class: 'hidden' },
                    el('h3', {}, 'Files'),
                    this.filesTable = el('table', { class: 'list' }),
                    this.otherFiles = el('p', { class: 'hint' }),
                    el('h3', {}, 'config.txt (rpiboot options, not the OS config.txt)'),
                    this.flagsBox = el('div', { class: 'flags' }),
                    this.extraBox = el('div')),
                el('div', { class: 'row' },
                    this.btnRun = el('button', { class: 'danger', disabled: true, onclick: () => this.run() }, this.cfg.runLabel),
                    this.btnAbort = el('button', { disabled: true, onclick: () => abortRun() }, 'Abort'),
                    this.runHint = el('span', { class: 'muted' }, 'choose a directory and select a module')),
                el('div', { class: 'progress' }, this.progressBar = el('div')),
                this.progressLabel = el('div', { class: 'progress-label' }),
                this.resultBox = el('div', { class: 'result hidden' }),
            );
            if (this.cfg.keyHashCheck) {
                this.extraBox.append(
                    el('h3', {}, 'Expected customer key hash'),
                    el('div', { class: 'row' }, this.keyHashInput = el('input', { type: 'text', class: 'mono', size: 70, placeholder: 'sha256 of the module public key, 64 hex — from the server (optional)' })),
                    el('p', { class: 'hint' }, 'After the run, CUSTOMER_KEY_HASH from the metadata is compared with this value (the stage-1 check of the design).'));
            }
        }

        async chooseDir() {
            if (window.showDirectoryPicker) {
                try {
                    const handle = await window.showDirectoryPicker({ mode: 'read' });
                    await this.loadDir(BootDir.fromDirectoryHandle(handle));
                } catch (e) {
                    if (e.name !== 'AbortError') log('error', `Directory: ${e.message || e}`);
                }
            } else {
                this.fileInput.click();
            }
        }

        async loadDir(bootDir) {
            this.dir = bootDir;
            this.dirLabel.textContent = bootDir.name;
            this.dirBox.classList.remove('hidden');
            this.resultBox.classList.add('hidden');
            const rec = state.devices.get(state.selectedKey);
            this.chip = rec ? CHIPS[rec.usb.productId] : CHIPS[0x2712];
            log('info', `${this.title}: directory "${bootDir.name}" (files resolved for ${this.chip.name}, prefix ${this.chip.prefix}/)`);
            try {
                await this.renderFiles();
                await this.renderFlags();
            } catch (e) {
                log('error', `Reading the directory failed: ${e.message || e}`);
            }
            this.updateRunState();
        }

        async renderFiles() {
            const table = this.filesTable;
            table.replaceChildren(el('thead', {}, el('tr', {}, el('th', {}, 'Status'), el('th', {}, 'File'), el('th', {}, 'Resolved from'), el('th', {}, 'Size'), el('th', {}, 'SHA-256'))));
            const tbody = el('tbody');
            table.append(tbody);
            const problems = await this.dir.validate();
            for (const p of problems) tbody.append(el('tr', { class: 'missing' }, el('td', { colspan: 5 }, p)));
            const hashes = [];
            for (const exp of this.cfg.expected) {
                const found = await this.dir.resolve(exp.name, this.chip);
                const ok = found && !found.denied;
                const tr = el('tr', { class: ok ? 'ok' : exp.required ? 'missing' : '' },
                    el('td', { class: 'status' }, ok ? '✓' : exp.required ? 'missing' : 'optional, absent'),
                    el('td', { class: 'mono', title: exp.note }, exp.name),
                    el('td', { class: 'mono' }, ok ? found.origin : '—'),
                    el('td', {}, ok ? fmtBytes(found.data.byteLength) : '—'),
                    el('td', { class: 'hash' }, ok ? '…' : ''));
                tbody.append(tr);
                if (ok) hashes.push(BootDir.sha256Hex(found.data).then((h) => { tr.lastChild.textContent = h; }));
                exp.found = ok;
            }
            const top = await this.dir.listTop();
            const known = new Set(this.cfg.expected.map((e) => e.name.toLowerCase()));
            const others = top.filter((f) => !known.has(f.name.toLowerCase()));
            const tar = await this.dir.bootfiles();
            const tarNote = tar ? ` bootfiles.bin holds: ${OTP.tar.list(tar).map((e) => `${e.name} (${fmtBytes(e.size)})`).join(', ')}.` : '';
            this.otherFiles.textContent = (others.length ? 'Also in the directory: ' + others.map((f) => f.kind === 'dir' ? f.name + '/' : `${f.name} (${fmtBytes(f.size)})`).join(', ') + '.' : 'No other files.') + tarNote;
            await Promise.all(hashes);
        }

        async renderFlags() {
            const cfg = await this.dir.configTxt();
            this.flagsBox.replaceChildren();
            this.irreversible = [];
            this.otpRequested = false;
            if (!cfg) {
                this.flagsBox.append(el('div', { class: 'flag' }, el('span', { class: 'muted' }, 'no config.txt in the directory')));
            } else {
                const keys = Object.entries(cfg.keys);
                if (!keys.length) this.flagsBox.append(el('div', { class: 'flag' }, el('span', { class: 'muted' }, 'config.txt sets nothing (all lines commented out)')));
                for (const [k, v] of keys) {
                    const why = IRREVERSIBLE_KEYS[k];
                    const on = why && v !== '0' && v !== '';
                    if (on) this.irreversible.push({ key: k, value: v, why });
                    if (k === 'program_pubkey' && on) this.otpRequested = true;
                    this.flagsBox.append(el('div', { class: 'flag' + (on ? ' irreversible' : '') },
                        el('span', { class: 'k' }, `${k}=${v}`),
                        on ? el('span', { class: 'why' }, `IRREVERSIBLE: ${why}`) : null));
                }
            }
            if (this.cfg.stage === 1) {
                this.flagsBox.append(el('div', { class: 'flag' }, el('span', { class: this.otpRequested ? 'why' : 'muted' },
                    this.otpRequested ? 'This run burns the customer public key hash into OTP (program_pubkey=1).' : 'OTP is not written by this directory (program_pubkey is not set): the EEPROM is flashed, the SoC stays open.')));
            }
        }

        updateRunState() {
            const rec = state.devices.get(state.selectedKey);
            const missing = this.cfg.expected.filter((e) => e.required && !e.found).map((e) => e.name);
            const ready = !!this.dir && !!rec && rec.connected && !missing.length && !state.session;
            this.btnRun.disabled = !ready;
            this.runHint.textContent = !this.dir ? 'choose a directory' : missing.length ? `missing: ${missing.join(', ')}` : !rec ? 'select a module' : !rec.connected ? 'the selected module is disconnected' : state.session ? 'a run is in progress' : `ready for ${rec.usb.serialNumber || 'the selected module'}`;
        }

        async run() {
            const rec = state.devices.get(state.selectedKey);
            if (!rec) return;
            if (this.irreversible.length) {
                const ok = await confirmIrreversible({
                    what: `Directory "${this.dir.name}" sets rpiboot options that permanently change module ${rec.usb.serialNumber || ''}:`,
                    flags: this.irreversible,
                    token: rec.usb.serialNumber || 'BURN',
                    okLabel: 'Burn',
                });
                if (!ok) { log('info', 'Cancelled by the operator'); return; }
            }
            await runBootDir(this);
        }

        setRunning(on) {
            this.btnAbort.disabled = !on;
            this.btnChoose.disabled = on;
            if (on) { this.progress('', 0, 1); this.resultBox.classList.add('hidden'); this.metaLines = []; }
            this.updateRunState();
            for (const p of panels) if (p !== this) p.updateRunState();
        }

        progress(name, sent, total) {
            const pct = total ? Math.round((sent / total) * 100) : 0;
            this.progressBar.style.width = pct + '%';
            this.progressLabel.textContent = name ? `${name}: ${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%)` : '';
        }

        metadataLine(k, v) { /* the log already shows it; the table is built at the end */ }

        verdict(result) {
            const m = result.metadata;
            const notes = [];
            let ok = true;
            if (this.cfg.stage === 1) {
                if (!Object.keys(m).length) { ok = false; notes.push('No metadata received (old recovery.bin, recovery_metadata=0, or the run ended early).'); }
                if (m.EEPROM_UPDATE !== undefined) { notes.push(`EEPROM_UPDATE = ${m.EEPROM_UPDATE}`); if (m.EEPROM_UPDATE !== 'success') ok = false; }
                if (this.otpRequested) {
                    if (m.SECURE_BOOT_PROVISION === 'success') notes.push('SECURE_BOOT_PROVISION = success: the key hash is in OTP.');
                    else { ok = false; notes.push(`SECURE_BOOT_PROVISION = ${m.SECURE_BOOT_PROVISION || 'missing'}: OTP was NOT confirmed.`); }
                }
                const want = this.keyHashInput ? this.keyHashInput.value.trim().toLowerCase() : '';
                if (want) {
                    if ((m.CUSTOMER_KEY_HASH || '').toLowerCase() === want) notes.push('CUSTOMER_KEY_HASH matches the expected key.');
                    else { ok = false; notes.push(`CUSTOMER_KEY_HASH ${m.CUSTOMER_KEY_HASH ? 'does NOT match the expected key' : 'is missing'}.`); }
                }
            } else {
                const served = result.filesServed.map((f) => f.name.toLowerCase());
                if (served.includes('boot.img')) notes.push('boot.img delivered: the agent is booting.');
                else { ok = false; notes.push('boot.img was never requested by the bootloader.'); }
                if (result.interrupted) notes.push('The module left the file server before "Done" (normal when the ramdisk takes over USB).');
            }
            return { ok, notes };
        }

        showResult(result, verdict, json) {
            const box = this.resultBox;
            const m = result.metadata;
            box.replaceChildren(
                el('div', { class: 'verdict ' + (verdict.ok ? 'ok' : 'warn') }, verdict.ok ? `${this.cfg.doneLabel}` : `${this.title}: check the result`),
                ...verdict.notes.map((n) => el('div', {}, n)),
                el('h3', {}, 'Metadata'),
                Object.keys(m).length
                    ? el('table', { class: 'list' }, el('tbody', {}, ...Object.entries(m).map(([k, v]) => el('tr', {}, el('td', { class: 'mono' }, k), el('td', { class: 'mono' }, v)))))
                    : el('p', { class: 'muted' }, 'none'),
                el('div', { class: 'row' },
                    el('button', { class: 'small', onclick: () => downloadText(json.name, json.text), disabled: !Object.keys(m).length }, `Download ${json.name}`),
                    el('button', { class: 'small', onclick: () => navigator.clipboard.writeText(json.text), disabled: !Object.keys(m).length }, 'Copy JSON')),
                el('h3', {}, 'Files served'),
                result.filesServed.length
                    ? el('ul', {}, ...result.filesServed.map((f) => el('li', { class: 'mono' }, `${f.name} — ${fmtBytes(f.size)} from ${f.origin}`)))
                    : el('p', { class: 'muted' }, 'none'),
            );
            box.classList.remove('hidden');
        }

        showError(e) {
            this.resultBox.replaceChildren(el('div', { class: 'verdict err' }, `${this.title} failed: ${e.message || e}`));
            this.resultBox.classList.remove('hidden');
        }
    }

    const panels = [
        new BootRunPanel($('#stage-1'), {
            stage: 1,
            title: 'Stage 1 · OTP & EEPROM',
            stageDone: 'otp-burned',
            doneLabel: 'Stage 1 done: EEPROM flashed, metadata received',
            runLabel: 'Flash EEPROM / burn OTP',
            keyHashCheck: true,
            dirHint: 'secure-boot-recovery5 after update-pieeprom.sh: bootcode5.bin (counter-signed recovery.bin), pieeprom.bin, pieeprom.sig, config.txt',
            blurb: [
                'The station sends the recovery bootloader to the boot ROM; it flashes ', el('code', {}, 'pieeprom.bin'), ' (with the module public key and a signed config), optionally burns the SHA-256 of that key into OTP (', el('code', {}, 'program_pubkey=1'),
                ') and reports the metadata JSON (serial, DUID, MAC, ', el('code', {}, 'CUSTOMER_KEY_HASH'), ', ', el('code', {}, 'SECURE_BOOT_PROVISION'), '). Equivalent of ', el('code', {}, 'rpiboot -d secure-boot-recovery5 -j metadata'), '.',
            ],
            expected: [
                { name: 'bootcode5.bin', required: true, note: 'On Pi 5 this is recovery.bin, counter-signed with the module key once secure boot is on (update-pieeprom.sh -f)' },
                { name: 'pieeprom.bin', required: true, note: 'EEPROM image with the embedded public key and the signed boot.conf' },
                { name: 'pieeprom.sig', required: true, note: 'Signature of pieeprom.bin (rpi-eeprom-digest)' },
                { name: 'config.txt', required: true, note: 'rpiboot options: program_pubkey, program_jtag_lock, recovery_reboot, recovery_metadata' },
                { name: 'recovery.bin', required: false, note: 'Not used by rpiboot on Pi 5 (bootcode5.bin is the recovery)' },
            ],
        }),
        new BootRunPanel($('#stage-2'), {
            stage: 2,
            title: 'Stage 2 · Provisioning agent',
            stageDone: 'agent-booted',
            doneLabel: 'Stage 2 done: the agent ramdisk was delivered',
            runLabel: 'Boot the agent',
            dirHint: 'mass-storage-gadget64 style: bootfiles.bin, boot.img (+ boot.sig once secure boot is on), config.txt with boot_ramdisk=1',
            blurb: [
                'The bootloader (from ', el('code', {}, 'bootfiles.bin'), ') asks the station for ', el('code', {}, 'config.txt'), ', ', el('code', {}, 'boot.img'), ' and ', el('code', {}, 'boot.sig'),
                ' and boots the signed initramfs: the provisioning agent that writes the device secret into OTP and then exposes the storage (mass-storage or fastboot gadget). ',
                'For a demo without secure boot, the stock ', el('code', {}, 'mass-storage-gadget64'), ' directory of the rpiboot installer works as the "agent": after it boots, the SD card shows up as a USB disk.',
            ],
            expected: [
                { name: 'bootcode5.bin', required: true, note: 'Second stage, normally inside bootfiles.bin as 2712/bootcode5.bin' },
                { name: 'config.txt', required: true, note: 'boot_ramdisk=1 makes the bootloader load boot.img' },
                { name: 'boot.img', required: true, note: 'FAT image: kernel + DTB + initramfs (the agent)' },
                { name: 'boot.sig', required: false, note: 'rpi-eeprom-digest signature; mandatory once the module is locked to a key' },
            ],
        }),
    ];

    // ---------- stage 3: fastboot ----------
    const fb = { usb: null, dir: null, running: false, client: null };
    function fbUpdate() {
        const have = !!fb.usb;
        $('#fb-getvar').disabled = !have || fb.running;
        $('#fb-reboot').disabled = !have || fb.running;
        $('#fb-flash').disabled = !have || fb.running;
        $('#fb-run-idp').disabled = !have || !fb.dir || fb.running;
        $('#fb-abort').disabled = !fb.running;
        $('#fb-pick').disabled = fb.running;
    }
    function fbProgress(sent, total, name) {
        const pct = total ? Math.round((sent / total) * 100) : 0;
        $('#fb-progress').style.width = pct + '%';
        $('#fb-progress-label').textContent = `${name || 'download'}: ${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%)`;
    }
    async function withFastboot(fn) {
        if (!fb.usb) return;
        if (fb.running) return log('error', 'fastboot: busy');
        fb.running = true;
        fbUpdate();
        const client = new OTP.fastboot.FastbootClient(fb.usb);
        client.log = log;
        fb.client = client;
        try {
            await client.open();
            return await fn(client);
        } catch (e) {
            log('error', `fastboot: ${e.message || e}`);
        } finally {
            await client.close();
            fb.client = null;
            fb.running = false;
            fbUpdate();
        }
    }
    $('#fb-pick').addEventListener('click', async () => {
        try {
            fb.usb = await navigator.usb.requestDevice({ filters: OTP.fastboot.FILTERS });
            $('#fb-device').textContent = [fb.usb.productName, `${hex4(fb.usb.vendorId)}:${hex4(fb.usb.productId)}`, fb.usb.serialNumber].filter(Boolean).join(' · ');
            log('info', `fastboot device: ${$('#fb-device').textContent}`);
        } catch (e) {
            if (e.name !== 'NotFoundError') log('error', `requestDevice: ${e.message || e}`);
        }
        fbUpdate();
    });
    $('#fb-getvar').addEventListener('click', () => withFastboot(async (c) => {
        const vars = await c.getvarAll();
        const tbody = $('#fb-vars tbody');
        tbody.replaceChildren(...Object.entries(vars).map(([k, v]) => el('tr', {}, el('td', { class: 'mono' }, k), el('td', { class: 'mono' }, v))));
        log('ok', `getvar:all → ${Object.keys(vars).length} variables`);
    }));
    $('#fb-reboot').addEventListener('click', () => withFastboot(async (c) => { await c.reboot(); log('ok', 'reboot sent'); }));
    $('#fb-pick-dir').addEventListener('click', async () => {
        if (window.showDirectoryPicker) {
            try { fb.dir = BootDir.fromDirectoryHandle(await window.showDirectoryPicker({ mode: 'read' })); } catch (e) { if (e.name !== 'AbortError') log('error', e.message); return; }
        } else { $('#fb-dir-input').click(); return; }
        $('#fb-dir').textContent = fb.dir.name + ((await fb.dir.has('image.json')) ? ' (image.json found)' : ' (no image.json!)');
        fbUpdate();
    });
    $('#fb-dir-input').addEventListener('change', async (e) => {
        if (!e.target.files.length) return;
        fb.dir = BootDir.fromFileList(e.target.files);
        $('#fb-dir').textContent = fb.dir.name + ((await fb.dir.has('image.json')) ? ' (image.json found)' : ' (no image.json!)');
        fbUpdate();
    });
    $('#fb-run-idp').addEventListener('click', async () => {
        if (!fb.dir || !fb.usb) return;
        const imageJson = await fb.dir.readFile('image.json');
        if (!imageJson) return log('error', 'image.json not found in the chosen directory');
        const ok = await confirmIrreversible({
            what: `Provision module ${fb.usb.serialNumber || ''} from "${fb.dir.name}": the storage is repartitioned and rewritten.`,
            flags: [{ key: 'IDP', why: 'partitions and LUKS2 containers are recreated; everything on the module storage is lost' }],
            token: fb.usb.serialNumber || 'WRITE',
            okLabel: 'Write',
        });
        if (!ok) return;
        await withFastboot(async (c) => {
            await c.provisionIdp(imageJson, (name) => fb.dir.readFile(name), fbProgress);
            log('ok', 'IDP provisioning complete');
            if (fb.usb.serialNumber) { registry.upsert(fb.usb.serialNumber, { stage: 'flashed' }); registry.addEvent(fb.usb.serialNumber, 'flashed', fb.dir.name); renderRegistry(); }
        });
    });
    $('#fb-flash').addEventListener('click', async () => {
        const part = $('#fb-part').value.trim();
        const file = $('#fb-file').files[0];
        if (!part || !file) return log('error', 'fastboot flash: partition name and a file are required');
        const ok = await confirmIrreversible({ what: `flash:${part} ← ${file.name} (${fmtBytes(file.size)}) on ${fb.usb.serialNumber || 'the fastboot device'}`, flags: [{ key: 'flash', value: part, why: 'overwrites that partition' }], token: fb.usb.serialNumber || 'WRITE', okLabel: 'Flash' });
        if (!ok) return;
        const bytes = new Uint8Array(await file.arrayBuffer());
        await withFastboot(async (c) => { await c.flash(part, bytes, (s, t) => fbProgress(s, t, file.name)); log('ok', `flash:${part} done`); });
    });
    $('#fb-abort').addEventListener('click', () => { if (fb.client) fb.client.close(); });

    // ---------- registry ----------
    function renderRegistry() {
        const tbody = $('#registry-table tbody');
        tbody.replaceChildren();
        const rows = registry.all();
        if (!rows.length) { tbody.append(el('tr', {}, el('td', { colspan: 4, class: 'muted' }, 'empty'))); return; }
        for (const r of rows) {
            const tr = el('tr', { style: 'cursor:pointer', onclick: () => { const d = tr.nextSibling; if (d && d.classList.contains('details')) d.remove(); else tr.after(el('tr', { class: 'details' }, el('td', { colspan: 4 }, el('pre', { class: 'mono', style: 'margin:4px 0;white-space:pre-wrap' }, JSON.stringify({ metadata: r.metadata, events: r.events }, null, 2))))); } },
                el('td', { class: 'mono' }, r.serial),
                el('td', {}, r.chip || '—'),
                el('td', {}, registry.STAGES[r.stage] || r.stage),
                el('td', { class: 'muted' }, (r.lastSeen || '').slice(0, 16).replace('T', ' ')));
            tbody.append(tr);
        }
    }
    $('#btn-registry-export').addEventListener('click', () => downloadText('otp-provisioner-registry.json', registry.exportJson()));
    $('#btn-registry-clear').addEventListener('click', () => { if (confirm('Clear the module registry of this browser?')) { registry.clear(); renderRegistry(); renderDetail(); } });

    // ---------- stage navigation ----------
    for (const b of $('#stage-nav').querySelectorAll('button')) {
        b.addEventListener('click', () => showStage(b.dataset.stage));
    }
    function showStage(id) {
        for (const b of $('#stage-nav').querySelectorAll('button')) b.classList.toggle('active', b.dataset.stage === id);
        for (const s of document.querySelectorAll('.stage')) s.classList.toggle('hidden', s.id !== id);
        localStorage.setItem('otp.stage', id);
    }

    // ---------- USB events ----------
    if (navigator.usb) {
        navigator.usb.addEventListener('connect', (e) => {
            const usb = e.device;
            if (!isRpi(usb)) { log('debug', `USB connect (not a Pi boot device): ${hex4(usb.vendorId)}:${hex4(usb.productId)} ${usb.productName || ''}`); return; }
            const rec = upsertDevice(usb, true);
            log('info', `USB connect: ${CHIPS[usb.productId].name} ${usb.serialNumber || '(no serial)'}`);
            if (!state.selectedKey || !state.devices.get(state.selectedKey)) state.selectedKey = rec.key;
            renderDevices();
            renderDetail();
            for (const p of panels) p.updateRunState();
            if (state.waiter) state.waiter.offer(usb);
            else if (rec.key === state.selectedKey && $('#chk-autoprobe').checked) probe(rec);
        });
        navigator.usb.addEventListener('disconnect', (e) => {
            const usb = e.device;
            const rec = state.devices.get(keyOf(usb));
            if (rec && rec.usb === usb) { rec.connected = false; rec.probe = null; }
            if (isRpi(usb)) log('info', `USB disconnect: ${CHIPS[usb.productId].name} ${usb.serialNumber || ''}`);
            renderDevices();
            renderDetail();
            for (const p of panels) p.updateRunState();
        });
    }
    $('#btn-pick-device').addEventListener('click', pickDevice);
    $('#btn-refresh-devices').addEventListener('click', refreshDevices);

    // ---------- boot ----------
    renderCaps();
    renderRegistry();
    showStage(localStorage.getItem('otp.stage') || 'stage-1');
    fbUpdate();
    refreshDevices().then(() => { for (const p of panels) p.updateRunState(); });
    log('info', 'OTP Provisioner ready. Put the module in rpiboot mode and click "Select device…".');

    // exposed for the self-test page
    OTP.app = { state, panels, log, runBootDir, waitForDevice, BootRunPanel };
})();
