/*
 * app.js — the station UI, served by `uv run server.py` (nothing works without the server: it holds the
 * board secrets and builds every file).
 *
 *   Board card (Connect board, the server's record of the board), Registry (all boards on the server),
 *   OS image (settings and source), Provision card (three stages driven by OTP.Flow),
 *   Server builds (tools / gadget / image, live job log), Log.
 */
(function () {
    'use strict';
    const OTP = window.OTP;
    const api = OTP.api;

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
    /** node.replaceChildren() without the optional parts: the DOM method writes a null as the text "null". */
    function fill(node, ...children) {
        node.replaceChildren(...children.flat().filter((c) => c !== undefined && c !== null && c !== false));
        return node;
    }
    const fmtBytes = (n) => {
        if (n === undefined || n === null || n === '') return '—';
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KiB';
        if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MiB';
        return (n / 1073741824).toFixed(2) + ' GiB';
    };
    const fmtTime = (iso) => (iso ? String(iso).slice(0, 19).replace('T', ' ') : '—');
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const shortHex = (h, n) => (h ? (h.length > (n || 16) ? h.slice(0, n || 16) + '…' : h) : '—');
    function downloadText(name, text, type) {
        const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: type || 'application/json' })), download: name });
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }
    function lsGet(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } }
    function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }

    // ---------- log ----------
    const logEl = $('#log');
    const logEntries = [];
    let verbose = lsGet('otp.verbose', '0') === '1';
    function appendLogLine(entry) {
        const stick = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
        logEl.append(el('div', { class: 'log-' + entry.level, text: entry.line }));
        if (stick) logEl.scrollTop = logEl.scrollHeight;
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
        logEl.scrollTop = logEl.scrollHeight;
    }
    $('#chk-verbose').checked = verbose;
    $('#chk-verbose').addEventListener('change', (e) => { verbose = e.target.checked; lsSet('otp.verbose', verbose ? '1' : '0'); rerenderLog(); });
    $('#btn-log-copy').addEventListener('click', () => navigator.clipboard.writeText(logEntries.map((e) => e.line).join('\n')));
    $('#btn-log-save').addEventListener('click', () => downloadText(`otp-provisioner-${new Date().toISOString().replace(/[:.]/g, '-')}.log`, logEntries.map((e) => e.line).join('\n') + '\n', 'text/plain'));
    $('#btn-log-clear').addEventListener('click', () => { logEntries.length = 0; rerenderLog(); });

    // ---------- capabilities ----------
    function badge(label, cls, title) { return el('span', { class: 'badge ' + (cls || ''), title }, label); }
    function renderCaps() {
        const win = /Win/.test(navigator.platform);
        $('#caps').replaceChildren(
            badge('WebUSB' + (navigator.usb ? ' ✓' : ' ✗'), navigator.usb ? 'ok' : 'err', 'navigator.usb: Chrome / Edge / Opera'),
            badge('Secure context' + (window.isSecureContext ? ' ✓' : ' ✗'), window.isSecureContext ? 'ok' : 'err', 'WebUSB needs http://localhost, https:// or file://'),
            badge(win ? 'Windows · WinUSB' : 'Linux/macOS', '', win
                ? 'Chrome opens only devices bound to WinUSB: 0a5c:2712 (rpiboot installer) and 18d1:4e40 (fastboot gadget).'
                : 'The browser must be allowed to open 0a5c:2712 and 18d1:4e40 — see the udev rules in README.md.'),
        );
        if (!navigator.usb) log('error', 'WebUSB is not available in this browser. Use Chrome, Edge or another Chromium browser.');
    }

    // ---------- confirmation for irreversible steps ----------
    function confirmIrreversible({ what, flags, token, okLabel }) {
        return new Promise((resolve) => {
            const dlg = $('#confirm-dialog');
            $('#confirm-what').textContent = what;
            $('#confirm-flags').replaceChildren(...flags.map((f) => el('li', {}, el('code', {}, f.key + (f.value !== undefined && f.value !== '' ? '=' + f.value : '')), f.why ? ' — ' + f.why : '')));
            $('#confirm-serial').textContent = token;
            const input = $('#confirm-input');
            const ok = $('#confirm-ok');
            ok.textContent = okLabel || 'Proceed';
            input.value = '';
            ok.disabled = true;
            const onInput = () => { ok.disabled = input.value.trim().toLowerCase() !== String(token).toLowerCase(); };
            input.addEventListener('input', onInput);
            const cleanup = (v) => { input.removeEventListener('input', onInput); dlg.close(); resolve(v); };
            ok.onclick = () => cleanup(true);
            $('#confirm-cancel').onclick = () => cleanup(false);
            dlg.oncancel = (e) => { e.preventDefault(); cleanup(false); };
            dlg.showModal();
            input.focus();
        });
    }

    // =====================================================================================
    // Server mode
    // =====================================================================================

    // probed: false until the first /api/status answer (or failure), so the page shows "checking"
    // instead of flashing "Server offline" while the first request is in flight.
    const srv = { status: null, probed: false, modules: [], viewSerial: null, jobLogHandle: null, jobLogId: null, need: null, deviceConnected: false, pollTimer: null, scenario: '', googleError: '' };
    const SCENARIOS = {
        open: 'Open: unsigned bootloader, clear image; nothing is written to OTP',
        secure: 'Secure: signed bootloader (program_pubkey), LUKS-encrypted image, OTP device key exported to the server',
    };
    /** Signed in to Google and the settings sheet read (true when the server has no Google wiring, e.g. tests). */
    const googleReady = () => !srv.status || srv.status.google_ready !== false;
    const checking = () => !srv.probed && location.protocol !== 'file:';
    const STEP_INFO = {
        1: { title: 'EEPROM & OTP', sub: 'recovery flashes the EEPROM and reports the board metadata; the board reboots into RPIBOOT' },
        2: { title: 'Fastboot gadget', sub: 'the bootloader loads the rpi-fastbootd ramdisk from the station' },
        3: { title: 'Image', sub: 'fastboot IDP: (secure) OTP device key exported to the server, partitions (+ LUKS2), sparse images, power off' },
    };
    const ICONS = { idle: '○', running: '◐', waiting: '◔', done: '✓', failed: '✗' };
    const steps = {};

    function buildSteps() {
        const box = $('#steps');
        box.replaceChildren();
        for (const n of [1, 2, 3]) {
            const s = {};
            s.root = el('div', { class: 'step state-idle' },
                s.icon = el('div', { class: 'step-icon' }, ICONS.idle),
                el('div', { class: 'step-body' },
                    el('div', { class: 'step-title' }, el('span', { class: 'step-n' }, String(n)), STEP_INFO[n].title,
                        s.stateLabel = el('span', { class: 'step-state' }, '')),
                    el('div', { class: 'step-sub' }, STEP_INFO[n].sub),
                    s.detail = el('div', { class: 'step-detail' }),
                    s.progWrap = el('div', { class: 'progress hidden' }, s.bar = el('div')),
                    s.progLabel = el('div', { class: 'progress-label hidden' }),
                    s.notes = el('ul', { class: 'step-notes hidden' })),
                s.run = el('button', { class: 'small step-run', onclick: () => runOne(n), title: `Run only stage ${n}` }, 'Run'));
            steps[n] = s;
            box.append(s.root);
        }
    }

    function setStep(n, state, detail, extra) {
        const s = steps[n];
        if (!s) return;
        s.root.className = 'step state-' + state;
        s.icon.textContent = ICONS[state] || '○';
        s.stateLabel.textContent = state === 'idle' ? '' : state;
        s.detail.textContent = detail || '';
        if (state === 'running' || state === 'waiting') { s.progWrap.classList.remove('hidden'); s.progLabel.classList.remove('hidden'); }
        if (state === 'done') { s.bar.style.width = '100%'; }
        if (state === 'idle') { s.progWrap.classList.add('hidden'); s.progLabel.classList.add('hidden'); s.bar.style.width = '0'; s.progLabel.textContent = ''; }
        const notes = (extra && extra.verdict && extra.verdict.notes) || [];
        s.notes.replaceChildren(...notes.map((t) => el('li', {}, t)));
        s.notes.classList.toggle('hidden', !notes.length);
        s.notes.classList.toggle('bad', !!(extra && extra.verdict && !extra.verdict.ok));
        if (extra && extra.job) selectJobLog(extra.job);
        updateButtons();
    }

    function setStepProgress(n, p) {
        const s = steps[n];
        if (!s) return;
        const pct = p.total ? Math.min(100, Math.round((p.sent / p.total) * 100)) : 0;
        s.progWrap.classList.remove('hidden');
        s.progLabel.classList.remove('hidden');
        s.bar.style.width = pct + '%';
        s.progLabel.textContent = p.total ? `${p.label || ''}  ${fmtBytes(p.sent)} / ${fmtBytes(p.total)} (${pct}%)` : (p.label || '');
    }

    const flow = new OTP.Flow({
        api,
        options: { scenario: () => currentScenario() },
        hooks: {
            onStage: (n, state, detail, extra) => setStep(n, state, detail, extra),
            onProgress: (n, p) => setStepProgress(n, p),
            onLog: (level, msg) => log(level, msg),
            onModule: (m) => { srv.viewSerial = m.serial; upsertModule(m); renderBoard(); renderRegistry(); renderScenario(); },
            onBusy: () => updateButtons(),
            onNeed: (kind, info) => showNeed(kind, info),
            onConfirm: (req) => confirmIrreversible(Object.assign({ okLabel: 'Proceed' }, req)),
            onBuildWait: (n, info) => { if (info.job) selectJobLog(info.job); },
            onDevice: (usb, kind) => { srv.deviceConnected = !!usb; renderDeviceBadge(usb, kind); updateButtons(); },
        },
    });

    function renderDeviceBadge(usb, kind) {
        const b = $('#board-device');
        if (!usb) {
            b.className = 'badge' + (flow.module ? ' warn' : '');
            b.textContent = flow.module ? 'disconnected' : 'no board';
            return;
        }
        b.className = 'badge ok';
        const p = flow.probeInfo;
        b.textContent = kind === 'fastboot' ? 'fastboot gadget' : p && p.rom === false ? 'RPIBOOT · 2nd stage' : 'RPIBOOT';
    }

    function showNeed(kind, info) {
        srv.need = kind;
        const box = $('#need-box');
        $('#btn-connect-fastboot').classList.toggle('hidden', kind !== 'fastboot');
        $('#btn-select-device').classList.toggle('hidden', kind !== 'rpiboot');
        if (!kind) { box.classList.add('hidden'); box.replaceChildren(); return; }
        const drv = srv.status && srv.status.usb_driver;
        fill(box,
            kind === 'fastboot'
                ? el('div', {}, el('b', {}, 'The board is booting the fastboot gadget. '), 'Click ', el('b', {}, 'Connect fastboot gadget'),
                    ' and pick ', el('i', {}, 'Raspberry Pi …'), ' (USB 18d1:4e40) in Chrome\'s list. It appears about 20 s after stage 2; the list updates live.')
                : el('div', {}, el('b', {}, 'Chrome needs permission for the re-enumerated board. '), 'Click ', el('b', {}, 'Select device…'),
                    ' and pick ', el('i', {}, 'BCM2712 Boot'), '.'),
            kind === 'fastboot' && drv && drv.platform === 'windows' && drv.fastboot === false
                ? el('div', { class: 'warn-text' }, 'Windows has no WinUSB driver bound to 18d1:4e40 yet, so Chrome cannot open the gadget. ', drv.detail || '')
                : null);
        box.classList.remove('hidden');
        log('info', kind === 'fastboot' ? 'Action needed: click "Connect fastboot gadget"' : 'Action needed: click "Select device…"');
    }

    function updateButtons() {
        const running = flow.running;
        const online = api.available;
        const ready = online && googleReady();
        $('#btn-connect').disabled = running || !ready || !navigator.usb;
        $('#btn-abort').disabled = !running;
        const plan = flow.plan();
        const connected = !!flow.module && srv.deviceConnected;
        $('#btn-provision').disabled = running || !ready || !flow.module || !plan.length;
        for (const n of [1, 2, 3]) if (steps[n]) steps[n].run.disabled = running || !ready || !flow.module;
        for (const r of document.querySelectorAll('#scenario input')) r.disabled = running || (r.value === 'open' && !!(flow.module && flow.module.mode_locked));
        let hint = '';
        if (checking()) hint = 'checking the server…';
        else if (!online) hint = 'server offline: start it with "uv run server.py"';
        else if (!googleReady()) hint = 'sign in to Google first';
        else if (!flow.module) hint = 'connect a board first';
        else if (running) hint = `provisioning ${flow.serial}…`;
        else if (!plan.length) hint = `board ${flow.serial} is fully provisioned (${(flow.module && flow.module.mode) || ''} scenario)`;
        else hint = `will run stage${plan.length > 1 ? 's' : ''} ${plan.join(' → ')} · ${currentScenario()} scenario${flow.scenarioChanges() ? ' (switching: every stage is redone)' : ''}${connected ? '' : ' (connect the board first)'}`;
        $('#provision-hint').textContent = hint;
    }

    async function connectBoard() {
        $('#board-status').textContent = '';
        try {
            const m = await flow.connectBoard();
            if (!m) return;
            $('#board-status').textContent = '';
        } catch (e) {
            const msg = e.name === 'ApiError' ? `server: ${e.detail || e.message}` : e.message || String(e);
            $('#board-status').textContent = msg;
            log('error', `Connect board: ${msg}${/claim|access|busy/i.test(msg) ? ' — is rpiboot.exe or another tab holding the device?' : ''}`);
        }
        updateButtons();
    }

    async function provisionAll() {
        try { await flow.provision(); } catch (e) { log('error', e.message || String(e)); }
        refreshModules();
        updateButtons();
    }

    async function runOne(n) {
        if (!flow.module) return;
        try { await flow.runStage(n); } catch (e) { log('error', e.message || String(e)); }
        refreshModules();
        updateButtons();
    }

    $('#btn-connect').addEventListener('click', connectBoard);
    $('#btn-provision').addEventListener('click', provisionAll);
    $('#btn-abort').addEventListener('click', () => flow.abort());
    $('#btn-connect-fastboot').addEventListener('click', () => flow.connectFastboot().catch((e) => log('error', `Connect fastboot gadget: ${e.message || e}`)));
    $('#btn-select-device').addEventListener('click', () => flow.selectDevice().catch((e) => log('error', `Select device: ${e.message || e}`)));

    // ---------- board card ----------
    function upsertModule(m) {
        const i = srv.modules.findIndex((x) => x.serial === m.serial);
        if (i >= 0) srv.modules[i] = m; else srv.modules.unshift(m);
    }

    function kv(label, value, cls) { return [el('dt', {}, label), el('dd', { class: cls || '' }, value === undefined || value === null || value === '' ? '—' : value)]; }

    function renderBoard() {
        const box = $('#board-detail');
        const serial = srv.viewSerial;
        const m = serial ? (flow.module && flow.module.serial === serial ? flow.module : srv.modules.find((x) => x.serial === serial)) : null;
        if (!m) {
            box.replaceChildren(el('p', { class: 'muted' }, checking() ? 'Checking the server…' : api.available
                ? 'No board connected. Put the board into RPIBOOT mode (hold the power button while connecting USB-C) and click Connect board.'
                : 'The server is not reachable, so boards cannot be provisioned from here. Start it with "uv run server.py" and reload.'));
            return;
        }
        const live = flow.module && flow.module.serial === m.serial;
        const sec = m.secrets || {};
        const otp = m.otp || {};
        const otpText = otp.locked ? (otp.locked_to_our_key ? 'locked to this board\'s key' : 'LOCKED TO A DIFFERENT KEY')
            : otp.lock_suspected ? `probably locked to this board's key (not confirmed yet: ${otp.lock_note || 'see events'})`
                : 'not locked (OTP key hash empty)';
        const modeText = m.mode ? `${m.mode}${m.mode_chosen ? '' : ' (default)'}${m.mode_locked ? ' · OTP locked: secure only' : ''}` : '';
        const events = (m.events || []).slice(-8).reverse();
        fill(box,
            el('div', { class: 'serial-big' }, m.serial),
            el('div', { class: 'board-line' },
                el('span', { class: 'stage-pill stage-' + m.stage }, m.stage_label || m.stage),
                el('span', { class: 'muted' }, [m.chip, m.board].filter(Boolean).join(' · ')),
                live ? null : el('span', { class: 'badge' }, 'viewing record')),
            el('dl', { class: 'kv' },
                kv('Scenario', modeText),
                kv('Key hash', sec.customer_key_hash ? el('span', { title: sec.customer_key_hash }, shortHex(sec.customer_key_hash, 24)) : '—', 'mono'),
                kv('Signing key', sec.rsa_key ? `RSA-2048 ✓ ${sec.rsa_key_fingerprint ? '· ' + shortHex(sec.rsa_key_fingerprint, 16) : ''}` : 'not generated'),
                kv('Device secret', sec.device_secret ? '✓ stored' : '—'),
                kv('OTP', otpText, otp.locked && !otp.locked_to_our_key ? 'bad' : ''),
                kv('Secure boot', otp.secure_boot_provisioned ? 'provisioned' : 'not provisioned'),
                kv('Device key', otp.device_key ? el('span', { title: otp.device_key_fingerprint || '' }, 'ECDSA ✓ ' + shortHex(otp.device_key_fingerprint, 16) + (otp.device_key_exported ? ' · private key on the server' : '')) : '—', 'mono'),
                kv('DUID', m.duid, 'mono'),
                kv('MAC', m.mac, 'mono'),
                kv('Board rev', m.boardrev, 'mono'),
                kv('Updated', fmtTime(m.updated))),
            renderImager(m),
            events.length ? el('div', { class: 'events' },
                el('h3', {}, 'Events'),
                el('ul', {}, ...events.map((ev) => el('li', { class: /fail/i.test(ev.note) ? 'bad' : '' },
                    el('span', { class: 'muted mono' }, fmtTime(ev.t).slice(5)), ' ', el('b', {}, ev.kind), ' ', ev.note || '')))) : null,
        );
    }

    // ---------- the image file for Raspberry Pi Imager (board card, a board locked to its key) ----------
    // One element kept across renderBoard() calls (every poll), rebuilt only when what it shows changes, so the
    // source list keeps its state while the operator uses it.
    const imager = { box: el('div', { class: 'imager hidden' }), serial: null, source: null, busy: false, result: null, reason: '', error: '', sig: '' };
    const customList = () => (srv.status && srv.status.custom_images) || [];
    const scenarioName = (variant) => (variant === 'clear' ? 'open' : 'secure');

    /** null: not a board for an image file (section hidden); '' ready; else what is missing. */
    function imagerBlocker(m) {
        const otp = m.otp || {};
        if (!otp.locked_to_our_key) return null;
        const cid = ((m.facts || {}).fastboot || {})['mmc-cid'] || '';
        if (!otp.device_key_exported || !cid) {
            return 'Run stage 3 once in the secure scenario first: it exports the board\'s OTP device key and records its SD card, and the image file is keyed to both.';
        }
        return '';
    }

    function renderImager(m) {
        const why = imagerBlocker(m);
        if (why === null) { imager.box.classList.add('hidden'); return imager.box; }
        imager.box.classList.remove('hidden');
        if (imager.serial !== m.serial) {
            Object.assign(imager, { serial: m.serial, source: null, busy: false, result: null, reason: '', error: '', sig: '' });
        }
        if (imager.source === null) imager.source = (img.loaded && img.loaded.custom) || '';
        const opts = [['', 'Station image (Raspberry Pi OS Lite)'],
            ...customList().map((c) => [c.id, `Custom: ${c.name}${(c.variants && c.variants.crypt && c.variants.crypt.ready) ? '' : ' (not prepared for the secure scenario)'}`])];
        if (!opts.some(([v]) => v === imager.source)) opts.push([imager.source, `${imager.source} (not on this station)`]);
        const r = imager.result;
        const sig = JSON.stringify([m.serial, why, opts, imager.source, imager.busy, r && r.name, imager.reason, imager.error]);
        if (sig === imager.sig) return imager.box;
        imager.sig = sig;
        const select = el('select', { disabled: !!why || imager.busy, onchange: (e) => { imager.source = e.target.value; imager.result = null; imager.error = ''; renderBoard(); } },
            ...opts.map(([v, t]) => el('option', { value: v }, t)));
        select.value = imager.source;
        fill(imager.box,
            el('h3', {}, 'Image file for Raspberry Pi Imager'),
            el('p', { class: 'hint' }, 'This board\'s signed boot partition and its root file system encrypted with its OTP key, as one .img for its own SD card: write it with Raspberry Pi Imager in a card reader (Choose OS → Use custom; no OS customisation).'),
            why ? el('p', { class: 'hint bad' }, why) : null,
            el('div', { class: 'row' }, select,
                el('button', { class: 'small' + (r ? '' : ' primary'), disabled: !!why || imager.busy, onclick: prepareImager }, imager.busy ? 'Preparing…' : r ? 'Prepare again' : 'Prepare'),
                r ? el('button', { class: 'primary', onclick: () => downloadImager(r) }, `Download ${r.name} (${fmtBytes(r.size)})`) : null),
            imager.reason ? el('div', { class: 'hint' }, imager.reason) : null,
            imager.error ? el('div', { class: 'hint bad' }, imager.error) : null,
            r && r.notes && r.notes.length ? el('ul', {}, ...r.notes.map((n) => el('li', {}, n))) : null);
        return imager.box;
    }

    /** Ask the server for the image file; while a part is being built (409 + job), follow the job and ask again. */
    async function prepareImager() {
        const serial = imager.serial;
        if (!serial || imager.busy) return;
        Object.assign(imager, { busy: true, result: null, reason: '', error: '' });
        renderBoard();
        try {
            for (;;) {
                const r = await api.imagerImage(serial, imager.source);
                if (imager.serial !== serial) return;
                if (r.ready) {
                    imager.result = r;
                    log('ok', `Image file for ${serial}: ${r.name} (${fmtBytes(r.size)}) is ready to download`);
                    break;
                }
                if (r.job) selectJobLog(r.job);
                const waiting = r.job && (r.job.status === 'queued' || r.job.status === 'running');
                if (!waiting) { imager.error = r.reason || 'the server could not prepare the image file'; break; }
                imager.reason = `${r.reason || 'being prepared'}…`;
                renderBoard();
                await sleep(3000);
            }
        } catch (e) {
            imager.error = e.detail || e.message || String(e);
            log('error', `Image file for ${serial}: ${imager.error}`);
        } finally {
            imager.busy = false;
            imager.reason = '';
            renderBoard();
        }
    }

    function downloadImager(r) {
        const a = el('a', { href: r.url, download: r.name });
        document.body.append(a);
        a.click();
        a.remove();
        log('info', `Downloading ${r.name} (${fmtBytes(r.size)}): the browser saves it to its download folder`);
    }

    // ---------- registry ----------
    function renderRegistry() {
        const tbody = $('#registry-table tbody');
        const rows = srv.modules.slice().sort((a, b) => String(b.updated || '').localeCompare(String(a.updated || '')));
        tbody.replaceChildren();
        if (!api.available) { tbody.append(el('tr', {}, el('td', { colspan: 3, class: 'muted' }, checking() ? 'loading…' : 'server offline'))); return; }
        if (!rows.length) { tbody.append(el('tr', {}, el('td', { colspan: 3, class: 'muted' }, 'no boards yet'))); return; }
        for (const m of rows) {
            tbody.append(el('tr', { class: 'clickable' + (m.serial === srv.viewSerial ? ' selected' : ''), onclick: () => { srv.viewSerial = m.serial; renderBoard(); renderRegistry(); } },
                el('td', { class: 'mono' }, m.serial),
                el('td', {}, el('span', { class: 'stage-pill stage-' + m.stage }, m.stage_label || m.stage)),
                el('td', { class: 'muted' }, fmtTime(m.updated).slice(5, 16))));
        }
    }

    async function refreshModules() {
        if (!api.available) return;
        try {
            srv.modules = await api.modules();
            if (flow.module) upsertModule(flow.module);
            renderRegistry();
            renderBoard();
        } catch (e) { log('debug', `modules: ${e.message}`); }
    }
    $('#btn-registry-refresh').addEventListener('click', refreshModules);

    // ---------- OS image settings (image.* in the settings sheet) ----------
    const imageForm = $('#image-form');
    const IMAGE_TEXT = ['name', 'custom', 'hostname', 'timezone', 'keyboard', 'user', 'wifi_ssid', 'wifi_country'];
    const IMAGE_BOOL = ['ssh', 'ssh_password_login', 'wifi_hidden'];
    const IMAGE_SECRETS = ['password', 'wifi_password'];
    const img = { loaded: null, warnings: [], remove: { password: false, wifi_password: false }, saving: false, loading: false, choicesKey: '', customKey: '' };
    /** image.packages / image.apps as the operator is editing them (``draft``), the sandbox previews shown, the upload. */
    const pkgs = { draft: null, preview: {}, upload: null, kind: 'app', key: '' };
    const imageInput = (name) => imageForm.elements.namedItem(name);
    const imageKeys = () => imageInput('ssh_authorized_keys').value.split('\n').map((x) => x.trim()).filter(Boolean);

    /** What differs from the loaded settings: only these fields are sent ("" for a removed password). */
    function imageChanges() {
        const s = img.loaded;
        if (!s) return {};
        const out = {};
        for (const k of IMAGE_TEXT) {
            let v = imageInput(k).value.trim();
            if (k === 'wifi_country') v = v.toUpperCase();
            if (v !== String(s[k] || '')) out[k] = v;
        }
        for (const k of IMAGE_BOOL) if (imageInput(k).checked !== !!s[k]) out[k] = imageInput(k).checked;
        const keys = imageKeys();
        if (keys.join('\n') !== (s.ssh_authorized_keys || []).join('\n')) out.ssh_authorized_keys = keys;
        for (const k of IMAGE_SECRETS) {
            const v = imageInput(k).value;
            if (v) out[k] = v;
            else if (img.remove[k]) out[k] = '';
        }
        if (pkgs.draft) {
            const d = draftLines();
            if (d.packages.join('\n') !== (s.packages || []).join('\n')) out.packages = d.packages;
            if (d.apps.join('\n') !== (s.apps || []).join('\n')) out.apps = d.apps;
        }
        return out;
    }

    /** Current UTC offset of an IANA zone as "UTC+03:00" ("" when the browser does not know the zone). */
    function tzOffset(tz) {
        try {
            const part = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'longOffset' })
                .formatToParts(new Date()).find((x) => x.type === 'timeZoneName');
            return part ? part.value.replace(/^GMT/, 'UTC') : '';
        } catch (e) { return ''; }
    }

    /** The time zone, Wi-Fi country and keyboard lists (the image's tzdata, wireless-regdb, xkb-data, from the server). */
    function fillImageChoices(choices) {
        const tzs = (choices && choices.timezones) || [];
        const countries = (choices && choices.countries) || [];
        const keyboards = (choices && choices.keyboards) || [];
        const key = `${tzs.length}:${tzs[0] || ''}:${countries.length}:${keyboards.length}`;
        if (key === img.choicesKey) return;
        img.choicesKey = key;
        const groups = new Map();
        const loose = [];
        for (const tz of tzs) {
            const i = tz.indexOf('/');
            const off = tzOffset(tz);
            if (i < 0) { loose.push(el('option', { value: tz }, off && tz !== 'UTC' ? `${tz} (${off})` : tz)); continue; }
            const region = tz.slice(0, i);
            const label = tz.slice(i + 1).replace(/_/g, ' ');
            if (!groups.has(region)) groups.set(region, []);
            groups.get(region).push({ tz, text: off ? `${label} (${off})` : label, sort: label });
        }
        const optgroups = [...groups.keys()].sort().map((region) => el('optgroup', { label: region },
            ...groups.get(region).sort((a, b) => a.sort.localeCompare(b.sort)).map((o) => el('option', { value: o.tz }, o.text))));
        imageInput('timezone').replaceChildren(...loose, ...optgroups);
        const world = countries.filter(([code]) => code === '00');
        const named = countries.filter(([code]) => code !== '00').sort((a, b) => a[1].localeCompare(b[1]));
        imageInput('wifi_country').replaceChildren(...[...world, ...named].map(([code, name]) => el('option', { value: code }, `${name} (${code})`)));
        imageInput('keyboard').replaceChildren(...[...keyboards].sort((a, b) => a[1].localeCompare(b[1]))
            .map(([code, name]) => el('option', { value: code }, `${name} (${code})`)));
    }

    /** Select ``value``; a value the list lacks (typed into the sheet by hand) stays selectable, marked as such. */
    function setImageSelect(select, value) {
        for (const o of select.querySelectorAll('option[data-extra]')) o.remove();
        if (value && ![...select.options].some((o) => o.value === value)) {
            select.prepend(el('option', { value, 'data-extra': '1' }, `${value} (current value, not in the list)`));
        }
        select.value = value || '';
    }

    function setImageStatus(text, bad) {
        const box = $('#image-status');
        box.textContent = text || '';
        box.classList.toggle('bad', !!bad);
    }

    function renderImagePanel() {
        const s = img.loaded;
        const usable = !!s && api.available && googleReady();
        for (const field of imageForm.elements) if (!field.dataset.own) field.disabled = !usable || img.saving;
        if (usable && !img.saving) {
            const ssh = imageInput('ssh').checked;
            imageInput('ssh_password_login').disabled = !ssh;
            imageInput('ssh_authorized_keys').disabled = !ssh;
        }
        const set = { password: !!(s && s.password_set), wifi_password: !!(s && s.wifi_password_set) };
        imageInput('password').placeholder = img.remove.password ? 'will be removed'
            : set.password ? 'set: type to change' : 'none';
        imageInput('wifi_password').placeholder = img.remove.wifi_password ? 'will be removed (open network)'
            : set.wifi_password ? 'saved: type to change' : 'none (open network)';
        for (const b of imageForm.querySelectorAll('button[data-remove]')) {
            const k = b.dataset.remove;
            b.textContent = img.remove[k] ? 'keep' : 'remove';
            b.disabled = !usable || img.saving || (!set[k] && !img.remove[k]);
        }
        const dirty = Object.keys(imageChanges()).length > 0;
        $('#btn-image-save').disabled = !usable || img.saving || !dirty;
        $('#btn-image-revert').disabled = !usable || img.saving || !dirty;
        $('#image-warnings').replaceChildren(...img.warnings.map((w) => el('li', {}, w)));
        const chosen = customList().find((c) => c.id === imageInput('custom').value);
        $('#custom-note').textContent = !imageInput('custom').value ? ''
            : !chosen ? 'This image is not on this station: upload it again, or choose another one.'
                : chosen.cloud_init === false ? `${chosen.name} has no cloud-init: the settings below are not written to it; boards boot with the configuration the image was made with.`
                    : '';
        $('#btn-custom-upload').disabled = !usable || !!upload.handle;
        $('#btn-system-upload').disabled = !usable || !!pkgs.upload;
        $('#btn-app-upload').disabled = !usable || !!pkgs.upload;
        if (!s && !img.loading && !(api.available && googleReady())) setImageStatus('Available once the server is running and signed in to Google.');
    }

    function fillImageForm(view) {
        const s = view.settings || {};
        img.loaded = s;
        img.warnings = view.warnings || [];
        img.remove = { password: false, wifi_password: false };
        resetPackagesDraft(s);
        if (view.choices) fillImageChoices(view.choices);
        fillCustomSelect(true);
        for (const k of IMAGE_TEXT) {
            const f = imageInput(k);
            if (f.tagName === 'SELECT') setImageSelect(f, s[k] || '');
            else f.value = s[k] || '';
        }
        for (const k of IMAGE_BOOL) imageInput(k).checked = !!s[k];
        imageInput('ssh_authorized_keys').value = (s.ssh_authorized_keys || []).join('\n');
        for (const k of IMAGE_SECRETS) { imageInput(k).value = ''; imageInput(k).type = 'password'; }
        for (const b of imageForm.querySelectorAll('button[data-show]')) b.textContent = 'show';
        renderPackages();
        renderImagePanel();
    }

    async function loadImageSettings() {
        if (img.loading || !api.available || !googleReady()) return;
        img.loading = true;
        try {
            fillImageForm(await api.imageSettings());
            setImageStatus('');
        } catch (e) {
            setImageStatus(`Image settings: ${e.detail || e.message}`, true);
        } finally {
            img.loading = false;
            renderImagePanel();
        }
    }

    async function saveImageSettings() {
        const body = imageChanges();
        if (!Object.keys(body).length) return;
        img.saving = true;
        setImageStatus('Saving…');
        renderImagePanel();
        try {
            const r = await api.saveImageSettings(body);
            img.saving = false;
            fillImageForm(r);
            const names = (r.saved || []).map((k) => k.replace(/^image\./, '')).join(', ');
            const builds = srv.status && srv.status.config && srv.status.config.builds;
            const auto = !builds || builds.auto !== false;
            const renamed = (r.saved || []).some((k) => ['image.name', 'image.packages', 'image.apps'].includes(k));
            const source = (r.saved || []).includes('image.custom');
            const chosen = customList().find((c) => c.id === (r.settings && r.settings.custom));
            setImageStatus(`Saved: ${names}. ` + (source ? (chosen ? `Stage 3 now writes ${chosen.name}${chosen.ready ? '' : ' once it is prepared'}. ` : 'Stage 3 now writes the station image. ') : '')
                + (!renamed ? 'Boards flashed from now on get them at stage 3 (no rebuild).'
                    : auto ? 'The image changed (its name or its packages): the server rebuilds both images now, preparing apps that are not prepared yet first; stage 3 waits for them.'
                        : 'The image changed (its name or its packages): start the OS image build under Server builds (automatic builds are off).'));
            log('ok', `OS image settings saved: ${names}`);
            refreshStatus();
        } catch (e) {
            setImageStatus(`Not saved: ${e.detail || e.message}`, true);
        } finally {
            img.saving = false;
            renderImagePanel();
        }
    }

    imageForm.addEventListener('submit', (ev) => { ev.preventDefault(); saveImageSettings(); });
    imageForm.addEventListener('input', (ev) => {
        if (IMAGE_SECRETS.includes(ev.target.name) && ev.target.value) img.remove[ev.target.name] = false;
        renderImagePanel();
    });
    imageForm.addEventListener('change', () => renderImagePanel());
    for (const b of imageForm.querySelectorAll('button[data-show]')) {
        b.addEventListener('click', () => {
            const f = imageInput(b.dataset.show);
            f.type = f.type === 'password' ? 'text' : 'password';
            b.textContent = f.type === 'password' ? 'show' : 'hide';
        });
    }
    for (const b of imageForm.querySelectorAll('button[data-remove]')) {
        b.addEventListener('click', () => {
            const k = b.dataset.remove;
            img.remove[k] = !img.remove[k];
            if (img.remove[k]) imageInput(k).value = '';
            renderImagePanel();
        });
    }
    $('#btn-image-save').addEventListener('click', saveImageSettings);

    // ---------- custom OS images (the Source of the OS image panel) ----------
    const upload = { handle: null };

    /** The Image list: the station image and every uploaded image; keeps the operator's choice unless ``reset``. */
    function fillCustomSelect(reset) {
        const sel = imageInput('custom');
        const list = customList();
        const key = JSON.stringify(list.map((c) => [c.id, c.name, c.size, c.os && c.os.pretty_name]));
        if (key === img.customKey && !reset) return;
        const keep = sel.options.length ? sel.value : ((img.loaded && img.loaded.custom) || '');
        img.customKey = key;
        sel.replaceChildren(el('option', { value: '' }, 'Station image: Raspberry Pi OS Lite (built here)'),
            ...list.map((c) => el('option', { value: c.id }, `Custom: ${c.name} · ${fmtBytes(c.size)}${c.os && c.os.pretty_name ? ' · ' + c.os.pretty_name : ''}`)));
        if (!reset) setImageSelect(sel, keep);
    }

    function renderCustomImages() {
        fillCustomSelect(false);
        const usable = api.available && googleReady();
        $('#custom-images').replaceChildren(...customList().map((c) => {
            const job = c.job;
            const active = !!job && (job.status === 'queued' || job.status === 'running');
            const v = c.variants || {};
            const errors = active ? [] : ['clear', 'crypt'].filter((k) => v[k] && v[k].error).map((k) => `${scenarioName(k)}: ${v[k].error}`);
            const state = active ? 'preparing' : c.ready ? 'ready' : errors.length ? 'failed' : 'not prepared';
            const own = { 'data-own': '1', type: 'button' };
            return el('div', { class: 'custom-row' + (c.selected ? ' selected' : '') },
                el('div', { class: 'custom-main' },
                    el('div', { class: 'custom-title' }, c.name, badge(state, active ? 'warn' : c.ready ? 'ok' : 'err'), c.selected ? badge('stage 3 writes it', 'ok') : null),
                    el('div', { class: 'custom-meta mono', title: `sha256 ${c.sha256 || ''}` }, [fmtBytes(c.size), c.os && c.os.pretty_name,
                        c.cloud_init === true ? 'cloud-init' : c.cloud_init === false ? 'no cloud-init' : '', `uploaded ${fmtTime(c.uploaded)}`].filter(Boolean).join(' · ')),
                    el('div', { class: 'custom-detail' }, ['clear', 'crypt'].map((k) => `${scenarioName(k)} ${v[k] && v[k].ready ? '✓' : active ? '…' : '✗'}`).join(' · ')),
                    ...errors.map((t) => el('div', { class: 'custom-detail bad' }, t))),
                el('div', { class: 'custom-actions' },
                    job ? el('button', Object.assign({ class: 'small', onclick: () => selectJobLog(job, true) }, own), 'Log') : null,
                    el('button', Object.assign({ class: 'small', disabled: !usable || active, onclick: () => prepareCustom(c) }, own), c.ready ? 'Prepare again' : 'Prepare'),
                    el('button', Object.assign({ class: 'small danger-outline', disabled: !usable || active || c.selected, title: c.selected ? 'Stage 3 writes this image: choose another one and save first' : 'Remove the image and what was prepared from it from the station', onclick: () => deleteCustom(c) }, own), 'Delete')));
        }));
        renderImagePanel();
    }

    async function uploadCustom(file) {
        if (upload.handle) return;
        const bar = $('#custom-upload-progress');
        const status = $('#custom-upload-status');
        bar.classList.remove('hidden');
        bar.firstElementChild.style.width = '0';
        $('#btn-custom-cancel').classList.remove('hidden');
        log('info', `Uploading ${file.name} (${fmtBytes(file.size)}) to the station…`);
        upload.handle = api.uploadCustomImage(file, (sent, total) => {
            const pct = total ? Math.min(100, Math.round((100 * sent) / total)) : 0;
            bar.firstElementChild.style.width = pct + '%';
            status.textContent = `${file.name}: ${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%)`;
        });
        renderImagePanel();
        try {
            const r = await upload.handle.promise;
            status.textContent = r.new
                ? `${r.image.name} uploaded: the station now prepares it for both scenarios (the secure one installs packages inside the image: several minutes). Choose it above and save to use it.`
                : `${r.image.name} is already on the station.`;
            log('ok', `Custom image ${r.image.name} (${r.image.id}) ${r.new ? 'uploaded' : 'was uploaded before'}`);
            if (r.job) selectJobLog(r.job, true);
            await refreshStatus();
        } catch (e) {
            status.textContent = `Upload failed: ${e.detail || e.message}`;
            log('error', `Upload of ${file.name}: ${e.detail || e.message}`);
        } finally {
            upload.handle = null;
            bar.classList.add('hidden');
            $('#btn-custom-cancel').classList.add('hidden');
            renderImagePanel();
        }
    }

    async function prepareCustom(c) {
        try {
            const r = await api.prepareCustomImage(c.id, !!c.ready);
            log('info', `Prepare custom image ${c.name}: job ${r.job.id} ${r.job.status}`);
            selectJobLog(r.job, true);
        } catch (e) {
            log('error', `Prepare custom image ${c.name}: ${e.detail || e.message}`);
        }
        refreshStatus();
    }

    async function deleteCustom(c) {
        if (!window.confirm(`Remove ${c.name} and everything prepared from it from the station?`)) return;
        try {
            await api.deleteCustomImage(c.id);
            log('ok', `Custom image ${c.name} removed from the station`);
        } catch (e) {
            log('error', `Delete custom image ${c.name}: ${e.detail || e.message}`);
        }
        refreshStatus();
    }

    $('#btn-custom-upload').addEventListener('click', () => $('#custom-file').click());
    $('#custom-file').addEventListener('change', (e) => {
        const f = e.target.files && e.target.files[0];
        e.target.value = '';
        if (f) uploadCustom(f);
    });
    $('#btn-custom-cancel').addEventListener('click', () => { if (upload.handle) upload.handle.abort(); });

    // ---------- packages for the station image: system packages and sandboxed apps ----------
    const APP_DEFAULTS = { memory_mb: 256, cpus: 1, tasks: 512 };
    const APP_LIMITS = { memory_mb: [32, 8192, 1], cpus: [0.05, 4, 0.05], tasks: [16, 8192, 1] };
    const pkgStatus = () => (srv.status && srv.status.packages) || null;
    const pkgList = () => (pkgStatus() && pkgStatus().packages) || [];

    /** An image.apps line (the server checked it when it was saved) -> {id, slot, grant, memory_mb, cpus, tasks}. */
    function parseAppLine(line) {
        const [id, ...words] = String(line).trim().split(/\s+/);
        const e = { id, slot: 0, grant: [], ...APP_DEFAULTS };
        for (const w of words) {
            const i = w.indexOf('=');
            const k = w.slice(0, i);
            const v = w.slice(i + 1);
            if (k === 'slot') e.slot = Number(v);
            else if (k === 'grant') e.grant = v.split(',').filter(Boolean);
            else if (k === 'memory') e.memory_mb = Number(v);
            else if (k === 'cpus') e.cpus = Number(v);
            else if (k === 'tasks') e.tasks = Number(v);
        }
        return e;
    }

    /** The line the server writes for an entry (otp_server.imageconfig.format_app_line). */
    function formatAppLine(e) {
        const words = [e.id, `slot=${e.slot}`];
        if (e.grant.length) words.push('grant=' + [...e.grant].sort().join(','));
        if (e.memory_mb !== APP_DEFAULTS.memory_mb) words.push(`memory=${e.memory_mb}`);
        if (e.cpus !== APP_DEFAULTS.cpus) words.push(`cpus=${e.cpus}`);
        if (e.tasks !== APP_DEFAULTS.tasks) words.push(`tasks=${e.tasks}`);
        return words.join(' ');
    }

    function resetPackagesDraft(s) {
        pkgs.draft = { packages: [...((s && s.packages) || [])], apps: ((s && s.apps) || []).map(parseAppLine) };
        pkgs.key = '';
    }

    function draftLines() {
        const d = pkgs.draft || { packages: [], apps: [] };
        return { packages: [...d.packages], apps: d.apps.map(formatAppLine) };
    }

    /** Permissions the system packages of the draft declare: {name: {description, provider, calls}}. */
    function offeredPermissions() {
        const d = pkgs.draft || { packages: [] };
        const out = {};
        for (const p of pkgList()) {
            if (p.kind !== 'system' || !d.packages.includes(p.id)) continue;
            for (const [name, perm] of Object.entries(p.permissions || {})) {
                out[name] = { description: perm.description || '', provider: p.deb.package,
                    calls: (perm.calls || []).map((c) => `${c.interface}.${c.method}`) };
            }
        }
        return out;
    }

    const appEntry = (id) => ((pkgs.draft && pkgs.draft.apps) || []).find((a) => a.id === id) || null;

    function freeSlot() {
        const taken = new Set(((pkgs.draft && pkgs.draft.apps) || []).map((a) => a.slot));
        for (let s = 1; s <= 64; s++) if (!taken.has(s)) return s;
        return 0;
    }

    function setInImage(p, on) {
        const d = pkgs.draft;
        if (!d) return;
        if (p.kind === 'system') {
            d.packages = d.packages.filter((x) => x !== p.id);
            if (on) d.packages.push(p.id);
        } else if (!on) {
            d.apps = d.apps.filter((a) => a.id !== p.id);
        } else if (!appEntry(p.id)) {
            const slot = freeSlot();
            if (!slot) { log('error', 'All 64 app slots are taken'); return; }
            d.apps.push({ id: p.id, slot, grant: [], ...APP_DEFAULTS });
        }
    }

    function appState(p) {
        const job = p.job;
        const active = !!job && (job.status === 'queued' || job.status === 'running');
        if (active) return ['preparing', 'warn', active];
        if (p.prepared) return ['prepared', 'ok', false];
        return [p.error ? 'failed' : 'not prepared', 'err', false];
    }

    function packageRow(p, usable, offered) {
        const deb = p.deb || {};
        const own = { 'data-own': '1', type: 'button' };
        const entry = p.kind === 'app' ? appEntry(p.id) : null;
        const inImage = p.kind === 'system' ? pkgs.draft.packages.includes(p.id) : !!entry;
        const [state, tone, active] = p.kind === 'app' ? appState(p) : ['system · runs as root', 'warn', false];
        const title = el('div', { class: 'custom-title' }, `${deb.package} ${deb.version}`, badge(state, tone),
            inImage ? badge('in the image', 'ok') : null);
        const meta = el('div', { class: 'custom-meta mono', title: `sha256 ${p.sha256 || ''}` },
            [p.name, fmtBytes(p.size), deb.architecture, `uploaded ${fmtTime(p.uploaded)}`].filter(Boolean).join(' · '));
        const main = el('div', { class: 'custom-main' }, title, meta, el('div', { class: 'custom-detail' }, deb.summary || ''));
        if (p.kind === 'system') {
            const names = Object.keys(p.permissions || {}).sort();
            main.append(el('div', { class: 'custom-detail' }, names.length ? `Permissions it offers to apps: ${names.join(', ')}` : 'Offers no permissions to apps'));
        } else {
            if (deb.depends) main.append(el('div', { class: 'custom-detail mono' }, `Depends: ${deb.depends}`));
            if (p.prepared) {
                const rep = (p.prepared.rootfs && p.prepared.rootfs.report) || {};
                main.append(el('div', { class: 'custom-detail' }, `Root file system: ${p.prepared.base.packages} Debian packages, ${rep.members} files, ${fmtBytes(p.prepared.rootfs.size)}; installed in the VM in ${p.prepared.install.seconds} s`));
            }
            if (p.error && !active) main.append(el('div', { class: 'custom-detail bad' }, p.error));
            if (entry) main.append(appGrants(p, entry, offered), appLimits(entry));
        }
        const preview = pkgs.preview[p.id];
        if (preview) {
            main.append(el('details', { class: 'sandbox-files', open: true },
                el('summary', {}, `Sandbox on the board: slot ${preview.app.slot}, host UIDs ${preview.app.uids[0]}–${preview.app.uids[1]}${preview.in_image ? '' : ' (not in the image yet: no permissions)'}`),
                ...Object.entries(preview.files).map(([path, text]) => el('div', {},
                    el('div', { class: 'mono sandbox-path' }, '/' + path), el('pre', { class: 'mono' }, text)))));
        }
        const check = el('input', { type: 'checkbox', 'data-in-image': p.id });
        check.checked = inImage;
        const actions = el('div', { class: 'custom-actions' },
            el('label', { class: 'check', title: p.kind === 'system' ? 'Install it into the station image (as root)' : 'Build it into the station image, sandboxed' }, check, ' in the image'));
        if (p.kind === 'app') {
            if (p.job) actions.append(el('button', Object.assign({ class: 'small', onclick: () => selectJobLog(p.job, true) }, own), 'Log'));
            actions.append(el('button', Object.assign({ class: 'small', disabled: !usable || active, onclick: () => preparePackage(p) }, own), p.prepared ? 'Prepare again' : 'Prepare'),
                el('button', Object.assign({ class: 'small', disabled: !usable, onclick: () => toggleSandbox(p) }, own), preview ? 'Hide sandbox' : 'Sandbox'));
        }
        actions.append(el('button', Object.assign({ class: 'small danger-outline', disabled: !usable || active || p.selected, title: p.selected ? 'Part of the station image: take it out and save first' : 'Remove the package (and what was prepared from it) from the station', onclick: () => deletePackage(p) }, own), 'Delete'));
        return el('div', { class: 'custom-row' + (inImage ? ' selected' : '') }, main, actions);
    }

    function appGrants(p, entry, offered) {
        const requested = new Set(p.requested || []);
        const names = [...new Set([...Object.keys(offered), ...entry.grant])].sort();
        const box = el('div', { class: 'grants' }, el('div', { class: 'custom-detail' }, names.length
            ? `Permissions (slot ${entry.slot}): tick what this app may call on the system bus`
            : `No permissions to grant (slot ${entry.slot}): put a system package that offers some into the image`));
        for (const name of names) {
            const o = offered[name];
            const cb = el('input', { type: 'checkbox', 'data-grant': name, 'data-app': p.id });
            cb.checked = entry.grant.includes(name);
            box.append(el('label', { class: 'check' + (o ? '' : ' bad'), title: o ? `${o.description} (${o.calls.join(', ')}; from ${o.provider})` : 'No system package in the image offers this permission: the image cannot be built with it' },
                cb, ` ${name}`, requested.has(name) ? el('span', { class: 'muted' }, ' (requested)') : null, o ? null : el('span', {}, ' (not offered)')));
        }
        return box;
    }

    function appLimits(entry) {
        const field = (key, label) => {
            const [min, max, step] = APP_LIMITS[key];
            return el('label', { class: 'check' }, `${label} `, el('input', { type: 'number', class: 'limit', min, max, step, value: entry[key], 'data-limit': key, 'data-app': entry.id }));
        };
        return el('div', { class: 'grants' }, field('memory_mb', 'memory MiB'), field('cpus', 'CPUs'), field('tasks', 'tasks'));
    }

    function renderPackages() {
        if (!pkgs.draft && img.loaded) resetPackagesDraft(img.loaded);
        const st = pkgStatus();
        const usable = api.available && googleReady() && !!img.loaded && !img.saving;
        const key = JSON.stringify([st, pkgs.draft, Object.keys(pkgs.preview), usable]);
        const box = $('#packages-list');
        // Polling re-renders; never under the operator's fingers (a number being typed keeps its focus).
        if (key === pkgs.key || box.contains(document.activeElement) && document.activeElement.type === 'number') return;
        pkgs.key = key;
        const offered = offeredPermissions();
        box.replaceChildren(...(pkgs.draft ? pkgList().map((p) => packageRow(p, usable, offered)) : []));
        const notes = [...((st && st.notes) || []), ...((st && st.problems) || []).map((t) => `Saved settings: ${t}`)];
        const missing = pkgs.draft ? pkgs.draft.apps.filter((a) => !pkgList().some((p) => p.id === a.id)).map((a) => `app ${a.id} is not on this station`) : [];
        $('#packages-note').replaceChildren(...[...notes, ...missing].map((t) => el('div', { class: 'bad' }, t)));
        renderImagePanel();
    }

    $('#packages-list').addEventListener('change', (ev) => {
        const t = ev.target;
        const p = pkgList().find((x) => x.id === (t.dataset.inImage || t.dataset.app));
        if (!p || !pkgs.draft) return;
        if (t.dataset.inImage) setInImage(p, t.checked);
        else if (t.dataset.grant) {
            const e = appEntry(p.id);
            if (e) e.grant = t.checked ? [...new Set([...e.grant, t.dataset.grant])] : e.grant.filter((g) => g !== t.dataset.grant);
        }
        pkgs.key = '';
        renderPackages();
    });
    $('#packages-list').addEventListener('input', (ev) => {
        const t = ev.target;
        if (!t.dataset.limit) return;
        const e = appEntry(t.dataset.app);
        const [min, max] = APP_LIMITS[t.dataset.limit];
        const v = Number(t.value);
        t.classList.toggle('bad', !(v >= min && v <= max));
        if (e && v >= min && v <= max) e[t.dataset.limit] = t.dataset.limit === 'cpus' ? v : Math.round(v);
        renderImagePanel();
    });

    async function uploadPackage(file, kind) {
        if (pkgs.upload) return;
        const bar = $('#package-upload-progress');
        const status = $('#package-upload-status');
        bar.classList.remove('hidden');
        bar.firstElementChild.style.width = '0';
        $('#btn-package-cancel').classList.remove('hidden');
        log('info', `Uploading ${file.name} (${fmtBytes(file.size)}) to the station as ${kind === 'system' ? 'a system package' : 'an app'}…`);
        pkgs.upload = api.uploadPackage(file, kind, (sent, total) => {
            const pct = total ? Math.min(100, Math.round((100 * sent) / total)) : 0;
            bar.firstElementChild.style.width = pct + '%';
            status.textContent = `${file.name}: ${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%)`;
        });
        renderImagePanel();
        try {
            const r = await pkgs.upload.promise;
            const name = `${r.package.deb.package} ${r.package.deb.version}`;
            status.textContent = !r.new ? `${name} is already on the station.`
                : kind === 'app' ? `${name} uploaded: the station installs it into its own root file system now (a few minutes). Tick "in the image" and its permissions, then save.`
                    : `${name} uploaded. Tick "in the image" and save to install it into the station image.`;
            log('ok', `Package ${name} (${r.package.id}, ${r.package.kind}) ${r.new ? 'uploaded' : 'was uploaded before'}`);
            if (r.job) selectJobLog(r.job, true);
            await refreshStatus();
        } catch (e) {
            status.textContent = `Upload failed: ${e.detail || e.message}`;
            log('error', `Upload of ${file.name}: ${e.detail || e.message}`);
        } finally {
            pkgs.upload = null;
            bar.classList.add('hidden');
            $('#btn-package-cancel').classList.add('hidden');
            renderImagePanel();
        }
    }

    async function preparePackage(p) {
        try {
            const r = await api.preparePackage(p.id, !!p.prepared);
            log('info', `Prepare app ${p.deb.package}: job ${r.job.id} ${r.job.status}`);
            selectJobLog(r.job, true);
        } catch (e) {
            log('error', `Prepare app ${p.deb.package}: ${e.detail || e.message}`);
        }
        refreshStatus();
    }

    async function toggleSandbox(p) {
        if (pkgs.preview[p.id]) {
            delete pkgs.preview[p.id];
        } else {
            try {
                pkgs.preview[p.id] = await api.packageSandbox(p.id);
            } catch (e) {
                log('error', `Sandbox of ${p.deb.package}: ${e.detail || e.message}`);
            }
        }
        pkgs.key = '';
        renderPackages();
    }

    async function deletePackage(p) {
        if (!window.confirm(`Remove ${p.deb.package} ${p.deb.version} from the station?`)) return;
        try {
            await api.deletePackage(p.id);
            delete pkgs.preview[p.id];
            log('ok', `Package ${p.deb.package} removed from the station`);
        } catch (e) {
            log('error', `Delete package ${p.deb.package}: ${e.detail || e.message}`);
        }
        refreshStatus();
    }

    for (const [btn, kind] of [['#btn-system-upload', 'system'], ['#btn-app-upload', 'app']]) {
        $(btn).addEventListener('click', () => { pkgs.kind = kind; $('#package-file').click(); });
    }
    $('#package-file').addEventListener('change', (e) => {
        const f = e.target.files && e.target.files[0];
        e.target.value = '';
        if (f) uploadPackage(f, pkgs.kind);
    });
    $('#btn-package-cancel').addEventListener('click', () => { if (pkgs.upload) pkgs.upload.abort(); });
    $('#btn-image-revert').addEventListener('click', () => {
        if (img.loaded) fillImageForm({ settings: img.loaded, warnings: img.warnings });   // the lists stay
        setImageStatus('');
    });

    // ---------- server badges + builds ----------
    function renderServerBadges() {
        const s = srv.status;
        const box = $('#server-badges');
        if (!s && checking()) {
            box.replaceChildren(badge('Server …', '', 'Waiting for the first /api/status answer'));
            return;
        }
        if (!s) {
            box.replaceChildren(badge('Server offline', 'err', location.protocol === 'file:' ? 'Opened from file:// — start "uv run server.py" and open http://127.0.0.1:8765/' : 'The server did not answer /api/status'));
            $('#registry-backend').textContent = '';
            return;
        }
        const st = s.storage || {};
        const dk = s.docker || {};
        const drv = s.usb_driver;
        fill(box,
            badge(`Server ${s.version || ''} ✓`, 'ok', 'OTP_Provisioner server'),
            badge(`Storage: ${st.backend || '?'}${st.ok ? ' ✓' : ' ✗'}`, st.ok ? 'ok' : 'err', [st.location, st.detail].filter(Boolean).join('\n')),
            badge(`Docker${dk.ok ? ' ' + (dk.version || '') + ' ✓' : ' ✗'}`, dk.ok ? 'ok' : 'warn', [dk.detail, dk.arm64 === false ? 'arm64 emulation missing' : ''].filter(Boolean).join('\n')),
            drv ? badge(`USB driver: rpiboot ${drv.rpiboot ? '✓' : '✗'} · fastboot ${drv.fastboot ? '✓' : '✗'}`, drv.rpiboot && drv.fastboot ? 'ok' : 'warn', drv.detail || '') : null,
        );
        $('#registry-backend').textContent = st.backend ? `${st.backend}${st.location ? ' · ' + st.location : ''}` : '';
        $('#registry-backend').title = st.detail || '';
        const g = s.google;
        if (g && g.signed_in) {
            const who = g.email ? `Google: ${g.email}` : 'Google ✓';
            const sheet = g.spreadsheet_url ? el('a', { href: g.spreadsheet_url, target: '_blank', rel: 'noopener', class: 'badge ok', title: `${g.email || 'This account'}'s spreadsheet: settings + board registry` }, `${who} · Sheets ↗`) : null;
            box.append(sheet || badge(who, 'ok'), el('button', { class: 'small', title: 'Forget the Google login on this station (the next operator signs in with their own account and spreadsheet)', onclick: googleLogout }, 'Sign out'));
        }
        renderGoogle();
        renderScenario();
    }

    // ---------- Google sign-in gate ----------
    function renderGoogle() {
        const box = $('#google-gate');
        const s = srv.status;
        const g = s && s.google;
        let gated = false;
        let content = null;
        let err = false;
        if (s && g) {
            if (!g.client) {
                gated = true;
                err = true;
                content = [el('div', { class: 'gate-text' }, el('b', {}, 'No Google OAuth client. '),
                    'The station keeps its settings and the board registry in a Google spreadsheet. Create an OAuth client of type "Desktop app" in the Google Cloud console (enable the Google Sheets and Google Drive APIs), download its JSON, save it as ',
                    el('code', {}, g.client_file || 'google-oauth-client.json'), ' and reload this page.')];
            } else if (!g.signed_in) {
                gated = true;
                content = [el('div', { class: 'gate-text' }, el('b', {}, 'Sign in to Google. '),
                    'Settings and the board registry live in a Google spreadsheet; the server creates it on the first sign-in.'),
                el('a', { class: 'button primary big', href: '/api/google/login' }, 'Sign in with Google')];
            } else if (s.google_ready === false) {
                gated = true;
                err = true;
                const st = s.settings || {};
                content = [el('div', { class: 'gate-text' }, el('b', {}, 'Google Sheets is not usable: '), st.error || (s.storage && s.storage.detail) || g.error || 'the settings sheet has not been read yet'),
                    el('a', { class: 'button', href: '/api/google/login' }, 'Sign in again'),
                    el('button', { class: 'small', onclick: googleLogout }, 'Sign out')];
            }
        }
        if (srv.googleError) {
            err = true;
            content = [el('div', { class: 'gate-text bad' }, el('b', {}, 'Google sign-in: '), srv.googleError),
                ...(content ? content.slice(1) : []),
                el('button', { class: 'small', onclick: () => { srv.googleError = ''; renderGoogle(); } }, 'Dismiss')];
        }
        document.body.classList.toggle('gated', gated);
        box.classList.toggle('hidden', !content);
        box.classList.toggle('err', err);
        if (content) fill(box, content);
        const unknown = s && s.settings && s.settings.unknown && s.settings.unknown.length ? s.settings.unknown : null;
        if (unknown && !srv.unknownWarned) { srv.unknownWarned = true; log('warn', `settings sheet: unknown keys ignored: ${unknown.join(', ')}`); }
    }

    async function googleLogout() {
        try { await api.googleLogout(); log('info', 'Signed out of Google on this station'); } catch (e) { log('error', `Sign out: ${e.detail || e.message}`); }
        refreshStatus();
    }

    // ---------- scenario (Open / Secure) ----------
    function currentScenario() {
        if (flow.module && flow.module.mode_locked) return 'secure';
        if (srv.scenario === 'open' || srv.scenario === 'secure') return srv.scenario;
        const p = srv.status && srv.status.config && srv.status.config.provisioning;
        return (p && p.default_mode) || 'open';
    }

    function renderScenario() {
        const want = currentScenario();
        for (const r of document.querySelectorAll('#scenario input')) r.checked = r.value === want;
        const locked = !!(flow.module && flow.module.mode_locked);
        $('#provision-mode').textContent = SCENARIOS[want] + (locked ? ' (this board\'s OTP is locked: secure only)' : '');
        updateButtons();
    }

    for (const r of document.querySelectorAll('#scenario input')) {
        r.addEventListener('change', () => {
            if (!r.checked) return;
            srv.scenario = r.value;
            lsSet('otp.scenario', r.value);
            renderScenario();
        });
    }

    const BUILD_TITLES = { tools: 'Tools image', gadget: 'Fastboot gadget', image: 'OS image' };
    function renderBuilds() {
        const box = $('#builds');
        const s = srv.status;
        if (!s || !s.artifacts) {
            box.replaceChildren(el('p', { class: 'muted' }, checking() ? 'Loading…' : api.available ? 'no build information' : 'Server offline.'));
            return;
        }
        const dk = s.docker || {};
        $('#docker-note').textContent = dk.ok ? '' : 'Docker is not running';
        box.replaceChildren(...['tools', 'gadget', 'image'].map((t) => {
            const a = s.artifacts[t] || { target: t, ready: false };
            const job = a.job;
            const active = job && (job.status === 'queued' || job.status === 'running');
            const state = active ? job.status : a.ready ? 'ready' : 'missing';
            const cls = active ? 'warn' : a.ready ? 'ok' : 'err';
            return el('div', { class: 'build-row' },
                el('div', { class: 'build-main' },
                    el('div', { class: 'build-title' }, BUILD_TITLES[t] || t, badge(state, cls), a.source ? badge(a.source, '') : null),
                    el('div', { class: 'build-meta mono' }, [a.version, a.size ? fmtBytes(a.size) : '', a.built ? 'built ' + fmtTime(a.built) : ''].filter(Boolean).join(' · ') || '—'),
                    a.detail ? el('div', { class: 'build-detail muted', title: a.path || '' }, a.detail) : null,
                    job && job.status === 'failed' ? el('div', { class: 'build-detail bad' }, `last build failed${job.error ? ': ' + job.error : ''}`) : null),
                el('div', { class: 'build-actions' },
                    job ? el('button', { class: 'small', onclick: () => selectJobLog(job, true) }, 'Log') : null,
                    el('button', { class: 'small' + (a.ready ? '' : ' primary'), disabled: active || !dk.ok, onclick: () => startBuild(t, a.ready) }, a.ready ? 'Rebuild' : 'Build')));
        }));
    }

    async function startBuild(target, force) {
        try {
            const r = await api.startBuild(target, force);
            log('info', `Build ${target}: job ${r.job.id} ${r.job.status}`);
            selectJobLog(r.job, true);
            refreshStatus();
        } catch (e) {
            log('error', `Build ${target}: ${e.detail || e.message}`);
        }
    }

    function selectJobLog(job, force) {
        if (!job || !job.id) return;
        if (srv.jobLogId === job.id) return;
        // do not switch away from a running job the operator is watching unless asked
        if (!force && srv.jobLogHandle && srv.jobLogActive) return;
        if (srv.jobLogHandle) srv.jobLogHandle.close();
        srv.jobLogId = job.id;
        srv.jobLogActive = true;
        const pre = $('#job-log');
        pre.replaceChildren();
        $('#job-log-title').textContent = `${job.title || job.target} · ${job.id} · ${job.status}`;
        let pending = [];
        let scheduled = false;
        const flush = () => {
            scheduled = false;
            const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4;
            pre.append(pending.join('\n') + '\n');
            pending = [];
            while (pre.childNodes.length > 4000) pre.firstChild.remove();
            if (stick) pre.scrollTop = pre.scrollHeight;
        };
        try {
            srv.jobLogHandle = api.jobLog(job.id, (line) => {
                pending.push(line);
                if (!scheduled) { scheduled = true; requestAnimationFrame(flush); }
            }, (done) => {
                srv.jobLogActive = false;
                if (pending.length) flush();
                $('#job-log-title').textContent = `${job.title || job.target} · ${job.id} · ${done.status || 'finished'}${done.rc !== undefined && done.rc !== null ? ' (rc ' + done.rc + ')' : ''}`;
                refreshStatus();
            });
        } catch (e) {
            pre.textContent = `cannot follow the log: ${e.message}`;
        }
    }

    async function refreshStatus() {
        const s = await api.probe();
        const was = !!srv.status;
        const wasReady = googleReady();
        const first = !srv.probed;
        srv.probed = true;
        srv.status = s;
        document.body.classList.toggle('offline', !s);
        $('#offline-box').classList.toggle('hidden', !!s);
        renderServerBadges();
        renderBuilds();
        renderCustomImages();
        renderPackages();
        if (!googleReady() && img.loaded) {           // signed out: the next account has its own settings
            img.loaded = null;
            img.warnings = [];
        }
        if (!!s !== was || first || googleReady() !== wasReady) {
            renderBoard(); renderRegistry(); updateButtons(); renderImagePanel();
            if (s && googleReady() && !wasReady && !first) refreshModules();
        }
        if (s && googleReady() && !img.loaded) loadImageSettings();
        if (s && !srv.jobLogId) {
            const running = (s.jobs || []).find((j) => j.status === 'running' || j.status === 'queued');
            if (running) selectJobLog(running);
        }
        return s;
    }

    function schedulePoll() {
        clearTimeout(srv.pollTimer);
        srv.pollTimer = setTimeout(async () => {
            if (!document.hidden && location.protocol !== 'file:') {
                await refreshStatus();
                if (api.available && googleReady() && !flow.running) await refreshModules();
            }
            schedulePoll();
        }, api.available ? 5000 : 15000);
    }

    // ---------- boot ----------
    srv.scenario = lsGet('otp.scenario', '');
    {
        const q = new URLSearchParams(location.search);
        if (q.get('google_error')) {
            srv.googleError = q.get('google_error');
            history.replaceState(null, '', location.pathname);
        }
    }
    renderCaps();
    buildSteps();
    renderServerBadges();
    renderBuilds();
    renderBoard();
    renderRegistry();
    renderDeviceBadge(null, null);
    updateButtons();
    const ready = refreshStatus().then(async (s) => {
        if (s) {
            log('info', s.google_ready === false
                ? `Server ${s.version || ''} online. Sign in to Google first: the settings and the board registry live in Google Sheets.`
                : `Server ${s.version || ''} online · registry: Google Sheets. Pick the scenario (Open / Secure), put the board into RPIBOOT mode and click "Connect board".`);
            if (googleReady()) await refreshModules();
        } else {
            log('warn', location.protocol === 'file:'
                ? 'Opened from file://: there is no server. Run "uv run server.py" and open http://127.0.0.1:8765/.'
                : 'The server did not answer: start it with "uv run server.py" and reload the page.');
        }
        updateButtons();
        schedulePoll();
    });

    // exposed for the self-test page
    OTP.app = { log, flow, srv, steps, setStep, renderBoard, renderRegistry, refreshStatus, ready, confirmIrreversible, renderGoogle, renderScenario, currentScenario,
        img, loadImageSettings, renderImagePanel, tzOffset, imager, renderImager, prepareImager, renderCustomImages, uploadCustom, upload, showNeed,
        pkgs, renderPackages, uploadPackage, parseAppLine, formatAppLine };
})();
