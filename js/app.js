/*
 * app.js — the station UI.
 *
 * Server mode (the normal case, page served by `python server.py`):
 *   Board card (Connect board, the server's record of the board), Registry (all boards on the server),
 *   Provision card (three stages driven by OTP.Flow), Server builds (tools / gadget / image, live job log), Log.
 * Manual mode ("Advanced (manual)", works from file:// or without the server):
 *   the rpiboot runs from a local boot directory (stages 1 and 2) and manual fastboot (stage 3).
 */
(function () {
    'use strict';
    const OTP = window.OTP;
    const { RPI_VID, USB_FILTERS, RpiDevice, RpiBootSession, runSession, sleep } = OTP.rpiboot;
    const { BootDir, CHIPS, IRREVERSIBLE_KEYS } = OTP;
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
    const hex4 = (n) => n.toString(16).padStart(4, '0');
    const fmtBytes = (n) => {
        if (n === undefined || n === null || n === '') return '—';
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KiB';
        if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MiB';
        return (n / 1073741824).toFixed(2) + ' GiB';
    };
    const fmtTime = (iso) => (iso ? String(iso).slice(0, 19).replace('T', ' ') : '—');
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
        3: { title: 'Image', sub: 'fastboot IDP: (secure) OTP device key exported to the server, partitions (+ LUKS2), sparse images, reboot' },
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
        box.replaceChildren(
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
        else if (!online) hint = 'server offline: use Advanced (manual) below';
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
                : 'The server is not reachable, so boards cannot be provisioned from here. Start it with "python server.py", or use Advanced (manual) below.'));
            return;
        }
        const live = flow.module && flow.module.serial === m.serial;
        const sec = m.secrets || {};
        const otp = m.otp || {};
        const otpText = otp.locked ? (otp.locked_to_our_key ? 'locked to this board\'s key' : 'LOCKED TO A DIFFERENT KEY') : 'not locked (OTP key hash empty)';
        const modeText = m.mode ? `${m.mode}${m.mode_chosen ? '' : ' (default)'}${m.mode_locked ? ' · OTP locked: secure only' : ''}` : '';
        const events = (m.events || []).slice(-8).reverse();
        box.replaceChildren(
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
            events.length ? el('div', { class: 'events' },
                el('h3', {}, 'Events'),
                el('ul', {}, ...events.map((ev) => el('li', { class: /fail/i.test(ev.note) ? 'bad' : '' },
                    el('span', { class: 'muted mono' }, fmtTime(ev.t).slice(5)), ' ', el('b', {}, ev.kind), ' ', ev.note || '')))) : null,
        );
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
    const IMAGE_TEXT = ['name', 'hostname', 'timezone', 'user', 'wifi_ssid', 'wifi_country'];
    const IMAGE_BOOL = ['ssh', 'ssh_password_login', 'wifi_hidden'];
    const IMAGE_SECRETS = ['password', 'wifi_password'];
    const img = { loaded: null, warnings: [], remove: { password: false, wifi_password: false }, saving: false, loading: false, choicesKey: '' };
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

    /** The time zone and Wi-Fi country lists (the image's tzdata and wireless-regdb, from the server). */
    function fillImageChoices(choices) {
        const tzs = (choices && choices.timezones) || [];
        const countries = (choices && choices.countries) || [];
        const key = `${tzs.length}:${tzs[0] || ''}:${countries.length}`;
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
        for (const field of imageForm.elements) field.disabled = !usable || img.saving;
        if (usable && !img.saving) {
            const ssh = imageInput('ssh').checked;
            imageInput('ssh_password_login').disabled = !ssh;
            imageInput('ssh_authorized_keys').disabled = !ssh;
        }
        const set = { password: !!(s && s.password_set), wifi_password: !!(s && s.wifi_password_set) };
        imageInput('password').placeholder = img.remove.password ? 'will be removed'
            : set.password ? 'set: type to change' : 'none: password login is off';
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
        if (!s && !img.loading && !(api.available && googleReady())) setImageStatus('Available once the server is running and signed in to Google.');
    }

    function fillImageForm(view) {
        const s = view.settings || {};
        img.loaded = s;
        img.warnings = view.warnings || [];
        img.remove = { password: false, wifi_password: false };
        if (view.choices) fillImageChoices(view.choices);
        for (const k of IMAGE_TEXT) {
            const f = imageInput(k);
            if (f.tagName === 'SELECT') setImageSelect(f, s[k] || '');
            else f.value = s[k] || '';
        }
        for (const k of IMAGE_BOOL) imageInput(k).checked = !!s[k];
        imageInput('ssh_authorized_keys').value = (s.ssh_authorized_keys || []).join('\n');
        for (const k of IMAGE_SECRETS) { imageInput(k).value = ''; imageInput(k).type = 'password'; }
        for (const b of imageForm.querySelectorAll('button[data-show]')) b.textContent = 'show';
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
            setImageStatus(`Saved: ${names}. ` + (auto ? 'The server rebuilds both images now; stage 3 waits for them.'
                : 'Start the OS image build under Server builds (automatic builds are off).'));
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
            box.replaceChildren(badge('Server offline', 'err', location.protocol === 'file:' ? 'Opened from file:// — start "python server.py" and open http://127.0.0.1:8765/' : 'The server did not answer /api/status'));
            $('#registry-backend').textContent = '';
            return;
        }
        const st = s.storage || {};
        const dk = s.docker || {};
        const drv = s.usb_driver;
        box.replaceChildren(
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
        if (content) box.replaceChildren(...content);
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

    // =====================================================================================
    // Manual mode (Advanced): local boot directories + manual fastboot
    // =====================================================================================

    const state = { devices: new Map(), selectedKey: null, session: null, waiter: null, busy: false };
    const keyOf = (usb) => `${hex4(usb.vendorId)}:${hex4(usb.productId)}:${usb.serialNumber || ''}`;
    const isRpi = (usb) => usb.vendorId === RPI_VID && !!CHIPS[usb.productId];
    const advanced = $('#advanced');

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
        if (!rec || !rec.connected || state.session || state.busy || flow.running) return;
        state.busy = true;
        const dev = new RpiDevice(rec.usb);
        try {
            await dev.open();
            rec.probe = { iSerial: dev.iSerial, serial: dev.serial, stage: dev.stageName, rom: dev.isRomStage, bcdDevice: dev.bcdDevice, error: dev.descriptorError ? String(dev.descriptorError.message || dev.descriptorError) : null };
            log('info', `${dev.chip.name} ${dev.serial || '(no serial)'}: ${dev.stageName} (iSerialNumber=${dev.iSerial})`);
        } catch (e) {
            rec.probe = { error: e.message || String(e) };
            log('error', `Probe failed: ${e.message || e}${/claim|access|busy/i.test(String(e.message)) ? ' — is rpiboot.exe or another tab holding the device?' : ''}`);
        } finally {
            await dev.close();
            state.busy = false;
        }
        renderDevices();
        renderDetail();
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
            ul.append(el('li', { class: 'empty' }, 'No authorized Raspberry Pi devices yet. Put the board in RPIBOOT mode and click "Select device…".'));
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
        if (!rec) { box.replaceChildren(el('p', { class: 'muted' }, 'No device selected.')); return; }
        const chip = CHIPS[rec.usb.productId];
        const p = rec.probe || {};
        const serial = rec.usb.serialNumber || p.serial || '';
        box.replaceChildren(
            el('div', { class: 'serial-big' }, serial || '—'),
            el('div', { class: 'row' },
                el('button', { class: 'small', onclick: () => navigator.clipboard.writeText(serial), disabled: !serial }, 'Copy serial'),
                el('button', { class: 'small', onclick: () => probe(rec), disabled: !rec.connected }, 'Probe stage')),
            el('p', { class: 'hint' }, 'The USB serial is the lower 32 bits of the board serial. The full serial, MAC addresses and the DUID (FACTORY_UUID) arrive in the metadata once a bootloader runs (stage 1).'),
            el('dl', { class: 'kv' },
                el('dt', {}, 'SoC'), el('dd', {}, `${chip.name} (${chip.board})`),
                el('dt', {}, 'USB'), el('dd', {}, [`${hex4(rec.usb.vendorId)}:${hex4(rec.usb.productId)}`, rec.usb.manufacturerName, rec.usb.productName].filter(Boolean).join(' ')),
                el('dt', {}, 'State'), el('dd', {}, rec.connected ? 'connected' : 'disconnected'),
                el('dt', {}, 'Stage'), el('dd', {}, p.stage ? `${p.stage} (iSerialNumber=${p.iSerial})` : p.error ? `probe failed: ${p.error}` : 'not probed'),
                el('dt', {}, 'bcdDevice'), el('dd', {}, p.bcdDevice != null ? hex4(p.bcdDevice) : '—')));
    }

    /** Resolve with the next Raspberry Pi device of the same product that is not `previous` (connect event, manual pick or polling). */
    function waitForDevice({ previous, productId, timeoutMs }) {
        return new Promise((resolve, reject) => {
            let done = false;
            const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); if (state.waiter === waiter) state.waiter = null; fn(v); };
            const timer = setTimeout(() => finish(reject, new Error(`timed out after ${timeoutMs / 1000} s waiting for the board to re-enumerate`)), timeoutMs);
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

    /** Run a local boot directory against the selected device (rpiboot's main loop, OTP.rpiboot.runSession). */
    /**
     * Run one manual rpiboot directory against `rec` — the device the panel checked and confirmed
     * (never re-read from the current selection: it may have changed while the operator confirmed).
     */
    async function runBootDir(panel, rec, chip) {
        if (!rec) return log('error', 'Select a device first');
        if (!rec.connected) return log('error', 'The selected device is not connected');
        if (chip && CHIPS[rec.usb.productId] && CHIPS[rec.usb.productId].prefix !== chip.prefix) {
            return log('error', `The device is a ${CHIPS[rec.usb.productId].name}, but config.txt was checked for ${chip.name}; click Run again`);
        }
        if (state.session) return log('error', 'Another run is in progress');
        if (flow.running) return log('error', 'A server provisioning run is in progress');
        const session = new RpiBootSession(panel.dir, {
            log,
            onProgress: (name, s, t) => panel.progress(name, s, t),
        });
        state.session = session;
        panel.setRunning(true);
        let out = null;
        log('info', `=== ${panel.title}: "${panel.dir.name}" → ${CHIPS[rec.usb.productId].name} ${rec.usb.serialNumber || ''} ===`);
        try {
            out = await runSession(session, rec.usb, (prev) => waitForDevice({ previous: prev, productId: prev.productId, timeoutMs: 60000 }), {
                log,
                onDevice: (u) => { upsertDevice(u, true); renderDevices(); },
            });
        } catch (e) {
            log('error', `${panel.title} failed: ${e.message || e}`);
            panel.showError(e);
        } finally {
            state.session = null;
            if (state.waiter) state.waiter.cancel();
            panel.setRunning(false);
        }
        if (!out) return;
        const result = out.result;
        const meta = result.metadata;
        const key = out.serial || meta.USER_SERIAL_NUM || meta.SERIAL_NUMBER || '';
        log('ok', `${panel.title} finished: ${Object.keys(meta).length} metadata fields, ${result.filesServed.length} files served`);
        const verdict = panel.verdict(result);
        panel.showResult(result, verdict, session.metadataJson(key));
    }

    /** Irreversible rpiboot options set by parsed config.txt keys → {flags: [{key, value, why}], otp}. */
    function irreversibleOf(keys) {
        const flags = [];
        let otp = false;
        for (const [k, v] of Object.entries(keys || {})) {
            const why = IRREVERSIBLE_KEYS[k];
            if (!why || v === '0' || v === '') continue;
            flags.push({ key: k, value: v, why });
            if (k === 'program_pubkey') otp = true;
        }
        return { flags, otp };
    }

    // ---------- a stage that runs a local boot directory ----------
    class BootRunPanel {
        constructor(root, cfg) {
            this.root = root;
            this.cfg = cfg;
            this.title = cfg.title;
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
                    el('div', { class: 'table-wrap' }, this.filesTable = el('table', { class: 'list' })),
                    this.otherFiles = el('p', { class: 'hint' }),
                    el('h3', {}, 'config.txt (rpiboot options, not the OS config.txt)'),
                    this.flagsBox = el('div', { class: 'flags' }),
                    this.extraBox = el('div')),
                el('div', { class: 'row' },
                    this.btnRun = el('button', { class: 'danger', disabled: true, onclick: () => this.run() }, this.cfg.runLabel),
                    this.btnAbort = el('button', { disabled: true, onclick: () => abortRun() }, 'Abort'),
                    this.runHint = el('span', { class: 'muted' }, 'choose a directory and select a device')),
                el('div', { class: 'progress' }, this.progressBar = el('div')),
                this.progressLabel = el('div', { class: 'progress-label' }),
                this.resultBox = el('div', { class: 'result hidden' }),
            );
            if (this.cfg.keyHashCheck) {
                this.extraBox.append(
                    el('h3', {}, 'Expected customer key hash'),
                    el('div', { class: 'row' }, this.keyHashInput = el('input', { type: 'text', class: 'mono wide', placeholder: 'sha256 of the board public key, 64 hex (optional)' })),
                    el('p', { class: 'hint' }, 'After the run, CUSTOMER_KEY_HASH from the metadata is compared with this value.'));
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

        /**
         * The flags come from the config.txt the file server will actually serve to this.chip (BootDir.resolve:
         * <prefix>/config.txt overlay, the bootfiles.bin member, then the top-level file), not from the top-level
         * file alone; config.txt files that are shadowed and differ are listed as a warning.
         */
        async renderFlags() {
            const chip = this.chip;
            const cfg = await this.dir.configTxt(chip);
            const candidates = await this.dir.configCandidates(chip);
            this.flagsBox.replaceChildren();
            const { flags, otp } = irreversibleOf(cfg ? cfg.keys : {});
            this.irreversible = flags;
            this.otpRequested = otp;
            if (!cfg) {
                this.flagsBox.append(el('div', { class: 'flag' }, el('span', { class: 'muted' }, 'no config.txt in the directory')));
            } else {
                this.flagsBox.append(el('div', { class: 'flag config-origin' }, el('span', { class: 'muted' }, `served to ${chip.name}: ${cfg.origin}`)));
                const keys = Object.entries(cfg.keys);
                if (!keys.length) this.flagsBox.append(el('div', { class: 'flag' }, el('span', { class: 'muted' }, 'config.txt sets nothing (all lines commented out)')));
                for (const [k, v] of keys) {
                    const why = IRREVERSIBLE_KEYS[k];
                    const on = why && v !== '0' && v !== '';
                    this.flagsBox.append(el('div', { class: 'flag' + (on ? ' irreversible' : '') },
                        el('span', { class: 'k' }, `${k}=${v}`),
                        on ? el('span', { class: 'why' }, `IRREVERSIBLE: ${why}`) : null));
                }
                for (const c of candidates.filter((x) => x.text !== cfg.text)) {
                    const theirs = irreversibleOf(c.keys).flags.map((f) => `${f.key}=${f.value}`);
                    this.flagsBox.append(el('div', { class: 'flag config-shadowed' }, el('span', { class: 'why' },
                        `${c.origin} differs and is NOT served to ${chip.name} (${cfg.origin} takes priority)${theirs.length ? '; it sets ' + theirs.join(', ') : ''}`)));
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
            const ready = !!this.dir && !!rec && rec.connected && !missing.length && !state.session && !this.preparing;
            this.btnRun.disabled = !ready;
            this.runHint.textContent = !this.dir ? 'choose a directory' : missing.length ? `missing: ${missing.join(', ')}` : !rec ? 'select a device' : !rec.connected ? 'the selected device is disconnected' : state.session ? 'a run is in progress' : this.preparing ? 'checking config.txt…' : `ready for ${rec.usb.serialNumber || 'the selected device'}`;
        }

        /**
         * Before a run: parse the config.txt the file server will serve to `chip` (the selected device's SoC) and
         * pin exactly those bytes in the BootDir, so the board receives what the irreversible-key check read.
         * Returns {cfg, flags}.
         */
        async prepareRun(chip) {
            if (chip !== this.chip) {
                this.chip = chip;
                await this.renderFiles();
                await this.renderFlags();
            }
            this.dir.unpin('config.txt', chip);
            const cfg = await this.dir.configTxt(chip);
            if (cfg) this.dir.pin('config.txt', chip, cfg);
            const { flags, otp } = irreversibleOf(cfg ? cfg.keys : {});
            this.irreversible = flags;
            this.otpRequested = otp;
            return { cfg, flags };
        }

        async run() {
            const rec = state.devices.get(state.selectedKey);
            if (!rec || this.preparing) return;
            const chip = CHIPS[rec.usb.productId] || this.chip;
            // No second click / selection change may slip in while the files are re-read and hashed:
            // the run must go to exactly the board (and SoC) that was checked, pinned and confirmed.
            this.preparing = true;
            this.updateRunState();
            let prep;
            try {
                prep = await this.prepareRun(chip);
                if (prep.flags.length) {
                    const ok = await confirmIrreversible({
                        what: `Directory "${this.dir.name}" sets rpiboot options (${prep.cfg.origin}) that permanently change board ${rec.usb.serialNumber || ''}:`,
                        flags: prep.flags,
                        token: rec.usb.serialNumber || 'BURN',
                        okLabel: 'Burn',
                    });
                    if (!ok) { this.dir.unpin('config.txt', chip); log('info', 'Cancelled by the operator'); return; }
                }
            } catch (e) {
                log('error', `Reading config.txt failed: ${e.message || e}`);
                return;
            } finally {
                this.preparing = false;
                this.updateRunState();
            }
            if (state.selectedKey !== rec.key || !rec.connected) {
                this.dir.unpin('config.txt', chip);
                log('error', `The selected device changed or disconnected after the check of ${rec.usb.serialNumber || 'the board'}; nothing was sent. Click Run again.`);
                return;
            }
            await runBootDir(this, rec, chip);
        }

        setRunning(on) {
            this.btnAbort.disabled = !on;
            this.btnChoose.disabled = on;
            if (on) { this.progress('', 0, 1); this.resultBox.classList.add('hidden'); }
            this.updateRunState();
            for (const p of panels) if (p !== this) p.updateRunState();
        }

        progress(name, sent, total) {
            const pct = total ? Math.round((sent / total) * 100) : 0;
            this.progressBar.style.width = pct + '%';
            this.progressLabel.textContent = name ? `${name}: ${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%)` : '';
        }

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
                if (served.includes('boot.img')) notes.push('boot.img delivered: the ramdisk is booting.');
                else { ok = false; notes.push('boot.img was never requested by the bootloader.'); }
                if (result.interrupted) notes.push('The board left the file server before "Done" (normal when the ramdisk takes over USB).');
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
            title: 'Stage 1 · EEPROM & OTP',
            doneLabel: 'Stage 1 done: EEPROM flashed, metadata received',
            runLabel: 'Flash EEPROM / burn OTP',
            keyHashCheck: true,
            dirHint: 'secure-boot-recovery5 style: bootcode5.bin (recovery.bin), pieeprom.bin, pieeprom.sig, config.txt',
            blurb: [
                'The station sends the recovery bootloader to the boot ROM; it flashes ', el('code', {}, 'pieeprom.bin'), ', optionally burns the SHA-256 of the public key into OTP (', el('code', {}, 'program_pubkey=1'),
                ') and reports the metadata (serial, DUID, MAC, ', el('code', {}, 'CUSTOMER_KEY_HASH'), ', ', el('code', {}, 'SECURE_BOOT_PROVISION'), '). Equivalent of ', el('code', {}, 'rpiboot -d <dir> -j metadata'), '.',
            ],
            expected: [
                { name: 'bootcode5.bin', required: true, note: 'On Pi 5 this is recovery.bin (counter-signed only when the OTP already holds the key hash)' },
                { name: 'pieeprom.bin', required: true, note: 'EEPROM image with the embedded public key and the boot.conf' },
                { name: 'pieeprom.sig', required: true, note: 'Signature of pieeprom.bin (rpi-eeprom-digest)' },
                { name: 'config.txt', required: true, note: 'rpiboot options: program_pubkey, program_jtag_lock, recovery_reboot, set_reboot_order' },
                { name: 'recovery.bin', required: false, note: 'Not used by rpiboot on Pi 5 (bootcode5.bin is the recovery)' },
            ],
        }),
        new BootRunPanel($('#stage-2'), {
            stage: 2,
            title: 'Stage 2 · Gadget / agent ramdisk',
            doneLabel: 'Stage 2 done: the ramdisk was delivered',
            runLabel: 'Boot the ramdisk',
            dirHint: 'bootfiles.bin, boot.img (+ boot.sig once the board is locked), config.txt with boot_ramdisk=1 — e.g. the server\'s stage-2 files',
            blurb: [
                'The bootloader (from ', el('code', {}, 'bootfiles.bin'), ') asks the station for ', el('code', {}, 'config.txt'), ', ', el('code', {}, 'boot.img'), ' and ', el('code', {}, 'boot.sig'),
                ' and boots the initramfs: the fastboot gadget the server builds, or the stock mass-storage gadget (', el('code', {}, 'external/usbboot/mass-storage-gadget64'), ').',
            ],
            expected: [
                { name: 'bootcode5.bin', required: true, note: 'Second stage, normally inside bootfiles.bin as 2712/bootcode5.bin' },
                { name: 'config.txt', required: true, note: 'boot_ramdisk=1 makes the bootloader load boot.img' },
                { name: 'boot.img', required: true, note: 'FAT image: kernel + DTB + initramfs' },
                { name: 'boot.sig', required: false, note: 'rpi-eeprom-digest signature; mandatory once the board is locked to a key' },
            ],
        }),
    ];

    // ---------- manual stage 3: fastboot ----------
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
        $('#fb-progress').style.width = (total ? pct : 0) + '%';
        $('#fb-progress-label').textContent = total ? `${name || 'download'}: ${fmtBytes(sent)} / ${fmtBytes(total)} (${pct}%)` : `${name || 'download'}: ${fmtBytes(sent)}`;
    }
    async function withFastboot(fn) {
        if (!fb.usb) return;
        if (fb.running) return log('error', 'fastboot: busy');
        if (flow.running) return log('error', 'A server provisioning run is in progress');
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
    async function fbSetDir(dir) {
        fb.dir = dir;
        $('#fb-dir').textContent = fb.dir.name + ((await fb.dir.has('image.json')) ? ' (image.json found)' : ' (no image.json!)');
        fbUpdate();
    }
    $('#fb-pick-dir').addEventListener('click', async () => {
        if (!window.showDirectoryPicker) { $('#fb-dir-input').click(); return; }
        try { await fbSetDir(BootDir.fromDirectoryHandle(await window.showDirectoryPicker({ mode: 'read' }))); } catch (e) { if (e.name !== 'AbortError') log('error', e.message); }
    });
    $('#fb-dir-input').addEventListener('change', async (e) => {
        if (e.target.files.length) await fbSetDir(BootDir.fromFileList(e.target.files));
    });
    $('#fb-run-idp').addEventListener('click', async () => {
        if (!fb.dir || !fb.usb) return;
        const imageJson = await fb.dir.readFile('image.json');
        if (!imageJson) return log('error', 'image.json not found in the chosen directory');
        const erase = $('#fb-opt-erase').checked;
        const fwc = $('#fb-opt-fwcrypto').checked;
        const flags = [{ key: 'IDP', why: 'partitions and LUKS2 containers are recreated; everything on the board storage is lost' }];
        if (erase) flags.push({ key: 'erase', value: 'mmcblk0', why: 'wipes the whole SD card first' });
        if (fwc) flags.push({ key: 'oem fwcrypto init', why: 'creates the device key in OTP (irreversible)' });
        const ok = await confirmIrreversible({
            what: `Provision board ${fb.usb.serialNumber || ''} from "${fb.dir.name}": the storage is repartitioned and rewritten.`,
            flags,
            token: fb.usb.serialNumber || 'WRITE',
            okLabel: 'Write',
        });
        if (!ok) return;
        await withFastboot(async (c) => {
            await c.provisionIdp(imageJson, (name) => fb.dir.readFile(name), fbProgress, { erase, fwcryptoInit: fwc });
            log('ok', 'IDP provisioning complete');
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

    // ---------- stage navigation (manual) ----------
    for (const b of $('#stage-nav').querySelectorAll('button')) {
        b.addEventListener('click', () => showStage(b.dataset.stage));
    }
    function showStage(id) {
        for (const b of $('#stage-nav').querySelectorAll('button')) b.classList.toggle('active', b.dataset.stage === id);
        for (const s of document.querySelectorAll('.stage')) s.classList.toggle('hidden', s.id !== id);
        lsSet('otp.stage', id);
    }

    // ---------- USB events (manual device list; the Flow listens on its own) ----------
    if (navigator.usb) {
        navigator.usb.addEventListener('connect', (e) => {
            const usb = e.device;
            if (!isRpi(usb)) { log('debug', `USB connect: ${hex4(usb.vendorId)}:${hex4(usb.productId)} ${usb.productName || ''}`); return; }
            const rec = upsertDevice(usb, true);
            log('debug', `USB connect: ${CHIPS[usb.productId].name} ${usb.serialNumber || '(no serial)'}`);
            if (!state.selectedKey || !state.devices.get(state.selectedKey)) state.selectedKey = rec.key;
            renderDevices();
            renderDetail();
            for (const p of panels) p.updateRunState();
            if (state.waiter) state.waiter.offer(usb);
            else if (rec.key === state.selectedKey && advanced.open && !flow.running && $('#chk-autoprobe').checked) probe(rec);
        });
        navigator.usb.addEventListener('disconnect', (e) => {
            const usb = e.device;
            const rec = state.devices.get(keyOf(usb));
            if (rec && rec.usb === usb) { rec.connected = false; rec.probe = null; }
            if (isRpi(usb)) log('debug', `USB disconnect: ${CHIPS[usb.productId].name} ${usb.serialNumber || ''}`);
            renderDevices();
            renderDetail();
            for (const p of panels) p.updateRunState();
        });
    }
    $('#btn-pick-device').addEventListener('click', pickDevice);
    $('#btn-refresh-devices').addEventListener('click', refreshDevices);
    advanced.addEventListener('toggle', () => {
        if (advanced.dataset.auto) { delete advanced.dataset.auto; return; } // opened by the page, not by the operator
        lsSet('otp.advanced', advanced.open ? '1' : '0');
    });
    $('#btn-open-advanced').addEventListener('click', () => { advanced.open = true; advanced.scrollIntoView({ behavior: 'smooth', block: 'start' }); });

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
    showStage(lsGet('otp.stage', 'stage-1'));
    fbUpdate();
    refreshDevices().then(() => { for (const p of panels) p.updateRunState(); });
    const ready = refreshStatus().then(async (s) => {
        if (s) {
            log('info', s.google_ready === false
                ? `Server ${s.version || ''} online. Sign in to Google first: the settings and the board registry live in Google Sheets.`
                : `Server ${s.version || ''} online · registry: Google Sheets. Pick the scenario (Open / Secure), put the board into RPIBOOT mode and click "Connect board".`);
            if (googleReady()) await refreshModules();
        } else {
            log('warn', location.protocol === 'file:'
                ? 'Opened from file://: no server. The manual mode (Advanced) works; for provisioning run "python server.py".'
                : 'The server did not answer: only the manual mode (Advanced) is available.');
            if (!advanced.open) { advanced.dataset.auto = '1'; advanced.open = true; }
        }
        if (lsGet('otp.advanced', '0') === '1' && !advanced.open) { advanced.dataset.auto = '1'; advanced.open = true; }
        updateButtons();
        schedulePoll();
    });

    // exposed for the self-test page
    OTP.app = { state, panels, log, runBootDir, waitForDevice, BootRunPanel, flow, srv, steps, setStep, renderBoard, renderRegistry, refreshStatus, ready, confirmIrreversible, renderGoogle, renderScenario, currentScenario,
        img, loadImageSettings, renderImagePanel, tzOffset };
})();
