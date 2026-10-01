/*
 * flow.js — OTP.Flow, the server-driven provisioning state machine.
 *
 *   connectBoard()  Chrome's device chooser → probe (ROM / second stage / fastboot gadget) → api.hello or
 *                   api.identify → the board's record ("module") on the server.
 *   provision()     runs the stages that are not done yet, in order:
 *     1  EEPROM / OTP   rpiboot with the server's stage-1 directory; the board reboots back into RPIBOOT
 *     2  gadget         rpiboot with the stage-2 directory; the board boots the fastboot gadget
 *     3  image          fastboot IDP (FastbootClient.idpProvision) with the server's image set; in the
 *                       secure scenario the OTP device key is exported to the server first
 *   runStage(n)     one stage on its own (the per-stage "Run" buttons).
 *   Before a run the operator's scenario (options.scenario: "open" | "secure") is sent to the server
 *   (api.setMode); the server plans every stage for it (open: unsigned EEPROM + clear image, OTP untouched;
 *   secure: signed EEPROM + program_pubkey, LUKS image, device key export).
 *   selectDevice() / connectFastboot()   user-gesture handlers for when Chrome needs a new permission.
 *   abort()
 *
 * The flow never touches the DOM: it reports through hooks
 *   onStage(n, state, detail, extra)  state: idle | running | waiting | done | failed
 *   onProgress(n, {label, sent, total}) · onLog(level, msg) · onModule(module) · onBusy(bool)
 *   onNeed(kind | null, info)         kind: 'rpiboot' (show "Select device") | 'fastboot' ("Connect fastboot gadget")
 *   onConfirm({what, flags, token})   → Promise<bool>, typed-serial confirmation of irreversible steps
 *   onBuildWait(n, {reason, job})     the server is still building what this stage needs
 *   onDevice(usb | null, kind)        the current USB device changed
 *
 * Serial identity: the BCM2712 boot ROM reports the 8-hex serial; the fastboot gadget reports the 16-hex
 * 64-bit serial whose last 8 hex are the same value. The server keys boards by the 8-hex value.
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});
    const { RpiDevice, RpiBootSession, runSession, isGone, DeviceGone, RPI_VID, RPI_PIDS } = OTP.rpiboot;
    const { FastbootClient, FastbootError, isFastbootDevice, clean } = OTP.fastboot;

    const STAGE_INDEX = { new: 0, eeprom: 1, gadget: 2, flashed: 3 };
    const STAGE_TITLES = { 1: 'EEPROM & OTP', 2: 'Fastboot gadget', 3: 'Image' };
    const FASTBOOT_VARS = ['product', 'version-bootloader', 'version-fastbootd', 'secure', 'secure-otp', 'secure-devkey',
        'mmc-cid', 'mac-ethernet', 'rpi-duid', 'otp-lock-status', 'block-devices', 'max-download-size'];
    const USB_FILTERS = [...OTP.rpiboot.USB_FILTERS, ...OTP.fastboot.FILTERS];
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    /** Uint8Array -> base64 (small payloads: the exported device key). */
    const toBase64 = (bytes) => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };

    class FlowAbort extends Error { constructor(msg) { super(msg || 'aborted by the operator'); this.name = 'FlowAbort'; } }
    class FlowCancelled extends Error { constructor(msg) { super(msg || 'cancelled by the operator'); this.name = 'FlowCancelled'; } }

    /** 8 hex (ROM) or 16 hex (gadget, last 8 used) → 8 lowercase hex; anything else → ''. */
    function normalizeSerial(s) {
        const v = String(s || '').replace(/\0/g, '').trim().toLowerCase();
        if (/^[0-9a-f]{8}$/.test(v)) return v;
        if (/^[0-9a-f]{16}$/.test(v)) return v.slice(-8);
        return '';
    }

    const isRpiboot = (u) => !!u && u.vendorId === RPI_VID && RPI_PIDS.includes(u.productId);

    function errText(e) {
        if (!e) return 'unknown error';
        if (e.name === 'ApiError') return `server: ${e.detail || e.message}`;
        return e.message || String(e);
    }

    class Flow {
        constructor(opts) {
            opts = opts || {};
            this.api = opts.api || OTP.api;
            this.usb = opts.usb || (typeof navigator !== 'undefined' ? navigator.usb : null);
            const noop = () => {};
            this.hooks = Object.assign({
                onStage: noop, onProgress: noop, onLog: noop, onModule: noop, onBusy: noop,
                onNeed: noop, onBuildWait: noop, onDevice: noop,
                onConfirm: async () => true,
            }, opts.hooks || {});
            this.opt = Object.assign({
                reenumTimeoutMs: 90000,      // rpiboot re-enumeration
                fastbootTimeoutMs: 600000,   // waiting for the gadget (operator has to click)
                pollMs: 1000,
                needDeviceAfterMs: 6000,     // show "Select device" when no permitted device showed up by then
                buildPollMs: 3000,
                eraseSettleMs: 3000,
                fileServerIdleMs: 180000,    // rpiboot file server: give up when an attached board asks for nothing this long
                fileServerRetryMs: 1000,     // rpiboot file server: pause between failed reads (usbboot: sleep(1))
                rpibootSettleMs: 1000,       // rpiboot: leave a freshly enumerated board alone this long before opening it (usbboot: sleep(1))
                confirmIrreversible: null,   // null → from /api/status config (default true)
                scenario: null,              // "open" | "secure" (or a function returning it): sent to the server before a run
                keyExportTimeoutMs: 30000,   // secure scenario: the gadget generating + exporting the OTP device key
            }, opts.options || {});
            this.module = null;
            this.serial = '';
            this.device = null;          // current USBDevice
            this.deviceKind = null;      // 'rpiboot' | 'fastboot'
            this.deviceStale = false;    // the board was handed control and re-enumerates: wait for a new USBDevice object
            this.probeInfo = null;
            this.running = false;
            this.aborted = false;
            this.session = null;
            this.client = null;
            this.stages = { 1: { state: 'idle', detail: '' }, 2: { state: 'idle', detail: '' }, 3: { state: 'idle', detail: '' } };
            this._waiters = new Set();
            this._confirmed = new Set();
            this._sleepers = new Set();
            if (this.usb && this.usb.addEventListener) {
                this.usb.addEventListener('connect', (e) => this._offer(e.device));
                this.usb.addEventListener('disconnect', (e) => {
                    if (e.device && e.device === this.device) { this.hooks.onDevice(null, this.deviceKind); }
                });
            }
        }

        static get USB_FILTERS() { return USB_FILTERS; }
        static normalizeSerial(s) { return normalizeSerial(s); }

        log(level, msg) { this.hooks.onLog(level, msg); }

        _setStage(n, state, detail, extra) {
            this.stages[n] = Object.assign({ state, detail: detail || '' }, extra || {});
            this.hooks.onStage(n, state, detail || '', extra || {});
        }

        _setModule(m) {
            if (!m) return;
            this.module = m;
            if (m.serial) this.serial = m.serial;
            this.hooks.onModule(m);
        }

        _setDevice(usb, kind) {
            this.device = usb;
            this.deviceKind = kind;
            this.deviceStale = false;
            this.hooks.onDevice(usb, kind);
        }

        /** Stage states derived from the server record (done / idle). */
        _stagesFromModule() {
            if (!this.module) return;
            const st = STAGE_INDEX[this.module.stage] || 0;
            for (const n of [1, 2, 3]) {
                if (this.stages[n].state === 'running' || this.stages[n].state === 'waiting') continue;
                if (st >= n) this._setStage(n, 'done', this.stages[n].state === 'done' && this.stages[n].detail ? this.stages[n].detail : `done (server record: ${this.module.stage_label || this.module.stage})`);
                else if (this.stages[n].state !== 'failed') this._setStage(n, 'idle', '');
            }
        }

        // ---------------------------------------------------------------- devices

        async _devices() {
            try { return await this.usb.getDevices(); } catch (e) { return []; }
        }

        async _isConnected(u) { return !!u && (await this._devices()).includes(u); }

        _sameBoard(u) {
            const s = normalizeSerial(u && u.serialNumber);
            return !s || !this.serial || s === this.serial;
        }

        _offer(u) {
            for (const w of [...this._waiters]) w.offer(u);
        }

        /**
         * Wait for a device matching `match` (connect events, polling getDevices, or a device the operator
         * picks after onNeed). Resolves with the USBDevice.
         */
        _waitForDevice({ match, timeoutMs, need, needAfterMs, what }) {
            return new Promise((resolve, reject) => {
                let done = false;
                let timer = null;
                let needTimer = null;
                const waiter = {
                    match,
                    offer: (u) => { if (!done && u && match(u)) finish(resolve, u); },
                    cancel: (err) => finish(reject, err || new FlowAbort()),
                };
                const finish = (fn, v) => {
                    if (done) return;
                    done = true;
                    clearTimeout(timer);
                    clearTimeout(needTimer);
                    this._waiters.delete(waiter);
                    if (need) this.hooks.onNeed(null, {});
                    fn(v);
                };
                this._waiters.add(waiter);
                if (timeoutMs) timer = setTimeout(() => finish(reject, new Error(`timed out after ${Math.round(timeoutMs / 1000)} s waiting for ${what || 'the board'}`)), timeoutMs);
                if (need) {
                    const show = () => { if (!done) this.hooks.onNeed(need, { what }); };
                    if (!needAfterMs) show(); else needTimer = setTimeout(show, needAfterMs);
                }
                (async () => {
                    while (!done) {
                        for (const u of await this._devices()) waiter.offer(u);
                        if (done) break;
                        await sleep(this.opt.pollMs);
                    }
                })();
            });
        }

        _cancelWaiters(err) { for (const w of [...this._waiters]) w.cancel(err); }

        async _sleep(ms) {
            if (this.aborted) throw new FlowAbort();
            await new Promise((resolve) => {
                const t = setTimeout(() => { this._sleepers.delete(s); resolve(); }, ms);
                const s = () => { clearTimeout(t); resolve(); };
                this._sleepers.add(s);
            });
            if (this.aborted) throw new FlowAbort();
        }

        /** User gesture: pick a device in Chrome's chooser (rpiboot + fastboot filters) and hand it to a waiting stage. */
        async selectDevice(filters) {
            let u;
            try {
                u = await this.usb.requestDevice({ filters: filters || USB_FILTERS });
            } catch (e) {
                if (e && e.name === 'NotFoundError') return null; // chooser closed
                throw e;
            }
            const waiting = this._waiters.size;
            this._offer(u);
            if (waiting && this._waiters.size === waiting) this.log('warn', `The selected device (${u.productName || 'USB'} ${u.serialNumber || ''}) is not the one this stage waits for`);
            return u;
        }

        /** User gesture: "Connect fastboot gadget". */
        async connectFastboot() {
            return this.selectDevice(OTP.fastboot.FILTERS);
        }

        // ---------------------------------------------------------------- connect / identify

        /** "Connect board": Chrome's chooser, then attach(). Returns the module or null when the chooser was closed. */
        async connectBoard() {
            if (!this.usb) throw new Error('WebUSB is not available in this browser');
            let u;
            try {
                u = await this.usb.requestDevice({ filters: USB_FILTERS });
            } catch (e) {
                if (e && e.name === 'NotFoundError') return null;
                throw e;
            }
            return this.attach(u);
        }

        /** Probe a device (ROM / second stage / fastboot gadget) and fetch or create its server record. */
        async attach(u) {
            if (!this.api || !this.api.available) throw new Error('the server is not reachable: use "Advanced (manual)" below');
            if (this.running) throw new Error('a provisioning run is in progress');
            this._rejectedFastboot = null;   // an explicit "Connect board" starts a fresh selection
            for (const n of [1, 2, 3]) this._setStage(n, 'idle', '');
            if (isFastbootDevice(u)) {
                const client = new FastbootClient(u);
                client.log = (l, m) => this.log(l === 'info' ? 'debug' : l, m);
                try {
                    await client.open();
                    const id = await this._fastbootIdentity(client);
                    const r = await this.api.identify(id);
                    this.probeInfo = { kind: 'fastboot', serialno: id.serialno, vars: id.vars };
                    this._setModule(r.module);
                    this.log('ok', `Fastboot gadget ${id.serialno} → board ${r.module.serial} (${r.created ? 'new record' : r.module.stage_label || r.module.stage})`);
                } finally {
                    await client.close();
                }
                this._setDevice(u, 'fastboot');
            } else if (isRpiboot(u)) {
                const dev = new RpiDevice(u);
                try {
                    await dev.open();
                } finally {
                    await dev.close();
                }
                if (!dev.chip || dev.chip.name !== 'BCM2712') throw new Error(`${dev.chip ? dev.chip.name : 'unknown chip'}: the server flow provisions Raspberry Pi 5 / CM5 (BCM2712) only; use Advanced (manual)`);
                const serial = normalizeSerial(dev.serial || u.serialNumber);
                if (!serial) throw new Error(`the board reported no usable USB serial ("${dev.serial || u.serialNumber || ''}")`);
                const body = {
                    serial,
                    chip: dev.chip.name,
                    board: dev.chip.board,
                    usb: { vendor_id: u.vendorId, product_id: u.productId, product_name: u.productName || '', manufacturer: u.manufacturerName || '', serial_number: u.serialNumber || '' },
                    rom_stage: dev.iSerial === null ? 'unknown' : dev.isRomStage ? 'rom' : 'second-stage',
                };
                this.probeInfo = { kind: 'rpiboot', serial, iSerial: dev.iSerial, rom: dev.isRomStage, chip: dev.chip };
                const r = await this.api.hello(body);
                this._setModule(r.module);
                this.log('ok', `Board ${serial} (${dev.chip.name}, ${dev.stageName}): ${r.created ? 'new record, secrets generated' : r.module.stage_label || r.module.stage}`);
                this._setDevice(u, 'rpiboot');
            } else {
                throw new Error(`not a Raspberry Pi boot device or fastboot gadget (${(u.vendorId || 0).toString(16)}:${(u.productId || 0).toString(16)})`);
            }
            this._stagesFromModule();
            return this.module;
        }

        async _fastbootIdentity(client) {
            const serialno = clean(await client.getvarText('serialno'));
            if (!normalizeSerial(serialno)) throw new Error(`the fastboot gadget reports an unusable serial "${serialno}"`);
            const vars = await client.getvars(FASTBOOT_VARS);
            return { serialno, vars };
        }

        /** Stages that still have to run for the current board and device. */
        /** The scenario the operator picked on the page ("open" | "secure"), or "" when none is set. */
        scenario() {
            const s = typeof this.opt.scenario === 'function' ? this.opt.scenario() : this.opt.scenario;
            return s === 'open' || s === 'secure' ? s : '';
        }

        /**
         * The picked scenario differs from the one the board's stages ran in (module.mode: the chosen one, or
         * the server's default for a board without a choice) on a board with progress: every stage is redone.
         */
        scenarioChanges() {
            const want = this.scenario();
            const m = this.module;
            return !!(m && want && m.mode && m.mode !== want && (STAGE_INDEX[m.stage] || 0) > 0);
        }

        plan() {
            if (!this.module) return [];
            if (this.scenarioChanges()) return [1, 2, 3];
            const st = STAGE_INDEX[this.module.stage] || 0;
            if (st >= 3) return [];
            // A board that runs the gadget has done stage 2 -- unless the server just reset it to "new" (a
            // scenario switch): then every stage is redone, starting in RPIBOOT mode.
            if (this.deviceKind === 'fastboot') return st >= 1 ? [3] : [1, 2, 3];
            return st >= 1 ? [2, 3] : [1, 2, 3];
        }

        _confirmWanted() {
            if (this.opt.confirmIrreversible !== null) return !!this.opt.confirmIrreversible;
            const s = this.api && this.api.lastStatus;
            const p = s && s.config && s.config.provisioning;
            return !(p && p.confirm_irreversible === false);
        }

        /** Ask once per run for every irreversible item that was not confirmed yet in this run (ids carry the board serial). */
        async _confirm(items) {
            const todo = items.filter((it) => !this._confirmed.has(it.id));
            if (!todo.length || !this._confirmWanted()) { for (const it of todo) this._confirmed.add(it.id); return; }
            const ok = await this.hooks.onConfirm({
                what: `These steps permanently change board ${this.serial}:`,
                flags: todo.map((it) => ({ key: `stage ${it.stage}: ${it.key}`, value: it.value, why: it.why })),
                token: this.serial,
            });
            if (!ok) throw new FlowCancelled('irreversible steps not confirmed');
            for (const it of todo) this._confirmed.add(it.id);
        }

        _irreversibleOf(n, manifest) {
            return ((manifest && manifest.irreversible) || []).map((f) => ({
                id: `${this.serial}|${n}|${f.key}|${f.value}`, stage: n, key: f.key, value: f.value === '' || f.value === undefined ? undefined : f.value, why: f.why || '',
            }));
        }

        // ---------------------------------------------------------------- running

        /** Run the given stages (default: plan()) in order; stops at the first failure. Returns true when all succeeded. */
        /** Tell the server which scenario this board is provisioned in (the operator's choice on the page). */
        async _applyScenario() {
            const want = this.scenario();
            if (!want || !this.module) return;
            if (this.module.mode_locked && want !== 'secure') {
                throw new Error(`board ${this.serial}: its OTP holds a key hash (secure boot is on), so only the secure scenario is possible`);
            }
            if (this.module.mode_chosen === want) return;
            const before = this.module.stage;
            const r = await this.api.setMode(this.serial, want);
            this._setModule(r.module);
            const reset = before !== 'new' && r.module && r.module.stage === 'new';
            this.log('info', `Board ${this.serial}: ${want} scenario${reset ? ' (every stage is redone, starting with stage 1)' : ''}`);
        }

        async provision(stages) {
            if (this.running) throw new Error('a provisioning run is already in progress');
            if (!this.module) throw new Error('connect a board first');
            await this._applyScenario();
            const list = stages || this.plan();
            if (!list.length) {
                this.log('ok', `Board ${this.serial} is already provisioned (${this.module.stage_label || this.module.stage}); use a stage's Run button to repeat it`);
                return true;
            }
            this.running = true;
            this.aborted = false;
            this._confirmed = new Set();
            this.hooks.onBusy(true);
            this.log('info', `=== Provisioning ${this.serial}: stage${list.length > 1 ? 's' : ''} ${list.join(', ')} ===`);
            try {
                // one confirmation for the whole run, from the manifests the server can already give
                const early = [];
                for (const n of list) {
                    try {
                        const m = await this.api.stage(this.serial, n);
                        if (m && m.ready !== false) early.push(...this._irreversibleOf(n, m));
                    } catch (e) { /* the stage itself reports it */ }
                }
                try {
                    await this._confirm(early);
                } catch (e) {
                    this.log('info', 'Cancelled by the operator');
                    return false;
                }
                for (const n of list) {
                    if (!(await this._runStage(n))) return false;
                }
                this.log('ok', `=== Board ${this.serial}: ${this.module.stage_label || this.module.stage} ===`);
                return true;
            } finally {
                this.running = false;
                this.hooks.onBusy(false);
                this.hooks.onNeed(null, {});
            }
        }

        /** One stage on its own (per-stage Run button). */
        async runStage(n) { return this.provision([n]); }

        abort() {
            if (!this.running) return;
            this.aborted = true;
            this.log('warn', 'Aborting…');
            if (this.session) this.session.abort();
            this._cancelWaiters(new FlowAbort());
            for (const s of [...this._sleepers]) s();
            if (this.client) this.client.close();
        }

        async _runStage(n) {
            this._setStage(n, 'running', 'starting…');
            try {
                if (n === 3) await this._fastbootStage();
                else await this._rpibootStage(n);
                return true;
            } catch (e) {
                let msg;
                if (e instanceof FlowAbort || this.aborted) msg = 'aborted by the operator';
                else if (e instanceof FlowCancelled) msg = e.message;
                else if (isGone(e) || e instanceof DeviceGone) msg = `the board was disconnected during stage ${n}. Reconnect it in RPIBOOT mode (hold the power button while plugging in), click "Connect board", then "Provision" to resume from stage ${n}.`;
                else msg = errText(e);
                this.log('error', `Stage ${n} (${STAGE_TITLES[n]}) failed: ${msg}`);
                this._setStage(n, 'failed', msg, e && e.verdict ? { verdict: e.verdict } : {});
                return false;
            }
        }

        async _manifest(n) {
            let announced = null;
            for (;;) {
                if (this.aborted) throw new FlowAbort();
                const m = await this.api.stage(this.serial, n);
                if (m && m.ready !== false) return m;
                const job = m && m.job;
                const reason = (m && m.reason) || 'the server has no files for this stage yet';
                if (job && (job.status === 'queued' || job.status === 'running')) {
                    if (announced !== job.id) {
                        this.log('info', `Stage ${n}: waiting for the server (${reason}); job ${job.id} "${job.title || job.target}"`);
                        announced = job.id;
                    }
                    this._setStage(n, 'waiting', `waiting for the server: ${reason}`, { job });
                    this.hooks.onBuildWait(n, { reason, job });
                    await this._sleep(this.opt.buildPollMs);
                    continue;
                }
                throw new Error(job && job.status === 'failed' ? `${reason} (build job ${job.id} failed${job.error ? ': ' + job.error : ''})` : reason);
            }
        }

        /** The board in RPIBOOT mode: the current device if still valid, else the next enumeration. */
        async _rpibootDevice(n) {
            if (this.device && this.deviceKind === 'rpiboot' && !this.deviceStale && (await this._isConnected(this.device))) return this.device;
            this._setStage(n, 'waiting', 'waiting for the board in RPIBOOT mode…');
            const u = await this._waitRpiboot(this.deviceStale || this.deviceKind !== 'rpiboot' ? this.device : null);
            this._setDevice(u, 'rpiboot');
            return u;
        }

        _waitRpiboot(previous) {
            return this._waitForDevice({
                match: (u) => isRpiboot(u) && u !== previous && this._sameBoard(u),
                timeoutMs: this.opt.reenumTimeoutMs,
                need: 'rpiboot',
                needAfterMs: this.opt.needDeviceAfterMs,
                what: `board ${this.serial} to re-enumerate (RPIBOOT)`,
            });
        }

        async _rpibootStage(n) {
            const manifest = await this._manifest(n);
            if (manifest.kind && manifest.kind !== 'rpiboot') throw new Error(`stage ${n}: unexpected manifest kind "${manifest.kind}"`);
            await this._confirm(this._irreversibleOf(n, manifest));
            const usb = await this._rpibootDevice(n);
            this._setStage(n, 'running', `${manifest.title || STAGE_TITLES[n]} · ${manifest.mode || ''} · ${(manifest.files || []).length} files`);
            const bootDir = OTP.BootDir.fromManifest(manifest, {
                fetchBytes: (url, p) => this.api.fetchBytes(url, p),
                onFetch: (name, got, total) => this.hooks.onProgress(n, { label: `${name} from server`, sent: got, total }),
            });
            const session = new RpiBootSession(bootDir, {
                log: (l, m) => this.log(l, m),
                onProgress: (name, s, t) => this.hooks.onProgress(n, { label: name, sent: s, total: t }),
                usb: this.usb,
                idleTimeoutMs: this.opt.fileServerIdleMs,
                retryMs: this.opt.fileServerRetryMs,
            });
            this.session = session;
            let out = null;
            let error = null;
            try {
                out = await runSession(session, usb, (prev) => this._waitRpiboot(prev), {
                    log: (l, m) => this.log(l, m),
                    settleMs: this.opt.rpibootSettleMs,
                    onDevice: (u) => this._setDevice(u, 'rpiboot'),
                });
            } catch (e) {
                error = this.aborted ? new FlowAbort() : e;
            } finally {
                this.session = null;
            }
            // Stale only once the board was handed control (second stage written, file server answered, or the run
            // finished): it re-enumerates and this USBDevice goes away. A run that failed before that (missing file,
            // server error, ...) leaves the board waiting in the same enumeration, and a retry must reuse it.
            this.deviceStale = !!(out || session.handedOff);
            const r = out ? out.result : { metadata: session.metadata, filesServed: session.filesServed, interrupted: false };
            const collected = Object.keys(r.metadata || {}).length || r.filesServed.length;
            if (error && !collected) throw error;
            const body = {
                ok: !error,
                metadata: r.metadata || {},
                files_served: r.filesServed.map((f) => ({ name: f.name, size: f.size })),
                interrupted: !!r.interrupted,
                error: error ? errText(error) : null,
                expect: manifest.expect || { secure_boot_provision: false, customer_key_hash: null },
            };
            const res = await this.api.result(this.serial, n, body);
            this._setModule(res.module);
            const verdict = res.verdict || { ok: false, notes: ['no verdict from the server'] };
            if (error) throw error;
            if (!verdict.ok) {
                const e = new Error(`the server did not accept the result: ${verdict.notes.join(' ') || 'no details'}`);
                e.verdict = verdict;
                throw e;
            }
            const notes = this._calmNotes(n, verdict.notes, r);
            const shown = Object.assign({}, verdict, { notes });
            this._setStage(n, 'done', this._doneSummary(n, r), { verdict: shown, metadata: r.metadata, filesServed: r.filesServed });
            this.log('ok', `Stage ${n} (${STAGE_TITLES[n]}) done`);
            for (const note of notes) this.log('info', `Stage ${n}: ${note}`);
        }

        /** The board leaving USB right after boot.img is the hand-off to the gadget ramdisk, not a problem. */
        _expectedHandoff(n, r) {
            return n === 2 && !!r.interrupted && (r.filesServed || []).some((f) => String(f.name).toLowerCase() === 'boot.img');
        }

        /** Server notes of an accepted stage, shown as information; a generic "interrupted" note is explained. */
        _calmNotes(n, notes, r) {
            const out = [];
            for (const note of notes || []) {
                let t = String(note);
                if (/^run was interrupted$/i.test(t.trim()) && this._expectedHandoff(n, r)) t = 'the board left USB after boot.img (expected: the fastboot gadget took over)';
                if (!out.includes(t)) out.push(t);
            }
            return out;
        }

        _doneSummary(n, r) {
            const files = (r.filesServed || []).length;
            const meta = Object.keys(r.metadata || {}).length;
            if (n === 2) return this._expectedHandoff(n, r) ? 'boot.img delivered; the board is booting the fastboot gadget' : `${files} file${files === 1 ? '' : 's'} served`;
            const eeprom = r.metadata && r.metadata.EEPROM_UPDATE;
            return `${eeprom ? 'EEPROM_UPDATE = ' + eeprom + ' · ' : ''}${meta} metadata field${meta === 1 ? '' : 's'}, ${files} file${files === 1 ? '' : 's'} served`;
        }

        async _fastbootUsb() {
            // Reuse the current gadget only if it is this board's and was not refused by the serialno check
            // (a refused foreign gadget would otherwise be picked again on every retry).
            if (this.device && this.deviceKind === 'fastboot' && this.device !== this._rejectedFastboot
                && this._sameBoard(this.device) && (await this._isConnected(this.device))) return this.device;
            this._setStage(3, 'waiting', 'waiting for the fastboot gadget: click "Connect fastboot gadget" and pick it in Chrome\'s list (it appears once Linux has booted, ~20 s)');
            this.log('info', 'Waiting for the fastboot gadget (USB 18d1:4e40 "Raspberry Pi")…');
            const u = await this._waitForDevice({
                match: (d) => isFastbootDevice(d) && d !== this._rejectedFastboot && this._sameBoard(d),
                timeoutMs: this.opt.fastbootTimeoutMs,
                need: 'fastboot',
                needAfterMs: 0,
                what: `the fastboot gadget of board ${this.serial}`,
            });
            this._setDevice(u, 'fastboot');
            return u;
        }

        async _fetchVerified(item, onProgress) {
            const data = await this.api.fetchBytes(item.url, onProgress);
            if (item.size !== undefined && item.size !== null && data.byteLength !== item.size) throw new Error(`${item.name}: server sent ${data.byteLength} bytes, manifest says ${item.size}`);
            if (item.sha256) {
                const h = await OTP.BootDir.sha256Hex(data);
                if (h !== String(item.sha256).toLowerCase()) throw new Error(`${item.name}: SHA-256 mismatch`);
            }
            return data;
        }

        async _fastbootStage() {
            const usb = await this._fastbootUsb();
            this._setStage(3, 'running', 'identifying the fastboot gadget…');
            const client = new FastbootClient(usb);
            client.log = (l, m) => this.log(l, m);
            client.eraseSettleMs = this.opt.eraseSettleMs;
            this.client = client;
            let details = { flashed: [], crypt: [], device_key_pem: null };
            let posted = false;
            const want = this.serial; // the board this run is for; identify() below would switch this.serial
            try {
                await client.open();
                const id = await this._fastbootIdentity(client);
                // getvar:serialno is authoritative (the USB iSerial may be missing or unusable): refuse a foreign
                // gadget before the server creates or touches a record for it
                if (want && normalizeSerial(id.serialno) !== want) {
                    posted = true; // nothing ran on this board; the server record of `want` is left alone
                    // forget the foreign gadget so a retry asks for (and waits for) the right one
                    this._rejectedFastboot = usb;
                    this.device = null;
                    this.deviceKind = null;
                    this.hooks.onDevice(null, 'fastboot');
                    throw new Error(`the fastboot gadget belongs to board ${normalizeSerial(id.serialno)}, not ${want}; connect the gadget of board ${want}`);
                }
                const idr = await this.api.identify(id);
                this._setModule(idr.module);
                this.log('ok', `Fastboot gadget: serialno ${id.serialno}, ${id.vars.product || ''} ${id.vars['version-fastbootd'] ? 'fastbootd ' + id.vars['version-fastbootd'] : ''}`);

                const manifest = await this._manifest(3);
                if (manifest.kind && manifest.kind !== 'fastboot-idp') throw new Error(`stage 3: unexpected manifest kind "${manifest.kind}"`);
                await this._confirm(this._irreversibleOf(3, manifest));
                if (this.aborted) throw new FlowAbort();
                const img = manifest.image || {};
                this._setStage(3, 'running', `${img.name || 'image'} ${img.version || ''} → ${manifest.storage_device || 'mmcblk0'}${img.encrypted ? ' (LUKS2)' : ''}`);
                const imageJson = await this._fetchVerified(manifest.image_json);
                if (manifest.key_export) {
                    details.device_key_pem = await this._exportDeviceKey(client, manifest.key_export);
                    this._setStage(3, 'running', `${img.name || 'image'} ${img.version || ''} → ${manifest.storage_device || 'mmcblk0'}${img.encrypted ? ' (LUKS2)' : ''}`);
                }
                const postKey = async (pem) => {
                    details.device_key_pem = pem;
                    try {
                        const f = await this.api.facts(this.serial, { device_key_pem: pem, duid: id.serialno });
                        this._setModule(f.module);
                    } catch (e) { this.log('warn', `Could not store the device key: ${errText(e)}`); }
                };
                if (manifest.fwcrypto_init === false) {
                    const pem = await client.publicKey();
                    if (pem) await postKey(pem);
                }
                const total = manifest.total_bytes || 0;
                const res = await client.idpProvision({
                    imageJson,
                    parts: manifest.parts || {},
                    readPiece: (p, prog) => this._fetchVerified(p, prog),
                    storageDevice: manifest.storage_device || 'mmcblk0',
                    erase: manifest.erase !== false,
                    fwcryptoInit: manifest.fwcrypto_init !== false,
                    crypt: manifest.crypt || [],
                    reboot: true,
                    totalBytes: total,
                    onDeviceKey: postKey,
                    log: (l, m) => this.log(l, m),
                    onProgress: (p) => {
                        const label = p.phase === 'fetch' ? `${p.piece}: from server${p.fetchTotal ? ' ' + Math.round((100 * p.fetched) / p.fetchTotal) + '%' : ''}`
                            : p.phase === 'download' ? `${p.piece} → ${p.dev}`
                                : p.phase || '';
                        this.hooks.onProgress(3, { label, sent: p.sent, total: p.total });
                    },
                });
                details = { flashed: res.flashed, crypt: res.crypt, device_key_pem: res.device_key_pem || details.device_key_pem };
                posted = true;
                const rr = await this.api.result(this.serial, 3, { ok: true, error: null, details });
                this._setModule(rr.module);
                const verdict = rr.verdict || { ok: true, notes: [] };
                if (!verdict.ok) {
                    const e = new Error(`the server did not accept the result: ${verdict.notes.join(' ')}`);
                    e.verdict = verdict;
                    throw e;
                }
                const summary = `${res.flashed.map((f) => `${f.simage} → ${f.dev}`).join(', ')}${res.crypt.length ? `; recovery passphrase on ${res.crypt.map((c) => c.dev).join(', ')}` : ''}; rebooting`;
                this._setStage(3, 'done', summary, { verdict });
                this.log('ok', `Stage 3 (Image) done: ${summary}`);
                this.deviceStale = true;
            } catch (e) {
                if (!posted) {
                    posted = true;
                    try {
                        const rr = await this.api.result(this.serial, 3, { ok: false, error: errText(this.aborted ? new FlowAbort() : e), details });
                        this._setModule(rr.module);
                    } catch (e2) { this.log('warn', `Could not report the failure to the server: ${errText(e2)}`); }
                }
                throw e;
            } finally {
                this.client = null;
                await client.close();
            }
        }
    }

    /**
     * Secure scenario, first thing in stage 3 (before anything is erased): fetch the OTP device key the
     * gadget exports and hand it to the server, which checks it against the board's public key and keeps
     * it. Returns the board's public key PEM.
     */
    Flow.prototype._exportDeviceKey = async function (client, keyExport) {
        this._setStage(3, 'running', 'exporting the OTP device key…');
        const r = await client.exportDeviceKey(keyExport, { log: (l, m) => this.log(l, m), timeoutMs: this.opt.keyExportTimeoutMs });
        const pem = await client.publicKey();
        if (!pem) throw new Error('the gadget exported a device key but getvar:public-key returned none');
        const res = await this.api.deviceKey(this.serial, { key_der_b64: toBase64(r.der), device_key_pem: pem });
        this._setModule(res.module);
        const dk = res.device_key || {};
        this.log('ok', `OTP device key ${dk.already ? 'was already on the server' : 'stored on the server'} (${String(dk.fingerprint || '').slice(0, 16)})`);
        if (dk.zero_words) this.log('warn', `${dk.zero_words} of the 8 OTP words of the device key are zero: its generation was probably interrupted (power loss?)`);
        return pem;
    };

    Flow.STAGE_TITLES = STAGE_TITLES;
    Flow.STAGE_INDEX = STAGE_INDEX;
    Flow.FASTBOOT_VARS = FASTBOOT_VARS;
    Flow.FlowAbort = FlowAbort;
    Flow.FlowCancelled = FlowCancelled;
    OTP.Flow = Flow;
})();
