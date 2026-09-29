/*
 * registry.js — the station's memory of modules it has seen.
 *
 * In the real system this is the server database (module state changes only
 * on evidence coming back from the module: metadata after stage 1, the
 * agent's self-check after stage 2, the first-boot report after stage 3).
 * The demo keeps the same shape in localStorage of this browser profile.
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});
    const KEY = 'otp_provisioner.registry.v1';

    const STAGES = {
        new: 'New (serial seen)',
        'otp-burned': 'Stage 1 done: OTP / EEPROM',
        'agent-booted': 'Stage 2 done: agent booted',
        flashed: 'Stage 3 done: image written',
    };
    const STAGE_ORDER = ['new', 'otp-burned', 'agent-booted', 'flashed'];

    function load() {
        try {
            const raw = localStorage.getItem(KEY);
            return raw ? JSON.parse(raw) : {};
        } catch (e) {
            return {};
        }
    }

    function save(db) {
        try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) { /* quota / private mode */ }
    }

    const registry = {
        STAGES,
        all() {
            const db = load();
            return Object.values(db).sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''));
        },
        get(serial) { return load()[serial] || null; },
        /** Create or update a module record; `stage` only ever advances. */
        upsert(serial, patch) {
            if (!serial) return null;
            const db = load();
            const now = new Date().toISOString();
            const rec = db[serial] || { serial, firstSeen: now, stage: 'new', metadata: {}, events: [] };
            const prevStage = rec.stage || 'new';
            const prevMetadata = rec.metadata || {};
            const { stage: nextStage, metadata: newMetadata, ...rest } = patch;
            Object.assign(rec, rest, { lastSeen: now });
            if (nextStage) {
                const cur = STAGE_ORDER.indexOf(prevStage);
                const nxt = STAGE_ORDER.indexOf(nextStage);
                rec.stage = STAGE_ORDER[Math.max(cur, nxt, 0)];
            }
            if (newMetadata) rec.metadata = Object.assign({}, prevMetadata, newMetadata);
            db[serial] = rec;
            save(db);
            return rec;
        },
        addEvent(serial, kind, note) {
            if (!serial) return;
            const db = load();
            const rec = db[serial];
            if (!rec) return;
            rec.events.push({ t: new Date().toISOString(), kind, note: note || '' });
            if (rec.events.length > 50) rec.events.splice(0, rec.events.length - 50);
            save(db);
        },
        exportJson() { return JSON.stringify(load(), null, 2); },
        clear() { localStorage.removeItem(KEY); },
    };

    OTP.registry = registry;
})();
