/*
 * bootdir.js — the "boot directory" that rpiboot serves files from.
 *
 * Mirrors check_file() in usbboot/main.c:
 *   1. names containing ".." are refused (path traversal);
 *   2. if the directory holds bootfiles.bin (a tar), look for
 *      <dir>/<prefix>/<name> as an overlay first, then <prefix>/<name>
 *      inside the tar (case-insensitive);
 *   3. otherwise <dir>/<prefix>/<name>, then <dir>/<name>.
 * <prefix> is "2712" for BCM2712 (Pi 5 / CM5), "2711" for BCM2711 and
 * "2710" for the older SoCs.
 *
 * The files come from a stage manifest of the OTP_Provisioner server (fetched
 * lazily by name, size + SHA-256 checked): BootDir.fromManifest().
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});

    const CHIPS = {
        0x2763: { name: 'BCM2835', prefix: '2710', secondStage: 'bootcode.bin', board: 'Pi 1 / Zero / CM1' },
        0x2764: { name: 'BCM2836/BCM2837', prefix: '2710', secondStage: 'bootcode.bin', board: 'Pi 2 / Pi 3 / CM3' },
        0x2711: { name: 'BCM2711', prefix: '2711', secondStage: 'bootcode4.bin', board: 'Pi 4 / CM4' },
        0x2712: { name: 'BCM2712', prefix: '2712', secondStage: 'bootcode5.bin', board: 'Pi 5 / CM5 / Pi 500' },
    };

    class BootDir {
        constructor(name, reader) {
            this.name = name;
            this._read = reader;            // async (relPath) => Uint8Array|null
            this._tar = undefined;          // Uint8Array | null once loaded
            this._cache = new Map();
        }

        /**
         * A stage directory served by the OTP_Provisioner server: manifest = the stage-1/2 manifest
         * ({files: [{name, size, sha256, url}], mode, title, stage}). Files are fetched lazily by name,
         * once, and checked against the manifest's size and sha256.
         * opts.fetchBytes(url, onProgress) → Uint8Array (default OTP.api.fetchBytes); opts.onFetch(name, got, total).
         */
        static fromManifest(manifest, opts) {
            opts = opts || {};
            const fetchBytes = opts.fetchBytes || ((url, p) => OTP.api.fetchBytes(url, p));
            const files = new Map();
            for (const f of (manifest && manifest.files) || []) files.set(String(f.name).replace(/\\/g, '/').toLowerCase(), f);
            const pending = new Map();
            const reader = async (relPath) => {
                const key = String(relPath).toLowerCase();
                const f = files.get(key);
                if (!f) return null;
                if (!pending.has(key)) {
                    pending.set(key, (async () => {
                        const data = await fetchBytes(f.url, (got, total) => opts.onFetch && opts.onFetch(f.name, got, total));
                        if (typeof f.size === 'number' && data.byteLength !== f.size) {
                            throw new Error(`${f.name}: server sent ${data.byteLength} bytes, manifest says ${f.size}`);
                        }
                        if (f.sha256) {
                            const h = await BootDir.sha256Hex(data);
                            if (h !== String(f.sha256).toLowerCase()) throw new Error(`${f.name}: SHA-256 mismatch (got ${h.slice(0, 16)}…, manifest ${String(f.sha256).slice(0, 16)}…)`);
                        }
                        return data;
                    })());
                    pending.get(key).catch(() => pending.delete(key)); // allow a retry after a failed download
                }
                return pending.get(key);
            };
            const label = manifest ? `server stage ${manifest.stage || '?'}${manifest.mode ? ' (' + manifest.mode + ')' : ''}` : 'server';
            const bd = new BootDir(label, reader);
            bd.manifest = manifest;
            return bd;
        }

        static chipForProductId(pid) { return CHIPS[pid] || null; }

        async readFile(relPath) {
            if (this._cache.has(relPath)) return this._cache.get(relPath);
            const data = await this._read(relPath);
            if (data && data.byteLength <= 4 * 1024 * 1024) this._cache.set(relPath, data);
            return data;
        }

        async has(relPath) { return (await this.readFile(relPath)) !== null; }

        /** bootfiles.bin (tar) if present in the directory root. */
        async bootfiles() {
            if (this._tar === undefined) this._tar = await this._read('bootfiles.bin');
            return this._tar;
        }

        /**
         * check_file(): resolve a name the device asked for.
         * Returns {data, origin} or {denied, reason} or null. origin is a human-readable description.
         */
        async resolve(fname, chip) {
            if (fname.includes('..')) return { denied: true, reason: 'path traversal (..)' };
            if (fname.startsWith('/') || fname.startsWith('\\')) return { denied: true, reason: 'absolute path' };
            const prefix = chip.prefix;
            const tar = await this.bootfiles();
            if (tar) {
                const overlay = await this.readFile(prefix + '/' + fname);
                if (overlay) return { data: overlay, origin: `${this.name}/${prefix}/${fname} (bootfiles.bin overlay)` };
                const inTar = OTP.tar.find(tar, prefix + '/' + fname);
                if (inTar) return { data: inTar, origin: `bootfiles.bin:${prefix}/${fname}` };
            }
            const sub = await this.readFile(prefix + '/' + fname);
            if (sub) return { data: sub, origin: `${this.name}/${prefix}/${fname}` };
            const top = await this.readFile(fname);
            if (top) return { data: top, origin: `${this.name}/${fname}` };
            return null;
        }

        /** SHA-256 of a byte array, hex, via WebCrypto. */
        static async sha256Hex(bytes) {
            const digest = await crypto.subtle.digest('SHA-256', bytes);
            return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
        }
    }

    OTP.BootDir = BootDir;
    OTP.CHIPS = CHIPS;
})();
