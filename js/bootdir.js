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
 * Two sources are supported: a FileSystemDirectoryHandle from
 * window.showDirectoryPicker() (lazy reads, no size limit) and a FileList
 * from <input type="file" webkitdirectory> (fallback).
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

        /** Directory picked with the File System Access API. */
        static fromDirectoryHandle(handle) {
            const reader = async (relPath) => {
                const parts = relPath.split('/').filter(Boolean);
                let dir = handle;
                try {
                    for (let i = 0; i < parts.length - 1; i++) dir = await dir.getDirectoryHandle(parts[i]);
                    const fh = await dir.getFileHandle(parts[parts.length - 1]);
                    const file = await fh.getFile();
                    return new Uint8Array(await file.arrayBuffer());
                } catch (e) {
                    if (e && (e.name === 'NotFoundError' || e.name === 'TypeMismatchError')) return null;
                    throw e;
                }
            };
            const bd = new BootDir(handle.name, reader);
            bd._listTop = async () => {
                const out = [];
                for await (const [name, h] of handle.entries()) {
                    if (h.kind === 'file') {
                        const f = await h.getFile();
                        out.push({ name, size: f.size, kind: 'file' });
                    } else out.push({ name, size: 0, kind: 'dir' });
                }
                return out;
            };
            return bd;
        }

        /** Entries [{path, file}] with paths relative to the directory root ("2712/bootcode5.bin"). */
        static fromEntries(name, entries) {
            const map = new Map(entries.map((e) => [e.path.replace(/\\/g, '/'), e.file]));
            const reader = async (relPath) => {
                const f = map.get(relPath);
                if (!f) return null;
                return new Uint8Array(await f.arrayBuffer());
            };
            const bd = new BootDir(name, reader);
            bd._listTop = async () => {
                const out = [];
                const dirs = new Set();
                for (const [p, f] of map) {
                    const i = p.indexOf('/');
                    if (i < 0) out.push({ name: p, size: f.size, kind: 'file' });
                    else dirs.add(p.slice(0, i));
                }
                for (const d of dirs) out.push({ name: d, size: 0, kind: 'dir' });
                return out;
            };
            return bd;
        }

        /** FileList from <input type="file" webkitdirectory>. */
        static fromFileList(files) {
            const arr = Array.from(files);
            if (!arr.length) throw new Error('empty directory');
            const first = arr[0].webkitRelativePath || arr[0].name;
            const root = first.split('/')[0];
            const entries = arr.map((f) => {
                const rel = f.webkitRelativePath || f.name;
                const path = rel.startsWith(root + '/') ? rel.slice(root.length + 1) : rel;
                return { path, file: f };
            });
            return BootDir.fromEntries(root, entries);
        }

        static chipForProductId(pid) { return CHIPS[pid] || null; }

        async listTop() { return this._listTop ? this._listTop() : []; }

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

        /** main(): a boot directory must contain bootfiles.bin or a bootcode*.bin. */
        async validate() {
            const problems = [];
            const tar = await this.bootfiles();
            const hasBootcode = (await this.has('bootcode.bin')) || (await this.has('bootcode4.bin')) || (await this.has('bootcode5.bin'));
            if (!tar && !hasBootcode) problems.push("No 'bootfiles.bin' or 'bootcode*.bin' in the directory: rpiboot would refuse it.");
            return problems;
        }

        /** Parse the rpiboot-side config.txt (NOT the OS config.txt) into {text, keys}. */
        async configTxt() {
            const data = await this.readFile('config.txt');
            if (!data) return null;
            const text = new TextDecoder().decode(data);
            const keys = {};
            for (const raw of text.split(/\r?\n/)) {
                const line = raw.trim();
                if (!line || line.startsWith('#')) continue;
                const m = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
                if (m) keys[m[1]] = m[2].trim();
            }
            return { text, keys };
        }

        /** SHA-256 of a byte array, hex, via WebCrypto. */
        static async sha256Hex(bytes) {
            const digest = await crypto.subtle.digest('SHA-256', bytes);
            return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
        }
    }

    /**
     * Keys of the rpiboot config.txt that change the SoC or the EEPROM
     * permanently. The UI refuses to run a directory that sets any of them
     * without an explicit, typed confirmation.
     */
    const IRREVERSIBLE_KEYS = {
        program_pubkey: 'writes the SHA-256 of the customer public key into OTP: the SoC boots only firmware counter-signed with that key, forever',
        program_jtag_lock: 'permanently disables VideoCore JTAG',
        eeprom_write_protect: 'sets the EEPROM write-protect bit (permanent while /WP is pulled low)',
        revoke_devkey: 'revokes the development key in OTP',
        program_rpiboot_gpio: 'programs the nRPIBOOT GPIO selection into OTP',
    };

    OTP.BootDir = BootDir;
    OTP.CHIPS = CHIPS;
    OTP.IRREVERSIBLE_KEYS = IRREVERSIBLE_KEYS;
})();
