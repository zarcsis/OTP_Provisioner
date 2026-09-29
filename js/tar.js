/*
 * tar.js — minimal reader for bootfiles.bin.
 *
 * rpiboot packages the second-stage bootloader, firmware and default config
 * files for each SoC in a plain POSIX tar (bootfiles.bin) so that they stay
 * in sync (see usbboot/bootfiles.c). We only need "find an entry by name",
 * compared case-insensitively exactly like the C code (strcasecmp).
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});
    const BLOCK = 512;
    const dec = new TextDecoder('latin1');

    function cstr(bytes, off, max) {
        let end = off;
        const lim = Math.min(bytes.length, off + max);
        while (end < lim && bytes[end] !== 0) end++;
        return dec.decode(bytes.subarray(off, end));
    }

    function parseOctal(bytes, off, len) {
        const s = cstr(bytes, off, len).trim();
        if (s === '') return 0;
        const v = parseInt(s, 8);
        return Number.isFinite(v) ? v : 0;
    }

    /** List entries: [{name, size, offset}] (offset = start of file data). */
    function list(buffer) {
        const b = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const out = [];
        let off = 0;
        while (off + BLOCK <= b.length) {
            // an all-zero header block ends the archive
            let zero = true;
            for (let i = 0; i < BLOCK; i++) if (b[off + i] !== 0) { zero = false; break; }
            if (zero) break;
            let name = cstr(b, off, 100);
            const size = parseOctal(b, off + 124, 12);
            const magic = cstr(b, off + 257, 6);
            if (magic === 'ustar') {
                const prefix = cstr(b, off + 345, 155);
                if (prefix) name = prefix + '/' + name;
            }
            const typeflag = b[off + 156];
            const dataOff = off + BLOCK;
            if (dataOff + size > b.length) throw new Error('tar: corrupted archive (entry "' + name + '" exceeds archive size)');
            if (typeflag === 0 || typeflag === 0x30 /* '0' regular */ || typeflag === 0x37 /* '7' contiguous */) {
                out.push({ name, size, offset: dataOff });
            }
            off = dataOff + Math.ceil(size / BLOCK) * BLOCK;
        }
        return out;
    }

    /** Find an entry by name (case-insensitive, like strcasecmp); returns a Uint8Array view or null. */
    function find(buffer, name) {
        const b = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const want = String(name).toLowerCase();
        for (const e of list(b)) {
            if (e.name.toLowerCase() === want) return b.subarray(e.offset, e.offset + e.size);
        }
        return null;
    }

    OTP.tar = { list, find };
})();
