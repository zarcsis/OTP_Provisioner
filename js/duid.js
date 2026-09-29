/*
 * duid.js — decoder for the FACTORY_UUID metadata field.
 *
 * rpiboot receives the factory DUID from the bootloader as a list of 32-bit
 * hex words joined with "_"; each 16-bit half encodes three C40 characters
 * (Data Matrix C40 alphabet: digits and upper-case letters). This is a
 * line-by-line port of usbboot/decode_duid.c (duid_decode_c40), including
 * the C integer truncation semantics.
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});

    const C40_DIGIT0 = 4;   // char_to_c40('0')
    const C40_ALPHA0 = 14;  // char_to_c40('A')

    function c40ToChar(v) {
        if (v >= C40_DIGIT0 && v <= C40_DIGIT0 + 9) return String.fromCharCode(48 + v - C40_DIGIT0);
        if (v >= C40_ALPHA0 && v <= C40_ALPHA0 + 25) return String.fromCharCode(65 + v - C40_ALPHA0);
        return null;
    }

    function charToC40(ch) {
        const c = ch.toUpperCase();
        if (c >= '0' && c <= '9') return C40_DIGIT0 + (c.charCodeAt(0) - 48);
        if (c >= 'A' && c <= 'Z') return C40_ALPHA0 + (c.charCodeAt(0) - 65);
        return -1;
    }

    // decode_half_word(): one 16-bit value → three C40 indices (C truncating division)
    function decodeHalfWord(hw, out) {
        const a = Math.trunc((hw - 1) / 1600);
        out.push(a);
        hw -= a * 1600;
        const b = Math.trunc((hw - 1) / 40);
        out.push(b);
        hw -= b * 40;
        out.push(hw - 1);
    }

    // encode: inverse of decodeHalfWord (used by the self-test and handy for fixtures)
    function encodeC40(str) {
        const idx = Array.from(str, charToC40);
        if (idx.some((v) => v < 0) || idx.length % 3 !== 0) throw new Error('encodeC40: only [0-9A-Z], length multiple of 3');
        const halves = [];
        for (let i = 0; i < idx.length; i += 3) halves.push(idx[i] * 1600 + idx[i + 1] * 40 + idx[i + 2] + 1);
        const words = [];
        for (let i = 0; i < halves.length; i += 2) {
            const lo = halves[i];
            const hi = i + 1 < halves.length ? halves[i + 1] : 0;
            words.push((((hi << 16) | lo) >>> 0).toString(16));
        }
        return words.join('_');
    }

    /**
     * Decode "w1_w2_..." (hex words) into the printable DUID.
     * Returns null when a value is outside the C40 alphabet (the C code returns -1).
     */
    function decodeC40(wordsStr) {
        const list = [];
        for (const tok of String(wordsStr).split('_')) {
            if (tok === '') continue;
            const word = parseInt(tok, 16);
            if (!Number.isFinite(word) || word === 0) break; // strtoul → 0 stops the loop
            const w = word >>> 0;
            decodeHalfWord(w & 0xffff, list);
            const msig = w >>> 16;
            if (msig > 0) decodeHalfWord(msig, list);
        }
        let s = '';
        for (const v of list) {
            const ch = c40ToChar(v);
            if (ch === null) return null;
            s += ch;
        }
        return s;
    }

    OTP.duid = { decodeC40, encodeC40 };
})();
