/*
 * server.js — client for the OTP_Provisioner HTTP API (same origin).
 *
 * OTP.api is the default instance (window.fetch / window.EventSource);
 * OTP.createApi({fetch, EventSource, base}) builds another one (tests inject
 * fakes). All calls return parsed JSON and throw ApiError {status, detail}
 * on HTTP errors, except stage() which resolves the 409 "not ready" body
 * ({ready:false, reason, job}) so the caller can wait for a build.
 *
 * OTP.api.available is false when the page is opened from file:// or the
 * server did not answer /api/status; the page then only says how to start it.
 */
(function () {
    'use strict';
    const OTP = (window.OTP = window.OTP || {});

    class ApiError extends Error {
        constructor(status, detail, body) {
            super(detail ? `${detail} (HTTP ${status})` : `HTTP ${status}`);
            this.name = 'ApiError';
            this.status = status;
            this.detail = detail || '';
            this.body = body;
        }
    }

    const enc = encodeURIComponent;

    function createApi(opts) {
        opts = opts || {};
        const fetchFn = opts.fetch || ((...a) => window.fetch(...a));
        const EventSourceCls = opts.EventSource || window.EventSource;
        const base = opts.base || '';

        async function parseBody(res) {
            const text = await res.text();
            if (!text) return null;
            try { return JSON.parse(text); } catch (e) { return { detail: text.slice(0, 500) }; }
        }

        function detailOf(body) {
            if (!body) return '';
            const d = body.detail !== undefined ? body.detail : body.reason;
            if (typeof d === 'string') return d;
            if (Array.isArray(d)) return d.map((x) => (x && x.msg) || JSON.stringify(x)).join('; ');
            return d ? JSON.stringify(d) : '';
        }

        async function request(method, path, body, { allow } = {}) {
            const init = { method, headers: { Accept: 'application/json' }, cache: 'no-store' };
            if (body !== undefined) {
                init.headers['Content-Type'] = 'application/json';
                init.body = JSON.stringify(body);
            }
            let res;
            try {
                res = await fetchFn(base + path, init);
            } catch (e) {
                api.available = false;
                throw new ApiError(0, `server not reachable: ${e.message || e}`);
            }
            const data = await parseBody(res);
            if (res.ok || (allow && allow.includes(res.status))) return data;
            throw new ApiError(res.status, detailOf(data), data);
        }

        const api = {
            available: false,
            lastStatus: null,
            ApiError,

            /** GET /api/status; also sets `available`. Returns the status or null. */
            async probe() {
                if (typeof location !== 'undefined' && location.protocol === 'file:' && !opts.fetch) {
                    api.available = false;
                    return null;
                }
                try {
                    const s = await request('GET', '/api/status');
                    api.available = !!(s && s.version !== undefined);
                    api.lastStatus = api.available ? s : null;
                    return api.lastStatus;
                } catch (e) {
                    api.available = false;
                    return null;
                }
            },
            async status() { const s = await request('GET', '/api/status'); api.available = true; api.lastStatus = s; return s; },
            modules() { return request('GET', '/api/modules'); },
            hello(body) { return request('POST', '/api/modules/hello', body); },
            module(serial) { return request('GET', `/api/modules/${enc(serial)}`); },
            /** Stage manifest, or {ready:false, reason, job} when the server answers 409. */
            async stage(serial, n) {
                const r = await request('GET', `/api/modules/${enc(serial)}/stage/${n}`, undefined, { allow: [409] });
                if (r && r.ready === undefined) r.ready = true;
                return r;
            },
            result(serial, n, body) { return request('POST', `/api/modules/${enc(serial)}/stage/${n}/result`, body); },
            facts(serial, body) { return request('POST', `/api/modules/${enc(serial)}/facts`, body); },
            /** Choose the provisioning scenario of a board: "open" | "secure". */
            setMode(serial, mode) { return request('POST', `/api/modules/${enc(serial)}/mode`, { mode }); },
            /** Hand over the OTP device key the gadget exported: {key_der_b64, device_key_pem}. */
            deviceKey(serial, body) { return request('POST', `/api/modules/${enc(serial)}/device-key`, body); },
            googleLogout() { return request('POST', '/api/google/logout', {}); },
            /** The image.* settings of the OS image: {settings, warnings} (no password or hash, only *_set flags). */
            imageSettings() { return request('GET', '/api/image'); },
            /** Save changed image settings; password/wifi_password: "" removes, a string sets. */
            saveImageSettings(body) { return request('POST', '/api/image', body); },
            /** The uploaded custom OS images (also in /api/status as custom_images). */
            customImages() { return request('GET', '/api/custom-images'); },
            prepareCustomImage(id, force) { return request('POST', `/api/custom-images/${enc(id)}/prepare`, { force: !!force }); },
            deleteCustomImage(id) { return request('DELETE', `/api/custom-images/${enc(id)}`); },
            /**
             * Upload a raw .img (a File) as the request body, with progress: onProgress(sent, total).
             * Resolves {image, new, job}; rejects with ApiError. Returns {promise, abort()}.
             */
            uploadCustomImage(file, onProgress) {
                const XHR = opts.XMLHttpRequest || window.XMLHttpRequest;
                const xhr = new XHR();
                const promise = new Promise((resolve, reject) => {
                    xhr.open('PUT', `${base}/api/custom-images?name=${enc(file.name || 'custom.img')}`);
                    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
                    xhr.setRequestHeader('Accept', 'application/json');
                    if (xhr.upload && onProgress) xhr.upload.onprogress = (e) => onProgress(e.loaded, e.lengthComputable ? e.total : file.size);
                    xhr.onload = () => {
                        let data = null;
                        try { data = xhr.responseText ? JSON.parse(xhr.responseText) : null; } catch (e) { data = { detail: String(xhr.responseText).slice(0, 500) }; }
                        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
                        else reject(new ApiError(xhr.status, detailOf(data), data));
                    };
                    xhr.onerror = () => reject(new ApiError(0, 'the upload failed (connection lost)'));
                    xhr.onabort = () => reject(new ApiError(0, 'the upload was cancelled'));
                    xhr.send(file);
                });
                return { promise, abort: () => xhr.abort() };
            },
            /**
             * Prepare the image file of a locked board for Raspberry Pi Imager; source: "" = the station image,
             * a custom image id, or null (the image.custom setting). Resolves the summary ({ready:true, name,
             * size, url, notes}) or the 409 body ({ready:false, reason, job}) while a part is being built.
             */
            async imagerImage(serial, source) {
                const r = await request('POST', `/api/modules/${enc(serial)}/imager-image`, { source: source === undefined ? null : source }, { allow: [409] });
                if (r && r.ready === undefined) r.ready = true;
                return r;
            },
            identify(body) { return request('POST', '/api/fastboot/identify', body); },
            builds() { return request('GET', '/api/builds'); },
            startBuild(target, force) { return request('POST', `/api/builds/${enc(target)}`, { force: !!force }); },
            jobs() { return request('GET', '/api/jobs'); },
            job(id) { return request('GET', `/api/jobs/${enc(id)}`); },

            /**
             * Follow a job log over SSE. onLine(line) per line (buffered lines are replayed first),
             * onDone({status, rc}) once. Returns {close()}.
             */
            jobLog(id, onLine, onDone) {
                if (!EventSourceCls) throw new Error('EventSource is not available');
                const es = new EventSourceCls(`${base}/api/jobs/${enc(id)}/log`);
                let finished = false;
                const finish = (info) => {
                    if (finished) return;
                    finished = true;
                    es.close();
                    if (onDone) onDone(info);
                };
                es.onmessage = (ev) => {
                    let line = ev.data;
                    try { const j = JSON.parse(ev.data); if (j && typeof j.line === 'string') line = j.line; } catch (e) { /* plain text */ }
                    if (onLine) onLine(line);
                };
                es.addEventListener('done', (ev) => {
                    let info = {};
                    try { info = JSON.parse(ev.data); } catch (e) { /* ignore */ }
                    finish(info);
                });
                es.onerror = () => {
                    // EventSource reconnects by itself (the server replays the buffer); give up once closed.
                    if (es.readyState === 2) finish({ status: 'disconnected' });
                };
                return { close() { finished = true; es.close(); } };
            },

            /** Download a file as a Uint8Array, reporting (received, total) while it streams. */
            async fetchBytes(url, onProgress) {
                let res;
                try {
                    res = await fetchFn(url.startsWith('http') ? url : base + url, { cache: 'no-store' });
                } catch (e) {
                    throw new ApiError(0, `download failed: ${e.message || e}`);
                }
                if (!res.ok) throw new ApiError(res.status, detailOf(await parseBody(res)) || `cannot download ${url}`);
                const total = Number(res.headers && res.headers.get && res.headers.get('Content-Length')) || 0;
                if (!res.body || !res.body.getReader) {
                    const buf = new Uint8Array(await res.arrayBuffer());
                    if (onProgress) onProgress(buf.byteLength, buf.byteLength);
                    return buf;
                }
                const reader = res.body.getReader();
                let out = total ? new Uint8Array(total) : null;
                const chunks = [];
                let got = 0;
                for (;;) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (out && got + value.byteLength <= out.byteLength) out.set(value, got);
                    else { if (out) { chunks.push(out.subarray(0, got)); out = null; } chunks.push(value); }
                    got += value.byteLength;
                    if (onProgress) onProgress(got, total || got);
                }
                if (out) return got === out.byteLength ? out : out.subarray(0, got);
                const all = new Uint8Array(got);
                let off = 0;
                for (const c of chunks) { all.set(c, off); off += c.byteLength; }
                return all;
            },
        };
        return api;
    }

    OTP.ApiError = ApiError;
    OTP.createApi = createApi;
    OTP.api = createApi();
})();
