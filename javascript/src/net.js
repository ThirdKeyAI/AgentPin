/**
 * Hardened HTTP fetching shared by every network resolver.
 *
 * Every outbound request made by this package goes through
 * `fetchJsonBounded`, which enforces the network defaults the spec and the
 * security review require (AP-7, AP-12, AP-13): redirects are never
 * followed, a request timeout bounds stalls, the response body is capped
 * both by Content-Length and while streaming, the response must carry a
 * JSON Content-Type, and error strings are generic (URL and failure class,
 * never transport detail).
 */

import { lookup as dnsLookup } from 'node:dns';
import { isIP } from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { AgentPinError, ErrorCode } from './types.js';

export const DEFAULT_TIMEOUT_MS = 10000;
export const DEFAULT_MAX_RESPONSE_BYTES = 1 << 20;

function isJsonContentType(value) {
    if (typeof value !== 'string') return false;
    const media = value.split(';')[0].trim().toLowerCase();
    return media === 'application/json' || media.endsWith('+json');
}

function fail(message) {
    return new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, message);
}

async function readBounded(response, url, maxBytes) {
    const body = response.body;
    if (body && typeof body.getReader === 'function') {
        const reader = body.getReader();
        const chunks = [];
        let total = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) {
                try { await reader.cancel(); } catch { /* ignore */ }
                throw fail(`Response from ${url} exceeds ${maxBytes} bytes`);
            }
            chunks.push(Buffer.from(value));
        }
        return Buffer.concat(chunks).toString('utf8');
    }
    // Stub responses without a stream: fall back to text()/json() with a cap.
    const text = typeof response.text === 'function'
        ? await response.text()
        : JSON.stringify(await response.json());
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
        throw fail(`Response from ${url} exceeds ${maxBytes} bytes`);
    }
    return text;
}

/**
 * GET `url` and return its parsed JSON body, or `null` on HTTP 404.
 *
 * Rejects redirects, non-success statuses, non-JSON content types and
 * bodies larger than `maxBytes`.
 *
 * @param {string} url
 * @param {object} [opts]
 * @param {Function} [opts.fetchImpl] - fetch implementation (default globalThis.fetch)
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.maxBytes]
 * @returns {Promise<any|null>}
 */
export async function fetchJsonBounded(url, opts = {}) {
    const fetchImpl = opts.fetchImpl || globalThis.fetch;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBytes = opts.maxBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    if (!fetchImpl) {
        throw fail('No fetch implementation available');
    }
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

    let response;
    try {
        response = await fetchImpl(url, {
            redirect: 'error',
            headers: { Accept: 'application/json' },
            signal: controller ? controller.signal : undefined,
        });
    } catch {
        if (timer) clearTimeout(timer);
        throw fail(`Failed to fetch ${url}`);
    }

    try {
        const status = Number(response.status);
        if (status >= 300 && status < 400) {
            throw fail(`Redirect rejected fetching ${url} (status ${status})`);
        }
        if (status === 404) {
            return null;
        }
        if (!(status >= 200 && status < 300)) {
            throw fail(`HTTP ${status} fetching ${url}`);
        }
        const headers = response.headers;
        const contentType = headers && typeof headers.get === 'function' ? headers.get('content-type') : null;
        if (!isJsonContentType(contentType)) {
            throw fail(`Response from ${url} is not application/json`);
        }
        const contentLength = headers && typeof headers.get === 'function' ? headers.get('content-length') : null;
        if (contentLength !== null && contentLength !== undefined && Number(contentLength) > maxBytes) {
            throw fail(`Response from ${url} exceeds ${maxBytes} bytes`);
        }
        let text;
        try {
            text = await readBounded(response, url, maxBytes);
        } catch (e) {
            if (e instanceof AgentPinError) throw e;
            throw fail(`Failed to read response from ${url}`);
        }
        try {
            return JSON.parse(text);
        } catch {
            throw fail(`Invalid JSON from ${url}`);
        }
    } finally {
        if (timer) clearTimeout(timer);
    }
}

// ---------------------------------------------------------------------------
// Fetching client-supplied URLs (SSRF guard)
// ---------------------------------------------------------------------------

function parseIpv4(s) {
    const parts = s.split('.');
    if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
    return parts.map(Number);
}

function parseIpv6(s) {
    let str = s.replace(/^\[|\]$/g, '').split('%')[0];
    let tail = [];
    const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(str);
    if (v4) {
        const o = parseIpv4(v4[1]);
        if (!o) return null;
        tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
        str = str.slice(0, -v4[1].length);
        if (str.endsWith(':') && !str.endsWith('::')) str = str.slice(0, -1);
    }
    const halves = str.split('::');
    if (halves.length > 2) return null;
    const toSegs = (h) => (h === '' ? [] : h.split(':').map((x) => (/^[0-9a-f]{1,4}$/i.test(x) ? parseInt(x, 16) : NaN)));
    const head = toSegs(halves[0]);
    const rest = halves.length === 2 ? toSegs(halves[1]) : [];
    const known = head.length + rest.length + tail.length;
    if ([...head, ...rest].some(Number.isNaN)) return null;
    if (halves.length === 1 && known !== 8) return null;
    if (halves.length === 2 && known > 7) return null;
    return [...head, ...new Array(8 - known).fill(0), ...rest, ...tail];
}

function v4NonPublic(o) {
    return o[0] === 127 // loopback
        || o[0] === 10 || (o[0] === 172 && (o[1] & 0xf0) === 16) || (o[0] === 192 && o[1] === 168) // private
        || (o[0] === 169 && o[1] === 254) // link-local
        || (o[0] === 192 && o[1] === 0 && o[2] === 2) // documentation
        || (o[0] === 198 && o[1] === 51 && o[2] === 100)
        || (o[0] === 203 && o[1] === 0 && o[2] === 113)
        || (o[0] >= 224 && o[0] <= 239) // multicast
        || o[0] === 0 // unspecified, "this network"
        || (o[0] === 100 && (o[1] & 0xc0) === 64) // CGNAT
        || (o[0] === 192 && o[1] === 0 && o[2] === 0) // IETF protocol assignments
        || (o[0] === 198 && (o[1] & 0xfe) === 18) // benchmarking
        || o[0] >= 240; // reserved, broadcast
}

/**
 * `true` for addresses a server-side fetch driven by a client-supplied URL
 * must never reach: loopback, private, link-local, CGNAT, multicast,
 * documentation, unspecified and reserved ranges (IPv4, IPv6 and
 * IPv4-mapped IPv6). Unparsable input counts as non-public.
 * @param {string} ip
 * @returns {boolean}
 */
export function isNonPublic(ip) {
    const v4 = parseIpv4(ip);
    if (v4) return v4NonPublic(v4);
    const s = parseIpv6(ip);
    if (!s) return true;
    if (s.slice(0, 5).every((x) => x === 0) && s[5] === 0xffff) {
        return v4NonPublic([s[6] >> 8, s[6] & 0xff, s[7] >> 8, s[7] & 0xff]);
    }
    const allZeroPrefix = s.slice(0, 7).every((x) => x === 0);
    return (allZeroPrefix && (s[7] === 0 || s[7] === 1)) // unspecified, loopback
        || (s[0] & 0xff00) === 0xff00 // multicast
        || (s[0] & 0xfe00) === 0xfc00 // unique local
        || (s[0] & 0xffc0) === 0xfe80 // link-local
        || (s[0] === 0x2001 && s[1] === 0x0db8) // documentation
        || (s[0] === 0x0064 && s[1] === 0xff9b); // NAT64
}

/** DNS lookup that drops non-public addresses and fails when none remain. */
function publicOnlyLookup(hostname, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = {};
    }
    const family = typeof options === 'number' ? options : (options.family || 0);
    dnsLookup(hostname, { all: true, family }, (e, addrs) => {
        if (e) return callback(e);
        const ok = addrs.filter((a) => !isNonPublic(a.address));
        if (ok.length === 0) {
            const err = new Error('host resolves only to non-public addresses');
            err.code = 'ENOTFOUND';
            return callback(err);
        }
        if (options.all) return callback(null, ok);
        return callback(null, ok[0].address, ok[0].family);
    });
}

/**
 * GET `url` with no redirects, a timeout and a byte cap, and return status,
 * headers and body for any non-redirect status. With `publicOnly`, hosts
 * that are or resolve to non-public addresses are refused: every address
 * DNS returns is checked and the connection only uses public ones.
 *
 * @param {string} url - http or https URL
 * @param {object} [opts]
 * @param {string} [opts.accept='*\/*'] - Accept header
 * @param {number} [opts.timeoutMs=10000]
 * @param {number} [opts.maxBytes=1048576]
 * @param {boolean} [opts.publicOnly=true]
 * @returns {Promise<{ status: number, headers: Array<[string, string]>, body: Buffer }>}
 */
export function fetchBounded(url, opts = {}) {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBytes = opts.maxBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    const publicOnly = opts.publicOnly ?? true;
    return new Promise((resolve, reject) => {
        let u;
        try {
            u = new URL(url);
        } catch {
            return reject(fail(`Invalid URL ${url}`));
        }
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return reject(fail(`Unsupported URL scheme ${url}`));
        const host = u.hostname.replace(/^\[|\]$/g, '');
        if (publicOnly && isIP(host) && isNonPublic(host)) {
            return reject(fail(`Refusing to fetch non-public address ${url}`));
        }
        let settled = false;
        const done = (fn, v) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            fn(v);
        };
        const mod = u.protocol === 'https:' ? https : http;
        const req = mod.request(u, {
            method: 'GET',
            headers: { Accept: opts.accept ?? '*/*' },
            agent: false,
            lookup: publicOnly ? publicOnlyLookup : undefined,
        }, (res) => {
            const status = res.statusCode;
            if (status >= 300 && status < 400) {
                res.destroy();
                return done(reject, fail(`Redirect rejected fetching ${url} (status ${status})`));
            }
            const len = res.headers['content-length'];
            if (len !== undefined && Number(len) > maxBytes) {
                res.destroy();
                return done(reject, fail(`Response from ${url} exceeds ${maxBytes} bytes`));
            }
            const headers = [];
            for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
                headers.push([res.rawHeaders[i].toLowerCase(), res.rawHeaders[i + 1]]);
            }
            const chunks = [];
            let total = 0;
            res.on('data', (chunk) => {
                total += chunk.length;
                if (total > maxBytes) {
                    res.destroy();
                    req.destroy();
                    return done(reject, fail(`Response from ${url} exceeds ${maxBytes} bytes`));
                }
                chunks.push(chunk);
            });
            res.on('end', () => done(resolve, { status, headers, body: Buffer.concat(chunks) }));
            res.on('error', () => done(reject, fail(`Failed to read response from ${url}`)));
        });
        const timer = setTimeout(() => {
            req.destroy();
            done(reject, fail(`Failed to fetch ${url}`));
        }, timeoutMs);
        req.on('error', () => done(reject, fail(`Failed to fetch ${url}`)));
        req.end();
    });
}
