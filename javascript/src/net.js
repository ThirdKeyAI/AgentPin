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
