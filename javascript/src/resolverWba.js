/**
 * Web Bot Auth key directory resolution over HTTPS.
 *
 * The `Signature-Agent` URL comes from the client, so every fetch is
 * hardened against SSRF (draft §6.7): https only, no redirects, non-public
 * addresses refused (every resolved address is checked), bounded time,
 * bytes and key count. A resolved directory replaces the cached copy; a
 * failed fetch never evicts it, so a directory outage does not revoke an
 * agent's keys (§6.10).
 */

import { AgentPinError, ErrorCode } from './types.js';
import { fetchBounded, DEFAULT_TIMEOUT_MS } from './net.js';
import { combinedField } from './httpsig.js';
import {
    DIRECTORY_MEDIA_TYPE, findKey, normalizeSignatureAgent, parseDirectory, verifyDirectoryResponse,
} from './wba.js';

/** Default directory fetch options. */
export function defaultDirectoryFetchOptions() {
    return {
        timeoutMs: DEFAULT_TIMEOUT_MS,
        /** Response byte cap (64 KiB). */
        maxBytes: 64 * 1024,
        /** Refuse hosts that are or resolve to non-public addresses. Only disable for tests. */
        publicOnly: true,
        /** Require https URLs. Only disable for tests. */
        requireHttps: true,
        /**
         * Keep only keys with a valid directory response signature (Appendix
         * B.1). Default false: a directory the verifier resolved itself is
         * usable without proof.
         */
        requireProof: false,
        /** Cache lifetime when the response has no usable `max-age`. */
        defaultTtlSecs: 3600,
        /** Bounds applied to `max-age`. */
        minTtlSecs: 60,
        maxTtlSecs: 86400,
    };
}

function transport(message) {
    return new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, message);
}

/** `max-age` from Cache-Control, or null. */
export function maxAge(headers) {
    const cc = combinedField(headers, 'cache-control');
    if (cc === null) return null;
    for (const d of cc.split(',')) {
        const i = d.indexOf('=');
        if (i < 0) continue;
        if (d.slice(0, i).trim().toLowerCase() !== 'max-age') continue;
        const v = d.slice(i + 1).trim();
        if (/^\+?\d+$/.test(v)) return Number(v);
    }
    return null;
}

/**
 * Fetch and parse the key directory at `url`.
 * @param {string} url
 * @param {object} [opts] - See `defaultDirectoryFetchOptions`
 * @returns {Promise<{ directory: { keys: object[] }, ttlSecs: number }>}
 */
export async function fetchDirectory(url, opts = {}) {
    const o = { ...defaultDirectoryFetchOptions(), ...opts };
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw transport('invalid directory URL');
    }
    if (o.requireHttps && parsed.protocol !== 'https:') throw transport(`Directory ${url} is not https`);
    const resp = await fetchBounded(url, {
        accept: `${DIRECTORY_MEDIA_TYPE}, application/jwk-set+json, application/json`,
        timeoutMs: o.timeoutMs,
        maxBytes: o.maxBytes,
        publicOnly: o.publicOnly,
    });
    if (resp.status !== 200) throw transport(`HTTP ${resp.status} fetching ${url}`);
    const directory = o.requireProof
        ? verifyDirectoryResponse(resp.body, resp.headers, parsed.host, Math.floor(Date.now() / 1000), 60)
        : parseDirectory(resp.body);
    const ttl = maxAge(resp.headers) ?? o.defaultTtlSecs;
    return { directory, ttlSecs: Math.min(Math.max(ttl, o.minTtlSecs), o.maxTtlSecs) };
}

/**
 * Fetches key directories on demand and caches them per URL. Implements the
 * `lookup(signatureAgent, keyid)` interface `verifyRequest` uses.
 */
export class CachingDirectoryResolver {
    /** @param {object} [opts] - See `defaultDirectoryFetchOptions` */
    constructor(opts = {}) {
        this.opts = { ...defaultDirectoryFetchOptions(), ...opts };
        /** @type {Map<string, { directory: object, freshUntil: number }>} url -> entry (ms) */
        this._cache = new Map();
    }

    _cached(url, freshOnly) {
        const c = this._cache.get(url);
        if (!c) return null;
        return !freshOnly || c.freshUntil > Date.now() ? c.directory : null;
    }

    /**
     * @param {string} signatureAgent
     * @param {string} keyid
     * @returns {Promise<import('./httpsig.js').PublicKey|null>}
     */
    async lookup(signatureAgent, keyid) {
        // Verified requests always pass a normalized https URL; plain URLs
        // are only reachable with requireHttps off (tests).
        const url = this.opts.requireHttps ? normalizeSignatureAgent(signatureAgent) : signatureAgent;
        const now = Math.floor(Date.now() / 1000);
        const fresh = this._cached(url, true);
        if (fresh) {
            const k = findKey(fresh, keyid, now, 60);
            if (k) return k;
        }
        let fetched;
        try {
            fetched = await fetchDirectory(url, this.opts);
        } catch (e) {
            // A failed fetch is not evidence: fall back to the last resolved copy (§6.10).
            const stale = this._cached(url, false);
            if (stale) return findKey(stale, keyid, now, 60);
            throw e;
        }
        this._cache.set(url, { directory: fetched.directory, freshUntil: Date.now() + fetched.ttlSecs * 1000 });
        return findKey(fetched.directory, keyid, now, 60);
    }
}
