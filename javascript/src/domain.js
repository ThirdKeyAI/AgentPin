/**
 * Domain-name normalization and validation.
 *
 * DNS, TLS hostname matching and the HTTP Host header are case-insensitive,
 * but the TOFU pin store, the discovery URL and the `entity == iss`
 * comparison used to operate on the literal `iss` string, so `EXAMPLE.COM`,
 * `example.com.` and the U-label/A-label forms of an IDN were distinct
 * identities with independent pins (AP-3), and an `iss` containing a path,
 * port or userinfo was interpolated unescaped into URLs (AP-12).
 * `normalizeDomain` is the single choke point applied by every verifier,
 * resolver and discovery validator.
 */

import { AgentPinError, ErrorCode } from './types.js';

const MAX_HOSTNAME_LEN = 253;
const MAX_LABEL_LEN = 63;
const LABEL_RE = /^[a-z0-9-]+$/;

function invalid(reason) {
    return new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Invalid domain: ${reason}`);
}

function looksLikeIpv4(host) {
    const parts = host.split('.');
    return parts.length === 4 && parts.every((p) => /^[0-9]+$/.test(p));
}

function validateAsciiHostname(host) {
    if (host.length > MAX_HOSTNAME_LEN) throw invalid('hostname too long');
    if (looksLikeIpv4(host)) throw invalid('IP literals are not allowed');
    for (const label of host.split('.')) {
        if (label.length === 0) throw invalid('empty label');
        if (label.length > MAX_LABEL_LEN) throw invalid('label too long');
        if (label.startsWith('-') || label.endsWith('-')) throw invalid('label starts or ends with a hyphen');
        if (!LABEL_RE.test(label)) throw invalid('label contains characters outside [a-z0-9-]');
    }
}

/**
 * Normalize a domain name to its canonical lowercase A-label form.
 *
 * Exactly one trailing dot is removed; the name is lowercased and IDNA
 * mapped; anything that is not a bare hostname is rejected (scheme,
 * userinfo, port, path, query, fragment, whitespace, control characters, IP
 * literals, empty or over-long labels, leading/trailing hyphens). The result
 * is safe as a pin-store key and URL host.
 *
 * @param {string} input
 * @returns {string}
 * @throws {AgentPinError} DISCOVERY_INVALID
 */
export function normalizeDomain(input) {
    if (typeof input !== 'string' || input.length === 0) throw invalid('empty');
    // eslint-disable-next-line no-control-regex
    if (/[\s\u0000-\u001f\u007f]/.test(input)) throw invalid('contains whitespace or control characters');
    if (/[/\\?#@:[\]%]/.test(input)) throw invalid('not a bare hostname');

    const trimmed = input.endsWith('.') ? input.slice(0, -1) : input;
    if (trimmed.length === 0 || trimmed.endsWith('.')) throw invalid('empty label');

    let url;
    try {
        url = new URL(`https://${trimmed}/`);
    } catch {
        throw invalid('unparsable');
    }
    const host = url.hostname;
    if (!host || host.startsWith('[')) throw invalid('IP literals are not allowed');
    if (url.port !== '' || url.pathname !== '/' || url.username !== '' || url.password !== '' ||
        url.search !== '' || url.hash !== '') {
        throw invalid('not a bare hostname');
    }
    validateAsciiHostname(host);
    return host;
}

/**
 * Parse `rawUrl`, require https, no userinfo, no explicit port and no
 * fragment, and return its normalized domain host (IP literals rejected).
 * @param {string} rawUrl
 * @returns {string}
 */
export function httpsUrlHost(rawUrl) {
    if (typeof rawUrl !== 'string' || /\s/.test(rawUrl)) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Invalid URL');
    }
    let url;
    try {
        url = new URL(rawUrl);
    } catch {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Invalid URL');
    }
    if (url.protocol !== 'https:') throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'URL must use https');
    if (url.username !== '' || url.password !== '') throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'URL must not contain userinfo');
    if (url.port !== '') throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'URL must not specify a port');
    if (url.hash !== '') throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'URL must not contain a fragment');
    if (!url.hostname || url.hostname.startsWith('[')) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'URL host must be a domain name');
    }
    return normalizeDomain(url.hostname);
}

/**
 * Check that `rawUrl` is an https URL whose host is exactly `domain` after
 * normalization (AP-12).
 * @param {string} rawUrl
 * @param {string} domain
 */
export function validateHttpsUrlForDomain(rawUrl, domain) {
    const expected = normalizeDomain(domain);
    const host = httpsUrlHost(rawUrl);
    if (host !== expected) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `URL host '${host}' does not match domain '${expected}'`
        );
    }
}

/**
 * The default revocation endpoint for a domain (spec §8.1).
 * @param {string} domain
 * @returns {string}
 */
export function defaultRevocationEndpoint(domain) {
    return `https://${domain}/.well-known/agent-identity-revocations.json`;
}
