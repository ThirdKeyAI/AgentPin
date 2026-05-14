/**
 * DNS TXT cross-verification at `_agentpin.{domain}` (v0.3.0).
 *
 * Mirrors the Rust `agentpin::dns` module. The wire format is
 *
 *   _agentpin.example.com.  3600  IN  TXT  "v=agentpin1; kid=acme-2026-04; fp=sha256:a1b2c3..."
 *
 * Semantics:
 *   - Absent record   -> no effect (DNS TXT is purely additive)
 *   - Present matching -> verification succeeds
 *   - Present mismatching / malformed -> hard failure (DISCOVERY_INVALID)
 *
 * Mismatch is fail-closed because a publisher who *intentionally* published a
 * TXT record has signaled DNS is part of their trust chain.
 */

import { jwkThumbprint } from './jwk.js';
import { AgentPinError, ErrorCode } from './types.js';

const VERSION = 'agentpin1';
const FP_PREFIX = 'sha256:';

/**
 * Parse a raw TXT record value (e.g. `"v=agentpin1; kid=acme-2026-04; fp=sha256:..."`).
 *
 * Whitespace around `;` and `=` is tolerated. Field order is not significant.
 * Throws on missing `v`/`fp`, unknown version, or malformed fingerprint.
 * Unknown fields are ignored for forward compatibility.
 *
 * @param {string} value
 * @returns {{ version: string, kid: string|null, fingerprint: string }}
 */
export function parseTxtRecord(value) {
    let version = null;
    let kid = null;
    let fp = null;

    for (const rawPart of value.split(';')) {
        const part = rawPart.trim();
        if (part.length === 0) continue;
        const eq = part.indexOf('=');
        if (eq === -1) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                `DNS TXT field missing '=': ${part}`
            );
        }
        const k = part.slice(0, eq).trim().toLowerCase();
        const v = part.slice(eq + 1).trim();
        switch (k) {
        case 'v':
            version = v;
            break;
        case 'kid':
            kid = v;
            break;
        case 'fp':
            fp = v.toLowerCase();
            break;
        default:
            // Forward-compat: ignore unknown fields.
            break;
        }
    }

    if (version === null) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "DNS TXT record missing required 'v' field"
        );
    }
    if (version !== VERSION) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `DNS TXT unsupported version: ${version}`
        );
    }
    if (fp === null) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "DNS TXT record missing required 'fp' field"
        );
    }
    if (!fp.startsWith(FP_PREFIX)) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `DNS TXT 'fp' must be sha256:<hex>: ${fp}`
        );
    }

    return { version, kid, fingerprint: fp };
}

/**
 * Cross-check a parsed TXT record's fingerprint against a discovery document.
 *
 * Returns nothing on success. Throws `AgentPinError(DISCOVERY_INVALID)` when no
 * key in `discovery.public_keys` matches `txt.fingerprint` (and `txt.kid` when
 * present).
 *
 * @param {object} discovery
 * @param {{ kid: string|null, fingerprint: string }} txt
 */
export function verifyDnsMatch(discovery, txt) {
    const target = txt.fingerprint.toLowerCase();
    for (const jwk of discovery.public_keys || []) {
        let computed = jwkThumbprint(jwk).toLowerCase();
        if (!computed.startsWith(FP_PREFIX)) {
            computed = `${FP_PREFIX}${computed}`;
        }
        if (computed !== target) continue;
        if (txt.kid && jwk.kid !== txt.kid) continue;
        return;
    }
    throw new AgentPinError(
        ErrorCode.DISCOVERY_INVALID,
        `DNS TXT fingerprint ${target} does not match any key in the discovery document`
    );
}

/**
 * Build the lookup name for a domain: `_agentpin.{domain}` with any trailing
 * dot stripped.
 *
 * @param {string} domain
 * @returns {string}
 */
export function txtRecordName(domain) {
    return `_agentpin.${domain.replace(/\.+$/, '')}`;
}

/**
 * Fetch and parse the `_agentpin.{domain}` TXT record using Node's built-in
 * `dns/promises`.
 *
 * Returns:
 *   - `null` when no `_agentpin` TXT record exists (or DNS NODATA/NOTFOUND)
 *   - parsed record when present
 * Throws `AgentPinError(DISCOVERY_INVALID)` when the record exists but is
 * malformed, or `AgentPinError(DISCOVERY_FETCH_FAILED)` for other DNS errors.
 *
 * When multiple TXT records exist at the same name, the first whose value
 * contains `v=agentpin1` is used. Multiple chunks per record are joined per
 * RFC 1464.
 *
 * @param {string} domain
 * @returns {Promise<{ version: string, kid: string|null, fingerprint: string }|null>}
 */
export async function fetchDnsTxt(domain) {
    const { resolveTxt } = await import('dns/promises');
    const name = txtRecordName(domain);

    let records;
    try {
        records = await resolveTxt(name);
    } catch (err) {
        if (err && (err.code === 'ENODATA' || err.code === 'ENOTFOUND')) {
            return null;
        }
        throw new AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            `DNS TXT lookup failed for ${name}: ${err.message || err}`
        );
    }

    for (const chunks of records) {
        const joined = chunks.join('');
        if (joined.includes('v=agentpin1')) {
            return parseTxtRecord(joined);
        }
    }
    return null;
}
