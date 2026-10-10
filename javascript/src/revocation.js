/**
 * Revocation document handling for AgentPin.
 */

import { AgentPinError, ErrorCode } from './types.js';
import { httpsUrlHost, normalizeDomain } from './domain.js';
import { fetchJsonBounded } from './net.js';
import { signData, verifySignature, domainSeparatedInput, CTX_REVOCATION } from './crypto.js';
import { jwkToPem } from './jwk.js';
import { canonicalizeForSigning } from './a2a.js';

/**
 * Build an empty revocation document.
 * @param {string} entity
 * @returns {object}
 */
export function buildRevocationDocument(entity) {
    return {
        agentpin_version: '0.1',
        entity,
        updated_at: new Date().toISOString(),
        revoked_credentials: [],
        revoked_agents: [],
        revoked_keys: [],
    };
}

/**
 * Add a revoked credential to the document.
 * @param {object} doc
 * @param {string} jti
 * @param {string} reason - One of RevocationReason values
 */
export function addRevokedCredential(doc, jti, reason) {
    doc.revoked_credentials.push({
        jti,
        revoked_at: new Date().toISOString(),
        reason,
    });
    doc.updated_at = new Date().toISOString();
}

/**
 * Add a revoked agent to the document.
 * @param {object} doc
 * @param {string} agentId
 * @param {string} reason
 */
export function addRevokedAgent(doc, agentId, reason) {
    doc.revoked_agents.push({
        agent_id: agentId,
        revoked_at: new Date().toISOString(),
        reason,
    });
    doc.updated_at = new Date().toISOString();
}

/**
 * Add a revoked key to the document.
 * @param {object} doc
 * @param {string} kid
 * @param {string} reason
 */
export function addRevokedKey(doc, kid, reason) {
    doc.revoked_keys.push({
        kid,
        revoked_at: new Date().toISOString(),
        reason,
    });
    doc.updated_at = new Date().toISOString();
}

/**
 * Check if a credential, agent, or key is revoked.
 * @param {object} doc - Revocation document
 * @param {string} jti
 * @param {string} agentId
 * @param {string} kid
 * @throws {AgentPinError} if revoked
 */
export function checkRevocation(doc, jti, agentId, kid) {
    const rc = (doc.revoked_credentials || []).find(r => r && r.jti === jti);
    if (rc) {
        throw new AgentPinError(
            ErrorCode.CREDENTIAL_REVOKED,
            `Credential ${jti} revoked: ${rc.reason}`
        );
    }

    const ra = (doc.revoked_agents || []).find(r => r && r.agent_id === agentId);
    if (ra) {
        throw new AgentPinError(
            ErrorCode.AGENT_INACTIVE,
            `Agent ${agentId} revoked: ${ra.reason}`
        );
    }

    const rk = (doc.revoked_keys || []).find(r => r && r.kid === kid);
    if (rk) {
        throw new AgentPinError(
            ErrorCode.KEY_REVOKED,
            `Key ${kid} revoked: ${rk.reason}`
        );
    }
}

/**
 * Fetch a revocation document from a URL. Any failure, including HTTP 404,
 * throws so callers fail closed for an explicitly declared endpoint.
 * @param {string} url
 * @param {object} [opts] - Forwarded to `fetchJsonBounded`
 * @returns {Promise<object>}
 */
export async function fetchRevocationDocument(url, opts = {}) {
    const doc = await fetchRevocationDocumentIfPresent(url, opts);
    if (doc === null) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `HTTP 404 fetching ${url}`);
    }
    return doc;
}

/**
 * Fetch a revocation document, returning `null` on HTTP 404. Used for the
 * spec §8.1 default endpoint when the discovery document declares none: an
 * issuer that publishes no revocation document is not an error, but any
 * other failure still fails closed.
 * @param {string} url
 * @param {object} [opts]
 * @returns {Promise<object|null>}
 */
export async function fetchRevocationDocumentIfPresent(url, opts = {}) {
    // Only https URLs with a domain host are ever fetched, and never through
    // a redirect (AP-12). Same-host binding to the issuer is enforced by the
    // caller / discovery validation.
    httpsUrlHost(url);
    return fetchJsonBounded(url, opts);
}

// ---------------------------------------------------------------------------
// Signed revocation documents and freshness (design issue 3)
// ---------------------------------------------------------------------------

/**
 * Signing input: the `agentpin-revocation-v1` context over the canonical
 * JSON of the document with `signature` cleared.
 * @param {object} doc
 * @returns {Buffer}
 */
export function revocationSigningInput(doc) {
    const rest = { ...doc };
    delete rest.signature;
    return domainSeparatedInput(CTX_REVOCATION, [Buffer.from(canonicalizeForSigning(rest), 'utf8')]);
}

/**
 * Sign a revocation document in place with a discovery-document key.
 * @param {object} doc
 * @param {string} privateKeyPem
 * @param {string} kid
 */
export function signRevocationDocument(doc, privateKeyPem, kid) {
    doc.kid = kid;
    delete doc.signature;
    doc.signature = signData(privateKeyPem, revocationSigningInput(doc));
    return doc;
}

/**
 * Validate a revocation document against the discovery document it belongs
 * to: wire version, entity binding, and (when present) its signature under
 * a key from `discovery.public_keys`.
 * @param {object} doc
 * @param {object} discovery
 * @throws {AgentPinError} DISCOVERY_INVALID
 */
export function verifyRevocationDocument(doc, discovery) {
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Revocation document is not an object');
    }
    if (doc.agentpin_version !== '0.1') {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Unsupported revocation document version: ${doc.agentpin_version}`);
    }
    let docEntity;
    try {
        docEntity = normalizeDomain(doc.entity);
    } catch (e) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Invalid revocation entity: ${e.message}`);
    }
    const discEntity = normalizeDomain(discovery.entity);
    if (docEntity !== discEntity) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `Revocation document entity '${doc.entity}' does not match discovery entity '${discovery.entity}'`
        );
    }
    // Structural check (AP-8): every entry must carry its identifying field.
    // An operator who publishes the wrong field name (e.g. "id") must get a
    // hard failure, not a document that silently never matches anything.
    const lists = [
        ['revoked_credentials', 'jti'],
        ['revoked_agents', 'agent_id'],
        ['revoked_keys', 'kid'],
    ];
    for (const [list, field] of lists) {
        const entries = doc[list];
        if (entries === undefined || entries === null) continue;
        if (!Array.isArray(entries)) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `${list} is not an array`);
        }
        entries.forEach((entry, i) => {
            if (!entry || typeof entry !== 'object' || typeof entry[field] !== 'string' || !entry[field]) {
                throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `${list}[${i}] is missing ${field}`);
            }
        });
    }
    if (doc.signature !== undefined && doc.signature !== null) {
        if (typeof doc.kid !== 'string' || !doc.kid) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Signed revocation document has no kid');
        }
        const jwk = (discovery.public_keys || []).find((k) => k.kid === doc.kid);
        if (!jwk) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Revocation document kid '${doc.kid}' not found in discovery document`);
        }
        const ok = verifySignature(jwkToPem(jwk), revocationSigningInput(doc), String(doc.signature));
        if (!ok) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Revocation document signature did not verify');
        }
    }
}

/**
 * Reject a revocation document whose `updated_at` is unparsable or older
 * than `maxAgeSecs`.
 * @param {object} doc
 * @param {number} maxAgeSecs
 */
export function checkRevocationFreshness(doc, maxAgeSecs) {
    const updated = new Date(doc.updated_at);
    if (typeof doc.updated_at !== 'string' || Number.isNaN(updated.getTime())) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Revocation document updated_at is not RFC 3339');
    }
    const age = Math.floor((Date.now() - updated.getTime()) / 1000);
    if (age > maxAgeSecs) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Revocation document is stale (${age} seconds old, max ${maxAgeSecs})`);
    }
}
