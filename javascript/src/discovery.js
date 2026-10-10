/**
 * Discovery document handling for AgentPin.
 */

import { AgentPinError, ErrorCode } from './types.js';
import { normalizeDomain, validateHttpsUrlForDomain } from './domain.js';
import { fetchJsonBounded } from './net.js';
import { domainPatternMatches } from './constraint.js';

/**
 * Build a new discovery document.
 * @param {string} entity - Domain name
 * @param {string} entityType - One of EntityType values
 * @param {object[]} publicKeys - Array of JWK objects
 * @param {object[]} agents - Array of AgentDeclaration objects
 * @param {number} maxDelegationDepth
 * @param {string} updatedAt - ISO 8601 timestamp
 * @param {object} [opts]
 * @param {string} [opts.a2aEndpoint] - Optional A2A AgentCard endpoint URL (v0.3.0)
 * @returns {object} Discovery document
 */
export function buildDiscoveryDocument(entity, entityType, publicKeys, agents, maxDelegationDepth, updatedAt, opts = {}) {
    const doc = {
        agentpin_version: '0.1',
        entity,
        entity_type: entityType,
        public_keys: publicKeys,
        agents,
        revocation_endpoint: `https://${entity}/.well-known/agent-identity-revocations.json`,
        max_delegation_depth: maxDelegationDepth,
        updated_at: updatedAt,
    };
    if (opts.a2aEndpoint) {
        doc.a2a_endpoint = opts.a2aEndpoint;
    }
    return doc;
}

/**
 * Validate a discovery document's basic structural requirements.
 * @param {object} doc
 * @param {string} expectedEntity
 * @throws {AgentPinError}
 */
export function validateDiscoveryDocument(doc, expectedEntity) {
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Discovery document must be a JSON object');
    }
    if (doc.agentpin_version !== '0.1') {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `Unsupported version: ${doc.agentpin_version}`
        );
    }
    // Compare entity and the expected domain in normalized form (AP-3).
    const expected = normalizeDomain(expectedEntity);
    let entity;
    try {
        entity = normalizeDomain(doc.entity);
    } catch (e) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Invalid entity: ${e.message}`);
    }
    if (entity !== expected) {
        throw new AgentPinError(
            ErrorCode.DOMAIN_MISMATCH,
            `Discovery entity '${doc.entity}' does not match expected '${expectedEntity}'`
        );
    }
    // Endpoints the verifier may fetch must be https on the entity's own
    // host (AP-12; spec §17 for a2a_endpoint).
    if (doc.revocation_endpoint !== undefined && doc.revocation_endpoint !== null) {
        try {
            validateHttpsUrlForDomain(doc.revocation_endpoint, entity);
        } catch (e) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Invalid revocation_endpoint: ${e.message}`);
        }
    }
    if (doc.a2a_endpoint !== undefined && doc.a2a_endpoint !== null) {
        try {
            validateHttpsUrlForDomain(doc.a2a_endpoint, entity);
        } catch (e) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, `Invalid a2a_endpoint: ${e.message}`);
        }
    }
    if (!doc.public_keys || doc.public_keys.length === 0) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'Discovery document must have at least one public key'
        );
    }
    if (doc.max_delegation_depth > 3) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'max_delegation_depth must be 0-3'
        );
    }
}

/**
 * Find a public key by kid in a discovery document.
 * @param {object} doc
 * @param {string} kid
 * @returns {object|null}
 */
export function findKeyByKid(doc, kid) {
    return doc.public_keys.find(k => k.kid === kid) || null;
}

/**
 * Find an agent declaration by agent_id.
 * @param {object} doc
 * @param {string} agentId
 * @returns {object|null}
 */
export function findAgentById(doc, agentId) {
    return doc.agents.find(a => a.agent_id === agentId) || null;
}

/**
 * Helpers for working with the `allowed_domains` constraint as a typed
 * allow-list (v0.3.0, made a proper tri-state in v0.4 — AP-6).
 *
 * Three states: `null`/`undefined` is *unrestricted* (the field is absent on
 * the wire); an array, including an empty one, is *restricted* to the listed
 * literals and `*.` patterns (spec §5.5). "No restriction" and "restricted to
 * nothing" are therefore distinct: the intersection of two disjoint
 * allow-lists is `[]`, which allows nothing and is never re-interpreted as
 * unrestricted. Mirrors `AllowedDomains` in the Rust SDK.
 */
export const AllowedDomains = Object.freeze({
    /** The unrestricted allow-list (`null`). */
    unrestricted() {
        return null;
    },
    /** Construct a restricted list from any iterable of strings; empty allows nothing. */
    fromDomains(iter) {
        return Array.from(iter, (d) => String(d));
    },
    /** `true` when the list places no restriction (`null`/`undefined`). */
    isUnrestricted(list) {
        return list === null || list === undefined;
    },
    /** `true` when `domain` is allowed: unrestricted allows all, entries use §5.5 patterns, `[]` allows nothing. */
    allows(list, domain) {
        if (this.isUnrestricted(list)) return true;
        return list.some((pattern) => domainPatternMatches(pattern, domain));
    },
    /**
     * Intersection of two allow-lists. `unrestricted ∩ X = X`; otherwise the
     * entries of either list that are allowed by the other (so
     * `*.corp.com ∩ api.corp.com = api.corp.com`). Disjoint lists yield `[]`,
     * which allows nothing.
     */
    intersect(a, b) {
        if (this.isUnrestricted(a)) return this.isUnrestricted(b) ? null : [...b];
        if (this.isUnrestricted(b)) return [...a];
        const out = [];
        for (const d of a) if (this.allows(b, d) && !out.includes(d)) out.push(d);
        for (const d of b) if (this.allows(a, d) && !out.includes(d)) out.push(d);
        return out;
    },
    /**
     * Pull the typed list out of a `Constraints` object. Returns
     * `unrestricted()` when the constraints have no `allowed_domains` and a
     * copy of the list (including an empty one) when present.
     */
    fromConstraints(constraints) {
        if (!constraints || constraints.allowed_domains === undefined || constraints.allowed_domains === null) {
            return this.unrestricted();
        }
        return [...constraints.allowed_domains];
    },
});

/**
 * Fetch a discovery document from a domain over HTTPS.
 *
 * No redirects, 10 s timeout, 1 MiB body cap, JSON content type required
 * (see `net.js`).
 * @param {string} domain
 * @param {object} [opts] - Forwarded to `fetchJsonBounded` (fetchImpl, timeoutMs, maxBytes)
 * @returns {Promise<object>}
 */
export async function fetchDiscoveryDocument(domain, opts = {}) {
    domain = normalizeDomain(domain);
    const url = `https://${domain}/.well-known/agent-identity.json`;
    const doc = await fetchJsonBounded(url, opts);
    if (doc === null) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `HTTP 404 fetching ${url}`);
    }
    validateDiscoveryDocument(doc, domain);
    return doc;
}
