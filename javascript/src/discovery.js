/**
 * Discovery document handling for AgentPin.
 */

import { AgentPinError, ErrorCode } from './types.js';

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
    if (doc.agentpin_version !== '0.1') {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `Unsupported version: ${doc.agentpin_version}`
        );
    }
    if (doc.entity !== expectedEntity) {
        throw new AgentPinError(
            ErrorCode.DOMAIN_MISMATCH,
            `Discovery entity '${doc.entity}' does not match expected '${expectedEntity}'`
        );
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
 * allow-list (v0.3.0). Convention: an empty list means *unrestricted* (all
 * domains trusted); a non-empty list restricts the agent to exactly those
 * domains. Mirrors `AllowedDomains` in the Rust SDK.
 */
export const AllowedDomains = Object.freeze({
    /** Construct an empty (unrestricted) list. */
    unrestricted() {
        return [];
    },
    /** Construct from any iterable of strings. */
    fromDomains(iter) {
        return Array.from(iter, (d) => String(d));
    },
    /** `true` when the list is empty (no restriction). */
    isUnrestricted(list) {
        return !list || list.length === 0;
    },
    /** `true` when `domain` is allowed under this list. Empty list = all allowed. */
    allows(list, domain) {
        return this.isUnrestricted(list) || list.some((d) => d === domain);
    },
    /**
     * Intersection of two allow-lists. `unrestricted ∩ X = X`. The intersection
     * of two non-empty lists may itself be empty (which then means
     * unrestricted under our convention) — callers that care about the
     * difference between "intentionally restricted to nothing" and
     * "unrestricted" should not use this helper.
     */
    intersect(a, b) {
        if (this.isUnrestricted(a)) return [...(b || [])];
        if (this.isUnrestricted(b)) return [...a];
        return a.filter((d) => b.includes(d));
    },
    /**
     * Pull the typed list out of a `Constraints` object. Returns
     * `unrestricted()` when the constraints have no `allowed_domains`.
     */
    fromConstraints(constraints) {
        if (!constraints || !constraints.allowed_domains) {
            return this.unrestricted();
        }
        return [...constraints.allowed_domains];
    },
});

/**
 * Fetch a discovery document from a domain over HTTPS.
 * @param {string} domain
 * @returns {Promise<object>}
 */
export async function fetchDiscoveryDocument(domain) {
    const url = `https://${domain}/.well-known/agent-identity.json`;

    const response = await fetch(url, {
        redirect: 'error',
        headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            `HTTP ${response.status} fetching ${url}`
        );
    }

    const doc = await response.json();
    validateDiscoveryDocument(doc, domain);
    return doc;
}
