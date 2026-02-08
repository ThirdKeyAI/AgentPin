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
 * @returns {object} Discovery document
 */
export function buildDiscoveryDocument(entity, entityType, publicKeys, agents, maxDelegationDepth, updatedAt) {
    return {
        agentpin_version: '0.1',
        entity,
        entity_type: entityType,
        public_keys: publicKeys,
        agents,
        revocation_endpoint: `https://${entity}/.well-known/agent-identity-revocations.json`,
        max_delegation_depth: maxDelegationDepth,
        updated_at: updatedAt,
    };
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
