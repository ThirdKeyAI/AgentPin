/**
 * Revocation document handling for AgentPin.
 */

import { AgentPinError, ErrorCode } from './types.js';

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
    const rc = doc.revoked_credentials.find(r => r.jti === jti);
    if (rc) {
        throw new AgentPinError(
            ErrorCode.CREDENTIAL_REVOKED,
            `Credential ${jti} revoked: ${rc.reason}`
        );
    }

    const ra = doc.revoked_agents.find(r => r.agent_id === agentId);
    if (ra) {
        throw new AgentPinError(
            ErrorCode.AGENT_INACTIVE,
            `Agent ${agentId} revoked: ${ra.reason}`
        );
    }

    const rk = doc.revoked_keys.find(r => r.kid === kid);
    if (rk) {
        throw new AgentPinError(
            ErrorCode.KEY_REVOKED,
            `Key ${kid} revoked: ${rk.reason}`
        );
    }
}

/**
 * Fetch a revocation document from a URL.
 * @param {string} url
 * @returns {Promise<object>}
 */
export async function fetchRevocationDocument(url) {
    const response = await fetch(url, {
        headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            `HTTP ${response.status} fetching ${url}`
        );
    }

    return response.json();
}
