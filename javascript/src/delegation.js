/**
 * Delegation attestation creation and verification for AgentPin.
 */

import { signData, verifySignature } from './crypto.js';
import { capabilitiesHash } from './capability.js';
import { AgentPinError, ErrorCode } from './types.js';

/**
 * Create the canonical attestation input string.
 * Format: `{domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{capabilities_hash}`
 * @param {string} domain
 * @param {string} role
 * @param {string} agentId
 * @param {string} delegateeDomain
 * @param {string} delegateeAgentId
 * @param {Capability[]} capabilities
 * @returns {string}
 */
export function canonicalAttestationInput(domain, role, agentId, delegateeDomain, delegateeAgentId, capabilities) {
    const capHash = capabilitiesHash(capabilities);
    return `${domain}|${role}|${agentId}|${delegateeDomain}|${delegateeAgentId}|${capHash}`;
}

/**
 * Create a delegation attestation signed by the attesting entity.
 * @param {string} privateKeyPem
 * @param {string} kid
 * @param {string} domain
 * @param {string} role
 * @param {string} agentId
 * @param {string} delegateeDomain
 * @param {string} delegateeAgentId
 * @param {Capability[]} capabilities
 * @returns {object} DelegationAttestation
 */
export function createAttestation(
    privateKeyPem, kid, domain, role, agentId,
    delegateeDomain, delegateeAgentId, capabilities
) {
    const input = canonicalAttestationInput(
        domain, role, agentId, delegateeDomain, delegateeAgentId, capabilities
    );
    const signature = signData(privateKeyPem, Buffer.from(input));

    return {
        domain,
        role,
        agent_id: agentId,
        kid,
        attestation: signature,
    };
}

/**
 * Verify a single delegation attestation signature.
 * @param {object} attestation
 * @param {string} publicKeyPem
 * @param {string} delegateeDomain
 * @param {string} delegateeAgentId
 * @param {Capability[]} capabilities
 * @throws {AgentPinError}
 */
export function verifyAttestation(attestation, publicKeyPem, delegateeDomain, delegateeAgentId, capabilities) {
    const input = canonicalAttestationInput(
        attestation.domain, attestation.role, attestation.agent_id,
        delegateeDomain, delegateeAgentId, capabilities
    );

    const valid = verifySignature(publicKeyPem, Buffer.from(input), attestation.attestation);
    if (!valid) {
        throw new AgentPinError(
            ErrorCode.DELEGATION_INVALID,
            `Delegation attestation from ${attestation.domain} failed signature verification`
        );
    }
}

/**
 * Verify the depth of a delegation chain does not exceed the minimum max_delegation_depth.
 * @param {number} chainLen
 * @param {number[]} maxDepths
 * @throws {AgentPinError}
 */
export function verifyChainDepth(chainLen, maxDepths) {
    const minDepth = Math.min(...maxDepths);
    if (chainLen > minDepth) {
        throw new AgentPinError(
            ErrorCode.DELEGATION_DEPTH_EXCEEDED,
            `Delegation chain depth ${chainLen} exceeds minimum max_delegation_depth ${minDepth}`
        );
    }
}
