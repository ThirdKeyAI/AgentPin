/**
 * Delegation attestation creation and verification for AgentPin (spec §5.6 / §6.4).
 *
 * An attestation is a signature over the domain-separated structure
 *
 *   "agentpin-attestation-v1" 0x00 len(domain) domain len(role) role
 *       len(agent_id) agent_id len(delegatee_domain) delegatee_domain
 *       len(delegatee_agent_id) delegatee_agent_id
 *       len(capabilities_hash) capabilities_hash len(kid) kid len(exp) exp
 *
 * `kid` binds the attestation to the attesting key; `exp` (decimal Unix
 * seconds, empty when absent) bounds its lifetime.
 */

import { signData, verifySignature, domainSeparatedInput, CTX_ATTESTATION } from './crypto.js';
import { capabilitiesHash } from './capability.js';
import { normalizeDomain } from './domain.js';
import { AgentPinError, ErrorCode } from './types.js';

function normalizeOrRaw(domain) {
    try {
        return normalizeDomain(domain);
    } catch {
        return String(domain);
    }
}

/**
 * Create the domain-separated attestation signing input.
 * @param {string} domain
 * @param {string} role
 * @param {string} agentId
 * @param {string} delegateeDomain
 * @param {string} delegateeAgentId
 * @param {Capability[]} capabilities
 * @param {string} kid
 * @param {number|null|undefined} exp - Optional expiry (Unix seconds)
 * @returns {Buffer}
 */
export function canonicalAttestationInput(
    domain, role, agentId, delegateeDomain, delegateeAgentId, capabilities, kid, exp = null
) {
    const capHash = capabilitiesHash(capabilities);
    const expStr = (exp === null || exp === undefined) ? '' : String(exp);
    // Domains are compared in normalized form everywhere else (AP-3), so the
    // signed input uses the normalized form too; invalid names are signed
    // verbatim and can never match a normalized issuer.
    return domainSeparatedInput(CTX_ATTESTATION, [
        normalizeOrRaw(domain), String(role), String(agentId),
        normalizeOrRaw(delegateeDomain), String(delegateeAgentId),
        capHash, String(kid), expStr,
    ]);
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
 * @param {number|null} [exp] - Optional attestation expiry (Unix seconds)
 * @returns {object} DelegationAttestation
 */
export function createAttestation(
    privateKeyPem, kid, domain, role, agentId,
    delegateeDomain, delegateeAgentId, capabilities, exp = null
) {
    const input = canonicalAttestationInput(
        domain, role, agentId, delegateeDomain, delegateeAgentId, capabilities, kid, exp
    );
    const signature = signData(privateKeyPem, input);

    const att = {
        domain,
        role,
        agent_id: agentId,
        kid,
        attestation: signature,
    };
    if (exp !== null && exp !== undefined) {
        att.exp = exp;
    }
    return att;
}

/**
 * Verify a single delegation attestation signature (and expiry, when present).
 * @param {object} attestation
 * @param {string} publicKeyPem
 * @param {string} delegateeDomain
 * @param {string} delegateeAgentId
 * @param {Capability[]} capabilities
 * @throws {AgentPinError}
 */
export function verifyAttestation(attestation, publicKeyPem, delegateeDomain, delegateeAgentId, capabilities) {
    const exp = attestation.exp;
    if (exp !== undefined && exp !== null) {
        if (!Number.isSafeInteger(exp) || exp < Math.floor(Date.now() / 1000)) {
            throw new AgentPinError(
                ErrorCode.DELEGATION_INVALID,
                `Delegation attestation from ${attestation.domain} has expired`
            );
        }
    }
    const input = canonicalAttestationInput(
        attestation.domain, attestation.role, attestation.agent_id,
        delegateeDomain, delegateeAgentId, capabilities, attestation.kid,
        exp === undefined ? null : exp
    );

    const valid = verifySignature(publicKeyPem, input, attestation.attestation);
    if (!valid) {
        throw new AgentPinError(
            ErrorCode.DELEGATION_INVALID,
            `Delegation attestation from ${attestation.domain} failed signature verification`
        );
    }
}

/**
 * Verify the depth of a delegation chain does not exceed the minimum max_delegation_depth.
 * An empty depth list means depth 0 (no delegation permitted).
 * @param {number} chainLen
 * @param {number[]} maxDepths
 * @throws {AgentPinError}
 */
export function verifyChainDepth(chainLen, maxDepths) {
    const minDepth = (maxDepths && maxDepths.length) ? Math.min(...maxDepths) : 0;
    if (chainLen > minDepth) {
        throw new AgentPinError(
            ErrorCode.DELEGATION_DEPTH_EXCEEDED,
            `Delegation chain depth ${chainLen} exceeds minimum max_delegation_depth ${minDepth}`
        );
    }
}
