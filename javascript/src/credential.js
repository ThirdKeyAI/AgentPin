/**
 * Agent credential issuance and validation for AgentPin.
 */

import { randomUUID } from 'crypto';
import { encodeJwt, validateClaims } from './jwt.js';
import { Capability, capabilitiesSubset } from './capability.js';
import { AgentPinError, ErrorCode } from './types.js';

/**
 * Issue a new agent credential JWT.
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} kid - Key ID
 * @param {string} issuer - Issuer domain
 * @param {string} agentId - Agent identifier (URN)
 * @param {string|null} audience - Optional audience
 * @param {Capability[]} capabilities - List of capabilities
 * @param {object|null} constraints - Optional constraints
 * @param {object[]|null} delegationChain - Optional delegation chain
 * @param {number} ttlSecs - Time-to-live in seconds
 * @returns {string} Compact JWT string
 */
export function issueCredential(
    privateKeyPem,
    kid,
    issuer,
    agentId,
    audience,
    capabilities,
    constraints,
    delegationChain,
    ttlSecs
) {
    return issue(privateKeyPem, kid, issuer, agentId, audience, capabilities, constraints, delegationChain, ttlSecs, null);
}

/**
 * Issue a credential bound to the agent's Web Bot Auth key (spec §18):
 * `wbaJkt`, the key's JWK thumbprint (see `wba.thumbprint`), is carried as
 * `cnf.jkt`.
 * @param {string} privateKeyPem - PEM-encoded ECDSA P-256 private key
 * @param {string} kid
 * @param {string} issuer
 * @param {string} agentId
 * @param {string|null} audience
 * @param {Capability[]} capabilities
 * @param {object|null} constraints
 * @param {object[]|null} delegationChain
 * @param {number} ttlSecs
 * @param {string} wbaJkt - base64url SHA-256 JWK thumbprint of the WBA key
 * @returns {string} Compact JWT string
 * @throws {MalformedCredentialError} if `wbaJkt` is not a thumbprint
 */
export function issueBoundCredential(
    privateKeyPem,
    kid,
    issuer,
    agentId,
    audience,
    capabilities,
    constraints,
    delegationChain,
    ttlSecs,
    wbaJkt
) {
    return issue(privateKeyPem, kid, issuer, agentId, audience, capabilities, constraints, delegationChain, ttlSecs,
        { jkt: wbaJkt });
}

function issue(privateKeyPem, kid, issuer, agentId, audience, capabilities, constraints, delegationChain, ttlSecs, cnf) {
    const now = Math.floor(Date.now() / 1000);

    const header = {
        alg: 'ES256',
        typ: 'agentpin-credential+jwt',
        kid,
    };

    const payload = {
        iss: issuer,
        sub: agentId,
        iat: now,
        exp: now + ttlSecs,
        jti: randomUUID(),
        agentpin_version: '0.1',
        capabilities: capabilities.map(c => c.value || c),
    };

    if (audience) payload.aud = audience;
    if (constraints) payload.constraints = constraints;
    if (delegationChain) payload.delegation_chain = delegationChain;
    if (cnf) payload.cnf = cnf;
    validateClaims(payload);

    return encodeJwt(header, payload, privateKeyPem);
}

/**
 * Validate that credential capabilities are a subset of discovery agent capabilities.
 * @param {Capability[]|string[]} credentialCaps
 * @param {Capability[]|string[]} discoveryCaps
 * @throws {AgentPinError} if capabilities exceed discovery
 */
export function validateCredentialAgainstDiscovery(credentialCaps, discoveryCaps) {
    const credCaps = credentialCaps.map(c => c instanceof Capability ? c : new Capability(c));
    const discCaps = discoveryCaps.map(c => c instanceof Capability ? c : new Capability(c));

    if (!capabilitiesSubset(discCaps, credCaps)) {
        throw new AgentPinError(
            ErrorCode.CAPABILITY_EXCEEDED,
            'Credential capabilities exceed discovery document'
        );
    }
}
