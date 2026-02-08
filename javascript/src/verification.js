/**
 * Credential verification for AgentPin.
 * Implements the 12-step verification flow from the spec.
 */

import { decodeJwtUnverified, verifyJwt } from './jwt.js';
import { jwkToPem } from './jwk.js';
import { validateCredentialAgainstDiscovery } from './credential.js';
import { validateDiscoveryDocument, findKeyByKid, findAgentById, fetchDiscoveryDocument } from './discovery.js';
import { checkRevocation, fetchRevocationDocument } from './revocation.js';
import { checkPinning, PinningResult } from './pinning.js';
import { constraintsSubsetOf } from './constraint.js';
import { ErrorCode, AgentPinError } from './types.js';

/**
 * Default verifier configuration.
 * @returns {{ clockSkewSecs: number, maxTtlSecs: number }}
 */
export function defaultVerifierConfig() {
    return {
        clockSkewSecs: 60,
        maxTtlSecs: 86400,
    };
}

/**
 * Create a successful verification result.
 */
function successResult(agentId, issuer, capabilities, constraints, pinStatus) {
    return {
        valid: true,
        agent_id: agentId,
        issuer,
        capabilities,
        constraints: constraints || null,
        delegation_verified: null,
        delegation_chain: null,
        key_pinning: pinStatus,
        error_code: null,
        error_message: null,
        warnings: [],
    };
}

/**
 * Create a failed verification result.
 */
function failureResult(code, message) {
    return {
        valid: false,
        agent_id: null,
        issuer: null,
        capabilities: null,
        constraints: null,
        delegation_verified: null,
        delegation_chain: null,
        key_pinning: null,
        error_code: code,
        error_message: message,
        warnings: [],
    };
}

/**
 * Verify a credential offline using caller-provided documents.
 * Implements the 12-step verification flow from the spec.
 * @param {string} credentialJwt
 * @param {object} discovery - Discovery document
 * @param {object|null} revocation - Revocation document
 * @param {import('./pinning.js').KeyPinStore} pinStore
 * @param {string|null} audience
 * @param {object} config - Verifier config
 * @returns {object} VerificationResult
 */
export function verifyCredentialOffline(credentialJwt, discovery, revocation, pinStore, audience, config) {
    config = config || defaultVerifierConfig();

    // Step 1: Parse JWT (validates alg == ES256 and typ == agentpin-credential+jwt)
    let header, payload;
    try {
        ({ header, payload } = decodeJwtUnverified(credentialJwt));
    } catch (e) {
        return failureResult(ErrorCode.ALGORITHM_REJECTED, `JWT parse failed: ${e.message}`);
    }

    // Step 2: Check temporal validity
    const now = Math.floor(Date.now() / 1000);
    const skew = config.clockSkewSecs;

    if (payload.iat > now + skew) {
        return failureResult(ErrorCode.CREDENTIAL_EXPIRED, 'Credential issued in the future');
    }
    if (payload.exp <= now - skew) {
        return failureResult(ErrorCode.CREDENTIAL_EXPIRED, 'Credential has expired');
    }
    if (payload.nbf !== undefined && payload.nbf !== null && payload.nbf > now + skew) {
        return failureResult(ErrorCode.CREDENTIAL_EXPIRED, 'Credential not yet valid (nbf)');
    }

    // Check max TTL
    const lifetime = payload.exp - payload.iat;
    if (lifetime > config.maxTtlSecs) {
        return failureResult(
            ErrorCode.CREDENTIAL_EXPIRED,
            `Credential lifetime ${lifetime} exceeds max TTL ${config.maxTtlSecs}`
        );
    }

    // Step 3: Validate discovery document (entity matches iss)
    try {
        validateDiscoveryDocument(discovery, payload.iss);
    } catch (e) {
        return failureResult(ErrorCode.DISCOVERY_INVALID, `Discovery validation failed: ${e.message}`);
    }

    // Step 4: Resolve public key by kid
    const jwk = findKeyByKid(discovery, header.kid);
    if (!jwk) {
        return failureResult(ErrorCode.KEY_NOT_FOUND, `Key '${header.kid}' not found in discovery document`);
    }

    // Check key expiration
    if (jwk.exp) {
        const expDate = new Date(jwk.exp);
        if (expDate.getTime() / 1000 < now - skew) {
            return failureResult(ErrorCode.KEY_EXPIRED, `Key '${header.kid}' has expired`);
        }
    }

    // Convert JWK to PEM for verification
    let publicKeyPem;
    try {
        publicKeyPem = jwkToPem(jwk);
    } catch (e) {
        return failureResult(ErrorCode.KEY_NOT_FOUND, `Invalid key format for '${header.kid}': ${e.message}`);
    }

    // Step 5: Verify JWT signature
    try {
        verifyJwt(credentialJwt, publicKeyPem);
    } catch {
        return failureResult(ErrorCode.SIGNATURE_INVALID, `JWT signature verification failed for kid '${header.kid}'`);
    }

    // Step 6: Check revocation
    if (revocation) {
        try {
            checkRevocation(revocation, payload.jti, payload.sub, header.kid);
        } catch (e) {
            const code = e instanceof AgentPinError ? e.code : ErrorCode.CREDENTIAL_REVOKED;
            return failureResult(code, e.message);
        }
    }

    // Step 7: Validate agent status
    const agent = findAgentById(discovery, payload.sub);
    if (!agent) {
        return failureResult(ErrorCode.AGENT_NOT_FOUND, `Agent '${payload.sub}' not found in discovery document`);
    }
    if (agent.status !== 'active') {
        return failureResult(ErrorCode.AGENT_INACTIVE, `Agent '${payload.sub}' status is ${agent.status}`);
    }

    // Step 8: Validate capabilities
    try {
        validateCredentialAgainstDiscovery(payload.capabilities, agent.capabilities);
    } catch (e) {
        return failureResult(ErrorCode.CAPABILITY_EXCEEDED, e.message);
    }

    // Step 9: Validate constraints
    if (!constraintsSubsetOf(agent.constraints, payload.constraints)) {
        return failureResult(
            ErrorCode.CONSTRAINT_VIOLATION,
            'Credential constraints are less restrictive than discovery defaults'
        );
    }

    // Step 10: Validate delegation chain (offline mode: note only)
    let result = successResult(
        payload.sub,
        payload.iss,
        payload.capabilities,
        payload.constraints,
        { status: 'unknown', first_seen: null }
    );

    if (payload.delegation_chain) {
        const entries = payload.delegation_chain.map(att => ({
            domain: att.domain,
            role: att.role,
            verified: false,
        }));
        result.delegation_chain = entries;
        result.delegation_verified = false;
        result.warnings.push('Delegation chain present but not verified in offline mode');
    }

    // Step 11: TOFU key pinning
    try {
        const pinResult = checkPinning(pinStore, payload.iss, jwk);
        if (pinResult === PinningResult.FIRST_USE) {
            result.key_pinning = {
                status: 'first_use',
                first_seen: new Date().toISOString(),
            };
        } else if (pinResult === PinningResult.MATCHED) {
            const domainData = pinStore.getDomain(payload.iss);
            const firstSeen = domainData?.pinned_keys?.[0]?.first_seen || null;
            result.key_pinning = {
                status: 'pinned',
                first_seen: firstSeen,
            };
        }
    } catch {
        return failureResult(
            ErrorCode.KEY_PIN_MISMATCH,
            `Key for '${payload.iss}' has changed since last pinned`
        );
    }

    // Step 12: Check audience
    if (audience && payload.aud) {
        if (payload.aud !== '*' && payload.aud !== audience) {
            return failureResult(
                ErrorCode.AUDIENCE_MISMATCH,
                `Credential audience '${payload.aud}' does not match verifier '${audience}'`
            );
        }
    }

    return result;
}

/**
 * Online verification that fetches discovery/revocation documents.
 * @param {string} credentialJwt
 * @param {import('./pinning.js').KeyPinStore} pinStore
 * @param {string|null} audience
 * @param {object} config
 * @returns {Promise<object>}
 */
export async function verifyCredential(credentialJwt, pinStore, audience, config) {
    config = config || defaultVerifierConfig();

    // Parse JWT to extract issuer domain
    let payload;
    try {
        ({ payload } = decodeJwtUnverified(credentialJwt));
    } catch (e) {
        return failureResult(ErrorCode.ALGORITHM_REJECTED, `JWT parse failed: ${e.message}`);
    }

    // Fetch discovery document
    let discovery;
    try {
        discovery = await fetchDiscoveryDocument(payload.iss);
    } catch (e) {
        return failureResult(ErrorCode.DISCOVERY_FETCH_FAILED, `Failed to fetch discovery document: ${e.message}`);
    }

    // Fetch revocation document
    let revocation = null;
    if (discovery.revocation_endpoint) {
        try {
            revocation = await fetchRevocationDocument(discovery.revocation_endpoint);
        } catch {
            return failureResult(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                'Revocation endpoint unreachable (fail-closed)'
            );
        }
    }

    return verifyCredentialOffline(credentialJwt, discovery, revocation, pinStore, audience, config);
}
