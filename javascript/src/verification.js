/**
 * Credential verification for AgentPin.
 * Implements the 12-step verification flow from the spec.
 */

import { decodeJwtUnverified, verifyJwt, MalformedCredentialError } from './jwt.js';
import { jwkToPem } from './jwk.js';
import { validateCredentialAgainstDiscovery } from './credential.js';
import { validateDiscoveryDocument, findKeyByKid, findAgentById, fetchDiscoveryDocument } from './discovery.js';
import {
    checkRevocation, fetchRevocationDocument, fetchRevocationDocumentIfPresent,
    verifyRevocationDocument, checkRevocationFreshness,
} from './revocation.js';
import { checkPinning, PinningResult } from './pinning.js';
import { mergeConstraints } from './constraint.js';
import { verifyAttestation, verifyChainDepth } from './delegation.js';
import { normalizeDomain, validateHttpsUrlForDomain, defaultRevocationEndpoint } from './domain.js';
import { ErrorCode, AgentPinError } from './types.js';

/**
 * Default verifier configuration.
 * @returns {{ clockSkewSecs: number, maxTtlSecs: number }}
 */
export function defaultVerifierConfig() {
    return {
        clockSkewSecs: 60,
        maxTtlSecs: 86400,
        /** Reject unsigned revocation documents (signed ones are always verified). */
        requireSignedRevocation: false,
        /** When set, reject revocation documents older than this many seconds. */
        revocationMaxAgeSecs: null,
        /**
         * When true (default), a credential carrying a delegation_chain is
         * rejected with DELEGATION_INVALID unless every attestation was
         * verified against the attester's discovery document (spec §6.1 step
         * 10). Set to false only to accept unverified chains, which are then
         * reported with delegation_verified: false and a warning (AP-2).
         */
        requireDelegationVerification: true,
    };
}

/** Default `credential_ttl_max` when an agent declaration omits it (spec §4.5). */
export const DEFAULT_CREDENTIAL_TTL_MAX = 86400;

/**
 * Reject keys that are expired, not marked for signature use, or whose
 * key_ops exclude "verify" (spec §4.4; AP-20, AP-21). An unparsable exp is
 * a failure, not a pass.
 * @param {object} jwk
 * @param {number} now
 * @param {number} skew
 * @throws {AgentPinError}
 */
export function checkKeyUsable(jwk, now, skew) {
    if (jwk.exp !== undefined && jwk.exp !== null) {
        const expDate = new Date(jwk.exp);
        if (typeof jwk.exp !== 'string' || Number.isNaN(expDate.getTime())) {
            throw new AgentPinError(ErrorCode.KEY_EXPIRED, `Key '${jwk.kid}' has an unparsable exp '${jwk.exp}'`);
        }
        if (expDate.getTime() / 1000 < now - skew) {
            throw new AgentPinError(ErrorCode.KEY_EXPIRED, `Key '${jwk.kid}' has expired`);
        }
    }
    if (jwk.use !== 'sig') {
        throw new AgentPinError(ErrorCode.KEY_NOT_FOUND, `Key '${jwk.kid}' is not a signature key (use = '${jwk.use}')`);
    }
    if (jwk.key_ops !== undefined && jwk.key_ops !== null) {
        if (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes('verify')) {
            throw new AgentPinError(ErrorCode.KEY_NOT_FOUND, `Key '${jwk.kid}' key_ops do not permit verify`);
        }
    }
}

/**
 * Spec §6.4: verify every attestation in the chain against its attester's
 * discovery document, check Maker/Deployer scope narrowing, and enforce the
 * minimum max_delegation_depth across all participants.
 * @returns {{ entries: object[] } | { failure: object }}
 */
function verifyDelegationChain(chain, issuer, payload, discovery, chainResolver, now, skew) {
    const fail = (message) => ({ failure: failureResult(ErrorCode.DELEGATION_INVALID, message) });
    const depths = [discovery.max_delegation_depth];
    const entries = [];
    for (const att of chain) {
        let domain;
        try {
            domain = normalizeDomain(att.domain);
        } catch (e) {
            return fail(`Delegation attester domain invalid: ${e.message}`);
        }
        let doc;
        try {
            doc = chainResolver.resolveDiscovery(domain);
            if (doc && typeof doc.then === 'function') {
                return fail('Delegation chain resolver must be synchronous; pre-resolve asynchronously');
            }
            validateDiscoveryDocument(doc, domain);
        } catch (e) {
            return fail(`Cannot resolve discovery document for delegation attester '${domain}': ${e.message}`);
        }
        const jwk = findKeyByKid(doc, att.kid);
        if (!jwk) return fail(`Delegation attester '${domain}' has no key '${att.kid}'`);
        let pem;
        try {
            checkKeyUsable(jwk, now, skew);
            pem = jwkToPem(jwk);
        } catch (e) {
            return fail(`Delegation attester '${domain}' key '${att.kid}' unusable: ${e.message}`);
        }
        try {
            verifyAttestation(att, pem, issuer, payload.sub, payload.capabilities);
        } catch (e) {
            return fail(e.message);
        }
        // Scope narrowing (spec §10.3): when the attester declares the
        // attested agent, it must be active and the credential capabilities
        // must be within what the attester declared for it.
        const agent = findAgentById(doc, att.agent_id);
        if (agent) {
            if (agent.status !== 'active') {
                return fail(`Delegation attester '${domain}' declares agent '${att.agent_id}' as ${agent.status}`);
            }
            try {
                validateCredentialAgainstDiscovery(payload.capabilities, agent.capabilities);
            } catch {
                return fail(`Credential capabilities exceed those declared by delegation attester '${domain}' for '${att.agent_id}'`);
            }
        }
        depths.push(doc.max_delegation_depth);
        entries.push({ domain, role: att.role, verified: true });
    }
    try {
        verifyChainDepth(chain.length, depths);
    } catch (e) {
        return { failure: failureResult(e instanceof AgentPinError ? e.code : ErrorCode.DELEGATION_DEPTH_EXCEEDED, e.message) };
    }
    return { entries };
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
 * Map a decode error: claim-shape problems are MALFORMED_CREDENTIAL,
 * everything else (structure, alg, typ) is ALGORITHM_REJECTED.
 */
function parseFailure(e) {
    if (e instanceof MalformedCredentialError) {
        return failureResult(ErrorCode.MALFORMED_CREDENTIAL, e.reason);
    }
    return failureResult(ErrorCode.ALGORITHM_REJECTED, `JWT parse failed: ${e.message}`);
}

/**
 * Verify a credential offline using caller-provided documents.
 * Implements the 12-step verification flow from the spec.
 *
 * Without `chainResolver` a delegation_chain cannot be verified; under the
 * default `requireDelegationVerification: true` such a credential is
 * rejected. Pass an object with a synchronous `resolveDiscovery(domain)`
 * (for example a trust bundle lookup) to verify chains offline.
 *
 * @param {string} credentialJwt
 * @param {object} discovery - Discovery document
 * @param {object|null} revocation - Revocation document
 * @param {import('./pinning.js').KeyPinStore} pinStore
 * @param {string|null} audience
 * @param {object} [config] - Verifier config
 * @param {{ resolveDiscovery: Function }|null} [chainResolver] - Resolver for delegation attesters' documents
 * @returns {object} VerificationResult
 */
export function verifyCredentialOffline(credentialJwt, discovery, revocation, pinStore, audience, config, chainResolver = null) {
    config = { ...defaultVerifierConfig(), ...(config || {}) };

    // Step 1: Parse JWT (validates alg == ES256 and typ == agentpin-credential+jwt,
    // then claim shape — AP-5 / AP-18)
    let header, payload;
    try {
        ({ header, payload } = decodeJwtUnverified(credentialJwt));
    } catch (e) {
        return parseFailure(e);
    }

    // Normalize the issuer domain before it is used as a lookup key anywhere
    // (pin store, entity comparison, resolver paths/URLs) — AP-3.
    let issuer;
    try {
        issuer = normalizeDomain(payload.iss);
    } catch (e) {
        return failureResult(ErrorCode.DISCOVERY_INVALID, `Invalid issuer domain: ${e.message}`);
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

    // Check max TTL. Claims were validated as safe non-negative integers with
    // exp > iat, so the difference is exact (AP-14).
    const lifetime = payload.exp - payload.iat;
    if (!Number.isSafeInteger(lifetime) || lifetime <= 0) {
        return failureResult(ErrorCode.MALFORMED_CREDENTIAL, 'exp must be greater than iat');
    }
    if (lifetime > config.maxTtlSecs) {
        return failureResult(
            ErrorCode.CREDENTIAL_EXPIRED,
            `Credential lifetime ${lifetime} exceeds max TTL ${config.maxTtlSecs}`
        );
    }

    // Step 3: Validate discovery document (entity matches iss)
    try {
        validateDiscoveryDocument(discovery, issuer);
    } catch (e) {
        return failureResult(ErrorCode.DISCOVERY_INVALID, `Discovery validation failed: ${e.message}`);
    }

    // Step 4: Resolve public key by kid
    const jwk = findKeyByKid(discovery, header.kid);
    if (!jwk) {
        return failureResult(ErrorCode.KEY_NOT_FOUND, `Key '${header.kid}' not found in discovery document`);
    }

    // Check key expiration and usage (an unparsable exp is a failure, not a
    // pass — AP-20; use/key_ops enforced — AP-21)
    try {
        checkKeyUsable(jwk, now, skew);
    } catch (e) {
        return failureResult(e instanceof AgentPinError ? e.code : ErrorCode.KEY_NOT_FOUND, e.message);
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

    // Step 6: Check revocation. The document must belong to this issuer and,
    // when signed, verify under a discovery key (design issue 3).
    if (revocation) {
        try {
            verifyRevocationDocument(revocation, discovery);
        } catch (e) {
            return failureResult(ErrorCode.DISCOVERY_INVALID, `Revocation document invalid: ${e.message}`);
        }
        if (config.requireSignedRevocation && (revocation.signature === undefined || revocation.signature === null)) {
            return failureResult(ErrorCode.DISCOVERY_INVALID, 'Revocation document is not signed');
        }
        if (config.revocationMaxAgeSecs !== null && config.revocationMaxAgeSecs !== undefined) {
            try {
                checkRevocationFreshness(revocation, config.revocationMaxAgeSecs);
            } catch (e) {
                return failureResult(ErrorCode.DISCOVERY_INVALID, `Revocation document invalid: ${e.message}`);
            }
        }
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

    // Spec §5.7: exp - iat MUST NOT exceed the agent's credential_ttl_max
    // (default 86400 when omitted) — AP-14.
    const ttlMax = Number.isSafeInteger(agent.credential_ttl_max) ? agent.credential_ttl_max : DEFAULT_CREDENTIAL_TTL_MAX;
    if (lifetime > ttlMax) {
        return failureResult(
            ErrorCode.CREDENTIAL_EXPIRED,
            `Credential lifetime ${lifetime} exceeds agent credential_ttl_max ${ttlMax}`
        );
    }

    // Step 8: Validate capabilities
    try {
        validateCredentialAgainstDiscovery(payload.capabilities, agent.capabilities);
    } catch (e) {
        return failureResult(ErrorCode.CAPABILITY_EXCEEDED, e.message);
    }

    // Step 9: Validate constraints and compute the effective (merged) set the
    // consumer must enforce: discovery defaults narrowed by the credential
    // (AP-15).
    let effectiveConstraints;
    try {
        effectiveConstraints = mergeConstraints(agent.constraints, payload.constraints);
    } catch (e) {
        return failureResult(
            ErrorCode.CONSTRAINT_VIOLATION,
            `Credential constraints are less restrictive than discovery defaults: ${e.message}`
        );
    }

    // Step 10: Validate delegation chain (offline mode: note only)
    let result = successResult(
        payload.sub,
        issuer,
        payload.capabilities,
        effectiveConstraints,
        { status: 'unknown', first_seen: null }
    );

    // Step 10: every attestation is verified against its attester's
    // discovery document (spec §6.4); a chain that cannot be verified fails
    // closed unless the verifier opted out (AP-2).
    if (payload.delegation_chain && payload.delegation_chain.length > 0) {
        if (chainResolver) {
            const outcome = verifyDelegationChain(payload.delegation_chain, issuer, payload, discovery, chainResolver, now, skew);
            if (outcome.failure) return outcome.failure;
            result.delegation_chain = outcome.entries;
            result.delegation_verified = true;
        } else if (config.requireDelegationVerification) {
            return failureResult(ErrorCode.DELEGATION_INVALID, 'Delegation chain present but no resolver is available to verify it');
        } else {
            result.delegation_chain = payload.delegation_chain.map(att => ({ domain: att.domain, role: att.role, verified: false }));
            result.delegation_verified = false;
            result.warnings.push('Delegation chain present but not verified (requireDelegationVerification is false)');
        }
    }

    // Step 11: TOFU key pinning
    try {
        const pinResult = checkPinning(pinStore, issuer, jwk);
        if (pinResult === PinningResult.FIRST_USE) {
            result.key_pinning = {
                status: 'first_use',
                first_seen: new Date().toISOString(),
            };
        } else if (pinResult === PinningResult.MATCHED) {
            const domainData = pinStore.getDomain(issuer);
            const firstSeen = domainData?.pinned_keys?.[0]?.first_seen || null;
            result.key_pinning = {
                status: 'pinned',
                first_seen: firstSeen,
            };
        }
    } catch {
        return failureResult(
            ErrorCode.KEY_PIN_MISMATCH,
            `Key for '${issuer}' has changed since last pinned`
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
    config = { ...defaultVerifierConfig(), ...(config || {}) };

    // Parse JWT to extract issuer domain
    let payload;
    try {
        ({ payload } = decodeJwtUnverified(credentialJwt));
    } catch (e) {
        return parseFailure(e);
    }

    let issuer;
    try {
        issuer = normalizeDomain(payload.iss);
    } catch (e) {
        return failureResult(ErrorCode.DISCOVERY_INVALID, `Invalid issuer domain: ${e.message}`);
    }

    // Fetch discovery document
    let discovery;
    try {
        discovery = await fetchDiscoveryDocument(issuer, config.fetch || {});
    } catch (e) {
        return failureResult(ErrorCode.DISCOVERY_FETCH_FAILED, `Failed to fetch discovery document: ${e.message}`);
    }

    // Fetch revocation document (https on the issuer's own host only — AP-12).
    // An explicitly declared endpoint fails closed on any error; when none is
    // declared the spec §8.1 default URL is used and only a 404 there means
    // "no revocations published" (design issue 3).
    let revocation = null;
    if (discovery.revocation_endpoint) {
        try {
            validateHttpsUrlForDomain(discovery.revocation_endpoint, issuer);
        } catch (e) {
            return failureResult(ErrorCode.DISCOVERY_INVALID, `Invalid revocation_endpoint: ${e.message}`);
        }
        try {
            revocation = await fetchRevocationDocument(discovery.revocation_endpoint, config.fetch || {});
        } catch {
            return failureResult(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                'Revocation endpoint unreachable (fail-closed)'
            );
        }
    } else {
        try {
            revocation = await fetchRevocationDocumentIfPresent(defaultRevocationEndpoint(issuer), config.fetch || {});
        } catch {
            return failureResult(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                'Revocation endpoint unreachable (fail-closed)'
            );
        }
    }

    // Pre-resolve the discovery documents of every delegation attester so
    // the chain can be verified by the synchronous core (AP-2).
    const chainDocs = new Map();
    for (const att of payload.delegation_chain || []) {
        let domain;
        try {
            domain = normalizeDomain(att.domain);
        } catch (e) {
            return failureResult(ErrorCode.DELEGATION_INVALID, `Delegation attester domain invalid: ${e.message}`);
        }
        if (chainDocs.has(domain)) continue;
        try {
            chainDocs.set(domain, await fetchDiscoveryDocument(domain, config.fetch || {}));
        } catch (e) {
            return failureResult(ErrorCode.DELEGATION_INVALID, `Cannot resolve discovery document for delegation attester '${domain}': ${e.message}`);
        }
    }
    const chainResolver = {
        resolveDiscovery(domain) {
            const doc = chainDocs.get(normalizeDomain(domain));
            if (!doc) throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `Domain '${domain}' not pre-resolved`);
            return doc;
        },
    };

    return verifyCredentialOffline(credentialJwt, discovery, revocation, pinStore, audience, config, chainResolver);
}
