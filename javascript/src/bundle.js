/**
 * Trust bundle support for AgentPin.
 *
 * A trust bundle is a pre-shared collection of discovery and revocation
 * documents, enabling verification in environments where the standard
 * .well-known HTTP discovery is unavailable.
 */

import { verifyCredentialOffline, defaultVerifierConfig } from './verification.js';
import { decodeJwtUnverified } from './jwt.js';
import { normalizeDomain } from './domain.js';
import { AgentPinError, ErrorCode } from './types.js';
import { signData, verifySignature, domainSeparatedInput, CTX_BUNDLE } from './crypto.js';
import { canonicalizeForSigning } from './a2a.js';

function bundleKey(entity) {
    try {
        return normalizeDomain(entity);
    } catch {
        return String(entity);
    }
}

/**
 * Create a new empty trust bundle.
 * @param {string} createdAt - ISO 8601 timestamp
 * @returns {object}
 */
export function createTrustBundle(createdAt) {
    return {
        agentpin_bundle_version: '0.1',
        created_at: createdAt || new Date().toISOString(),
        documents: [],
        revocations: [],
    };
}

/**
 * Find a discovery document in a bundle by domain.
 * @param {object} bundle
 * @param {string} domain
 * @returns {object|null}
 */
export function findBundleDiscovery(bundle, domain) {
    const key = bundleKey(domain);
    return bundle.documents.find(d => bundleKey(d.entity) === key) || null;
}

/**
 * Find a revocation document in a bundle by domain.
 * @param {object} bundle
 * @param {string} domain
 * @returns {object|null}
 */
export function findBundleRevocation(bundle, domain) {
    const key = bundleKey(domain);
    return (bundle.revocations || []).find(r => bundleKey(r.entity) === key) || null;
}

/**
 * Verify a credential using a trust bundle for discovery.
 *
 * Extracts the issuer domain from the JWT, looks up the discovery and
 * revocation documents from the bundle, then delegates to
 * verifyCredentialOffline.
 *
 * @param {string} credentialJwt
 * @param {object} bundle - Trust bundle
 * @param {import('./pinning.js').KeyPinStore} pinStore
 * @param {string|null} audience
 * @param {object} [config]
 * @returns {object} VerificationResult
 */
export function verifyCredentialWithBundle(credentialJwt, bundle, pinStore, audience, config) {
    config = config || defaultVerifierConfig();

    let payload;
    try {
        ({ payload } = decodeJwtUnverified(credentialJwt));
    } catch (e) {
        return {
            valid: false,
            agent_id: null,
            issuer: null,
            capabilities: null,
            constraints: null,
            delegation_verified: null,
            delegation_chain: null,
            key_pinning: null,
            error_code: ErrorCode.ALGORITHM_REJECTED,
            error_message: `JWT parse failed: ${e.message}`,
            warnings: [],
        };
    }

    const discovery = findBundleDiscovery(bundle, payload.iss);
    if (!discovery) {
        return {
            valid: false,
            agent_id: null,
            issuer: null,
            capabilities: null,
            constraints: null,
            delegation_verified: null,
            delegation_chain: null,
            key_pinning: null,
            error_code: ErrorCode.DISCOVERY_FETCH_FAILED,
            error_message: `Domain '${payload.iss}' not found in trust bundle`,
            warnings: [],
        };
    }

    const revocation = findBundleRevocation(bundle, payload.iss);
    const chainResolver = {
        resolveDiscovery(domain) {
            const doc = findBundleDiscovery(bundle, domain);
            if (!doc) throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `Domain '${domain}' not found in trust bundle`);
            return doc;
        },
    };
    return verifyCredentialOffline(credentialJwt, discovery, revocation, pinStore, audience, config, chainResolver);
}

// ---------------------------------------------------------------------------
// Signed trust bundles (design issue 5)
// ---------------------------------------------------------------------------

/**
 * Signing input: the `agentpin-bundle-v1` context over the canonical JSON of
 * the bundle with `signature` cleared.
 * @param {object} bundle
 * @returns {Buffer}
 */
export function bundleSigningInput(bundle) {
    const rest = { ...bundle };
    delete rest.signature;
    return domainSeparatedInput(CTX_BUNDLE, [Buffer.from(canonicalizeForSigning(rest), 'utf8')]);
}

/**
 * Sign a trust bundle in place with the operator key identified by `kid`.
 * @param {object} bundle
 * @param {string} privateKeyPem
 * @param {string} kid
 */
export function signTrustBundle(bundle, privateKeyPem, kid) {
    bundle.kid = kid;
    delete bundle.signature;
    bundle.signature = signData(privateKeyPem, bundleSigningInput(bundle));
    return bundle;
}

/**
 * Reject a bundle whose `expires_at` is unparsable or in the past.
 * @param {object} bundle
 */
export function checkBundleExpiry(bundle) {
    if (bundle.expires_at === undefined || bundle.expires_at === null) return;
    const exp = new Date(bundle.expires_at);
    if (typeof bundle.expires_at !== 'string' || Number.isNaN(exp.getTime())) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Trust bundle expires_at is not RFC 3339');
    }
    if (exp.getTime() < Date.now()) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Trust bundle has expired');
    }
}

/**
 * Verify a trust bundle's signature under `publicKeyPem` and reject it when
 * expired. Unsigned bundles are rejected.
 * @param {object} bundle
 * @param {string} publicKeyPem
 */
export function verifyTrustBundle(bundle, publicKeyPem) {
    if (bundle.signature === undefined || bundle.signature === null) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Trust bundle is not signed');
    }
    if (!verifySignature(publicKeyPem, bundleSigningInput(bundle), String(bundle.signature))) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'Trust bundle signature did not verify');
    }
    checkBundleExpiry(bundle);
}
