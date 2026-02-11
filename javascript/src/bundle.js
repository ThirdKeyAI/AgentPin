/**
 * Trust bundle support for AgentPin.
 *
 * A trust bundle is a pre-shared collection of discovery and revocation
 * documents, enabling verification in environments where the standard
 * .well-known HTTP discovery is unavailable.
 */

import { verifyCredentialOffline, defaultVerifierConfig } from './verification.js';
import { decodeJwtUnverified } from './jwt.js';
import { ErrorCode } from './types.js';

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
    return bundle.documents.find(d => d.entity === domain) || null;
}

/**
 * Find a revocation document in a bundle by domain.
 * @param {object} bundle
 * @param {string} domain
 * @returns {object|null}
 */
export function findBundleRevocation(bundle, domain) {
    return (bundle.revocations || []).find(r => r.entity === domain) || null;
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
    return verifyCredentialOffline(credentialJwt, discovery, revocation, pinStore, audience, config);
}
