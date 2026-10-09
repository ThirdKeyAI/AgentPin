/**
 * Mutual authentication challenge-response protocol for AgentPin (spec §9).
 *
 * The responder signs a domain-separated structure, never the raw nonce:
 *
 *   "agentpin-response-v1" 0x00 len(nonce) nonce len(timestamp) timestamp
 *                               len(kid) kid len(binding) binding
 *
 * where `binding` is the SHA-256 (hex) of the challenge's
 * `verifier_credential` when present (empty otherwise). This binds a response
 * to this verifier and this challenge only, and keeps the signature disjoint
 * from credential, attestation and AgentCard signatures (AP-1, design 8).
 *
 * Nonces are single-use by default: verification always goes through a nonce
 * store (a module-wide InMemoryNonceStore unless the caller supplies one) and
 * the nonce is recorded only after the signature verified, so a forged
 * response cannot burn a legitimate nonce (AP-19).
 */

import { randomBytes } from 'crypto';
import { signData, verifySignature, sha256Hex, domainSeparatedInput, CTX_RESPONSE } from './crypto.js';
import { InMemoryNonceStore } from './nonce.js';

export const NONCE_EXPIRY_SECS = 60;
export const NONCE_BYTES = 16;
export const NONCE_ENCODED_LEN = 22;
export const CHALLENGE_TYPE = 'agentpin-challenge';
export const RESPONSE_TYPE = 'agentpin-response';

const defaultNonceStore = new InMemoryNonceStore();

/**
 * Base64url encode bytes (no padding).
 * @param {Buffer} data
 * @returns {string}
 */
function base64urlEncode(data) {
    return data.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Create a challenge with a 128-bit random nonce.
 * @param {string|null} verifierCredential - Optional verifier credential JWT
 * @returns {object} Challenge object
 */
export function createChallenge(verifierCredential = null) {
    const nonceBytes = randomBytes(NONCE_BYTES);
    const nonce = base64urlEncode(nonceBytes);

    const challenge = {
        type: CHALLENGE_TYPE,
        nonce,
        timestamp: new Date().toISOString(),
    };

    if (verifierCredential) {
        challenge.verifier_credential = verifierCredential;
    }

    return challenge;
}

/**
 * Validate that a nonce is exactly 22 canonical base64url characters decoding
 * to 16 bytes, so a responder is never asked to sign caller-shaped bytes.
 * @param {string} nonce
 * @throws {Error}
 */
export function validateNonce(nonce) {
    if (typeof nonce !== 'string' || nonce.length !== NONCE_ENCODED_LEN) {
        throw new Error(`Challenge nonce must be ${NONCE_ENCODED_LEN} base64url characters`);
    }
    if (!/^[A-Za-z0-9_-]+$/.test(nonce)) {
        throw new Error('Challenge nonce is not valid base64url');
    }
    const bytes = Buffer.from(nonce, 'base64url');
    if (bytes.length !== NONCE_BYTES || base64urlEncode(bytes) !== nonce) {
        throw new Error(`Challenge nonce must decode to exactly ${NONCE_BYTES} bytes`);
    }
}

/**
 * SHA-256 hex of the challenge's verifier credential, or '' when absent.
 * @param {object} challenge
 * @returns {string}
 */
export function verifierBinding(challenge) {
    return challenge.verifier_credential ? sha256Hex(challenge.verifier_credential) : '';
}

/**
 * The bytes a responder with key `kid` commits to for `challenge`.
 * @param {object} challenge
 * @param {string} kid
 * @returns {Buffer}
 */
export function responseSigningInput(challenge, kid) {
    return domainSeparatedInput(CTX_RESPONSE, [
        challenge.nonce,
        challenge.timestamp,
        kid,
        verifierBinding(challenge),
    ]);
}

/**
 * Create a response by signing the domain-separated challenge structure.
 * @param {object} challenge
 * @param {string} privateKeyPem
 * @param {string} kid
 * @returns {object} Response object
 * @throws {Error} if the challenge nonce is malformed or the type is wrong
 */
export function createResponse(challenge, privateKeyPem, kid) {
    if (!challenge || challenge.type !== CHALLENGE_TYPE) {
        throw new Error(`Challenge type rejected, must be '${CHALLENGE_TYPE}'`);
    }
    validateNonce(challenge.nonce);
    const signature = signData(privateKeyPem, responseSigningInput(challenge, kid));

    return {
        type: RESPONSE_TYPE,
        nonce: challenge.nonce,
        signature,
        kid,
    };
}

/**
 * Verify a challenge response using the module-wide nonce store, so each
 * nonce is accepted at most once per process.
 * @param {object} response
 * @param {object} challenge
 * @param {string} publicKeyPem
 * @returns {boolean}
 * @throws {Error} if the challenge is malformed, expired, or the nonce was replayed
 */
export function verifyResponse(response, challenge, publicKeyPem) {
    return verifyResponseWithNonceStore(response, challenge, publicKeyPem, null);
}

/**
 * Verify a challenge response: nonce/type shape, challenge freshness,
 * signature, then single-use recording. Returns `false` when the nonce does
 * not match or the signature does not verify; throws for malformed input,
 * expired challenges and replayed nonces.
 * @param {object} response
 * @param {object} challenge
 * @param {string} publicKeyPem
 * @param {import('./nonce.js').InMemoryNonceStore|null} nonceStore - Store for replay prevention (module-wide default when null)
 * @returns {boolean}
 */
export function verifyResponseWithNonceStore(response, challenge, publicKeyPem, nonceStore = null) {
    if (!response || !challenge) return false;
    if (response.type !== RESPONSE_TYPE || challenge.type !== CHALLENGE_TYPE) {
        return false;
    }
    if (response.nonce !== challenge.nonce) {
        return false;
    }
    validateNonce(challenge.nonce);

    // An unparsable timestamp is treated as expired (fail closed).
    const ts = new Date(challenge.timestamp);
    if (typeof challenge.timestamp !== 'string' || Number.isNaN(ts.getTime())) {
        throw new Error('Challenge timestamp is not a valid ISO 8601 datetime');
    }
    const elapsed = (Date.now() - ts.getTime()) / 1000;
    if (elapsed > NONCE_EXPIRY_SECS) {
        throw new Error(
            `Challenge nonce expired (${Math.floor(elapsed)} seconds old, max ${NONCE_EXPIRY_SECS})`
        );
    }

    // Verify the signature before touching the nonce store so a forged
    // response cannot consume a legitimate nonce.
    const input = responseSigningInput(challenge, String(response.kid));
    if (!verifySignature(publicKeyPem, input, response.signature)) {
        return false;
    }

    const store = nonceStore || defaultNonceStore;
    if (!store.checkAndRecord(response.nonce, NONCE_EXPIRY_SECS * 1000)) {
        throw new Error('Nonce has already been used');
    }
    return true;
}
