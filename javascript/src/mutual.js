/**
 * Mutual authentication challenge-response protocol for AgentPin.
 */

import { randomBytes } from 'crypto';
import { signData, verifySignature } from './crypto.js';

const NONCE_EXPIRY_SECS = 60;

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
    const nonceBytes = randomBytes(16); // 128 bits
    const nonce = base64urlEncode(nonceBytes);

    const challenge = {
        type: 'agentpin-challenge',
        nonce,
        timestamp: new Date().toISOString(),
    };

    if (verifierCredential) {
        challenge.verifier_credential = verifierCredential;
    }

    return challenge;
}

/**
 * Create a response by signing the challenge nonce.
 * @param {object} challenge
 * @param {string} privateKeyPem
 * @param {string} kid
 * @returns {object} Response object
 */
export function createResponse(challenge, privateKeyPem, kid) {
    const signature = signData(privateKeyPem, Buffer.from(challenge.nonce));

    return {
        type: 'agentpin-response',
        nonce: challenge.nonce,
        signature,
        kid,
    };
}

/**
 * Verify a challenge response: check signature and that nonce hasn't expired.
 * @param {object} response
 * @param {object} challenge
 * @param {string} publicKeyPem
 * @returns {boolean}
 * @throws {Error} if nonce has expired
 */
export function verifyResponse(response, challenge, publicKeyPem) {
    // Check nonce matches
    if (response.nonce !== challenge.nonce) {
        return false;
    }

    // Check timestamp hasn't expired
    const ts = new Date(challenge.timestamp);
    const elapsed = (Date.now() - ts.getTime()) / 1000;
    if (elapsed > NONCE_EXPIRY_SECS) {
        throw new Error(
            `Challenge nonce expired (${Math.floor(elapsed)} seconds old, max ${NONCE_EXPIRY_SECS})`
        );
    }

    // Verify signature over the nonce
    return verifySignature(publicKeyPem, Buffer.from(challenge.nonce), response.signature);
}
