/**
 * ECDSA P-256 cryptographic operations for AgentPin.
 * Uses Node.js built-in crypto module — zero external dependencies.
 */

import { createSign, createVerify, generateKeyPairSync, createHash, createPublicKey } from 'crypto';

/**
 * Generate a new ECDSA P-256 keypair.
 * @returns {{ privateKeyPem: string, publicKeyPem: string }}
 */
export function generateKeyPair() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

/**
 * Sign data with a PEM-encoded private key. Returns base64-encoded DER signature.
 * @param {string} privateKeyPem
 * @param {Buffer|Uint8Array} data
 * @returns {string} Base64-encoded DER signature
 */
export function signData(privateKeyPem, data) {
    const sign = createSign('SHA256');
    sign.update(data);
    const signature = sign.sign(privateKeyPem);
    return signature.toString('base64');
}

/**
 * Verify a base64-encoded DER signature against data using a PEM public key.
 * @param {string} publicKeyPem
 * @param {Buffer|Uint8Array} data
 * @param {string} signatureB64 - Base64-encoded DER signature
 * @returns {boolean}
 */
export function verifySignature(publicKeyPem, data, signatureB64) {
    try {
        const verify = createVerify('SHA256');
        verify.update(data);
        const signature = Buffer.from(signatureB64, 'base64');
        return verify.verify(publicKeyPem, signature);
    } catch {
        return false;
    }
}

/**
 * Generate a key ID from a public key PEM: SHA-256 of DER-encoded SPKI, hex-encoded.
 * @param {string} publicKeyPem
 * @returns {string} Hex-encoded SHA-256 hash
 */
export function generateKeyId(publicKeyPem) {
    const keyObject = createPublicKey(publicKeyPem);
    const der = keyObject.export({ type: 'spki', format: 'der' });
    return sha256Hex(der);
}

/**
 * SHA-256 hash of arbitrary data.
 * @param {Buffer|Uint8Array|string} data
 * @returns {Buffer}
 */
export function sha256Hash(data) {
    return createHash('sha256').update(data).digest();
}

/**
 * SHA-256 hash, hex-encoded.
 * @param {Buffer|Uint8Array|string} data
 * @returns {string}
 */
export function sha256Hex(data) {
    return createHash('sha256').update(data).digest('hex');
}
