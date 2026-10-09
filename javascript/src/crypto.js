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

// ---------------------------------------------------------------------------
// Domain-separated signing (protocol v0.4)
// ---------------------------------------------------------------------------
//
// Every object AgentPin signs other than the credential JWT goes through
// domainSeparatedInput, which prefixes a fixed context label and
// length-prefixes each field. The JWT keeps the RFC 7515 "header.payload"
// signing input, whose alphabet (base64url plus '.') never contains the NUL
// byte that terminates every context label, so no signature produced for one
// object type can be replayed as another.

/** Context label for challenge responses. */
export const CTX_RESPONSE = 'agentpin-response-v1';
/** Context label for delegation attestations. */
export const CTX_ATTESTATION = 'agentpin-attestation-v1';
/** Context label for A2A AgentCard signatures. */
export const CTX_AGENTCARD = 'agentpin-agentcard-v1';
/** Context label for signed revocation documents. */
export const CTX_REVOCATION = 'agentpin-revocation-v1';
/** Context label for signed trust bundles. */
export const CTX_BUNDLE = 'agentpin-bundle-v1';

/**
 * Build the domain-separated signing input for `context` over `fields`:
 * `context || 0x00 || (u32_be(len(field)) || field)*`. Byte-identical to the
 * Rust, Go and Python SDKs.
 * @param {string} context
 * @param {Array<Buffer|Uint8Array|string>} fields
 * @returns {Buffer}
 */
export function domainSeparatedInput(context, fields) {
    const parts = [Buffer.from(context, 'utf8'), Buffer.from([0])];
    for (const field of fields) {
        const buf = Buffer.isBuffer(field) ? field : Buffer.from(field);
        const len = Buffer.alloc(4);
        len.writeUInt32BE(buf.length, 0);
        parts.push(len, buf);
    }
    return Buffer.concat(parts);
}

/**
 * Sign `fields` under `context` with a PEM private key. Returns the
 * standard-base64 DER signature.
 * @param {string} privateKeyPem
 * @param {string} context
 * @param {Array<Buffer|Uint8Array|string>} fields
 * @returns {string}
 */
export function signWithContext(privateKeyPem, context, fields) {
    return signData(privateKeyPem, domainSeparatedInput(context, fields));
}

/**
 * Verify a signature produced by `signWithContext`.
 * @param {string} publicKeyPem
 * @param {string} context
 * @param {Array<Buffer|Uint8Array|string>} fields
 * @param {string} signatureB64
 * @returns {boolean}
 */
export function verifyWithContext(publicKeyPem, context, fields, signatureB64) {
    return verifySignature(publicKeyPem, domainSeparatedInput(context, fields), signatureB64);
}

/**
 * Sign data with a PEM-encoded private key. Returns base64-encoded DER signature.
 *
 * This is a low-level primitive. Protocol objects MUST be signed through
 * `signWithContext` (or the JWT encoder) so signatures over different object
 * types can never be confused; never pass caller-supplied bytes here.
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
