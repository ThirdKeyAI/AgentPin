/**
 * ES256-only JWT encode/decode/verify for AgentPin.
 * No external JWT library — algorithm validation enforced inline.
 */

import { createSign, createVerify, createPrivateKey, createPublicKey } from 'crypto';

const REQUIRED_ALG = 'ES256';
const REQUIRED_TYP = 'agentpin-credential+jwt';

/**
 * Base64url encode bytes (no padding).
 * @param {Buffer|Uint8Array} data
 * @returns {string}
 */
export function base64urlEncode(data) {
    return Buffer.from(data)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Base64url decode a string.
 * @param {string} str
 * @returns {Buffer}
 */
export function base64urlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad === 2) base64 += '==';
    else if (pad === 3) base64 += '=';
    return Buffer.from(base64, 'base64');
}

/**
 * Encode a JWT from header + payload + PEM private key.
 * @param {{ alg: string, typ: string, kid: string }} header
 * @param {object} payload
 * @param {string} privateKeyPem
 * @returns {string} Compact JWT string
 */
export function encodeJwt(header, payload, privateKeyPem) {
    const headerJson = JSON.stringify(header);
    const payloadJson = JSON.stringify(payload);

    const headerB64 = base64urlEncode(Buffer.from(headerJson));
    const payloadB64 = base64urlEncode(Buffer.from(payloadJson));

    const signingInput = `${headerB64}.${payloadB64}`;

    const sign = createSign('SHA256');
    sign.update(signingInput);
    const keyObject = createPrivateKey(privateKeyPem);
    const signature = sign.sign({ key: keyObject, dsaEncoding: 'der' });
    const sigB64 = base64urlEncode(signature);

    return `${signingInput}.${sigB64}`;
}

/**
 * Decode a JWT without verifying the signature.
 * Validates algorithm and token type.
 * @param {string} jwt
 * @returns {{ header: object, payload: object, signatureB64: string }}
 */
export function decodeJwtUnverified(jwt) {
    const parts = jwt.split('.');
    if (parts.length !== 3) {
        throw new Error('JWT must have 3 parts');
    }

    const header = JSON.parse(base64urlDecode(parts[0]).toString());
    const payload = JSON.parse(base64urlDecode(parts[1]).toString());

    if (header.alg !== REQUIRED_ALG) {
        throw new Error(`Algorithm '${header.alg}' rejected, must be '${REQUIRED_ALG}'`);
    }

    if (header.typ !== REQUIRED_TYP) {
        throw new Error(`Token type '${header.typ}' rejected, must be '${REQUIRED_TYP}'`);
    }

    return { header, payload, signatureB64: parts[2] };
}

/**
 * Verify a JWT signature using a PEM public key.
 * @param {string} jwt
 * @param {string} publicKeyPem
 * @returns {{ header: object, payload: object }}
 */
export function verifyJwt(jwt, publicKeyPem) {
    const { header, payload } = decodeJwtUnverified(jwt);

    const parts = jwt.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const sigBytes = base64urlDecode(parts[2]);

    const verify = createVerify('SHA256');
    verify.update(signingInput);
    const keyObject = createPublicKey(publicKeyPem);
    const valid = verify.verify({ key: keyObject, dsaEncoding: 'der' }, sigBytes);

    if (!valid) {
        throw new Error('JWT signature verification failed');
    }

    return { header, payload };
}
