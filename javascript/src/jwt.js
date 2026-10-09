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

    if (!isPlainObject(header)) {
        throw new Error('JWT header is not a JSON object');
    }
    if (header.alg !== REQUIRED_ALG) {
        throw new Error(`Algorithm '${header.alg}' rejected, must be '${REQUIRED_ALG}'`);
    }

    if (header.typ !== REQUIRED_TYP) {
        throw new Error(`Token type '${header.typ}' rejected, must be '${REQUIRED_TYP}'`);
    }
    if (typeof header.kid !== 'string' || header.kid.length === 0) {
        throw new MalformedCredentialError('kid is missing');
    }

    // Payload shape: a JSON object whose claims have the right types;
    // anything else is a malformed credential (AP-5, AP-18).
    validateClaims(payload);

    return { header, payload, signatureB64: parts[2] };
}

/** Protocol version a credential's `agentpin_version` claim must carry. */
export const CREDENTIAL_VERSION = '0.1';

/**
 * Error for a JWT whose claims are missing, mistyped or inconsistent
 * (AP-5, AP-14, AP-18). Verifiers map it to MALFORMED_CREDENTIAL.
 */
export class MalformedCredentialError extends Error {
    constructor(reason) {
        super(`Malformed credential: ${reason}`);
        this.name = 'MalformedCredentialError';
        this.reason = reason;
    }
}

function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isNonNegativeInt(v) {
    return Number.isSafeInteger(v) && v >= 0;
}

/**
 * Validate the shape of a credential payload: required string identifiers,
 * safe non-negative integer timestamps with exp > iat, a capability array
 * of strings, a supported protocol version, and correctly typed optional
 * claims.
 * @param {*} payload
 * @throws {MalformedCredentialError}
 */
export function validateClaims(payload) {
    if (!isPlainObject(payload)) throw new MalformedCredentialError('JWT payload is not a JSON object');
    for (const claim of ['iss', 'sub', 'jti']) {
        if (typeof payload[claim] !== 'string' || payload[claim].length === 0) {
            throw new MalformedCredentialError(`${claim} is missing or not a non-empty string`);
        }
    }
    if (!isNonNegativeInt(payload.iat)) throw new MalformedCredentialError('iat is missing or not a non-negative integer');
    if (!isNonNegativeInt(payload.exp)) throw new MalformedCredentialError('exp is missing or not a non-negative integer');
    if (payload.exp <= payload.iat) throw new MalformedCredentialError('exp must be greater than iat');
    if (payload.nbf !== undefined && payload.nbf !== null && !isNonNegativeInt(payload.nbf)) {
        throw new MalformedCredentialError('nbf is not a non-negative integer');
    }
    if (payload.agentpin_version !== CREDENTIAL_VERSION) {
        throw new MalformedCredentialError(`Unsupported agentpin_version '${payload.agentpin_version}'`);
    }
    if (!Array.isArray(payload.capabilities) || !payload.capabilities.every((c) => typeof c === 'string')) {
        throw new MalformedCredentialError('capabilities must be an array of strings');
    }
    if (payload.aud !== undefined && payload.aud !== null && typeof payload.aud !== 'string') {
        throw new MalformedCredentialError('aud must be a string');
    }
    if (payload.nonce !== undefined && payload.nonce !== null && typeof payload.nonce !== 'string') {
        throw new MalformedCredentialError('nonce must be a string');
    }
    if (payload.constraints !== undefined && payload.constraints !== null && !isPlainObject(payload.constraints)) {
        throw new MalformedCredentialError('constraints must be an object');
    }
    if (payload.delegation_chain !== undefined && payload.delegation_chain !== null) {
        if (!Array.isArray(payload.delegation_chain)) throw new MalformedCredentialError('delegation_chain must be an array');
        for (const att of payload.delegation_chain) {
            if (!isPlainObject(att)) throw new MalformedCredentialError('delegation_chain entries must be objects');
            for (const field of ['domain', 'role', 'agent_id', 'kid', 'attestation']) {
                if (typeof att[field] !== 'string' || att[field].length === 0) {
                    throw new MalformedCredentialError(`delegation_chain entry ${field} is missing`);
                }
            }
            if (att.exp !== undefined && att.exp !== null && !isNonNegativeInt(att.exp)) {
                throw new MalformedCredentialError('delegation_chain entry exp is not a non-negative integer');
            }
        }
    }
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
