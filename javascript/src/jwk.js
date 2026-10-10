/**
 * JWK (JSON Web Key) operations for AgentPin.
 * Handles JWK↔PEM conversion and JWK thumbprint (RFC 7638).
 */

import { createPublicKey } from 'crypto';
import { sha256Hex } from './crypto.js';

/**
 * Convert a PEM public key to a JWK object.
 * @param {string} publicKeyPem
 * @param {string} kid - Key ID
 * @returns {{ kid: string, kty: string, crv: string, x: string, y: string, use: string, key_ops?: string[], exp?: string }}
 */
export function pemToJwk(publicKeyPem, kid) {
    const keyObject = createPublicKey(publicKeyPem);
    const jwkData = keyObject.export({ format: 'jwk' });

    return {
        kid,
        kty: jwkData.kty,
        crv: jwkData.crv,
        x: jwkData.x,
        y: jwkData.y,
        use: 'sig',
        key_ops: ['verify'],
    };
}

/**
 * Convert a JWK object to a PEM public key string.
 * @param {{ kty: string, crv: string, x: string, y: string }} jwk
 * @returns {string} PEM-encoded public key
 */
export function jwkToPem(jwk) {
    if (!jwk || typeof jwk !== 'object' || jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
        throw new Error('Invalid JWK: must be EC P-256');
    }

    let keyObject;
    try {
        keyObject = createPublicKey({
            key: {
                kty: jwk.kty,
                crv: jwk.crv,
                x: jwk.x,
                y: jwk.y,
            },
            format: 'jwk',
        });
    } catch {
        // Node raises TypeError for malformed coordinates; surface a plain error.
        throw new Error('Invalid JWK: not a valid P-256 public key');
    }

    return keyObject.export({ type: 'spki', format: 'pem' });
}

/**
 * Compute JWK thumbprint per RFC 7638.
 * SHA-256 of canonical JSON with alphabetically sorted required members: crv, kty, x, y.
 * @param {{ kty: string, crv: string, x: string, y: string }} jwk
 * @returns {string} Hex-encoded SHA-256 thumbprint
 */
export function jwkThumbprint(jwk) {
    const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
    return sha256Hex(canonical);
}
