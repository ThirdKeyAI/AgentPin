/**
 * Tests for JWT encode/decode/verify.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { encodeJwt, decodeJwtUnverified, verifyJwt } from '../src/jwt.js';

function makeTestJwt(privateKeyPem, kid) {
    const header = {
        alg: 'ES256',
        typ: 'agentpin-credential+jwt',
        kid,
    };
    const payload = {
        iss: 'example.com',
        sub: 'urn:agentpin:example.com:agent',
        aud: 'verifier.com',
        iat: 1738300800,
        exp: 1738304400,
        jti: 'test-jti-001',
        agentpin_version: '0.1',
        capabilities: ['read:data'],
    };
    const jwt = encodeJwt(header, payload, privateKeyPem);
    return { jwt, header, payload };
}

describe('JWT encode/decode roundtrip', () => {
    test('encodes and verifies JWT', () => {
        const kp = generateKeyPair();
        const { jwt, header: origHeader, payload: origPayload } = makeTestJwt(kp.privateKeyPem, 'test-key');

        const { header, payload } = verifyJwt(jwt, kp.publicKeyPem);
        assert.strictEqual(header.alg, origHeader.alg);
        assert.strictEqual(header.typ, origHeader.typ);
        assert.strictEqual(header.kid, origHeader.kid);
        assert.strictEqual(payload.iss, origPayload.iss);
        assert.strictEqual(payload.sub, origPayload.sub);
    });
});

describe('JWT security', () => {
    test('rejects wrong key', () => {
        const kp1 = generateKeyPair();
        const kp2 = generateKeyPair();
        const { jwt } = makeTestJwt(kp1.privateKeyPem, 'key1');
        assert.throws(() => verifyJwt(jwt, kp2.publicKeyPem));
    });

    test('rejects wrong algorithm', () => {
        const kp = generateKeyPair();
        const header = { alg: 'none', typ: 'agentpin-credential+jwt', kid: 'test' };
        const payload = {
            iss: 'example.com',
            sub: 'urn:agentpin:example.com:agent',
            iat: 1738300800,
            exp: 1738304400,
            jti: 'jti',
            agentpin_version: '0.1',
            capabilities: [],
        };
        const jwt = encodeJwt(header, payload, kp.privateKeyPem);
        assert.throws(() => decodeJwtUnverified(jwt), /rejected/);
    });

    test('rejects wrong token type', () => {
        const kp = generateKeyPair();
        const header = { alg: 'ES256', typ: 'JWT', kid: 'test' };
        const payload = {
            iss: 'example.com',
            sub: 'urn:agentpin:example.com:agent',
            iat: 1738300800,
            exp: 1738304400,
            jti: 'jti',
            agentpin_version: '0.1',
            capabilities: [],
        };
        const jwt = encodeJwt(header, payload, kp.privateKeyPem);
        assert.throws(() => decodeJwtUnverified(jwt), /rejected/);
    });

    test('rejects malformed JWT', () => {
        assert.throws(() => decodeJwtUnverified('not.a.jwt.token'));
        assert.throws(() => decodeJwtUnverified('only-one-part'));
    });
});
