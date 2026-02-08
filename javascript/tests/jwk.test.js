/**
 * Tests for JWK operations.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { pemToJwk, jwkToPem, jwkThumbprint } from '../src/jwk.js';

describe('JWK roundtrip', () => {
    test('PEM -> JWK -> PEM roundtrip', () => {
        const kp = generateKeyPair();
        const jwk = pemToJwk(kp.publicKeyPem, 'test-key-01');

        assert.strictEqual(jwk.kty, 'EC');
        assert.strictEqual(jwk.crv, 'P-256');
        assert.strictEqual(jwk.kid, 'test-key-01');
        assert.strictEqual(jwk.use, 'sig');

        const pemBack = jwkToPem(jwk);
        assert.strictEqual(pemBack, kp.publicKeyPem);
    });
});

describe('jwkThumbprint', () => {
    test('is deterministic', () => {
        const kp = generateKeyPair();
        const jwk = pemToJwk(kp.publicKeyPem, 'kid-1');
        const t1 = jwkThumbprint(jwk);
        const t2 = jwkThumbprint(jwk);
        assert.strictEqual(t1, t2);
        assert.strictEqual(t1.length, 64);
    });
});

describe('invalid JWK', () => {
    test('rejects RSA JWK', () => {
        const jwk = {
            kid: 'bad',
            kty: 'RSA',
            crv: 'P-256',
            x: 'AAAA',
            y: 'BBBB',
            use: 'sig',
        };
        assert.throws(() => jwkToPem(jwk), /Invalid JWK/);
    });
});
