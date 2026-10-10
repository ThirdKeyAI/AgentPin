/**
 * Tests for ECDSA P-256 cryptographic operations.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
    generateKeyPair,
    signData,
    verifySignature,
    generateKeyId,
    sha256Hash,
    sha256Hex,
} from '../src/crypto.js';

describe('generateKeyPair', () => {
    test('generates PEM-encoded keypair', () => {
        const kp = generateKeyPair();
        assert.ok(kp.privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----'));
        assert.ok(kp.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'));
    });
});

describe('signData and verifySignature', () => {
    test('sign and verify roundtrip', () => {
        const kp = generateKeyPair();
        const data = Buffer.from('hello agentpin');
        const sig = signData(kp.privateKeyPem, data);
        assert.ok(verifySignature(kp.publicKeyPem, data, sig));
    });

    test('verification fails with wrong data', () => {
        const kp = generateKeyPair();
        const data = Buffer.from('hello agentpin');
        const sig = signData(kp.privateKeyPem, data);
        assert.ok(!verifySignature(kp.publicKeyPem, Buffer.from('wrong data'), sig));
    });

    test('verification fails with wrong key', () => {
        const kp1 = generateKeyPair();
        const kp2 = generateKeyPair();
        const data = Buffer.from('test data');
        const sig = signData(kp1.privateKeyPem, data);
        assert.ok(!verifySignature(kp2.publicKeyPem, data, sig));
    });
});

describe('generateKeyId', () => {
    test('generates 64 hex char key ID', () => {
        const kp = generateKeyPair();
        const kid = generateKeyId(kp.publicKeyPem);
        assert.strictEqual(kid.length, 64);
    });

    test('is deterministic', () => {
        const kp = generateKeyPair();
        const kid1 = generateKeyId(kp.publicKeyPem);
        const kid2 = generateKeyId(kp.publicKeyPem);
        assert.strictEqual(kid1, kid2);
    });
});

describe('sha256Hex', () => {
    test('known hash of "test"', () => {
        const hash = sha256Hex('test');
        assert.strictEqual(hash.length, 64);
        assert.strictEqual(hash, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
    });
});

describe('sha256Hash', () => {
    test('returns Buffer', () => {
        const hash = sha256Hash('test');
        assert.ok(Buffer.isBuffer(hash));
        assert.strictEqual(hash.length, 32);
    });
});

describe('domain-separated signing', () => {
    test('input layout is context || NUL || length-prefixed fields', async () => {
        const { domainSeparatedInput } = await import('../src/crypto.js');
        const got = domainSeparatedInput('agentpin-response-v1', ['abc', '', 'xyz']);
        const want = Buffer.concat([
            Buffer.from('agentpin-response-v1\0'),
            Buffer.from([0, 0, 0, 3]), Buffer.from('abc'),
            Buffer.from([0, 0, 0, 0]),
            Buffer.from([0, 0, 0, 3]), Buffer.from('xyz'),
        ]);
        assert.ok(got.equals(want), got.toString('hex'));
    });

    test('a context signature does not verify under another context or bare', async () => {
        const { generateKeyPair, signWithContext, verifyWithContext, verifySignature, CTX_RESPONSE, CTX_ATTESTATION } =
            await import('../src/crypto.js');
        const kp = generateKeyPair();
        const sig = signWithContext(kp.privateKeyPem, CTX_RESPONSE, ['nonce']);
        assert.ok(verifyWithContext(kp.publicKeyPem, CTX_RESPONSE, ['nonce'], sig));
        assert.strictEqual(verifyWithContext(kp.publicKeyPem, CTX_ATTESTATION, ['nonce'], sig), false);
        assert.strictEqual(verifySignature(kp.publicKeyPem, Buffer.from('nonce'), sig), false);
    });
});
