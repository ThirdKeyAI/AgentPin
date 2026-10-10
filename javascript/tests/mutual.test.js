/**
 * Tests for mutual authentication challenge-response.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { createChallenge, createResponse, verifyResponse } from '../src/mutual.js';

describe('challenge-response', () => {
    test('roundtrip', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        assert.strictEqual(challenge.type, 'agentpin-challenge');
        assert.ok(challenge.nonce);

        const response = createResponse(challenge, kp.privateKeyPem, 'test-key');
        assert.strictEqual(response.type, 'agentpin-response');
        assert.strictEqual(response.nonce, challenge.nonce);

        const valid = verifyResponse(response, challenge, kp.publicKeyPem);
        assert.ok(valid);
    });

    test('wrong key rejected', () => {
        const kp1 = generateKeyPair();
        const kp2 = generateKeyPair();
        const challenge = createChallenge();
        const response = createResponse(challenge, kp1.privateKeyPem, 'key1');
        const valid = verifyResponse(response, challenge, kp2.publicKeyPem);
        assert.ok(!valid);
    });

    test('nonce mismatch rejected', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        const response = createResponse(challenge, kp.privateKeyPem, 'test-key');
        response.nonce = 'wrong-nonce';
        const valid = verifyResponse(response, challenge, kp.publicKeyPem);
        assert.ok(!valid);
    });

    test('expired nonce rejected', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        // Set timestamp to 120 seconds ago
        const past = new Date(Date.now() - 120000);
        challenge.timestamp = past.toISOString();

        const response = createResponse(challenge, kp.privateKeyPem, 'test-key');
        assert.throws(
            () => verifyResponse(response, challenge, kp.publicKeyPem),
            /expired/i
        );
    });

    test('nonce is 128 bits', () => {
        const challenge = createChallenge();
        // Base64url decode the nonce to check length
        let base64 = challenge.nonce.replace(/-/g, '+').replace(/_/g, '/');
        const pad = base64.length % 4;
        if (pad === 2) base64 += '==';
        else if (pad === 3) base64 += '=';
        const bytes = Buffer.from(base64, 'base64');
        assert.strictEqual(bytes.length, 16); // 128 bits = 16 bytes
    });

    test('challenge with verifier credential', () => {
        const challenge = createChallenge('eyJ...test-jwt');
        assert.strictEqual(challenge.verifier_credential, 'eyJ...test-jwt');
    });
});

describe('challenge-response hardening (AP-1, AP-19)', () => {
    test('default nonce store rejects replay', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        const response = createResponse(challenge, kp.privateKeyPem, 'k');
        assert.ok(verifyResponse(response, challenge, kp.publicKeyPem));
        assert.throws(() => verifyResponse(response, challenge, kp.publicKeyPem), /already been used/);
    });

    test('forged response does not consume the nonce', () => {
        const kp = generateKeyPair();
        const attacker = generateKeyPair();
        const challenge = createChallenge();
        const forged = createResponse(challenge, attacker.privateKeyPem, 'k');
        assert.strictEqual(verifyResponse(forged, challenge, kp.publicKeyPem), false);
        const genuine = createResponse(challenge, kp.privateKeyPem, 'k');
        assert.ok(verifyResponse(genuine, challenge, kp.publicKeyPem));
    });

    test('malformed timestamp is treated as expired', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        challenge.timestamp = 'not-a-timestamp';
        const response = createResponse(challenge, kp.privateKeyPem, 'k');
        assert.throws(() => verifyResponse(response, challenge, kp.publicKeyPem), /timestamp/i);
    });

    test('createResponse rejects a JWT-shaped or non-canonical nonce', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        const header = Buffer.from('{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"k"}').toString('base64url');
        const payload = Buffer.from('{"iss":"example.com"}').toString('base64url');
        challenge.nonce = `${header}.${payload}`;
        assert.throws(() => createResponse(challenge, kp.privateKeyPem, 'k'));
        challenge.nonce = 'AAAAAAAAAAAAAAAAAAAAAA==';
        assert.throws(() => createResponse(challenge, kp.privateKeyPem, 'k'));
        challenge.nonce = 'AAAAAAAAAAAAAAAAAAAAAB';
        assert.throws(() => createResponse(challenge, kp.privateKeyPem, 'k'));
        challenge.nonce = 'AAAAAAAAAAAAAAAAAAAAAA';
        assert.doesNotThrow(() => createResponse(challenge, kp.privateKeyPem, 'k'));
    });

    test('response signature is domain separated and bound to kid and verifier', async () => {
        const { verifySignature } = await import('../src/crypto.js');
        const kp = generateKeyPair();
        const challenge = createChallenge('eyJ.verifier.jwt');
        const response = createResponse(challenge, kp.privateKeyPem, 'k');
        assert.strictEqual(verifySignature(kp.publicKeyPem, Buffer.from(challenge.nonce), response.signature), false);
        assert.strictEqual(verifyResponse({ ...response, kid: 'other' }, challenge, kp.publicKeyPem), false);
        const otherVerifier = { ...challenge, verifier_credential: 'eyJ.someone.else' };
        assert.strictEqual(verifyResponse(response, otherVerifier, kp.publicKeyPem), false);
    });
});
