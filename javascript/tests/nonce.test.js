/**
 * Tests for nonce deduplication and replay prevention.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { InMemoryNonceStore } from '../src/nonce.js';
import { generateKeyPair } from '../src/crypto.js';
import { createChallenge, createResponse, verifyResponseWithNonceStore } from '../src/mutual.js';

describe('InMemoryNonceStore', () => {
    test('accepts fresh nonce', () => {
        const store = new InMemoryNonceStore();
        assert.strictEqual(store.checkAndRecord('nonce-1', 60000), true);
    });

    test('rejects duplicate nonce', () => {
        const store = new InMemoryNonceStore();
        assert.strictEqual(store.checkAndRecord('nonce-1', 60000), true);
        assert.strictEqual(store.checkAndRecord('nonce-1', 60000), false);
    });

    test('accepts different nonces', () => {
        const store = new InMemoryNonceStore();
        assert.strictEqual(store.checkAndRecord('nonce-1', 60000), true);
        assert.strictEqual(store.checkAndRecord('nonce-2', 60000), true);
    });

    test('expired nonces are cleaned up', () => {
        const store = new InMemoryNonceStore();
        // Insert with 0ms TTL (already expired)
        store._entries.set('old-nonce', Date.now() - 1);
        // Triggering checkAndRecord should clean up the expired entry
        assert.strictEqual(store.checkAndRecord('new-nonce', 60000), true);
        assert.ok(!store._entries.has('old-nonce'));
    });
});

describe('verifyResponseWithNonceStore', () => {
    test('passes with nonce store on first use', () => {
        const kp = generateKeyPair();
        const store = new InMemoryNonceStore();
        const challenge = createChallenge();
        const response = createResponse(challenge, kp.privateKeyPem, 'test-key');
        const valid = verifyResponseWithNonceStore(response, challenge, kp.publicKeyPem, store);
        assert.ok(valid);
    });

    test('rejects replay with nonce store', () => {
        const kp = generateKeyPair();
        const store = new InMemoryNonceStore();
        const challenge = createChallenge();
        const response = createResponse(challenge, kp.privateKeyPem, 'test-key');

        // First use succeeds
        verifyResponseWithNonceStore(response, challenge, kp.publicKeyPem, store);

        // Second use (replay) throws
        assert.throws(
            () => verifyResponseWithNonceStore(response, challenge, kp.publicKeyPem, store),
            /replay attack/
        );
    });

    test('works without nonce store (null)', () => {
        const kp = generateKeyPair();
        const challenge = createChallenge();
        const response = createResponse(challenge, kp.privateKeyPem, 'test-key');
        const valid = verifyResponseWithNonceStore(response, challenge, kp.publicKeyPem, null);
        assert.ok(valid);
    });
});
