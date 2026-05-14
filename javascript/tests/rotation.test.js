/**
 * Tests for key rotation helpers.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { prepareRotation, applyRotation, completeRotation } from '../src/rotation.js';
import { buildRevocationDocument } from '../src/revocation.js';

describe('key rotation', () => {
    test('prepareRotation generates new key and preserves oldKid', () => {
        const plan = prepareRotation('old-key-1');
        assert.strictEqual(plan.oldKid, 'old-key-1');
        assert.ok(plan.newKid);
        assert.ok(plan.newKeyPair.privateKeyPem);
        assert.ok(plan.newKeyPair.publicKeyPem);
        assert.strictEqual(plan.newJwk.kid, plan.newKid);
        assert.strictEqual(plan.newJwk.kty, 'EC');
        assert.strictEqual(plan.newJwk.crv, 'P-256');
    });

    test('applyRotation adds new key to discovery document', () => {
        const doc = {
            public_keys: [{ kid: 'old-key-1', kty: 'EC' }],
            updated_at: '2024-01-01T00:00:00.000Z',
        };
        const plan = prepareRotation('old-key-1');
        applyRotation(doc, plan);
        assert.strictEqual(doc.public_keys.length, 2);
        assert.strictEqual(doc.public_keys[1].kid, plan.newKid);
        assert.notStrictEqual(doc.updated_at, '2024-01-01T00:00:00.000Z');
    });

    test('completeRotation removes old key and adds revocation', () => {
        const plan = prepareRotation('old-key-1');
        const doc = {
            public_keys: [
                { kid: 'old-key-1', kty: 'EC' },
                plan.newJwk,
            ],
            updated_at: '2024-01-01T00:00:00.000Z',
        };
        const revDoc = buildRevocationDocument('example.com');

        completeRotation(doc, revDoc, 'old-key-1', 'superseded');

        assert.strictEqual(doc.public_keys.length, 1);
        assert.strictEqual(doc.public_keys[0].kid, plan.newKid);
        assert.strictEqual(revDoc.revoked_keys.length, 1);
        assert.strictEqual(revDoc.revoked_keys[0].kid, 'old-key-1');
        assert.strictEqual(revDoc.revoked_keys[0].reason, 'superseded');
    });
});
