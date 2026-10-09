/**
 * Tests for revocation document handling.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { RevocationReason } from '../src/types.js';
import {
    buildRevocationDocument,
    addRevokedCredential,
    addRevokedAgent,
    addRevokedKey,
    checkRevocation,
} from '../src/revocation.js';

describe('buildRevocationDocument', () => {
    test('creates empty document', () => {
        const doc = buildRevocationDocument('example.com');
        assert.strictEqual(doc.entity, 'example.com');
        assert.strictEqual(doc.revoked_credentials.length, 0);
        assert.strictEqual(doc.revoked_agents.length, 0);
        assert.strictEqual(doc.revoked_keys.length, 0);
    });
});

describe('add revocations', () => {
    test('adds and counts revocations', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedCredential(doc, 'jti-123', RevocationReason.KEY_COMPROMISE);
        addRevokedAgent(doc, 'urn:agentpin:example.com:bad-agent', RevocationReason.POLICY_VIOLATION);
        addRevokedKey(doc, 'old-key-01', RevocationReason.SUPERSEDED);

        assert.strictEqual(doc.revoked_credentials.length, 1);
        assert.strictEqual(doc.revoked_agents.length, 1);
        assert.strictEqual(doc.revoked_keys.length, 1);
    });
});

describe('checkRevocation', () => {
    test('clean document passes', () => {
        const doc = buildRevocationDocument('example.com');
        assert.doesNotThrow(() => checkRevocation(doc, 'jti-1', 'agent-1', 'key-1'));
    });

    test('revoked credential detected', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedCredential(doc, 'jti-bad', RevocationReason.KEY_COMPROMISE);
        assert.throws(() => checkRevocation(doc, 'jti-bad', 'agent-1', 'key-1'), /jti-bad/);
        assert.doesNotThrow(() => checkRevocation(doc, 'jti-good', 'agent-1', 'key-1'));
    });

    test('revoked agent detected', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedAgent(doc, 'bad-agent', RevocationReason.PRIVILEGE_WITHDRAWN);
        assert.throws(() => checkRevocation(doc, 'jti-1', 'bad-agent', 'key-1'), /bad-agent/);
    });

    test('revoked key detected', () => {
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'bad-key', RevocationReason.SUPERSEDED);
        assert.throws(() => checkRevocation(doc, 'jti-1', 'agent-1', 'bad-key'), /bad-key/);
    });
});

describe('signed revocation documents (design issue 3)', () => {
    test('signature verifies under the discovery key; tampering and foreign entities fail', async () => {
        const { generateKeyPair } = await import('../src/crypto.js');
        const { pemToJwk } = await import('../src/jwk.js');
        const { buildDiscoveryDocument } = await import('../src/discovery.js');
        const { signRevocationDocument, verifyRevocationDocument, addRevokedKey, buildRevocationDocument, checkRevocationFreshness } =
            await import('../src/revocation.js');
        const kp = generateKeyPair();
        const discovery = buildDiscoveryDocument('example.com', 'maker', [pemToJwk(kp.publicKeyPem, 'k1')], [], 2, '2026-01-15T00:00:00Z');
        const doc = buildRevocationDocument('example.com');
        addRevokedKey(doc, 'old', 'superseded');
        assert.doesNotThrow(() => verifyRevocationDocument(doc, discovery));
        signRevocationDocument(doc, kp.privateKeyPem, 'k1');
        assert.doesNotThrow(() => verifyRevocationDocument(doc, discovery));
        assert.doesNotThrow(() => verifyRevocationDocument(JSON.parse(JSON.stringify(doc)), discovery));
        assert.throws(() => verifyRevocationDocument({ ...doc, revoked_keys: [] }, discovery), /did not verify/);
        assert.throws(() => verifyRevocationDocument({ ...doc, kid: 'other' }, discovery), /not found/);
        assert.throws(() => verifyRevocationDocument(buildRevocationDocument('other.com'), discovery), /does not match/);
        assert.doesNotThrow(() => verifyRevocationDocument(buildRevocationDocument('EXAMPLE.com.'), discovery));

        const fresh = buildRevocationDocument('example.com');
        assert.doesNotThrow(() => checkRevocationFreshness(fresh, 3600));
        assert.throws(() => checkRevocationFreshness({ ...fresh, updated_at: new Date(Date.now() - 7200000).toISOString() }, 3600), /stale/);
        assert.throws(() => checkRevocationFreshness({ ...fresh, updated_at: 'yesterday' }, 3600), /RFC 3339/);
    });
});
