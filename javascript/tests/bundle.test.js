/**
 * Tests for trust bundle support.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { pemToJwk } from '../src/jwk.js';
import { Capability } from '../src/capability.js';
import { issueCredential } from '../src/credential.js';
import { buildDiscoveryDocument } from '../src/discovery.js';
import { buildRevocationDocument, addRevokedCredential } from '../src/revocation.js';
import { KeyPinStore } from '../src/pinning.js';
import { ErrorCode, EntityType, AgentStatus, DataClassification, RevocationReason } from '../src/types.js';
import { decodeJwtUnverified } from '../src/jwt.js';
import {
    createTrustBundle,
    findBundleDiscovery,
    findBundleRevocation,
    verifyCredentialWithBundle,
} from '../src/bundle.js';

function setup() {
    const kp = generateKeyPair();
    const jwk = pemToJwk(kp.publicKeyPem, 'test-2026-01');

    const discovery = buildDiscoveryDocument(
        'example.com',
        EntityType.MAKER,
        [jwk],
        [{
            agent_id: 'urn:agentpin:example.com:agent',
            name: 'Test Agent',
            capabilities: ['read:*', 'write:report'],
            constraints: {
                data_classification_max: DataClassification.CONFIDENTIAL,
                rate_limit: '100/hour',
            },
            status: AgentStatus.ACTIVE,
        }],
        2,
        '2026-01-15T00:00:00Z'
    );

    const revocation = buildRevocationDocument('example.com');

    const jwt = issueCredential(
        kp.privateKeyPem,
        'test-2026-01',
        'example.com',
        'urn:agentpin:example.com:agent',
        'verifier.com',
        [new Capability('read:data'), new Capability('write:report')],
        {
            data_classification_max: DataClassification.INTERNAL,
            rate_limit: '50/hour',
        },
        null, // no delegation chain
        3600
    );

    return { kp, jwk, discovery, revocation, jwt };
}

describe('TrustBundle', () => {
    test('createTrustBundle produces valid structure', () => {
        const bundle = createTrustBundle('2026-02-10T00:00:00Z');
        assert.strictEqual(bundle.agentpin_bundle_version, '0.1');
        assert.strictEqual(bundle.created_at, '2026-02-10T00:00:00Z');
        assert.deepStrictEqual(bundle.documents, []);
        assert.deepStrictEqual(bundle.revocations, []);
    });

    test('findBundleDiscovery returns document for matching domain', () => {
        const f = setup();
        const bundle = createTrustBundle();
        bundle.documents.push(f.discovery);

        const doc = findBundleDiscovery(bundle, 'example.com');
        assert.ok(doc);
        assert.strictEqual(doc.entity, 'example.com');
    });

    test('findBundleDiscovery returns null for missing domain', () => {
        const bundle = createTrustBundle();
        assert.strictEqual(findBundleDiscovery(bundle, 'missing.com'), null);
    });

    test('findBundleRevocation returns document when present', () => {
        const f = setup();
        const bundle = createTrustBundle();
        bundle.revocations.push(f.revocation);

        const doc = findBundleRevocation(bundle, 'example.com');
        assert.ok(doc);
        assert.strictEqual(doc.entity, 'example.com');
    });

    test('findBundleRevocation returns null when absent', () => {
        const bundle = createTrustBundle();
        assert.strictEqual(findBundleRevocation(bundle, 'example.com'), null);
    });

    test('JSON roundtrip preserves bundle', () => {
        const f = setup();
        const bundle = createTrustBundle('2026-02-10T00:00:00Z');
        bundle.documents.push(f.discovery);
        bundle.revocations.push(f.revocation);

        const json = JSON.stringify(bundle);
        const parsed = JSON.parse(json);

        assert.strictEqual(parsed.agentpin_bundle_version, '0.1');
        assert.strictEqual(parsed.documents.length, 1);
        assert.strictEqual(parsed.documents[0].entity, 'example.com');
    });
});

describe('verifyCredentialWithBundle', () => {
    test('verifies valid credential from bundle', () => {
        const f = setup();
        const bundle = createTrustBundle();
        bundle.documents.push(f.discovery);
        bundle.revocations.push(f.revocation);

        const pinStore = new KeyPinStore();
        const result = verifyCredentialWithBundle(
            f.jwt, bundle, pinStore, 'verifier.com'
        );

        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.agent_id, 'urn:agentpin:example.com:agent');
        assert.strictEqual(result.issuer, 'example.com');
    });

    test('returns error for domain not in bundle', () => {
        const f = setup();
        const bundle = createTrustBundle(); // empty

        const pinStore = new KeyPinStore();
        const result = verifyCredentialWithBundle(
            f.jwt, bundle, pinStore, 'verifier.com'
        );

        assert.strictEqual(result.valid, false);
        assert.strictEqual(result.error_code, ErrorCode.DISCOVERY_FETCH_FAILED);
        assert.ok(result.error_message.includes('not found in trust bundle'));
    });

    test('detects revoked credential from bundle', () => {
        const f = setup();
        const bundle = createTrustBundle();
        bundle.documents.push(f.discovery);

        // Revoke the credential by its JTI
        const { payload } = decodeJwtUnverified(f.jwt);
        const revDoc = buildRevocationDocument('example.com');
        addRevokedCredential(revDoc, payload.jti, RevocationReason.KEY_COMPROMISE);
        bundle.revocations.push(revDoc);

        const pinStore = new KeyPinStore();
        const result = verifyCredentialWithBundle(
            f.jwt, bundle, pinStore, 'verifier.com'
        );

        assert.strictEqual(result.valid, false);
        assert.strictEqual(result.error_code, ErrorCode.CREDENTIAL_REVOKED);
    });
});
