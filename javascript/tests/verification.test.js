/**
 * Tests for credential verification (12-step flow).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { pemToJwk } from '../src/jwk.js';
import { encodeJwt } from '../src/jwt.js';
import { Capability } from '../src/capability.js';
import { issueCredential } from '../src/credential.js';
import { buildDiscoveryDocument } from '../src/discovery.js';
import { buildRevocationDocument, addRevokedCredential, addRevokedAgent } from '../src/revocation.js';
import { KeyPinStore } from '../src/pinning.js';
import { decodeJwtUnverified } from '../src/jwt.js';
import { verifyCredentialOffline, defaultVerifierConfig } from '../src/verification.js';
import { ErrorCode, EntityType, AgentStatus, RevocationReason, DataClassification } from '../src/types.js';

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
        null,
        3600
    );

    return {
        kp,
        jwt,
        discovery,
        revocation: buildRevocationDocument('example.com'),
        pinStore: new KeyPinStore(),
        config: defaultVerifierConfig(),
    };
}

describe('verifyCredentialOffline', () => {
    test('happy path', () => {
        const f = setup();
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(result.valid, `Expected valid, got: ${JSON.stringify(result)}`);
        assert.strictEqual(result.agent_id, 'urn:agentpin:example.com:agent');
        assert.strictEqual(result.issuer, 'example.com');
    });

    test('expired credential', () => {
        const f = setup();
        const header = { alg: 'ES256', typ: 'agentpin-credential+jwt', kid: 'test-2026-01' };
        const payload = {
            iss: 'example.com',
            sub: 'urn:agentpin:example.com:agent',
            iat: 1000000,
            exp: 1003600,
            jti: 'expired-jti',
            agentpin_version: '0.1',
            capabilities: ['read:data'],
        };
        const expiredJwt = encodeJwt(header, payload, f.kp.privateKeyPem);
        const result = verifyCredentialOffline(
            expiredJwt, f.discovery, null, new KeyPinStore(), null, f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.CREDENTIAL_EXPIRED);
    });

    test('wrong algorithm rejected', () => {
        const f = setup();
        const result = verifyCredentialOffline(
            'invalid.jwt.token', f.discovery, null, new KeyPinStore(), null, f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.ALGORITHM_REJECTED);
    });

    test('credential revoked', () => {
        const f = setup();
        const { payload } = decodeJwtUnverified(f.jwt);
        addRevokedCredential(f.revocation, payload.jti, RevocationReason.KEY_COMPROMISE);
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.CREDENTIAL_REVOKED);
    });

    test('agent revoked', () => {
        const f = setup();
        addRevokedAgent(f.revocation, 'urn:agentpin:example.com:agent', RevocationReason.PRIVILEGE_WITHDRAWN);
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(!result.valid);
    });

    test('inactive agent', () => {
        const f = setup();
        f.discovery.agents[0].status = AgentStatus.SUSPENDED;
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.AGENT_INACTIVE);
    });

    test('capability exceeded', () => {
        const f = setup();
        f.discovery.agents[0].capabilities = ['read:limited'];
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.CAPABILITY_EXCEEDED);
    });

    test('audience mismatch', () => {
        const f = setup();
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'wrong-verifier.com', f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.AUDIENCE_MISMATCH);
    });

    test('key pin change rejected', () => {
        const f = setup();
        // First verification pins the key
        const result1 = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(result1.valid);

        // Change key in discovery
        const kp2 = generateKeyPair();
        const jwk2 = pemToJwk(kp2.publicKeyPem, 'test-2026-01');
        f.discovery.public_keys = [jwk2];

        // Reissue credential with new key
        const jwt2 = issueCredential(
            kp2.privateKeyPem,
            'test-2026-01',
            'example.com',
            'urn:agentpin:example.com:agent',
            'verifier.com',
            [new Capability('read:data')],
            null,
            null,
            3600
        );

        const result2 = verifyCredentialOffline(
            jwt2, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config
        );
        assert.ok(!result2.valid);
        assert.strictEqual(result2.error_code, ErrorCode.KEY_PIN_MISMATCH);
    });

    test('domain mismatch', () => {
        const f = setup();
        f.discovery.entity = 'other.com';
        const result = verifyCredentialOffline(
            f.jwt, f.discovery, f.revocation, f.pinStore, null, f.config
        );
        assert.ok(!result.valid);
        assert.strictEqual(result.error_code, ErrorCode.DISCOVERY_INVALID);
    });

    test('wildcard audience accepted', () => {
        const kp = generateKeyPair();
        const jwk = pemToJwk(kp.publicKeyPem, 'test-key');

        const discovery = buildDiscoveryDocument(
            'example.com', EntityType.MAKER, [jwk],
            [{
                agent_id: 'urn:agentpin:example.com:agent',
                name: 'Test',
                capabilities: ['read:*'],
                status: AgentStatus.ACTIVE,
            }],
            2, '2026-01-15T00:00:00Z'
        );

        const jwt = issueCredential(
            kp.privateKeyPem, 'test-key', 'example.com',
            'urn:agentpin:example.com:agent', '*',
            [new Capability('read:data')], null, null, 3600
        );

        const result = verifyCredentialOffline(
            jwt, discovery, null, new KeyPinStore(), 'any-verifier.com', defaultVerifierConfig()
        );
        assert.ok(result.valid, 'Wildcard audience should be accepted');
    });
});
