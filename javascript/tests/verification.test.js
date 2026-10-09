/**
 * Tests for credential verification (12-step flow).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
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

describe('issuer normalization (AP-3, AP-10, AP-12)', () => {
    test('case variant of a pinned issuer hits the existing pin', () => {
        const f = setup();
        const r1 = verifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config);
        assert.ok(r1.valid, JSON.stringify(r1));
        const kp2 = generateKeyPair();
        const evil = { ...f.discovery, entity: 'EXAMPLE.COM', public_keys: [pemToJwk(kp2.publicKeyPem, 'evil-key')] };
        const evilJwt = issueCredential(kp2.privateKeyPem, 'evil-key', 'EXAMPLE.COM',
            'urn:agentpin:example.com:agent', 'verifier.com', [new Capability('read:data')], null, null, 3600);
        const r2 = verifyCredentialOffline(evilJwt, evil, null, f.pinStore, 'verifier.com', f.config);
        assert.strictEqual(r2.valid, false);
        assert.strictEqual(r2.error_code, ErrorCode.KEY_PIN_MISMATCH);
        assert.strictEqual(f.pinStore.getDomain('example.com').pinned_keys.length, 1);
    });

    test('issuer and entity are compared after normalization', () => {
        const f = setup();
        f.discovery.entity = 'Example.COM.';
        const r = verifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config);
        assert.ok(r.valid, JSON.stringify(r));
        assert.strictEqual(r.issuer, 'example.com');
    });

    test('non-hostname iss is rejected with DISCOVERY_INVALID', () => {
        const f = setup();
        for (const bad of ['127.0.0.1:8443', '../../tmp/x', '/srv/uploads/x', 'example.com/path', 'user@example.com']) {
            const jwt = issueCredential(f.kp.privateKeyPem, 'test-2026-01', bad,
                'urn:agentpin:example.com:agent', null, [new Capability('read:data')], null, null, 3600);
            const r = verifyCredentialOffline(jwt, f.discovery, null, new KeyPinStore(), null, f.config);
            assert.strictEqual(r.valid, false);
            assert.strictEqual(r.error_code, ErrorCode.DISCOVERY_INVALID, bad);
        }
    });
});

describe('revocation document validation (design issue 3)', () => {
    test('foreign, tampered, unsigned-under-strict and stale documents fail closed', async () => {
        const { signRevocationDocument } = await import('../src/revocation.js');
        const f = setup();
        const run = (rev, cfg) => verifyCredentialOffline(f.jwt, f.discovery, rev, new KeyPinStore(), 'verifier.com', cfg);
        assert.strictEqual(run({ ...f.revocation, entity: 'other.com' }, f.config).error_code, ErrorCode.DISCOVERY_INVALID);
        const strict = { ...f.config, requireSignedRevocation: true };
        assert.strictEqual(run(f.revocation, strict).error_code, ErrorCode.DISCOVERY_INVALID);
        const signed = signRevocationDocument({ ...f.revocation }, f.kp.privateKeyPem, 'test-2026-01');
        assert.ok(run(signed, strict).valid);
        assert.strictEqual(run({ ...signed, updated_at: '2030-01-01T00:00:00Z' }, f.config).error_code, ErrorCode.DISCOVERY_INVALID);
        const aged = { ...f.config, revocationMaxAgeSecs: 60 };
        assert.strictEqual(run({ ...f.revocation, updated_at: new Date(Date.now() - 3600000).toISOString() }, aged).error_code, ErrorCode.DISCOVERY_INVALID);
        assert.ok(run(f.revocation, aged).valid);
    });
});

describe('claim validation (AP-5, AP-14, AP-18)', () => {
    function rawCredential(kp, payload) {
        const { createSign, createPrivateKey } = require('node:crypto');
        const header = Buffer.from('{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"test-2026-01"}').toString('base64url');
        const signingInput = `${header}.${Buffer.from(payload).toString('base64url')}`;
        const sign = createSign('SHA256');
        sign.update(signingInput);
        const sig = sign.sign({ key: createPrivateKey(kp.privateKeyPem), dsaEncoding: 'der' });
        return `${signingInput}.${sig.toString('base64url')}`;
    }

    test('missing, string, negative or inconsistent exp/iat fail with MALFORMED_CREDENTIAL', () => {
        const f = setup();
        const now = Math.floor(Date.now() / 1000);
        const base = '"iss":"example.com","sub":"urn:agentpin:example.com:agent","jti":"j","agentpin_version":"0.1","capabilities":["read:data"]';
        const cases = [
            `{${base},"iat":${now}}`,
            `{${base},"iat":${now},"exp":"never"}`,
            `{${base},"iat":${now},"exp":{}}`,
            `{${base},"iat":-9223372036854775808,"exp":${now + 315360000}}`,
            `{${base},"iat":${now},"exp":${now}}`,
            `{${base},"iat":${now},"exp":${now + 1.5}}`,
            'null',
            '[]',
        ];
        for (const payload of cases) {
            const r = verifyCredentialOffline(rawCredential(f.kp, payload), f.discovery, null, new KeyPinStore(), null, f.config);
            assert.strictEqual(r.valid, false, payload);
            assert.strictEqual(r.error_code, ErrorCode.MALFORMED_CREDENTIAL, payload);
        }
    });

    test('missing kid or non-object header does not throw', () => {
        const f = setup();
        const header = Buffer.from('{"alg":"ES256","typ":"agentpin-credential+jwt"}').toString('base64url');
        const payload = Buffer.from('{"iss":"example.com"}').toString('base64url');
        const r = verifyCredentialOffline(`${header}.${payload}.sig`, f.discovery, null, new KeyPinStore(), null, f.config);
        assert.strictEqual(r.valid, false);
        assert.strictEqual(r.error_code, ErrorCode.MALFORMED_CREDENTIAL);
        const nullHeader = Buffer.from('null').toString('base64url');
        const r2 = verifyCredentialOffline(`${nullHeader}.${payload}.sig`, f.discovery, null, new KeyPinStore(), null, f.config);
        assert.strictEqual(r2.valid, false);
    });

    test('credential_ttl_max from the agent declaration is enforced', () => {
        const f = setup();
        f.discovery.agents[0].credential_ttl_max = 600;
        const long = issueCredential(f.kp.privateKeyPem, 'test-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', [new Capability('read:data')], null, null, 3600);
        const r = verifyCredentialOffline(long, f.discovery, null, new KeyPinStore(), 'verifier.com', f.config);
        assert.strictEqual(r.error_code, ErrorCode.CREDENTIAL_EXPIRED);
        assert.match(r.error_message, /credential_ttl_max/);
        const short = issueCredential(f.kp.privateKeyPem, 'test-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', [new Capability('read:data')], null, null, 600);
        assert.ok(verifyCredentialOffline(short, f.discovery, null, new KeyPinStore(), 'verifier.com', f.config).valid);
        delete f.discovery.agents[0].credential_ttl_max;
        const twoDays = issueCredential(f.kp.privateKeyPem, 'test-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', [new Capability('read:data')], null, null, 172800);
        const lax = { ...f.config, maxTtlSecs: 10 * 86400 };
        assert.strictEqual(verifyCredentialOffline(twoDays, f.discovery, null, new KeyPinStore(), 'verifier.com', lax).error_code, ErrorCode.CREDENTIAL_EXPIRED);
    });
});

describe('revocation document structure (AP-8)', () => {
    test('a document using the wrong field names fails closed instead of being ignored', () => {
        const f = setup();
        const { payload } = decodeJwtUnverified(f.jwt);
        const wrong = {
            agentpin_version: '0.1',
            entity: 'example.com',
            revoked_credentials: [{ id: payload.jti, reason: 'key_compromise', revoked_at: '2026-02-15T00:00:00Z' }],
            revoked_agents: [],
            revoked_keys: [{ id: 'test-2026-01', reason: 'key_compromise', revoked_at: '2026-02-15T00:00:00Z' }],
            updated_at: '2026-02-15T00:00:00Z',
        };
        const r = verifyCredentialOffline(f.jwt, f.discovery, wrong, new KeyPinStore(), 'verifier.com', f.config);
        assert.strictEqual(r.valid, false);
        assert.strictEqual(r.error_code, ErrorCode.DISCOVERY_INVALID);
    });
});

describe('effective constraints (AP-15)', () => {
    test('a credential that omits constraints inherits the discovery defaults; widening is rejected', () => {
        const f = setup();
        f.discovery.agents[0].constraints = { allowed_domains: ['*.client-corp.com'], rate_limit: '100/hour' };
        const jwt = issueCredential(f.kp.privateKeyPem, 'test-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', [new Capability('read:data')], null, null, 3600);
        const r = verifyCredentialOffline(jwt, f.discovery, null, new KeyPinStore(), 'verifier.com', f.config);
        assert.ok(r.valid, JSON.stringify(r));
        assert.deepStrictEqual(r.constraints.allowed_domains, ['*.client-corp.com']);
        assert.strictEqual(r.constraints.rate_limit, '100/hour');
        const wide = issueCredential(f.kp.privateKeyPem, 'test-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', [new Capability('read:data')], { allowed_domains: ['evil.com'] }, null, 3600);
        assert.strictEqual(verifyCredentialOffline(wide, f.discovery, null, new KeyPinStore(), 'verifier.com', f.config).error_code, ErrorCode.CONSTRAINT_VIOLATION);
    });
});
