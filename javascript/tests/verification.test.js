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

    test('key rotation with continuity accepted and pinned', () => {
        const f = setup();
        assert.ok(verifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config).valid);
        const kp2 = generateKeyPair();
        f.discovery.public_keys = [...f.discovery.public_keys, pemToJwk(kp2.publicKeyPem, 'test-2026-02')];
        const jwt2 = issueCredential(kp2.privateKeyPem, 'test-2026-02', 'example.com',
            'urn:agentpin:example.com:agent', 'verifier.com', [new Capability('read:data')], null, null, 3600);
        const r2 = verifyCredentialOffline(jwt2, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config);
        assert.ok(r2.valid, JSON.stringify(r2));
        assert.strictEqual(r2.key_pinning.status, 'rotated');
        f.discovery.public_keys = f.discovery.public_keys.slice(1);
        const r3 = verifyCredentialOffline(jwt2, f.discovery, f.revocation, f.pinStore, 'verifier.com', f.config);
        assert.ok(r3.valid);
        assert.strictEqual(r3.key_pinning.status, 'pinned');
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

describe('delegation chain verification (AP-2, AP-20, AP-21)', () => {
    async function delegationFixture() {
        const { createAttestation } = await import('../src/delegation.js');
        const { DelegationRole } = await import('../src/types.js');
        const maker = generateKeyPair();
        const makerDoc = buildDiscoveryDocument('maker.com', EntityType.MAKER, [pemToJwk(maker.publicKeyPem, 'maker-2026-01')],
            [{ agent_id: 'urn:agentpin:maker.com:agent-type', name: 'Agent Type', capabilities: ['read:*'], status: AgentStatus.ACTIVE }],
            2, '2026-01-15T00:00:00Z');
        const deployer = generateKeyPair();
        const deployerDoc = buildDiscoveryDocument('example.com', EntityType.DEPLOYER, [pemToJwk(deployer.publicKeyPem, 'deployer-2026-01')],
            [{ agent_id: 'urn:agentpin:example.com:agent', agent_type: 'urn:agentpin:maker.com:agent-type', name: 'Deployed', capabilities: ['read:*'], status: AgentStatus.ACTIVE }],
            2, '2026-01-15T00:00:00Z');
        const caps = [new Capability('read:data')];
        const att = createAttestation(maker.privateKeyPem, 'maker-2026-01', 'maker.com', DelegationRole.MAKER,
            'urn:agentpin:maker.com:agent-type', 'example.com', 'urn:agentpin:example.com:agent', caps);
        const jwt = issueCredential(deployer.privateKeyPem, 'deployer-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', caps, null, [att], 3600);
        const resolverFor = (...docs) => ({ resolveDiscovery(d) { const doc = docs.find((x) => x.entity === d); if (!doc) throw new Error(`no doc for ${d}`); return doc; } });
        return { jwt, makerDoc, deployerDoc, deployer, caps, resolverFor };
    }

    test('a genuine chain verifies end to end', async () => {
        const f = await delegationFixture();
        const r = verifyCredentialOffline(f.jwt, f.deployerDoc, null, new KeyPinStore(), 'verifier.com', undefined, f.resolverFor(f.makerDoc));
        assert.ok(r.valid, JSON.stringify(r));
        assert.strictEqual(r.delegation_verified, true);
        assert.deepStrictEqual(r.delegation_chain, [{ domain: 'maker.com', role: 'maker', verified: true }]);
        assert.deepStrictEqual(r.warnings, []);
    });

    test('a forged attestation is rejected; unverifiable chains fail closed by default', async () => {
        const f = await delegationFixture();
        const forged = issueCredential(f.deployer.privateKeyPem, 'deployer-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', f.caps, null, [{ domain: 'maker.com', role: 'maker', agent_id: 'urn:agentpin:maker.com:agent-type', kid: 'maker-2026-01', attestation: 'AAAA' }], 3600);
        const r1 = verifyCredentialOffline(forged, f.deployerDoc, null, new KeyPinStore(), 'verifier.com', undefined, f.resolverFor(f.makerDoc));
        assert.strictEqual(r1.valid, false);
        assert.strictEqual(r1.error_code, ErrorCode.DELEGATION_INVALID);
        const r2 = verifyCredentialOffline(f.jwt, f.deployerDoc, null, new KeyPinStore(), 'verifier.com');
        assert.strictEqual(r2.valid, false);
        assert.strictEqual(r2.error_code, ErrorCode.DELEGATION_INVALID);
        const r3 = verifyCredentialOffline(f.jwt, f.deployerDoc, null, new KeyPinStore(), 'verifier.com', { requireDelegationVerification: false });
        assert.ok(r3.valid);
        assert.strictEqual(r3.delegation_verified, false);
        assert.ok(r3.warnings.length > 0);
    });

    test('unresolvable attester, unknown kid, depth and scope widening fail', async () => {
        const f = await delegationFixture();
        const run = (doc) => verifyCredentialOffline(f.jwt, f.deployerDoc, null, new KeyPinStore(), 'verifier.com', undefined, f.resolverFor(doc));
        assert.strictEqual(run({ entity: 'other.com' }).error_code, ErrorCode.DELEGATION_INVALID);
        assert.strictEqual(run({ ...f.makerDoc, public_keys: [{ ...f.makerDoc.public_keys[0], kid: 'maker-2026-02' }] }).error_code, ErrorCode.DELEGATION_INVALID);
        assert.strictEqual(run({ ...f.makerDoc, max_delegation_depth: 0 }).error_code, ErrorCode.DELEGATION_DEPTH_EXCEEDED);
        const narrow = run({ ...f.makerDoc, agents: [{ ...f.makerDoc.agents[0], capabilities: ['read:public'] }] });
        assert.strictEqual(narrow.error_code, ErrorCode.DELEGATION_INVALID);
        assert.match(narrow.error_message, /exceed/);
        assert.strictEqual(run({ ...f.makerDoc, agents: [{ ...f.makerDoc.agents[0], status: 'suspended' }] }).error_code, ErrorCode.DELEGATION_INVALID);
    });

    test('key metadata is enforced: unparsable exp, use != sig, key_ops without verify', () => {
        const f = setup();
        const run = (mutate) => {
            const doc = { ...f.discovery, public_keys: [{ ...f.discovery.public_keys[0], ...mutate }] };
            return verifyCredentialOffline(f.jwt, doc, null, new KeyPinStore(), 'verifier.com', f.config);
        };
        assert.strictEqual(run({ exp: 'expired' }).error_code, ErrorCode.KEY_EXPIRED);
        assert.strictEqual(run({ exp: '2020-01-01T00:00:00Z' }).error_code, ErrorCode.KEY_EXPIRED);
        assert.strictEqual(run({ use: 'enc' }).error_code, ErrorCode.KEY_NOT_FOUND);
        assert.strictEqual(run({ key_ops: ['sign'] }).error_code, ErrorCode.KEY_NOT_FOUND);
        assert.ok(run({ exp: '2099-01-01T00:00:00Z' }).valid);
    });
});

describe('capability taxonomy (AP-21)', () => {
    test('admin:* is never accepted; strict mode rejects non-reverse-domain custom actions', () => {
        const f = setup();
        const issue = (caps) => issueCredential(f.kp.privateKeyPem, 'test-2026-01', 'example.com', 'urn:agentpin:example.com:agent',
            'verifier.com', caps.map((c) => new Capability(c)), null, null, 3600);
        const admin = { ...f.discovery, agents: [{ ...f.discovery.agents[0], capabilities: ['admin:*'] }] };
        const lax = { ...f.config, strictCapabilities: false };
        for (const cfg of [f.config, lax]) {
            assert.strictEqual(verifyCredentialOffline(issue(['admin:*']), admin, null, new KeyPinStore(), 'verifier.com', cfg).error_code, ErrorCode.CAPABILITY_EXCEEDED);
        }
        const custom = { ...f.discovery, agents: [{ ...f.discovery.agents[0], capabilities: ['scan:target', 'com.example.scan:target'] }] };
        assert.strictEqual(verifyCredentialOffline(issue(['scan:target']), custom, null, new KeyPinStore(), 'verifier.com', f.config).error_code, ErrorCode.CAPABILITY_EXCEEDED);
        assert.ok(verifyCredentialOffline(issue(['scan:target']), custom, null, new KeyPinStore(), 'verifier.com', lax).valid);
        const rev = { ...f.discovery, agents: [{ ...f.discovery.agents[0], capabilities: ['com.example.scan:target'] }] };
        assert.ok(verifyCredentialOffline(issue(['com.example.scan:target']), rev, null, new KeyPinStore(), 'verifier.com', f.config).valid);
    });
});
