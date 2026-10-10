/**
 * Cross-SDK conformance vectors shared with the Rust, Go and Python suites
 * (testdata/conformance/vectors.json at the repository root).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { generateKeyPair, domainSeparatedInput } from '../src/crypto.js';
import { pemToJwk } from '../src/jwk.js';
import { Capability } from '../src/capability.js';
import { issueCredential } from '../src/credential.js';
import { validateDiscoveryDocument } from '../src/discovery.js';
import { KeyPinStore } from '../src/pinning.js';
import { verifyAgentpinExtension } from '../src/a2a.js';
import { verifyCredentialOffline } from '../src/verification.js';

const dir = new URL('../../testdata/conformance/', import.meta.url);
const read = (name) => readFileSync(new URL(name, dir), 'utf8');
const vectors = JSON.parse(read('vectors.json'));
const discovery = () => JSON.parse(read('discovery.json'));
const AGENT = 'urn:agentpin:example.com:test-agent';

describe('conformance vectors', () => {
    test('malformed credentials are rejected', () => {
        for (const c of vectors.credentials) {
            const r = verifyCredentialOffline(c.jwt, discovery(), null, new KeyPinStore(), null, {});
            assert.ok(!r.valid, `${c.name} accepted`);
            assert.strictEqual(r.error_code, c.error_code, c.name);
        }
    });

    test('case-variant issuer hits the existing pin', () => {
        const v = vectors.case_variant_issuer;
        const d = discovery();
        const store = new KeyPinStore();
        store.checkAndPin('example.com', d.public_keys[0]);
        const kp = generateKeyPair();
        const evil = { ...d, entity: v.issuer, public_keys: [pemToJwk(kp.publicKeyPem, 'evil-key')] };
        const jwt = issueCredential(kp.privateKeyPem, 'evil-key', v.issuer, AGENT, null,
            [new Capability('read:data')], null, null, 3600);
        const r = verifyCredentialOffline(jwt, evil, null, store, null, {});
        assert.ok(!r.valid);
        assert.strictEqual(r.error_code, v.error_code);
    });

    test('revocation document with wrong field names is rejected', () => {
        const v = vectors.revocation_wrong_field_names;
        const jwt = issueCredential(read('example-2026-01.private.pem'), 'example-2026-01', 'example.com', AGENT,
            null, [new Capability('read:data')], null, null, 3600);
        const r = verifyCredentialOffline(jwt, discovery(), v.document, new KeyPinStore(), null, {});
        assert.ok(!r.valid);
        assert.strictEqual(r.error_code, v.error_code);
    });

    test('invalid revocation endpoints are rejected', () => {
        for (const url of vectors.invalid_revocation_endpoints) {
            const d = { ...discovery(), revocation_endpoint: url };
            assert.throws(() => validateDiscoveryDocument(d, 'example.com'), undefined, url);
        }
    });

    test('agent cards verify as expected', () => {
        for (const c of vectors.agent_cards) {
            let ok = true;
            try {
                verifyAgentpinExtension(c.card);
            } catch {
                ok = false;
            }
            assert.strictEqual(ok, c.valid, c.name);
        }
    });

    test('domain-separated input layout', () => {
        const v = vectors.domain_separated_input;
        const fields = v.fields_hex.map((h) => Buffer.from(h, 'hex'));
        assert.strictEqual(Buffer.from(domainSeparatedInput(v.context, fields)).toString('hex'), v.expected_hex);
    });
});
