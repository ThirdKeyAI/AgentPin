/**
 * Tests for credential issuance and validation.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { verifyJwt } from '../src/jwt.js';
import { Capability } from '../src/capability.js';
import { issueCredential, validateCredentialAgainstDiscovery } from '../src/credential.js';

describe('issueCredential', () => {
    test('issues and verifies credential', () => {
        const kp = generateKeyPair();

        const jwt = issueCredential(
            kp.privateKeyPem,
            'test-2026-01',
            'example.com',
            'urn:agentpin:example.com:agent',
            'verifier.com',
            [new Capability('read:data')],
            null,
            null,
            3600
        );

        const { header, payload } = verifyJwt(jwt, kp.publicKeyPem);
        assert.strictEqual(header.kid, 'test-2026-01');
        assert.strictEqual(payload.iss, 'example.com');
        assert.strictEqual(payload.sub, 'urn:agentpin:example.com:agent');
        assert.strictEqual(payload.aud, 'verifier.com');
        assert.strictEqual(payload.agentpin_version, '0.1');
        assert.ok(payload.exp > payload.iat);
    });
});

describe('validateCredentialAgainstDiscovery', () => {
    test('valid subset passes', () => {
        const discCaps = ['read:*', 'write:report'];
        const credCaps = ['read:data'];
        assert.doesNotThrow(() => validateCredentialAgainstDiscovery(credCaps, discCaps));
    });

    test('exceeding capabilities throws', () => {
        const discCaps = ['read:data'];
        const credCaps = ['delete:data'];
        assert.throws(
            () => validateCredentialAgainstDiscovery(credCaps, discCaps),
            /exceed/i
        );
    });
});
