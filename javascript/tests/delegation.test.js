/**
 * Tests for delegation attestation.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateKeyPair } from '../src/crypto.js';
import { Capability } from '../src/capability.js';
import { DelegationRole } from '../src/types.js';
import {
    createAttestation,
    verifyAttestation,
    verifyChainDepth,
} from '../src/delegation.js';

describe('createAttestation and verifyAttestation', () => {
    test('create and verify roundtrip', () => {
        const kp = generateKeyPair();
        const caps = [new Capability('read:data'), new Capability('write:report')];

        const att = createAttestation(
            kp.privateKeyPem,
            'maker-2026-01',
            'maker.com',
            DelegationRole.MAKER,
            'urn:agentpin:maker.com:agent-type',
            'deployer.com',
            'urn:agentpin:deployer.com:instance',
            caps
        );

        assert.strictEqual(att.domain, 'maker.com');
        assert.strictEqual(att.role, DelegationRole.MAKER);

        assert.doesNotThrow(() => verifyAttestation(
            att, kp.publicKeyPem,
            'deployer.com', 'urn:agentpin:deployer.com:instance', caps
        ));
    });

    test('wrong key rejected', () => {
        const kp1 = generateKeyPair();
        const kp2 = generateKeyPair();
        const caps = [new Capability('read:data')];

        const att = createAttestation(
            kp1.privateKeyPem, 'kid', 'domain',
            DelegationRole.MAKER, 'agent',
            'delegatee', 'delegatee-agent', caps
        );

        assert.throws(
            () => verifyAttestation(att, kp2.publicKeyPem, 'delegatee', 'delegatee-agent', caps),
            /failed/i
        );
    });

    test('wrong capabilities rejected', () => {
        const kp = generateKeyPair();
        const caps = [new Capability('read:data')];
        const wrongCaps = [new Capability('write:data')];

        const att = createAttestation(
            kp.privateKeyPem, 'kid', 'domain',
            DelegationRole.MAKER, 'agent',
            'delegatee', 'delegatee-agent', caps
        );

        assert.throws(
            () => verifyAttestation(att, kp.publicKeyPem, 'delegatee', 'delegatee-agent', wrongCaps),
            /failed/i
        );
    });
});

describe('verifyChainDepth', () => {
    test('within depth passes', () => {
        assert.doesNotThrow(() => verifyChainDepth(1, [2, 3]));
        assert.doesNotThrow(() => verifyChainDepth(2, [2, 3]));
    });

    test('exceeding depth throws', () => {
        assert.throws(() => verifyChainDepth(3, [2, 3]), /exceeds/i);
    });
});

describe('attestation binding (design 7, AP-1)', () => {
    test('attestation is bound to the attesting kid', () => {
        const kp = generateKeyPair();
        const caps = [new Capability('read:data')];
        const att = createAttestation(kp.privateKeyPem, 'kid-1', 'maker.com', DelegationRole.MAKER, 'a', 'deployer.com', 'da', caps);
        att.kid = 'kid-2';
        assert.throws(() => verifyAttestation(att, kp.publicKeyPem, 'deployer.com', 'da', caps), /failed/i);
    });

    test('expired attestations are rejected and exp is signed', () => {
        const kp = generateKeyPair();
        const caps = [new Capability('read:data')];
        const now = Math.floor(Date.now() / 1000);
        const fresh = createAttestation(kp.privateKeyPem, 'k', 'maker.com', DelegationRole.MAKER, 'a', 'deployer.com', 'da', caps, now + 3600);
        assert.doesNotThrow(() => verifyAttestation(fresh, kp.publicKeyPem, 'deployer.com', 'da', caps));
        const expired = createAttestation(kp.privateKeyPem, 'k', 'maker.com', DelegationRole.MAKER, 'a', 'deployer.com', 'da', caps, now - 10);
        assert.throws(() => verifyAttestation(expired, kp.publicKeyPem, 'deployer.com', 'da', caps), /expired/i);
        const stripped = { ...fresh };
        delete stripped.exp;
        assert.throws(() => verifyAttestation(stripped, kp.publicKeyPem, 'deployer.com', 'da', caps), /failed/i);
    });

    test('legacy pipe-joined attestation format is rejected', async () => {
        const { signData } = await import('../src/crypto.js');
        const { capabilitiesHash } = await import('../src/capability.js');
        const kp = generateKeyPair();
        const caps = [new Capability('read:data')];
        const legacy = `maker.com|maker|a|deployer.com|da|${capabilitiesHash(caps)}`;
        const att = { domain: 'maker.com', role: 'maker', agent_id: 'a', kid: 'k', attestation: signData(kp.privateKeyPem, Buffer.from(legacy)) };
        assert.throws(() => verifyAttestation(att, kp.publicKeyPem, 'deployer.com', 'da', caps), /failed/i);
    });

    test('verifyChainDepth with empty depth list means depth 0', () => {
        assert.throws(() => verifyChainDepth(1, []), /exceeds/i);
    });
});
