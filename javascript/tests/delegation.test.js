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
