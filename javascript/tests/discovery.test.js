/**
 * Tests for discovery document handling.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { EntityType, AgentStatus } from '../src/types.js';
import {
    buildDiscoveryDocument,
    validateDiscoveryDocument,
    findKeyByKid,
    findAgentById,
} from '../src/discovery.js';

function makeTestDoc() {
    return buildDiscoveryDocument(
        'example.com',
        EntityType.MAKER,
        [{
            kid: 'example-2026-01',
            kty: 'EC',
            crv: 'P-256',
            x: 'test-x',
            y: 'test-y',
            use: 'sig',
            key_ops: ['verify'],
        }],
        [{
            agent_id: 'urn:agentpin:example.com:agent',
            name: 'Test Agent',
            capabilities: ['read:*'],
            status: AgentStatus.ACTIVE,
        }],
        2,
        '2026-01-15T00:00:00Z'
    );
}

describe('validateDiscoveryDocument', () => {
    test('valid document passes', () => {
        const doc = makeTestDoc();
        assert.doesNotThrow(() => validateDiscoveryDocument(doc, 'example.com'));
    });

    test('domain mismatch rejected', () => {
        const doc = makeTestDoc();
        assert.throws(
            () => validateDiscoveryDocument(doc, 'other.com'),
            /does not match/
        );
    });
});

describe('findKeyByKid', () => {
    test('finds existing key', () => {
        const doc = makeTestDoc();
        assert.ok(findKeyByKid(doc, 'example-2026-01'));
    });

    test('returns null for missing key', () => {
        const doc = makeTestDoc();
        assert.strictEqual(findKeyByKid(doc, 'nonexistent'), null);
    });
});

describe('findAgentById', () => {
    test('finds existing agent', () => {
        const doc = makeTestDoc();
        assert.ok(findAgentById(doc, 'urn:agentpin:example.com:agent'));
    });

    test('returns null for missing agent', () => {
        const doc = makeTestDoc();
        assert.strictEqual(findAgentById(doc, 'urn:agentpin:example.com:other'), null);
    });
});
