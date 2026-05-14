/**
 * Tests for LocalAgentCardStore (v0.3.0).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    generateKeyPair,
    buildAndSignAgentCard,
    LocalAgentCardStore,
    cardEndpointHost,
    deriveDiscoveryFromCard,
    AgentStatus,
} from '../src/index.js';

function declaration() {
    return {
        agent_id: 'urn:agentpin:example.com:tester',
        name: 'Tester',
        description: 'Test agent',
        version: '1.0.0',
        capabilities: ['read:*'],
        constraints: { allowed_domains: ['partner.com'] },
        credential_ttl_max: 3600,
        status: AgentStatus.ACTIVE,
    };
}

function signedCard() {
    const { privateKeyPem } = generateKeyPair();
    return buildAndSignAgentCard(
        'https://example.com/agent',
        declaration(),
        privateKeyPem,
        'kid-1',
        'https://example.com/.well-known/agent-identity.json'
    );
}

describe('cardEndpointHost', () => {
    it('returns the host of the agentpin endpoint URL', () => {
        const card = signedCard();
        assert.equal(cardEndpointHost(card), 'example.com');
    });

    it('throws when the card has no agentpin extension', () => {
        assert.throws(() => cardEndpointHost({ name: 'x' }));
    });
});

describe('deriveDiscoveryFromCard', () => {
    it('produces a discovery document with the card key and skills', () => {
        const card = signedCard();
        const doc = deriveDiscoveryFromCard(card);
        assert.equal(doc.entity, 'example.com');
        assert.equal(doc.public_keys.length, 1);
        assert.equal(doc.agents.length, 1);
        assert.equal(doc.agents[0].name, 'Tester');
        assert.deepEqual(doc.agents[0].capabilities, ['read:*']);
        assert.deepEqual(doc.agents[0].constraints.allowed_domains, ['partner.com']);
        assert.equal(doc.a2a_endpoint, 'https://example.com/.well-known/agent-identity.json');
    });
});

describe('LocalAgentCardStore', () => {
    it('registers then resolves', () => {
        const store = new LocalAgentCardStore();
        store.register(signedCard());
        assert.equal(store.size, 1);
        const doc = store.resolveDiscovery('example.com');
        assert.equal(doc.entity, 'example.com');
        assert.equal(doc.agents[0].name, 'Tester');
    });

    it('propagates signature failures from register()', () => {
        const card = signedCard();
        card.url = 'https://attacker.example/agent'; // tampered
        const store = new LocalAgentCardStore();
        assert.throws(() => store.register(card));
        assert.ok(store.isEmpty());
    });

    it('resolveDiscovery throws for unknown domain', () => {
        const store = new LocalAgentCardStore();
        assert.throws(() => store.resolveDiscovery('missing.com'));
    });

    it('re-registering replaces the prior entry', () => {
        const store = new LocalAgentCardStore();
        store.register(signedCard());
        store.register(signedCard());
        assert.equal(store.size, 1);
    });

    it('remove() drops the entry', () => {
        const store = new LocalAgentCardStore();
        store.register(signedCard());
        assert.equal(store.remove('example.com'), true);
        assert.ok(store.isEmpty());
        assert.equal(store.remove('example.com'), false);
    });

    it('resolveCard returns the original card', () => {
        const store = new LocalAgentCardStore();
        store.register(signedCard());
        const card = store.resolveCard('example.com');
        assert.equal(card.name, 'Tester');
    });

    it('resolveRevocation returns null', () => {
        const store = new LocalAgentCardStore();
        store.register(signedCard());
        const doc = store.resolveDiscovery('example.com');
        assert.equal(store.resolveRevocation('example.com', doc), null);
    });

    it('preserves allowed_domains into the derived discovery doc', () => {
        const store = new LocalAgentCardStore();
        store.register(signedCard());
        const doc = store.resolveDiscovery('example.com');
        assert.deepEqual(doc.agents[0].constraints.allowed_domains, ['partner.com']);
    });
});
