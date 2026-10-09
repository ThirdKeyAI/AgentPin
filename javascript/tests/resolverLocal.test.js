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
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        assert.equal(store.size, 1);
        const doc = store.resolveDiscovery('example.com');
        assert.equal(doc.entity, 'example.com');
        assert.equal(doc.agents[0].name, 'Tester');
    });

    it('propagates signature failures from register()', () => {
        const card = signedCard();
        card.url = 'https://attacker.example/agent'; // tampered
        const store = new LocalAgentCardStore({ unanchored: true });
        assert.throws(() => store.register(card));
        assert.ok(store.isEmpty());
    });

    it('resolveDiscovery throws for unknown domain', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        assert.throws(() => store.resolveDiscovery('missing.com'));
    });

    it('re-registering replaces the prior entry', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        store.register(signedCard());
        assert.equal(store.size, 1);
    });

    it('remove() drops the entry', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        assert.equal(store.remove('example.com'), true);
        assert.ok(store.isEmpty());
        assert.equal(store.remove('example.com'), false);
    });

    it('resolveCard returns the original card', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        const card = store.resolveCard('example.com');
        assert.equal(card.name, 'Tester');
    });

    it('resolveRevocation returns null', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        const doc = store.resolveDiscovery('example.com');
        assert.equal(store.resolveRevocation('example.com', doc), null);
    });

    it('preserves allowed_domains into the derived discovery doc', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        const doc = store.resolveDiscovery('example.com');
        assert.deepEqual(doc.agents[0].constraints.allowed_domains, ['partner.com']);
    });
});

describe('credential verification through a card-derived discovery document', () => {
    // AP-9 regression: the derived document must carry wire version "0.1";
    // before the fix it was stamped "0.3" and the verifier rejected it.
    it('verifies a credential signed with the card key', async () => {
        const { issueCredential, verifyCredentialOffline, KeyPinStore, Capability } =
            await import('../src/index.js');
        const { privateKeyPem } = generateKeyPair();
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            declaration(),
            privateKeyPem,
            'kid-1',
            'https://example.com/.well-known/agent-identity.json'
        );
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(card);
        const doc = store.resolveDiscovery('example.com');
        assert.equal(doc.agentpin_version, '0.1');

        const jwt = issueCredential(
            privateKeyPem, 'kid-1', 'example.com', 'urn:agentpin:example.com:tester',
            null, [new Capability('read:data')], null, null, 3600
        );
        const result = verifyCredentialOffline(
            jwt, doc, store.resolveRevocation('example.com', doc), new KeyPinStore(), null, undefined
        );
        assert.equal(result.valid, true, JSON.stringify(result));
        assert.equal(result.agent_id, 'urn:agentpin:example.com:tester');
    });
});

describe('endpoint and lookup hardening (AP-3, AP-12)', () => {
    it('rejects non-https or IP agentpin endpoints at registration', () => {
        const { privateKeyPem } = generateKeyPair();
        for (const bad of [
            'http://example.com/.well-known/agent-identity.json',
            'https://127.0.0.1/.well-known/agent-identity.json',
            'https://example.com:8443/.well-known/agent-identity.json',
            'https://user@example.com/.well-known/agent-identity.json',
        ]) {
            const card = buildAndSignAgentCard('https://example.com/agent', declaration(), privateKeyPem, 'kid-1', bad);
            assert.throws(() => new LocalAgentCardStore({ unanchored: true }).register(card), bad);
        }
    });

    it('normalizes lookups', () => {
        const store = new LocalAgentCardStore({ unanchored: true });
        store.register(signedCard());
        assert.ok(store.resolveDiscovery('EXAMPLE.COM.'));
        assert.ok(store.resolveCard('Example.com'));
    });
});


describe('trust anchor (AP-4, design issue 9)', () => {
    const storeTrusting = async (card) => {
        const { extensionKeyThumbprint } = await import('../src/index.js');
        return new LocalAgentCardStore({ trustedThumbprints: [extensionKeyThumbprint(card.agentpin)] });
    };

    it('a store with no trusted key refuses every registration', () => {
        const store = new LocalAgentCardStore();
        assert.throws(() => store.register(signedCard()), /not a trusted thumbprint/);
        assert.ok(store.isEmpty());
    });

    it('refuses a self-signed card that claims another domain', async () => {
        const { buildDiscoveryDocument, pemToJwk, EntityType, cardKeyPublishedIn } = await import('../src/index.js');
        const attacker = generateKeyPair();
        const evil = buildAndSignAgentCard('https://attacker.example/agent', declaration(), attacker.privateKeyPem, 'kid-1',
            'https://bank.example/.well-known/agent-identity.json');
        const store = await storeTrusting(signedCard());
        assert.throws(() => store.register(evil));
        assert.equal(store.resolveCard('bank.example'), null);

        const bank = generateKeyPair();
        const bankDoc = buildDiscoveryDocument('bank.example', EntityType.DEPLOYER, [pemToJwk(bank.publicKeyPem, 'bank-1')], [], 0, '2026-01-15T00:00:00Z');
        assert.equal(cardKeyPublishedIn(bankDoc, evil), false);
        const resolverStore = new LocalAgentCardStore({ resolver: { resolveDiscovery: () => bankDoc } });
        assert.throws(() => resolverStore.register(evil), /not published/);
        assert.ok(resolverStore.isEmpty());
    });

    it('resolver anchor accepts a key published in the discovery document', async () => {
        const { buildDiscoveryDocument, pemToJwk, EntityType, cardKeyPublishedIn } = await import('../src/index.js');
        const kp = generateKeyPair();
        const card = buildAndSignAgentCard('https://example.com/agent', declaration(), kp.privateKeyPem, 'kid-1',
            'https://example.com/.well-known/agent-identity.json');
        const doc = buildDiscoveryDocument('example.com', EntityType.BOTH, [pemToJwk(kp.publicKeyPem, 'kid-1')], [], 0, '2026-01-15T00:00:00Z');
        assert.ok(cardKeyPublishedIn(doc, card));
        const store = new LocalAgentCardStore({ resolver: { resolveDiscovery: () => doc } });
        store.register(card);
        assert.equal(store.size, 1);
    });

    it('registerForDomain requires a matching host; trustThumbprint enables registration', async () => {
        const { extensionKeyThumbprint } = await import('../src/index.js');
        const card = signedCard();
        const store = await storeTrusting(card);
        assert.throws(() => store.registerForDomain(card, 'other.com'));
        store.registerForDomain(card, 'EXAMPLE.com.');
        assert.equal(store.size, 1);
        const fresh = new LocalAgentCardStore();
        assert.throws(() => fresh.register(card));
        fresh.trustThumbprint(extensionKeyThumbprint(card.agentpin));
        fresh.register(card);
        assert.throws(() => new LocalAgentCardStore({ unanchored: true }).trustThumbprint('x'));
    });
});
