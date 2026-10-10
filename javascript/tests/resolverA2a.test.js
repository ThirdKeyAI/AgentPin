/**
 * Tests for A2aAgentCardResolver (v0.3.0).
 *
 * Uses a stub `fetchImpl` so we don't need a real HTTP server.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    generateKeyPair,
    buildAndSignAgentCard,
    A2aAgentCardResolver,
    AgentStatus,
} from '../src/index.js';

function signedCardForDomain(domain) {
    const { privateKeyPem } = generateKeyPair();
    const decl = {
        agent_id: `urn:agentpin:${domain}:test`,
        name: 'Test Agent',
        description: 'desc',
        version: '1.0.0',
        capabilities: ['read:*'],
        credential_ttl_max: 3600,
        status: AgentStatus.ACTIVE,
    };
    return buildAndSignAgentCard(
        `https://${domain}/agent`,
        decl,
        privateKeyPem,
        'kid-1',
        `https://${domain}/.well-known/agent-identity.json`
    );
}

function stubFetch(responses) {
    return async (url) => {
        const entry = responses[url];
        if (!entry) {
            throw new Error(`unexpected fetch: ${url}`);
        }
        if (entry.networkError) {
            throw new Error(entry.networkError);
        }
        // A realistic Response: the hardened fetch layer checks status,
        // content-type and body size before parsing.
        return new Response(entry.body === undefined ? '' : JSON.stringify(entry.body), {
            status: entry.status,
            headers: { 'content-type': 'application/json' },
        });
    };
}

describe('A2aAgentCardResolver', () => {
    it('resolves and verifies a card served over HTTPS', async () => {
        const card = signedCardForDomain('example.com');
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ requireDiscoveryBinding: false, fetchImpl });
        const doc = await resolver.resolveDiscovery('example.com');
        assert.equal(doc.entity, 'example.com');
        assert.equal(doc.public_keys.length, 1);
        assert.deepEqual(resolver.lastCard('example.com'), card);
    });

    it('rejects an HTTP error response', async () => {
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 404 },
        });
        const resolver = new A2aAgentCardResolver({ requireDiscoveryBinding: false, fetchImpl });
        await assert.rejects(() => resolver.resolveDiscovery('example.com'), /HTTP 404/);
    });

    it('rejects a card whose extension does not verify', async () => {
        const card = signedCardForDomain('example.com');
        card.url = 'https://attacker.example/agent'; // tamper
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ requireDiscoveryBinding: false, fetchImpl });
        await assert.rejects(() => resolver.resolveDiscovery('example.com'), /did not verify/);
    });

    it('rejects a card whose agentpin endpoint host disagrees with the fetch domain', async () => {
        const card = signedCardForDomain('other.com'); // valid for other.com
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ requireDiscoveryBinding: false, fetchImpl });
        await assert.rejects(() => resolver.resolveDiscovery('example.com'), /mismatch/);
    });

    it('resolveRevocation returns null', async () => {
        const card = signedCardForDomain('example.com');
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ requireDiscoveryBinding: false, fetchImpl });
        const doc = await resolver.resolveDiscovery('example.com');
        assert.equal(await resolver.resolveRevocation('example.com', doc), null);
    });
});


describe('discovery binding (AP-4, spec §4.10.4 step 5)', () => {
    it('requires the card key to be published in the discovery document', async () => {
        const { buildDiscoveryDocument, pemToJwk, EntityType } = await import('../src/index.js');
        const kp = generateKeyPair();
        const decl = { agent_id: 'urn:agentpin:example.com:test', name: 'Test Agent', capabilities: ['read:*'], status: AgentStatus.ACTIVE };
        const card = buildAndSignAgentCard('https://example.com/agent', decl, kp.privateKeyPem, 'kid-1', 'https://example.com/.well-known/agent-identity.json');
        const cardUrl = 'https://example.com/.well-known/agent-card.json';
        const docUrl = 'https://example.com/.well-known/agent-identity.json';
        const published = buildDiscoveryDocument('example.com', EntityType.BOTH, [pemToJwk(kp.publicKeyPem, 'kid-1')], [], 0, '2026-01-15T00:00:00Z');
        const ok = new A2aAgentCardResolver({ fetchImpl: stubFetch({ [cardUrl]: { status: 200, body: card }, [docUrl]: { status: 200, body: published } }) });
        const doc = await ok.resolveDiscovery('example.com');
        assert.equal(doc.entity, 'example.com');

        const other = generateKeyPair();
        const unrelated = buildDiscoveryDocument('example.com', EntityType.BOTH, [pemToJwk(other.publicKeyPem, 'other')], [], 0, '2026-01-15T00:00:00Z');
        const bad = new A2aAgentCardResolver({ fetchImpl: stubFetch({ [cardUrl]: { status: 200, body: card }, [docUrl]: { status: 200, body: unrelated } }) });
        await assert.rejects(bad.resolveDiscovery('example.com'), /not published/);

        const missing = new A2aAgentCardResolver({ fetchImpl: stubFetch({ [cardUrl]: { status: 200, body: card }, [docUrl]: { status: 404 } }) });
        await assert.rejects(missing.resolveDiscovery('example.com'));
    });
});
