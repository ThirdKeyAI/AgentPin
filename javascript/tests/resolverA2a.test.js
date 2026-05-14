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
        return {
            ok: entry.status >= 200 && entry.status < 300,
            status: entry.status,
            async json() {
                if (entry.body === undefined) throw new Error('no body');
                return entry.body;
            },
        };
    };
}

describe('A2aAgentCardResolver', () => {
    it('resolves and verifies a card served over HTTPS', async () => {
        const card = signedCardForDomain('example.com');
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ fetchImpl });
        const doc = await resolver.resolveDiscovery('example.com');
        assert.equal(doc.entity, 'example.com');
        assert.equal(doc.public_keys.length, 1);
        assert.deepEqual(resolver.lastCard('example.com'), card);
    });

    it('rejects an HTTP error response', async () => {
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 404 },
        });
        const resolver = new A2aAgentCardResolver({ fetchImpl });
        await assert.rejects(() => resolver.resolveDiscovery('example.com'), /HTTP 404/);
    });

    it('rejects a card whose extension does not verify', async () => {
        const card = signedCardForDomain('example.com');
        card.url = 'https://attacker.example/agent'; // tamper
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ fetchImpl });
        await assert.rejects(() => resolver.resolveDiscovery('example.com'), /did not verify/);
    });

    it('rejects a card whose agentpin endpoint host disagrees with the fetch domain', async () => {
        const card = signedCardForDomain('other.com'); // valid for other.com
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ fetchImpl });
        await assert.rejects(() => resolver.resolveDiscovery('example.com'), /mismatch/);
    });

    it('resolveRevocation returns null', async () => {
        const card = signedCardForDomain('example.com');
        const fetchImpl = stubFetch({
            'https://example.com/.well-known/agent-card.json': { status: 200, body: card },
        });
        const resolver = new A2aAgentCardResolver({ fetchImpl });
        const doc = await resolver.resolveDiscovery('example.com');
        assert.equal(await resolver.resolveRevocation('example.com', doc), null);
    });
});
