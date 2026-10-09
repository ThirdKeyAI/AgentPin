/**
 * Tests for A2A AgentCard types, builder, and verification (v0.3.0).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    generateKeyPair,
    generateKeyId,
    buildUnsignedAgentCard,
    signAgentCard,
    buildAndSignAgentCard,
    verifyAgentpinExtension,
    capabilityToSkill,
    extensionKeyThumbprint,
    canonicalizeForSigning,
    jwkThumbprint,
    AgentStatus,
} from '../src/index.js';

function declarationWith(capabilities, allowedDomains = null) {
    const decl = {
        agent_id: 'urn:agentpin:example.com:test',
        name: 'Test Agent',
        description: 'test',
        version: '1.0.0',
        capabilities,
        status: AgentStatus.ACTIVE,
        credential_ttl_max: 3600,
    };
    if (allowedDomains !== null) {
        decl.constraints = { allowed_domains: allowedDomains };
    }
    return decl;
}

describe('capabilityToSkill', () => {
    it('maps a string capability to a skill', () => {
        const skill = capabilityToSkill('read:customers/*');
        assert.equal(skill.id, 'read:customers/*');
        assert.equal(skill.name, 'read:customers/*');
        assert.equal(skill.description, undefined);
    });
});

describe('buildUnsignedAgentCard', () => {
    it('maps capabilities to skills 1:1', () => {
        const decl = declarationWith(['read:customers', 'write:invoices']);
        const card = buildUnsignedAgentCard('https://example.com/agent', decl);
        assert.equal(card.skills.length, 2);
        assert.equal(card.skills[0].id, 'read:customers');
        assert.equal(card.skills[1].id, 'write:invoices');
        assert.equal(card.agentpin, undefined);
    });

    it('maps allowed_domains constraint into capabilities', () => {
        const decl = declarationWith(['read:*'], ['a.com', 'b.com']);
        const card = buildUnsignedAgentCard('https://example.com/agent', decl);
        assert.deepEqual(card.capabilities.allowed_domains, ['a.com', 'b.com']);
    });

    it('omits allowed_domains when unrestricted', () => {
        const decl = declarationWith(['read:*']);
        const card = buildUnsignedAgentCard('https://example.com/agent', decl);
        assert.equal(card.capabilities.allowed_domains, undefined);
    });

    it('honours skill overrides', () => {
        const decl = declarationWith(['read:*']);
        const card = buildUnsignedAgentCard('https://example.com/agent', decl, {
            skills: [{ id: 'read:*', name: 'Read everything', description: 'desc' }],
        });
        assert.equal(card.skills[0].description, 'desc');
    });
});

describe('signAgentCard', () => {
    it('requires agentpinEndpoint', () => {
        const { privateKeyPem } = generateKeyPair();
        const decl = declarationWith(['read:*']);
        const unsigned = buildUnsignedAgentCard('https://example.com/agent', decl);
        assert.throws(() => signAgentCard(unsigned, privateKeyPem, 'kid-1', ''));
    });

    it('produces a card that verifies cleanly', () => {
        const { privateKeyPem } = generateKeyPair();
        const decl = declarationWith(['read:customers', 'write:invoices'], ['partner.com']);
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            decl,
            privateKeyPem,
            'kid-1',
            'https://example.com/.well-known/agent-identity.json',
            { streaming: true }
        );
        assert.ok(card.agentpin);
        verifyAgentpinExtension(card);
    });

    it('roundtrips through JSON and re-verifies', () => {
        const { privateKeyPem } = generateKeyPair();
        const decl = declarationWith(['read:*']);
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            decl,
            privateKeyPem,
            'kid-1',
            'https://example.com/.well-known/agent-identity.json'
        );
        const json = JSON.stringify(card);
        const parsed = JSON.parse(json);
        verifyAgentpinExtension(parsed);
    });
});

describe('verifyAgentpinExtension', () => {
    it('throws when extension is missing', () => {
        const decl = declarationWith(['read:*']);
        const card = buildUnsignedAgentCard('https://example.com/agent', decl);
        assert.throws(() => verifyAgentpinExtension(card), /no agentpin extension/);
    });

    it('throws when card has been tampered with', () => {
        const { privateKeyPem } = generateKeyPair();
        const decl = declarationWith(['read:customers']);
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            decl,
            privateKeyPem,
            'kid-1',
            'https://example.com/.well-known/agent-identity.json'
        );
        card.url = 'https://attacker.example/agent';
        assert.throws(() => verifyAgentpinExtension(card), /did not verify/);
    });
});

describe('extensionKeyThumbprint', () => {
    it('matches jwkThumbprint over the extension JWK', () => {
        const { privateKeyPem, publicKeyPem } = generateKeyPair();
        const decl = declarationWith(['read:*']);
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            decl,
            privateKeyPem,
            'kid-1',
            'https://example.com/.well-known/agent-identity.json'
        );
        const fromHelper = extensionKeyThumbprint(card.agentpin);
        const direct = jwkThumbprint(card.agentpin.public_key_jwk);
        assert.equal(fromHelper, direct);
    });
});

describe('canonicalizeForSigning', () => {
    it('produces sorted-key compact JSON', () => {
        const out = canonicalizeForSigning({ b: 1, a: { d: 4, c: 3 } });
        assert.equal(out, '{"a":{"c":3,"d":4},"b":1}');
    });

    it('drops undefined values', () => {
        const out = canonicalizeForSigning({ a: 1, b: undefined, c: 3 });
        assert.equal(out, '{"a":1,"c":3}');
    });

    it('recurses into arrays', () => {
        const out = canonicalizeForSigning([{ b: 1, a: 2 }]);
        assert.equal(out, '[{"a":2,"b":1}]');
    });
});

describe('AgentCard signature coverage (AP-1, AP-4)', () => {
    it('fails when agentpin_endpoint is rewritten after signing', async () => {
        const { generateKeyPair, buildAndSignAgentCard, verifyAgentpinExtension, AgentStatus } = await import('../src/index.js');
        const { privateKeyPem } = generateKeyPair();
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            { agent_id: 'urn:agentpin:example.com:t', name: 'T', capabilities: ['read:*'], status: AgentStatus.ACTIVE },
            privateKeyPem, 'kid-1', 'https://example.com/.well-known/agent-identity.json'
        );
        card.agentpin.agentpin_endpoint = 'https://bank.example/.well-known/agent-identity.json';
        assert.throws(() => verifyAgentpinExtension(card), /did not verify/);
    });

    it('fails when the extension JWK kid is rewritten', async () => {
        const { generateKeyPair, buildAndSignAgentCard, verifyAgentpinExtension, AgentStatus } = await import('../src/index.js');
        const { privateKeyPem } = generateKeyPair();
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            { agent_id: 'urn:agentpin:example.com:t', name: 'T', capabilities: ['read:*'], status: AgentStatus.ACTIVE },
            privateKeyPem, 'kid-1', 'https://example.com/.well-known/agent-identity.json'
        );
        card.agentpin.public_key_jwk.kid = 'kid-2';
        assert.throws(() => verifyAgentpinExtension(card), /did not verify/);
    });

    it('is domain separated and rejects the legacy extension-cleared format', async () => {
        const { generateKeyPair, buildAndSignAgentCard, verifyAgentpinExtension, agentCardSigningInput,
            canonicalizeForSigning, signData, verifySignature, CTX_AGENTCARD, AgentStatus } = await import('../src/index.js');
        const kp = generateKeyPair();
        const card = buildAndSignAgentCard(
            'https://example.com/agent',
            { agent_id: 'urn:agentpin:example.com:t', name: 'T', capabilities: ['read:*'], status: AgentStatus.ACTIVE },
            kp.privateKeyPem, 'kid-1', 'https://example.com/.well-known/agent-identity.json'
        );
        const input = agentCardSigningInput(card);
        assert.ok(input.subarray(0, CTX_AGENTCARD.length + 1).equals(Buffer.from(`${CTX_AGENTCARD}\0`)));
        const canonical = input.subarray(CTX_AGENTCARD.length + 1 + 4);
        assert.strictEqual(verifySignature(kp.publicKeyPem, canonical, card.agentpin.signature), false);

        const legacy = canonicalizeForSigning({ ...card, agentpin: undefined });
        const forged = { ...card, agentpin: { ...card.agentpin, signature: signData(kp.privateKeyPem, Buffer.from(legacy)) } };
        assert.throws(() => verifyAgentpinExtension(forged), /did not verify/);
    });
});
