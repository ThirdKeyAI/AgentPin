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
