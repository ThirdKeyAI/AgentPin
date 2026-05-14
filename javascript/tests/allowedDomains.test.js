/**
 * Tests for AllowedDomains helpers + a2a_endpoint discovery field (v0.3.0).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    AllowedDomains,
    EntityType,
    buildDiscoveryDocument,
} from '../src/index.js';

describe('AllowedDomains', () => {
    it('unrestricted accepts anything', () => {
        const ad = AllowedDomains.unrestricted();
        assert.ok(AllowedDomains.isUnrestricted(ad));
        assert.ok(AllowedDomains.allows(ad, 'anything.com'));
    });

    it('restricted filters', () => {
        const ad = AllowedDomains.fromDomains(['a.com', 'b.com']);
        assert.ok(!AllowedDomains.isUnrestricted(ad));
        assert.ok(AllowedDomains.allows(ad, 'a.com'));
        assert.ok(!AllowedDomains.allows(ad, 'c.com'));
    });

    it('intersects with unrestricted to return the other', () => {
        const unrestricted = AllowedDomains.unrestricted();
        const restricted = AllowedDomains.fromDomains(['a.com', 'b.com']);
        assert.deepEqual(AllowedDomains.intersect(unrestricted, restricted), restricted);
        assert.deepEqual(AllowedDomains.intersect(restricted, unrestricted), restricted);
    });

    it('intersect returns overlap', () => {
        const lhs = AllowedDomains.fromDomains(['a.com', 'b.com', 'c.com']);
        const rhs = AllowedDomains.fromDomains(['b.com', 'c.com', 'd.com']);
        assert.deepEqual(AllowedDomains.intersect(lhs, rhs), ['b.com', 'c.com']);
    });

    it('fromConstraints extracts existing list', () => {
        assert.deepEqual(
            AllowedDomains.fromConstraints({ allowed_domains: ['a.com'] }),
            ['a.com']
        );
    });

    it('fromConstraints returns unrestricted for missing fields', () => {
        assert.ok(AllowedDomains.isUnrestricted(AllowedDomains.fromConstraints({})));
        assert.ok(AllowedDomains.isUnrestricted(AllowedDomains.fromConstraints(null)));
    });
});

describe('buildDiscoveryDocument with a2a_endpoint', () => {
    it('includes a2a_endpoint when provided', () => {
        const doc = buildDiscoveryDocument(
            'example.com',
            EntityType.MAKER,
            [{ kid: 'k', kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }],
            [],
            2,
            '2026-05-01T00:00:00Z',
            { a2aEndpoint: 'https://example.com/.well-known/agent-card.json' }
        );
        assert.equal(doc.a2a_endpoint, 'https://example.com/.well-known/agent-card.json');
    });

    it('omits a2a_endpoint when not provided', () => {
        const doc = buildDiscoveryDocument(
            'example.com',
            EntityType.MAKER,
            [{ kid: 'k', kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }],
            [],
            2,
            '2026-05-01T00:00:00Z'
        );
        assert.equal(doc.a2a_endpoint, undefined);
    });
});
