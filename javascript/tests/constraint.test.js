/**
 * Tests for constraint validation.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { parseRateLimit, domainPatternMatches, constraintsSubsetOf } from '../src/constraint.js';

describe('parseRateLimit', () => {
    test('parses rates correctly', () => {
        assert.strictEqual(parseRateLimit('100/hour'), 100);
        assert.strictEqual(parseRateLimit('10/minute'), 600);
        assert.strictEqual(parseRateLimit('1/second'), 3600);
    });

    test('returns null for invalid input', () => {
        assert.strictEqual(parseRateLimit('invalid'), null);
        assert.strictEqual(parseRateLimit('100/day'), null);
    });
});

describe('domainPatternMatches', () => {
    test('exact match', () => {
        assert.ok(domainPatternMatches('example.com', 'example.com'));
    });

    test('wildcard match', () => {
        assert.ok(domainPatternMatches('*.example.com', 'sub.example.com'));
        assert.ok(!domainPatternMatches('*.example.com', 'example.com'));
    });

    test('no match', () => {
        assert.ok(!domainPatternMatches('other.com', 'example.com'));
    });
});

describe('constraintsSubsetOf', () => {
    test('valid subset', () => {
        const disc = {
            data_classification_max: 'confidential',
            rate_limit: '100/hour',
        };
        const cred = {
            data_classification_max: 'internal',
            rate_limit: '50/hour',
        };
        assert.ok(constraintsSubsetOf(disc, cred));
    });

    test('data classification exceeds', () => {
        const disc = { data_classification_max: 'confidential' };
        const cred = { data_classification_max: 'restricted' };
        assert.ok(!constraintsSubsetOf(disc, cred));
    });

    test('null discovery allows anything', () => {
        assert.ok(constraintsSubsetOf(null, { rate_limit: '1000/hour' }));
    });

    test('null credential is fine', () => {
        assert.ok(constraintsSubsetOf({ rate_limit: '100/hour' }, null));
    });
});

describe('mergeConstraints (AP-15)', () => {
    test('omitted credential fields inherit discovery defaults; widening throws', async () => {
        const { mergeConstraints } = await import('../src/constraint.js');
        const disc = {
            allowed_domains: ['*.client-corp.com'],
            denied_domains: ['internal.client-corp.com'],
            rate_limit: '100/hour',
            data_classification_max: 'confidential',
            ip_allowlist: ['203.0.113.0/24', '198.51.100.0/24'],
            valid_hours: { start: '08:00', end: '18:00', timezone: 'UTC' },
        };
        assert.deepStrictEqual(mergeConstraints(disc, null), disc);
        const merged = mergeConstraints(disc, { rate_limit: '1/minute', data_classification_max: 'internal', denied_domains: ['staging.client-corp.com'] });
        assert.deepStrictEqual(merged.allowed_domains, disc.allowed_domains);
        assert.strictEqual(merged.rate_limit, '1/minute');
        assert.strictEqual(merged.data_classification_max, 'internal');
        assert.deepStrictEqual(merged.denied_domains, ['internal.client-corp.com', 'staging.client-corp.com']);
        assert.deepStrictEqual(merged.ip_allowlist, disc.ip_allowlist);
        assert.deepStrictEqual(merged.valid_hours, disc.valid_hours);
        for (const widen of [
            { allowed_domains: ['evil.com'] }, { rate_limit: '1000/hour' }, { rate_limit: 'unlimited/hour' },
            { data_classification_max: 'restricted' }, { ip_allowlist: ['0.0.0.0/0'] },
            { valid_hours: { start: '07:00', end: '18:00', timezone: 'UTC' } },
            { valid_hours: { start: '09:00', end: '17:00', timezone: 'America/New_York' } },
        ]) {
            assert.throws(() => mergeConstraints(disc, widen), JSON.stringify(widen));
        }
        const narrow = mergeConstraints(disc, { allowed_domains: ['api.client-corp.com'], ip_allowlist: ['203.0.113.0/24'], valid_hours: { start: '09:00', end: '17:00', timezone: 'UTC' } });
        assert.deepStrictEqual(narrow.allowed_domains, ['api.client-corp.com']);
        assert.strictEqual(narrow.rate_limit, '100/hour');
        assert.throws(() => mergeConstraints(null, { rate_limit: 'x/hour' }));
        assert.strictEqual(mergeConstraints(null, null), null);
    });

    test('parseRateLimit rejects overflow and junk', () => {
        assert.strictEqual(parseRateLimit('9007199254740991/second'), null);
        assert.strictEqual(parseRateLimit('unlimited/hour'), null);
        assert.strictEqual(parseRateLimit('-5/hour'), null);
        assert.strictEqual(parseRateLimit('+5/hour'), null);
    });
});
