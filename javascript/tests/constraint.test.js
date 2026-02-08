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
