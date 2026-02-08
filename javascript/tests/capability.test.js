/**
 * Tests for capability parsing and matching.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { Capability, capabilitiesSubset, capabilitiesHash } from '../src/capability.js';

describe('Capability.parse', () => {
    test('parses action and resource', () => {
        const c = new Capability('read:codebase');
        assert.strictEqual(c.action, 'read');
        assert.strictEqual(c.resource, 'codebase');
    });
});

describe('Capability.matches', () => {
    test('wildcard match', () => {
        const wild = new Capability('read:*');
        assert.ok(wild.matches(new Capability('read:codebase')));
        assert.ok(wild.matches(new Capability('read:database')));
        assert.ok(!wild.matches(new Capability('write:codebase')));
    });

    test('exact match', () => {
        const cap = new Capability('write:report');
        assert.ok(cap.matches(new Capability('write:report')));
        assert.ok(!cap.matches(new Capability('write:text')));
    });

    test('scoped match', () => {
        const cap = new Capability('read:codebase');
        assert.ok(cap.matches(new Capability('read:codebase.github.com/org/repo')));
        assert.ok(!cap.matches(new Capability('read:codebase_other')));
    });
});

describe('capabilitiesSubset', () => {
    test('valid subset', () => {
        const declared = [new Capability('read:*'), new Capability('write:report')];
        const requested = [new Capability('read:codebase'), new Capability('write:report')];
        assert.ok(capabilitiesSubset(declared, requested));
    });

    test('invalid subset', () => {
        const declared = [new Capability('read:*'), new Capability('write:report')];
        const requested = [new Capability('delete:database')];
        assert.ok(!capabilitiesSubset(declared, requested));
    });
});

describe('capabilitiesHash', () => {
    test('is deterministic', () => {
        const caps = [new Capability('write:report'), new Capability('read:codebase')];
        const h1 = capabilitiesHash(caps);
        const h2 = capabilitiesHash(caps);
        assert.strictEqual(h1, h2);
        assert.strictEqual(h1.length, 64);
    });

    test('is order-independent', () => {
        const caps1 = [new Capability('read:codebase'), new Capability('write:report')];
        const caps2 = [new Capability('write:report'), new Capability('read:codebase')];
        assert.strictEqual(capabilitiesHash(caps1), capabilitiesHash(caps2));
    });
});
