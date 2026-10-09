/**
 * Tests for domain normalization (AP-3, AP-10, AP-12).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { normalizeDomain, validateHttpsUrlForDomain } from '../src/domain.js';

describe('normalizeDomain', () => {
    test('canonicalizes case, trailing dot and IDN', () => {
        assert.strictEqual(normalizeDomain('example.com'), 'example.com');
        assert.strictEqual(normalizeDomain('EXAMPLE.COM'), 'example.com');
        assert.strictEqual(normalizeDomain('Example.Com.'), 'example.com');
        assert.strictEqual(normalizeDomain('bücher.example'), 'xn--bcher-kva.example');
        assert.strictEqual(normalizeDomain('XN--BCHER-KVA.example'), 'xn--bcher-kva.example');
        assert.strictEqual(normalizeDomain('localhost'), 'localhost');
        assert.strictEqual(normalizeDomain('a-b.c1.example'), 'a-b.c1.example');
    });

    test('rejects anything that is not a bare hostname', () => {
        const bad = [
            '', '.', '..', '../../tmp/x', '/srv/uploads/x', 'example.com/path',
            'example.com\\evil', 'https://example.com', 'user@example.com',
            'example.com:8443', '127.0.0.1', '127.0.0.1:8443', '[::1]', '::1',
            'example.com?x=1', 'example.com#frag', ' example.com', 'example.com ',
            'exa mple.com', 'example..com', '.example.com', '-example.com',
            'example-.com', 'exam_ple.com', 'example.com..', 'a%2eb', '\u0000example.com',
            `${'a'.repeat(64)}.example`, `${'abcdefghij.'.repeat(26)}example`, null, 42,
        ];
        for (const input of bad) {
            assert.throws(() => normalizeDomain(input), `expected rejection of ${JSON.stringify(input)}`);
        }
    });
});

describe('validateHttpsUrlForDomain', () => {
    test('accepts https same-host URLs', () => {
        assert.doesNotThrow(() => validateHttpsUrlForDomain('https://example.com/.well-known/agent-identity-revocations.json', 'example.com'));
        assert.doesNotThrow(() => validateHttpsUrlForDomain('https://EXAMPLE.com/x', 'example.com.'));
    });

    test('rejects other schemes, hosts, ports, userinfo, IPs', () => {
        const bad = [
            'http://example.com/x', 'https://other.com/x', 'https://example.com:8443/x',
            'https://user@example.com/x', 'https://169.254.169.254/latest/meta-data/',
            'https://[::1]/x', 'https://example.com/x#frag', 'ftp://example.com/x', 'not a url',
        ];
        for (const input of bad) {
            assert.throws(() => validateHttpsUrlForDomain(input, 'example.com'), `expected rejection of ${input}`);
        }
    });
});
