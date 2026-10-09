/**
 * Property-based fuzzing of parsers that consume untrusted input.
 * Each property asserts the parser fails only with a controlled error.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import fc from 'fast-check';
import { decodeJwtUnverified, base64urlEncode } from '../src/jwt.js';
import { parseTxtRecord } from '../src/dns.js';
import { jwkToPem, jwkThumbprint } from '../src/jwk.js';
import { validateDiscoveryDocument } from '../src/discovery.js';
import { agentCardSigningInput, verifyAgentpinExtension } from '../src/a2a.js';
import { verifyCredentialOffline } from '../src/verification.js';
import { KeyPinStore } from '../src/pinning.js';

const RUNS = { numRuns: 500 };

/** Errors a parser may raise on hostile input; anything else is a crash. */
function controlled(fn) {
    try {
        fn();
    } catch (e) {
        assert.ok(!(e instanceof TypeError) && !(e instanceof RangeError), `uncontrolled ${e?.name}: ${e?.message}`);
    }
}

const jwtLike = fc.tuple(fc.json(), fc.json(), fc.string()).map(
    ([h, p, s]) => `${base64urlEncode(Buffer.from(h))}.${base64urlEncode(Buffer.from(p))}.${s}`
);

describe('fuzz', () => {
    test('decodeJwtUnverified', () => {
        fc.assert(fc.property(fc.oneof(fc.string(), jwtLike), (s) => controlled(() => decodeJwtUnverified(s))), RUNS);
    });

    test('verifyCredentialOffline never throws', () => {
        const disc = { agentpin_version: '0.1', entity: 'example.com', public_keys: [], agents: [] };
        fc.assert(fc.property(fc.oneof(fc.string(), jwtLike), (s) => {
            const r = verifyCredentialOffline(s, disc, null, new KeyPinStore(), null, {});
            assert.strictEqual(r.valid, false);
        }), RUNS);
    });

    test('parseTxtRecord', () => {
        fc.assert(fc.property(fc.string(), (s) => controlled(() => parseTxtRecord(s))), RUNS);
    });

    test('jwkToPem / jwkThumbprint', () => {
        const jwk = fc.record({ kid: fc.string(), kty: fc.constantFrom('EC', 'RSA'), crv: fc.constantFrom('P-256', 'P-384'),
            x: fc.string(), y: fc.string(), use: fc.string() });
        fc.assert(fc.property(jwk, (j) => {
            controlled(() => jwkToPem(j));
            controlled(() => jwkThumbprint(j));
        }), RUNS);
    });

    test('validateDiscoveryDocument', () => {
        fc.assert(fc.property(fc.jsonValue(), (v) => controlled(() => validateDiscoveryDocument(v, 'example.com'))), RUNS);
    });

    test('AgentCard canonicalization is stable across a JSON round trip', () => {
        const card = fc.record({
            name: fc.string(), url: fc.string(), capabilities: fc.dictionary(fc.string(), fc.jsonValue()),
            skills: fc.array(fc.dictionary(fc.string(), fc.jsonValue())),
            extra: fc.jsonValue(),
        });
        fc.assert(fc.property(card, (c) => {
            let first;
            try {
                first = agentCardSigningInput(c);
            } catch {
                return;
            }
            const again = agentCardSigningInput(JSON.parse(JSON.stringify(c)));
            assert.deepStrictEqual(Buffer.from(again), Buffer.from(first));
            controlled(() => verifyAgentpinExtension(c));
        }), RUNS);
    });
});
