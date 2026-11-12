/**
 * Tests for RFC 9421 HTTP Message Signatures and the structured-field codec.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
    Component, PrivateKey, PublicKey, ALG_RSA_PSS_SHA512,
    httpRequest, withHeaders, combinedField, parseSignatures, sign, verify,
    contentDigest, contentDigestMatches, parseDictionary, serializeDictionary,
} from '../src/httpsig.js';
import { parseItem, parseList, serializeItem, serializeList } from '../src/sf.js';
import { ErrorCode } from '../src/types.js';

/** RFC 9421 Appendix B.1.4 test key (test-key-ed25519). */
const RFC_ED25519_PEM = '-----BEGIN PRIVATE KEY-----\n'
    + 'MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n'
    + '-----END PRIVATE KEY-----\n';
const rfcKey = () => PrivateKey.fromPem(RFC_ED25519_PEM);

function signed(req, f) {
    return withHeaders(req, [['Signature-Input', f.signatureInput], ['Signature', f.signature]]);
}

function value(req, c) {
    const f = sign(req, 's', [c], [], rfcKey());
    const s = signed(req, f);
    const base = parseSignatures(s.headers)[0].signatureBase(s);
    return base.slice(base.indexOf(': ') + 2, base.indexOf('\n'));
}

describe('structured fields', () => {
    test('dictionary round trips byte for byte', () => {
        for (const v of [
            'a=1, b=?0, c, d;x=1.5;y="q\\"\\\\", e=(1 2 tok);p=:AQID:',
            'sig1=("@authority" "signature-agent";key="sig1");created=1;keyid="k";tag="web-bot-auth"',
            'n=-12.25, d=@1659578233, s=%"caf%c3%a9"',
            'k=1.0, z=0.0, m=-0.001',
        ]) {
            assert.strictEqual(serializeDictionary(parseDictionary(v)), v);
        }
    });

    test('whitespace, duplicates and booleans follow RFC 8941', () => {
        assert.strictEqual(serializeDictionary(parseDictionary('  a=1 ,\tb=2  ')), 'a=1, b=2');
        // Duplicate keys keep the first position and take the last value.
        assert.strictEqual(serializeDictionary(parseDictionary('a=1, b=2, a=3')), 'a=3, b=2');
        assert.strictEqual(serializeDictionary(parseDictionary('a=?1;x')), 'a;x');
        assert.strictEqual(serializeItem(parseItem('"x";a;b=?0')), '"x";a;b=?0');
        assert.strictEqual(serializeList(parseList('a, (b c), ?1')), 'a, (b c), ?1');
        assert.strictEqual(parseDictionary('').size, 0);
    });

    test('rejects malformed input', () => {
        for (const v of [
            'A=1', 'a=1,', 'a=1 b=2', 'a="unterminated', 'a="\\x"', 'a=1234567890123456',
            'a=1.2345', 'a=1.', 'a=:AQ=:', 'a=:A:', 'a=?2', 'a=(1  2', 'a=%"%ZZ"', 'a=%"%ff"',
            'a="é"', '\ta=1', 'a=@1.5', 'a=1234567890123.0',
        ]) {
            assert.throws(() => parseDictionary(v), undefined, v);
        }
    });

    test('byte sequences accept unpadded base64', () => {
        assert.deepStrictEqual([...parseItem(':AQID:').value.value], [1, 2, 3]);
        assert.deepStrictEqual([...parseItem(':AQI:').value.value], [1, 2]);
        assert.deepStrictEqual([...parseItem(':AQI=:').value.value], [1, 2]);
    });
});

describe('httpsig', () => {
    test('RFC 9421 B.2.6 Ed25519 vector', () => {
        const req = httpRequest('POST', 'https://example.com/foo?param=Value&Pet=dog', [
            ['Host', 'example.com'],
            ['Date', 'Tue, 20 Apr 2021 02:07:55 GMT'],
            ['Content-Type', 'application/json'],
            ['Content-Length', '18'],
        ]);
        const f = sign(req, 'sig-b26',
            ['date', '@method', '@path', '@authority', 'content-type', 'content-length'],
            [['created', 1618884473], ['keyid', 'test-key-ed25519']], rfcKey());
        assert.strictEqual(f.signature,
            'sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:');
        assert.strictEqual(f.signatureInput,
            'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"');
        const s = signed(req, f);
        const parsed = parseSignatures(s.headers);
        assert.strictEqual(parsed.length, 1);
        verify(s, parsed[0], rfcKey().publicKey());
    });

    test('tampered component fails', () => {
        const req = httpRequest('GET', 'https://example.com/a');
        const f = sign(req, 's', ['@authority', '@path'], [['created', 1]], rfcKey());
        const moved = signed(httpRequest('GET', 'https://example.com/b'), f);
        const parsed = parseSignatures(moved.headers);
        assert.throws(() => verify(moved, parsed[0], rfcKey().publicKey()),
            (e) => e.code === ErrorCode.SIGNATURE_INVALID);
    });

    test('derived components', () => {
        const req = httpRequest('GET', 'https://Example.COM:8443/p/q?x=1');
        assert.strictEqual(value(req, '@authority'), 'example.com:8443');
        assert.strictEqual(value(req, '@scheme'), 'https');
        assert.strictEqual(value(req, '@path'), '/p/q');
        assert.strictEqual(value(req, '@query'), '?x=1');
        assert.strictEqual(value(req, '@request-target'), '/p/q?x=1');
        assert.strictEqual(value(req, '@target-uri'), 'https://example.com:8443/p/q?x=1');
        const plain = httpRequest('GET', 'https://example.com');
        assert.strictEqual(value(plain, '@authority'), 'example.com');
        assert.strictEqual(value(plain, '@path'), '/');
        assert.strictEqual(value(plain, '@query'), '?');
        assert.strictEqual(value(httpRequest('GET', 'https://example.com/?'), '@request-target'), '/?');
        assert.throws(() => sign(plain, 's', ['@status'], [], rfcKey()));
    });

    test('combined fields and dictionary members', () => {
        const req = httpRequest('GET', 'https://example.com', [
            ['X-A', ' one '], ['x-a', 'two'],
            ['Sig-Agent', 'a="https://a.test", b="https://b.test"'],
        ]);
        assert.strictEqual(combinedField(req.headers, 'x-a'), 'one, two');
        assert.strictEqual(value(req, 'x-a'), 'one, two');
        assert.strictEqual(value(req, Component.keyed('sig-agent', 'b')), '"https://b.test"');
        assert.throws(() => sign(req, 's', [Component.keyed('sig-agent', 'c')], [], rfcKey()));
        assert.throws(() => sign(req, 's', ['missing'], [], rfcKey()));
        assert.throws(() => sign(req, 's', ['x-a', 'x-a'], [], rfcKey()));
    });

    test('response components and req parameter', () => {
        const request = httpRequest('GET', 'https://dir.example/x');
        const msg = { status: 200, headers: [['Content-Digest', contentDigest('{}')]], request };
        const f = sign(msg, 'r', [Component.ofRequest('@authority'), '@status', 'content-digest'], [], rfcKey());
        assert.match(f.signatureInput, /^r=\("@authority";req "@status" "content-digest"\)$/);
        const s = { ...msg, headers: [...msg.headers, ['Signature-Input', f.signatureInput], ['Signature', f.signature]] };
        verify(s, parseSignatures(s.headers)[0], rfcKey().publicKey());
        assert.throws(() => sign({ ...msg, request: undefined }, 'r', [Component.ofRequest('@authority')], [], rfcKey()));
    });

    test('rejects bad identifiers', () => {
        for (const input of [
            's=("Date");created=1',
            's=("date";sf);created=1',
            's=("date";bs);created=1',
            's=("date";tr);created=1',
            's=("@signature-params");created=1',
            's=("date" "date");created=1',
            's=("@method";key="x");created=1',
            's=("date";req=?0);created=1',
            's=("@query-param");created=1',
            's=("@method";name="x");created=1',
            's=date;created=1',
            's=(date);created=1',
            's=("date");created="1"',
        ]) {
            assert.throws(() => parseSignatures([['Signature-Input', input], ['Signature', 's=:AAAA:']]), undefined, input);
        }
        assert.throws(() => parseSignatures([['Signature-Input', 's=("date");created=1']]));
        assert.throws(() => parseSignatures([['Signature-Input', 's=("date")'], ['Signature', 's="x"']]));
    });

    test('content digest round trip', () => {
        const body = '{"hello": "world"}\n';
        assert.strictEqual(contentDigest(body), 'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:');
        const h = [['Content-Digest', contentDigest(body)]];
        assert.ok(contentDigestMatches(h, body));
        assert.ok(contentDigestMatches(h, Buffer.from(body)));
        assert.ok(!contentDigestMatches(h, 'other'));
        assert.ok(!contentDigestMatches([], body));
        assert.ok(!contentDigestMatches([['Content-Digest', 'garbage(']], body));
    });

    test('query-param values (RFC 9421 §2.2.8)', () => {
        const req = httpRequest('GET', 'https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value'
            + '&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&dup=1&dup=2&qux=');
        assert.strictEqual(value(req, Component.queryParam('var')), 'this%20is%20a%20big%0Amultiline%20value');
        assert.strictEqual(value(req, Component.queryParam('bar')), 'with%20plus%20whitespace');
        assert.strictEqual(value(req, Component.queryParam('façade": ')), 'something');
        assert.strictEqual(value(req, Component.queryParam('qux')), '');
        assert.throws(() => sign(req, 's', [Component.queryParam('dup')], [], rfcKey()));
        assert.throws(() => sign(req, 's', [Component.queryParam('missing')], [], rfcKey()));
        assert.strictEqual(Component.queryParam('façade": ').identifier(), '"@query-param";name="fa%C3%A7ade%22%3A%20"');

        const f = sign(req, 's', [Component.queryParam('var'), '@authority'], [['created', 1]], rfcKey());
        const s = signed(req, f);
        const parsed = parseSignatures(s.headers);
        assert.ok(parsed[0].covers(Component.queryParam('var')));
        verify(s, parsed[0], rfcKey().publicKey());
    });

    test('alg parameter must match key', () => {
        const req = httpRequest('GET', 'https://example.com/');
        const f = sign(req, 's', ['@authority'], [['alg', ALG_RSA_PSS_SHA512]], rfcKey());
        const s = signed(req, f);
        assert.throws(() => verify(s, parseSignatures(s.headers)[0], rfcKey().publicKey()));
    });

    test('signature parameters are validated when signing', () => {
        const req = httpRequest('GET', 'https://example.com/');
        assert.throws(() => sign(req, 's', ['@authority'], [['created', 1], ['created', 2]], rfcKey()));
        assert.throws(() => sign(req, 's', ['@authority'], [['bogus', 'x']], rfcKey()));
        assert.throws(() => sign(req, 's', ['@authority'], [['keyid', 'é']], rfcKey()));
        assert.throws(() => sign(req, 'Bad', ['@authority'], [], rfcKey()));
    });

    test('Ed25519 verification is strict about small-order keys', () => {
        assert.throws(() => PublicKey.ed25519(Buffer.alloc(31)));
        // The identity point is a valid encoding but of small order.
        const identity = Buffer.alloc(32);
        identity[0] = 1;
        const weak = PublicKey.ed25519(identity);
        assert.throws(() => weak.verify(Buffer.from('m'), Buffer.alloc(64)), (e) => e.code === ErrorCode.SIGNATURE_INVALID);
        // A y coordinate with no matching x is not a point.
        const notPoint = Buffer.alloc(32);
        notPoint[0] = 2;
        assert.throws(() => PublicKey.ed25519(notPoint));
    });

    test('private key loading', () => {
        assert.throws(() => PrivateKey.fromPem('not a key'), (e) => e.code === ErrorCode.INVALID_KEY_FORMAT);
        const k = PrivateKey.generateEd25519();
        assert.ok(PrivateKey.fromPem(k.toPem()).publicKey().equals(k.publicKey()));
    });
});
