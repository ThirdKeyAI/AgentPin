/**
 * Tests for the Web Bot Auth profile and its AgentPin binding (spec §18).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import * as wba from '../src/wba.js';
import { Component, httpRequest, withHeaders, sign, parseSignatures, verify, combinedField } from '../src/httpsig.js';
import { InMemoryNonceStore } from '../src/nonce.js';
import { generateKeyPair, generateKeyId } from '../src/crypto.js';
import { pemToJwk } from '../src/jwk.js';
import { Capability } from '../src/capability.js';
import { issueCredential, issueBoundCredential } from '../src/credential.js';
import { buildDiscoveryDocument, validateDiscoveryDocument } from '../src/discovery.js';
import { buildRevocationDocument } from '../src/revocation.js';
import { httpFormatAuthorizationHeader } from '../src/transport.js';
import { KeyPinStore } from '../src/pinning.js';
import { decodeJwtUnverified, encodeJwt, validateClaims } from '../src/jwt.js';

const { WbaOutcome, BindingFailure } = wba;

const RFC_ED25519_PEM = '-----BEGIN PRIVATE KEY-----\n'
    + 'MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n'
    + '-----END PRIVATE KEY-----\n';
const RFC_KEYID = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
const RFC_X = 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs';
const AGENT = 'https://signature-agent.test';
const now = () => Math.floor(Date.now() / 1000);

const rfcKey = () => wba.loadSigningKey(RFC_ED25519_PEM);
const gen = () => wba.generateSigningKey();

function signedRequest(key, opts = {}, agent = AGENT, url = 'https://origin.example/path?q=1') {
    const req = httpRequest('GET', url);
    return wba.signRequest(req, key, agent, opts).apply(req);
}

function storeWith(key, agent = AGENT) {
    const store = new wba.DirectoryKeyStore();
    store.insert(agent, wba.directoryFromKeys([key.publicKey()]));
    return store;
}

const outcome = async (req, store, opts) => (await wba.verifyRequest(req, store, opts)).outcome;

describe('wba keys and directories', () => {
    test('thumbprint matches the draft vector', () => {
        const key = rfcKey().publicKey();
        assert.strictEqual(wba.thumbprint(key), RFC_KEYID);
        const jwk = wba.jwkFromPublicKey(key);
        assert.strictEqual(jwk.x, RFC_X);
        assert.strictEqual(jwk.kid, RFC_KEYID);
        assert.ok(wba.publicKeyFromJwk(jwk).equals(key));
    });

    test('directory parse skips foreign keys and honors validity', () => {
        const key = gen();
        const jwk = { ...wba.jwkFromPublicKey(key.publicKey()), nbf: 100, exp: 200, extra: 'dropped' };
        const json = JSON.stringify({ keys: [
            { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
            { kty: 'OKP', crv: 'Ed25519', x: 'short' },
            { kty: 'OKP', crv: 'Ed25519', x: RFC_X, kid: 7 },
            { kty: 'RSA', n: 'AQAB', e: 'AQAB' },
            jwk,
        ] });
        const dir = wba.parseDirectory(json);
        assert.strictEqual(dir.keys.length, 1);
        assert.strictEqual(dir.keys[0].extra, undefined);
        const tp = wba.thumbprint(key.publicKey());
        assert.ok(wba.findKey(dir, tp, 150, 0));
        assert.strictEqual(wba.findKey(dir, tp, 50, 0), null);
        assert.strictEqual(wba.findKey(dir, tp, 250, 0), null);

        const many = JSON.stringify({ keys: new Array(wba.MAX_DIRECTORY_KEYS + 1).fill({}) });
        assert.throws(() => wba.parseDirectory(many));
        assert.throws(() => wba.parseDirectory('[]'));
        assert.throws(() => wba.parseDirectory('not json'));
    });

    test('RSA JWKs need minimal encodings and 2048-8192 bits', () => {
        const n = Buffer.alloc(256, 0xff);
        const ok = { kty: 'RSA', n: n.toString('base64url'), e: 'AQAB' };
        assert.ok(wba.jwkThumbprint(ok));
        assert.strictEqual(wba.jwkThumbprint({ ...ok, n: Buffer.concat([Buffer.alloc(1), n]).toString('base64url') }), null);
        assert.strictEqual(wba.jwkThumbprint({ ...ok, e: 'AAEAAQ' }), null);
        assert.strictEqual(wba.jwkThumbprint({ ...ok, e: 'AQABAQAB' }), null);
        assert.strictEqual(wba.jwkThumbprint({ ...ok, n: Buffer.alloc(255, 0xff).toString('base64url') }), null);
        assert.strictEqual(wba.jwkThumbprint({ ...ok, n: `${ok.n}=` }), null);
    });

    test('PEM round trip', () => {
        const key = gen();
        assert.ok(wba.loadSigningKey(wba.signingKeyToPem(key)).publicKey().equals(key.publicKey()));
        assert.throws(() => wba.loadSigningKey('not a key'));
        const ec = generateKeyPair();
        assert.throws(() => wba.loadSigningKey(ec.privateKeyPem));
    });

    test('normalizes identifiers', () => {
        assert.strictEqual(wba.normalizeSignatureAgent('HTTPS://Agent.Example:443/dir?x=1#f'), 'https://agent.example/dir');
        assert.throws(() => wba.normalizeSignatureAgent('http://agent.example'));
        assert.throws(() => wba.normalizeSignatureAgent('https://u:p@agent.example'));
        assert.throws(() => wba.normalizeSignatureAgent('/relative'));
    });
});

describe('wba draft vectors', () => {
    test('E.2.1: Dictionary Signature-Agent reproduces and verifies', async () => {
        const req = httpRequest('GET', 'https://example.com/', [['Signature-Agent', 'agent2="https://signature-agent.test"']]);
        const f = sign(req, 'sig2', ['@authority', Component.keyed('signature-agent', 'agent2')], [
            ['created', 1735689600], ['keyid', RFC_KEYID], ['alg', 'ed25519'], ['expires', 4889289600],
            ['nonce', 'n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=='],
            ['tag', wba.TAG],
        ], rfcKey());
        assert.strictEqual(f.signature,
            'sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:');
        const signed = withHeaders(req, [['Signature-Input', f.signatureInput], ['Signature', f.signature]]);
        const store = storeWith(rfcKey());
        const r = await wba.verifyRequest(signed, store, { now: 1735689700, maxValiditySecs: Number.MAX_SAFE_INTEGER });
        assert.strictEqual(r.outcome, WbaOutcome.VERIFIED, r.reason);
        assert.strictEqual(r.agent.signatureAgent, 'https://signature-agent.test/');
        assert.strictEqual(r.agent.keyid, RFC_KEYID);
        assert.strictEqual(r.agent.label, 'sig2');
        // The default 24 h ceiling rejects the vector's long window.
        assert.strictEqual(await outcome(signed, store, { now: 1735689700 }), WbaOutcome.INVALID);
    });

    test('E.2.2: legacy bare-String Signature-Agent', async () => {
        const req = httpRequest('GET', 'https://example.com/', [
            ['Signature-Agent', '"https://signature-agent.test"'],
            ['Signature-Input', 'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"'],
            ['Signature', 'sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:'],
        ]);
        const store = storeWith(rfcKey());
        assert.strictEqual(await outcome(req, store, { now: 1735689700 }), WbaOutcome.VERIFIED);
        assert.strictEqual(await outcome(req, store, { now: 1735689700, acceptLegacySignatureAgent: false }), WbaOutcome.INVALID);
    });

    test('E.2.3: signed directory response', () => {
        const body = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"${RFC_KEYID}","x":"${RFC_X}","use":"sig"}]}`;
        assert.strictEqual(wba.directoryToJson(wba.directoryFromKeys([rfcKey().publicKey()])), body);
        const headers = wba.signDirectoryResponse(body, 'signature-agent.test', [rfcKey()], 1735689600, wba.MAX_VALIDITY_SECS);
        assert.strictEqual(headers[0][1], 'sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:');
        assert.match(headers[1][1], /^binding0=\("@authority";req "content-digest"\);created=1735689600;expires=1735776000;keyid="/);

        const vector = [
            ['Content-Digest', 'sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:'],
            ['Signature-Input', `binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="${RFC_KEYID}";tag="http-message-signatures-directory"`],
            ['Signature', 'binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:'],
        ];
        assert.strictEqual(wba.verifyDirectoryResponse(body, vector, 'signature-agent.test', 1735689700, 60).keys.length, 1);
        // Re-served under another authority: the proof does not carry over.
        assert.strictEqual(wba.verifyDirectoryResponse(body, vector, 'evil.test', 1735689700, 60).keys.length, 0);
        // Swapped body: digest mismatch.
        assert.throws(() => wba.verifyDirectoryResponse('{"keys":[]}', vector, 'signature-agent.test', 1735689700, 60));
        // Our own signing round-trips; future-dated proofs are rejected.
        assert.strictEqual(wba.verifyDirectoryResponse(body, headers, 'signature-agent.test', 1735689700, 60).keys.length, 1);
        assert.strictEqual(wba.verifyDirectoryResponse(body, headers, 'signature-agent.test', 1735680000, 60).keys.length, 0);
        assert.throws(() => wba.signDirectoryResponse(body, 'signature-agent.test', [rfcKey()], 1, 0));
    });
});

describe('wba sign and verify', () => {
    test('sign and verify round trip', async () => {
        const key = gen();
        const req = signedRequest(key);
        const [sig] = parseSignatures(req.headers);
        assert.strictEqual(sig.params.tag, wba.TAG);
        assert.strictEqual(Buffer.from(sig.params.nonce, 'base64').length, 64);
        assert.match(req.headers[1][1], /^sig1=\("@authority" "signature-agent";key="sig1" "@method" "@path"\);created=\d+;keyid="[^"]+";alg="ed25519";expires=\d+;nonce="[^"]+";tag="web-bot-auth"$/);
        verify(req, sig, key.publicKey());
        const r = await wba.verifyRequest(req, storeWith(key));
        assert.strictEqual(r.outcome, WbaOutcome.VERIFIED, r.reason);
        assert.ok(r.agent.covers('@method'));
        assert.ok(r.agent.covers(new Component('@path')));
        assert.strictEqual(r.agent.expires - r.agent.created, 300);
    });

    test('outcomes distinguish invalid and unverified', async () => {
        const key = gen();
        const req = signedRequest(key);
        // Unknown directory, directory without the key, unsigned request: unverified.
        assert.strictEqual(await outcome(req, new wba.DirectoryKeyStore()), WbaOutcome.UNVERIFIED);
        assert.strictEqual(await outcome(req, storeWith(gen())), WbaOutcome.UNVERIFIED);
        assert.strictEqual(await outcome(httpRequest('GET', 'https://origin.example/'), storeWith(key)), WbaOutcome.UNVERIFIED);
        // Expired: invalid.
        assert.strictEqual(await outcome(signedRequest(key, { created: now() - 10000 }), storeWith(key)), WbaOutcome.INVALID);
        // Future-dated: invalid.
        assert.strictEqual(await outcome(signedRequest(key, { created: now() + 1000 }), storeWith(key)), WbaOutcome.INVALID);
        // Path changed after signing: invalid.
        const moved = { ...req, url: 'https://origin.example/other' };
        assert.strictEqual(await outcome(moved, storeWith(key)), WbaOutcome.INVALID);
        // Malformed Signature-Input: invalid.
        const broken = withHeaders(httpRequest('GET', 'https://origin.example/'), [['Signature-Input', 'sig1=(']]);
        assert.strictEqual(await outcome(broken, storeWith(key)), WbaOutcome.INVALID);
        // A lookup that throws is unverified; one returning the wrong key is invalid.
        assert.strictEqual(await outcome(req, { lookup: async () => { throw new Error('down'); } }), WbaOutcome.UNVERIFIED);
        assert.strictEqual(await outcome(req, { lookup: async () => gen().publicKey() }), WbaOutcome.INVALID);
        assert.strictEqual(await outcome(req, { lookup: async () => key.publicKey() }), WbaOutcome.VERIFIED);
    });

    test('required components and validity ceiling', async () => {
        const key = gen();
        const req = signedRequest(key);
        assert.strictEqual(await outcome(req, storeWith(key), { requiredComponents: ['@query'] }), WbaOutcome.INVALID);
        assert.strictEqual(await outcome(req, storeWith(key), { requiredComponents: ['@path'] }), WbaOutcome.VERIFIED);
        const long = signedRequest(key, { validitySecs: 3600 });
        assert.strictEqual(await outcome(long, storeWith(key), { maxValiditySecs: 600 }), WbaOutcome.INVALID);
    });

    test('key is bound to its directory', async () => {
        const key = gen();
        const req = signedRequest(key, {}, 'https://victim.example/.well-known/http-message-signatures-directory', 'https://origin.example/');
        // The verifier learned this key from AGENT, not from victim.example.
        assert.strictEqual(await outcome(req, storeWith(key)), WbaOutcome.UNVERIFIED);
    });

    test('rejects Signature-Agent problems', async () => {
        const key = gen();
        const store = storeWith(key);

        // Member swapped after signing: lookup happens under the new URL, so
        // with no directory there it is unverified, with the same key there invalid.
        const req = signedRequest(key);
        req.headers = req.headers.map(([n, v]) => (n === 'Signature-Agent' ? [n, 'sig1="https://other.test"'] : [n, v]));
        assert.strictEqual(await outcome(req, store), WbaOutcome.UNVERIFIED);
        const both = storeWith(key);
        both.insert('https://other.test', wba.directoryFromKeys([key.publicKey()]));
        assert.strictEqual(await outcome(req, both), WbaOutcome.INVALID);

        // Two covered members: ambiguous attribution.
        const two = httpRequest('GET', 'https://origin.example/', [['Signature-Agent', 'a="https://a.test", b="https://b.test"']]);
        const f = sign(two, 'a', ['@authority', Component.keyed('signature-agent', 'a'), Component.keyed('signature-agent', 'b')], [
            ['created', now()], ['expires', now() + 60], ['keyid', wba.thumbprint(key.publicKey())], ['tag', wba.TAG],
        ], key);
        const twoSigned = withHeaders(two, [['Signature-Input', f.signatureInput], ['Signature', f.signature]]);
        assert.strictEqual(await outcome(twoSigned, store), WbaOutcome.INVALID);

        const plain = httpRequest('GET', 'https://origin.example/');
        // Non-https Signature-Agent and validity above 24 h are refused at signing time.
        assert.throws(() => wba.signRequest(plain, key, 'http://insecure.test'));
        assert.throws(() => wba.signRequest(plain, key, AGENT, { validitySecs: wba.MAX_VALIDITY_SECS + 1 }));
        // Label collision with an existing Signature-Agent member.
        const dup = withHeaders(plain, [['Signature-Agent', 'sig1="https://a.test"']]);
        assert.throws(() => wba.signRequest(dup, key, AGENT));
        // A different label alongside an existing member is fine.
        const other = wba.signRequest(dup, key, AGENT, { label: 'sig2' }).apply(dup);
        assert.strictEqual(await outcome(other, store), WbaOutcome.VERIFIED);
    });

    test('member with parameters or a non-String value is invalid', async () => {
        const key = gen();
        for (const field of ['sig1="https://signature-agent.test";type=jwks_uri', 'sig1=agent', 'sig1=("https://signature-agent.test")']) {
            const base = httpRequest('GET', 'https://origin.example/', [['Signature-Agent', field]]);
            const f = sign(base, 'sig1', ['@authority', Component.keyed('signature-agent', 'sig1')], [
                ['created', now()], ['expires', now() + 60], ['keyid', wba.thumbprint(key.publicKey())], ['tag', wba.TAG],
            ], key);
            const s = withHeaders(base, [['Signature-Input', f.signatureInput], ['Signature', f.signature]]);
            assert.strictEqual(await outcome(s, storeWith(key)), WbaOutcome.INVALID, field);
        }
    });

    test('legacy signing round trip', async () => {
        const key = gen();
        const req = signedRequest(key, { legacySignatureAgent: true });
        assert.ok(combinedField(req.headers, 'signature-agent').startsWith('"'));
        assert.strictEqual(await outcome(req, storeWith(key)), WbaOutcome.VERIFIED);
        assert.strictEqual(await outcome(req, storeWith(key), { acceptLegacySignatureAgent: false }), WbaOutcome.INVALID);
        const existing = httpRequest('GET', 'https://origin.example/', [['Signature-Agent', 'a="https://a.test"']]);
        assert.throws(() => wba.signRequest(existing, key, AGENT, { legacySignatureAgent: true }));
    });

    test('nonce store rejects replays', async () => {
        const key = gen();
        const store = storeWith(key);
        const nonceStore = new InMemoryNonceStore();
        const opts = { nonceStore };
        const req = signedRequest(key);
        assert.strictEqual(await outcome(req, store, opts), WbaOutcome.VERIFIED);
        assert.deepStrictEqual(await wba.verifyRequest(req, store, opts), { outcome: WbaOutcome.INVALID, reason: 'nonce replayed' });
        // A fresh signature is fine; one without a nonce is not.
        assert.strictEqual(await outcome(signedRequest(key), store, opts), WbaOutcome.VERIFIED);
        assert.strictEqual(await outcome(signedRequest(key, { nonce: false }), store, opts), WbaOutcome.INVALID);
        // Forged signatures never reach the store.
        const before = nonceStore._entries.size;
        const forged = { ...signedRequest(key), url: 'https://origin.example/elsewhere' };
        assert.deepStrictEqual(await wba.verifyRequest(forged, store, opts),
            { outcome: WbaOutcome.INVALID, reason: 'signature verification failed' });
        assert.strictEqual(nonceStore._entries.size, before);
        // Keys are recorded per keyid with a TTL past expiry plus skew.
        let seen;
        await wba.verifyRequest(signedRequest(key), store, {
            nonceStore: { checkAndRecord: async (k, ttlMs) => { seen = { k, ttlMs }; return true; } },
        });
        assert.ok(seen.k.startsWith(`${wba.thumbprint(key.publicKey())} `));
        assert.ok(seen.ttlMs > 300000 && seen.ttlMs <= 361000);
        // A failing store makes the request invalid.
        const failing = { nonceStore: { checkAndRecord: () => { throw new Error('boom'); } } };
        assert.strictEqual(await outcome(signedRequest(key), store, failing), WbaOutcome.INVALID);
    });
});

// ---------------------------------------------------------------------------
// AgentPin binding
// ---------------------------------------------------------------------------

const AGENT_ID = 'urn:agentpin:example.com:crawler';

function setup(signatureAgents) {
    const kp = generateKeyPair();
    const kid = generateKeyId(kp.publicKeyPem);
    const discovery = buildDiscoveryDocument('example.com', 'maker', [pemToJwk(kp.publicKeyPem, kid)], [{
        agent_id: AGENT_ID,
        name: 'Crawler',
        capabilities: ['read:*'],
        status: 'active',
    }], 0, '2026-11-01T00:00:00Z', signatureAgents ? { signatureAgents } : {});
    validateDiscoveryDocument(discovery, 'example.com');
    return { kp, kid, discovery };
}

const resolver = (s) => ({
    resolveDiscovery: () => s.discovery,
    resolveRevocation: () => buildRevocationDocument('example.com'),
});

function credential(s, jkt) {
    const caps = [new Capability('read:pages')];
    return jkt === undefined
        ? issueCredential(s.kp.privateKeyPem, s.kid, 'example.com', AGENT_ID, null, caps, null, null, 600)
        : issueBoundCredential(s.kp.privateKeyPem, s.kid, 'example.com', AGENT_ID, null, caps, null, null, 600, jkt);
}

function boundRequest(wbaKey, signatureAgent, jwt, coverAuth) {
    const req = httpRequest('GET', 'https://shop.example/products', [['Authorization', httpFormatAuthorizationHeader(jwt)]]);
    const components = coverAuth ? ['@method', '@path', 'authorization'] : ['@method', '@path'];
    return wba.signRequest(req, wbaKey, signatureAgent, { components }).apply(req);
}

const verifyBound = (s, req, keys) => wba.verifyBoundRequest(req, keys, resolver(s), new KeyPinStore(), null, {}, {});

describe('wba AgentPin binding', () => {
    test('bound request verifies with the well-known directory', async () => {
        const s = setup();
        const key = gen();
        const url = wba.wellKnownDirectory('example.com');
        const req = boundRequest(key, url, credential(s, wba.thumbprint(key.publicKey())), true);
        const bound = await verifyBound(s, req, storeWith(key, url));
        assert.ok(bound.ok, bound.reason);
        assert.strictEqual(bound.agent.signatureAgent, url);
        assert.strictEqual(bound.credential.agent_id, AGENT_ID);
        assert.strictEqual(wba.requestCredential(req).split('.').length, 3);
    });

    test('discovery can vouch for a hosted directory', async () => {
        const hosted = 'https://bots.provider.example/keys/example-com';
        const s = setup([hosted]);
        const key = gen();
        const jwt = credential(s, wba.thumbprint(key.publicKey()));
        assert.ok((await verifyBound(s, boundRequest(key, hosted, jwt, true), storeWith(key, hosted))).ok);
        // Listing a hosted directory replaces the well-known default.
        const wk = wba.wellKnownDirectory('example.com');
        const r = await verifyBound(s, boundRequest(key, wk, jwt, true), storeWith(key, wk));
        assert.strictEqual(r.failure, BindingFailure.BINDING);
    });

    test('binding failures', async () => {
        const s = setup();
        const key = gen();
        const url = wba.wellKnownDirectory('example.com');
        const store = storeWith(key, url);
        const tp = wba.thumbprint(key.publicKey());

        // Credential without cnf.
        assert.strictEqual((await verifyBound(s, boundRequest(key, url, credential(s), true), store)).failure, BindingFailure.BINDING);
        // cnf names a different key.
        const other = wba.thumbprint(gen().publicKey());
        assert.strictEqual((await verifyBound(s, boundRequest(key, url, credential(s, other), true), store)).failure, BindingFailure.BINDING);
        // Signature does not cover the Authorization field.
        assert.strictEqual((await verifyBound(s, boundRequest(key, url, credential(s, tp), false), store)).failure, BindingFailure.BINDING);
        // Signature-Agent on a domain the issuer does not vouch for.
        const foreign = 'https://attacker.example/.well-known/http-message-signatures-directory';
        assert.strictEqual((await verifyBound(s, boundRequest(key, foreign, credential(s, tp), true), storeWith(key, foreign))).failure,
            BindingFailure.BINDING);
        // Credential swapped after signing: the covered Authorization changed.
        const req = boundRequest(key, url, credential(s, tp), true);
        const swapped = httpFormatAuthorizationHeader(credential(s, tp));
        req.headers = req.headers.map(([n, v]) => (n === 'Authorization' ? [n, swapped] : [n, v]));
        const r = await verifyBound(s, req, store);
        assert.strictEqual(r.failure, BindingFailure.WBA);
        assert.strictEqual(r.outcome.outcome, WbaOutcome.INVALID);
        // Forged credential: signed by a key the issuer does not publish.
        const rogue = setup();
        const forged = await verifyBound(s, boundRequest(key, url, credential(rogue, tp), true), store);
        assert.strictEqual(forged.failure, BindingFailure.CREDENTIAL);
        assert.strictEqual(forged.credential.valid, false);
        // Resolver failure is a credential failure.
        const down = await wba.verifyBoundRequest(boundRequest(key, url, credential(s, tp), true), store,
            { resolveDiscovery: async () => { throw new Error('offline'); } }, new KeyPinStore(), null);
        assert.strictEqual(down.failure, BindingFailure.CREDENTIAL);
    });

    test('checkBinding requires a matching verification result and issuer document', async () => {
        const s = setup();
        const key = gen();
        const url = wba.wellKnownDirectory('example.com');
        const req = boundRequest(key, url, credential(s, wba.thumbprint(key.publicKey())), true);
        const bound = await verifyBound(s, req, storeWith(key, url));
        assert.ok(bound.ok);
        wba.checkBinding(bound.agent, req, bound.credential, s.discovery);
        assert.throws(() => wba.checkBinding(bound.agent, req, { ...bound.credential, valid: false }, s.discovery));
        assert.throws(() => wba.checkBinding(bound.agent, req, { ...bound.credential, agent_id: 'urn:agentpin:example.com:other' }, s.discovery));
        assert.throws(() => wba.checkBinding(bound.agent, req, bound.credential, { ...s.discovery, entity: 'other.example' }));
    });

    test('invalid discovery web_bot_auth is rejected', () => {
        const s = setup();
        for (const agents of [[], ['http://insecure.example/dir'], ['https://u:p@x.example'], [42], new Array(17).fill('https://a.example')]) {
            assert.throws(() => validateDiscoveryDocument({ ...s.discovery, web_bot_auth: { signature_agents: agents } }, 'example.com'),
                undefined, JSON.stringify(agents));
        }
        assert.throws(() => validateDiscoveryDocument({ ...s.discovery, web_bot_auth: {} }, 'example.com'));
        validateDiscoveryDocument({ ...s.discovery, web_bot_auth: { signature_agents: ['https://hosted.example/k'] } }, 'example.com');
    });

    test('malformed cnf is rejected at issuance and on decode', () => {
        const s = setup();
        const caps = [new Capability('read:pages')];
        assert.throws(() => issueBoundCredential(s.kp.privateKeyPem, s.kid, 'example.com', AGENT_ID, null, caps, null, null, 600,
            'not-a-thumbprint'), /cnf\.jkt/);
        const tp = wba.thumbprint(gen().publicKey());
        const jwt = issueBoundCredential(s.kp.privateKeyPem, s.kid, 'example.com', AGENT_ID, null, caps, null, null, 600, tp);
        const { header, payload } = decodeJwtUnverified(jwt);
        assert.deepStrictEqual(payload.cnf, { jkt: tp });
        validateClaims({ ...payload, cnf: null });
        for (const cnf of [{}, { jkt: 7 }, { jkt: `${tp}A` }, { jkt: `${tp.slice(0, 42)}+` }, 'x', { jkt: `${tp.slice(0, 42)}B` }]) {
            assert.throws(() => validateClaims({ ...payload, cnf }), undefined, JSON.stringify(cnf));
        }
        const tampered = encodeJwt(header, { ...payload, cnf: { jkt: 'short' } }, s.kp.privateKeyPem);
        assert.throws(() => decodeJwtUnverified(tampered));
    });
});
