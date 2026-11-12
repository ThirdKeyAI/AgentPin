/**
 * Shared Web Bot Auth vectors (testdata/web_bot_auth/vectors.json at the
 * repository root), also run by the Rust, Python and Go SDKs.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import * as httpsig from '../src/httpsig.js';
import * as wba from '../src/wba.js';

const vectors = JSON.parse(readFileSync(new URL('../../testdata/web_bot_auth/vectors.json', import.meta.url), 'utf8'));
const NOW = 1735689700;

function request(v, withSig) {
    const headers = v.headers.filter(([name]) => withSig || (!name.startsWith('Signature-I') && name !== 'Signature'));
    return httpsig.httpRequest(v.method, v.url, headers);
}

const key = (name) => wba.loadSigningKey(vectors.keys[name].private_pem);

describe('web bot auth vectors', () => {
    test('keyids match PEM and JWK', () => {
        for (const name of ['ed25519', 'rsa']) {
            const k = vectors.keys[name];
            assert.strictEqual(wba.thumbprint(key(name).publicKey()), k.keyid, name);
            assert.strictEqual(wba.jwkThumbprint(k.jwk), k.keyid, name);
        }
    });

    test('request vectors verify and reproduce', async () => {
        const opts = { now: NOW, maxValiditySecs: Number.MAX_SAFE_INTEGER };
        assert.strictEqual(vectors.requests.length, 4);
        for (const t of vectors.requests) {
            const k = key(t.key);
            const store = new wba.DirectoryKeyStore();
            store.insert(t.signature_agent_url, wba.directoryFromKeys([k.publicKey()]));
            const req = request(t, true);
            const r = await wba.verifyRequest(req, store, opts);
            assert.strictEqual(r.outcome, wba.WbaOutcome.VERIFIED, `${t.name}: ${r.reason}`);

            // Re-sign over the same base: Ed25519 reproduces the signature;
            // RSA-PSS is randomized, so check that ours verifies.
            const [parsed] = httpsig.parseSignatures(req.headers);
            const p = parsed.params;
            const params = [
                ['created', p.created], ['keyid', p.keyid], ['alg', p.alg],
                ['expires', p.expires], ['nonce', p.nonce], ['tag', p.tag],
            ];
            const unsigned = request(t, false);
            const f = httpsig.sign(unsigned, parsed.label, parsed.components, params, k);
            assert.strictEqual(f.signatureInput, t.headers[1][1], t.name);
            if (t.reproducible) assert.strictEqual(f.signature, t.headers[2][1], t.name);
            const ours = httpsig.withHeaders(unsigned, [['Signature-Input', f.signatureInput], ['Signature', f.signature]]);
            assert.strictEqual((await wba.verifyRequest(ours, store, opts)).outcome, wba.WbaOutcome.VERIFIED, t.name);
        }
    });

    test('directory vector proves one key', () => {
        const d = vectors.directory;
        const proven = wba.verifyDirectoryResponse(d.body, d.headers, d.authority, NOW, 60);
        assert.strictEqual(proven.keys.length, 1);
    });

    test('RFC 9421 B.2.6, @query-param and Content-Digest', () => {
        const b = vectors.rfc9421_b26;
        const signed = httpsig.httpRequest(b.method, b.url, [
            ...b.headers, ['Signature-Input', b.signature_input], ['Signature', b.signature],
        ]);
        const [parsed] = httpsig.parseSignatures(signed.headers);
        httpsig.verify(signed, parsed, key('ed25519').publicKey());

        const q = vectors.query_param;
        const qreq = httpsig.httpRequest('GET', q.url);
        for (const [name, encoded, value] of q.values) {
            const c = httpsig.Component.queryParam(name);
            assert.strictEqual(c.queryName, encoded);
            const f = httpsig.sign(qreq, 'q', [c], [], key('ed25519'));
            const s = httpsig.withHeaders(qreq, [['Signature-Input', f.signatureInput], ['Signature', f.signature]]);
            const base = httpsig.parseSignatures(s.headers)[0].signatureBase(s);
            assert.ok(base.startsWith(`"@query-param";name="${encoded}": ${value}\n`), base);
        }
        for (const name of q.errors) {
            assert.throws(() => httpsig.sign(qreq, 'q', [httpsig.Component.queryParam(name)], [], key('ed25519')));
        }

        const d = vectors.content_digest;
        assert.strictEqual(httpsig.contentDigest(d.body), d.value);
    });

    test('RSA signing round trip and alg mismatch', async () => {
        const k = key('rsa');
        assert.strictEqual(k.alg, 'rsa-pss-sha512');
        const agent = 'https://agent.test/.well-known/http-message-signatures-directory';
        const req = wba.signRequest(httpsig.httpRequest('GET', 'https://origin.test/x'), k, agent)
            .apply(httpsig.httpRequest('GET', 'https://origin.test/x'));
        const store = new wba.DirectoryKeyStore();
        store.insert(agent, wba.directoryFromKeys([k.publicKey()]));
        assert.strictEqual((await wba.verifyRequest(req, store)).outcome, wba.WbaOutcome.VERIFIED);
        const bad = { ...req, headers: req.headers.map(([n, v]) => [n, v.replace('rsa-pss-sha512', 'ed25519')]) };
        assert.strictEqual((await wba.verifyRequest(bad, store)).outcome, wba.WbaOutcome.INVALID);
    });
});
