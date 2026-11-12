/**
 * Tests for Web Bot Auth key directory fetching (SSRF limits, caching) and
 * the non-public address guard.
 */

import { test, describe, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { CachingDirectoryResolver, fetchDirectory, maxAge } from '../src/resolverWba.js';
import { fetchBounded, isNonPublic } from '../src/net.js';
import * as wba from '../src/wba.js';
import { httpRequest, contentDigest } from '../src/httpsig.js';

const servers = [];
after(() => servers.forEach((s) => s.close()));

/**
 * Local HTTP server; `respond(url)` returns `{ status, headers, body }`
 * built from the directory URL. Counts requests.
 */
async function serve(respond) {
    const hits = { count: 0 };
    let response;
    const server = http.createServer((req, res) => {
        hits.count++;
        res.writeHead(response.status, response.headers);
        res.end(response.body);
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    servers.push(server);
    const url = `http://127.0.0.1:${server.address().port}${wba.DIRECTORY_PATH}`;
    response = respond(url);
    return { url, hits };
}

const local = { publicOnly: false, requireHttps: false };

describe('isNonPublic', () => {
    test('classifies addresses', () => {
        for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
            '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '240.0.0.1', '192.0.2.1', '198.51.100.7',
            '203.0.113.9', '198.18.0.1', '192.0.0.8', '::', '::1', 'fe80::1', 'fc00::1', 'fd12::1', 'ff02::1',
            '2001:db8::1', '64:ff9b::1.2.3.4', '::ffff:127.0.0.1', '::ffff:7f00:1', '[::1]', 'garbage']) {
            assert.ok(isNonPublic(ip), ip);
        }
        for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700::1111', '::ffff:8.8.8.8', '2001:4860::8888']) {
            assert.ok(!isNonPublic(ip), ip);
        }
    });
});

describe('directory fetching', () => {
    test('fetches a signed directory and caches it', async () => {
        const key = wba.generateSigningKey();
        const body = wba.directoryToJson(wba.directoryFromKeys([key.publicKey()]));
        const { url, hits } = await serve((u) => {
            const headers = {};
            const signedHeaders = wba.signDirectoryResponse(body, new URL(u).host, [key], Math.floor(Date.now() / 1000), 3600);
            const sigInputs = signedHeaders.filter(([n]) => n === 'Signature-Input').map(([, v]) => v);
            const sigs = signedHeaders.filter(([n]) => n === 'Signature').map(([, v]) => v);
            headers['Content-Digest'] = signedHeaders[0][1];
            headers['Signature-Input'] = sigInputs.join(', ');
            headers['Signature'] = sigs.join(', ');
            headers['Content-Type'] = wba.DIRECTORY_MEDIA_TYPE;
            headers['Cache-Control'] = 'max-age=600';
            return { status: 200, headers, body };
        });

        const { directory, ttlSecs } = await fetchDirectory(url, { ...local, requireProof: true });
        assert.strictEqual(directory.keys.length, 1);
        assert.strictEqual(ttlSecs, 600);

        const resolver = new CachingDirectoryResolver(local);
        const tp = wba.thumbprint(key.publicKey());
        hits.count = 0;
        assert.ok((await resolver.lookup(url, tp)).equals(key.publicKey()));
        assert.ok((await resolver.lookup(url, tp)).equals(key.publicKey()));
        assert.strictEqual(hits.count, 1, 'second lookup is cached');
        // A key the directory does not publish: resolved, not found.
        assert.strictEqual(await resolver.lookup(url, wba.thumbprint(wba.generateSigningKey().publicKey())), null);
    });

    test('a failed refetch keeps the cached directory', async () => {
        const key = wba.generateSigningKey();
        const tp = wba.thumbprint(key.publicKey());
        const url = 'http://127.0.0.1:9/.well-known/http-message-signatures-directory';
        const resolver = new CachingDirectoryResolver(local);
        resolver._cache.set(url, { directory: wba.directoryFromKeys([key.publicKey()]), freshUntil: Date.now() - 1 });
        assert.ok((await resolver.lookup(url, tp)).equals(key.publicKey()));
        await assert.rejects(new CachingDirectoryResolver(local).lookup(url, tp));
    });

    test('refuses unsafe directories', async () => {
        const body = '{"keys":[]}';
        const redirect = await serve(() => ({ status: 302, headers: { Location: 'http://127.0.0.1:9/' }, body }));
        await assert.rejects(fetchDirectory(redirect.url, local), /Redirect rejected/);

        const missing = await serve(() => ({ status: 404, headers: {}, body }));
        await assert.rejects(fetchDirectory(missing.url, local), /HTTP 404/);

        const ok = await serve(() => ({ status: 200, headers: {}, body }));
        // Default options: http and loopback are refused before connecting,
        // both as a literal and through DNS.
        await assert.rejects(fetchDirectory(ok.url), /not https/);
        await assert.rejects(fetchDirectory(ok.url, { requireHttps: false }), /non-public/);
        const viaDns = ok.url.replace('127.0.0.1', 'localhost');
        await assert.rejects(fetchDirectory(viaDns, { requireHttps: false }), /Failed to fetch/);
        assert.strictEqual(ok.hits.count, 0);
        // Reachable once the guard is off. Only the literal is fetched:
        // where `localhost` resolves to ::1 first, Node 18 dials only that
        // and misses this IPv4 listener.
        assert.strictEqual((await fetchDirectory(ok.url, local)).directory.keys.length, 0);
        assert.strictEqual(ok.hits.count, 1);

        // Oversized bodies, by Content-Length and while streaming.
        const big = JSON.stringify({ keys: [], pad: 'x'.repeat(70 * 1024) });
        const large = await serve(() => ({ status: 200, headers: {}, body: big }));
        await assert.rejects(fetchDirectory(large.url, local), /exceeds/);
        await assert.rejects(fetchBounded(large.url, { publicOnly: false, maxBytes: 1024 }), /exceeds/);
        const chunked = await serve(() => ({ status: 200, headers: { 'Transfer-Encoding': 'chunked' }, body: big }));
        await assert.rejects(fetchDirectory(chunked.url, local), /exceeds/);

        // Too many keys.
        const many = await serve(() => ({ status: 200, headers: {}, body: JSON.stringify({ keys: new Array(65).fill({}) }) }));
        await assert.rejects(fetchDirectory(many.url, local), /too many keys/);

        // requireProof drops unsigned keys.
        const key = wba.generateSigningKey();
        const keyBody = wba.directoryToJson(wba.directoryFromKeys([key.publicKey()]));
        const unsigned = await serve(() => ({ status: 200, headers: { 'Content-Digest': contentDigest(keyBody) }, body: keyBody }));
        assert.strictEqual((await fetchDirectory(unsigned.url, { ...local, requireProof: true })).directory.keys.length, 0);
        assert.strictEqual((await fetchDirectory(unsigned.url, local)).directory.keys.length, 1);
    });

    test('times out stalled servers', async () => {
        const server = http.createServer(() => { /* never respond */ });
        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        servers.push(server);
        const url = `http://127.0.0.1:${server.address().port}/`;
        await assert.rejects(fetchDirectory(url, { ...local, timeoutMs: 100 }), /Failed to fetch/);
        server.closeAllConnections?.();
    });

    test('verifyRequest resolves keys through the caching resolver', async () => {
        const key = wba.generateSigningKey();
        const body = wba.directoryToJson(wba.directoryFromKeys([key.publicKey()]));
        const { url } = await serve(() => ({ status: 200, headers: { 'Content-Type': wba.DIRECTORY_MEDIA_TYPE }, body }));
        const resolver = new CachingDirectoryResolver(local);
        const signAndVerify = async (k) => {
            // Signing requires an https Signature-Agent; point the lookup at the local server.
            const req = httpRequest('GET', 'https://origin.example/');
            const signed = wba.signRequest(req, k, 'https://agent.example/').apply(req);
            return wba.verifyRequest(signed, { lookup: (_agent, keyid) => resolver.lookup(url, keyid) });
        };
        assert.strictEqual((await signAndVerify(key)).outcome, wba.WbaOutcome.VERIFIED);
        assert.strictEqual((await signAndVerify(wba.generateSigningKey())).outcome, wba.WbaOutcome.UNVERIFIED);
        // With default options the https lookup goes through normalization and the SSRF guard.
        const strict = new CachingDirectoryResolver({ timeoutMs: 2000 });
        await assert.rejects(strict.lookup('http://agent.example/', 'x'));
        await assert.rejects(strict.lookup('https://127.0.0.1/', 'x'), /non-public/);
    });

    test('parses max-age', () => {
        assert.strictEqual(maxAge([['Cache-Control', 'public, max-age=120']]), 120);
        assert.strictEqual(maxAge([['Cache-Control', 'max-age=abc, max-age=5']]), 5);
        assert.strictEqual(maxAge([]), null);
    });
});
