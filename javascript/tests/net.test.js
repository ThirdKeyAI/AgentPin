/**
 * Tests for the hardened fetch layer (AP-7, AP-12, AP-13).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { fetchJsonBounded } from '../src/net.js';

function stub(status, headers, body) {
    return async () => new Response(body, { status, headers });
}

describe('fetchJsonBounded', () => {
    test('fetches small JSON', async () => {
        const doc = await fetchJsonBounded('https://example.com/x', {
            fetchImpl: stub(200, { 'content-type': 'application/json; charset=utf-8' }, '{"a":1}'),
        });
        assert.deepStrictEqual(doc, { a: 1 });
    });

    test('rejects redirects even if the fetch implementation returns one', async () => {
        await assert.rejects(
            fetchJsonBounded('https://example.com/x', {
                fetchImpl: stub(302, { location: 'https://evil.example/', 'content-type': 'application/json' }, '{}'),
            }),
            /Redirect rejected/
        );
    });

    test('rejects oversized bodies by content-length and while streaming', async () => {
        await assert.rejects(
            fetchJsonBounded('https://example.com/x', {
                maxBytes: 1024,
                fetchImpl: stub(200, { 'content-type': 'application/json', 'content-length': '2048' }, ' '.repeat(2048)),
            }),
            /exceeds/
        );
        const stream = new ReadableStream({
            start(controller) {
                for (let i = 0; i < 4; i++) controller.enqueue(new Uint8Array(1024).fill(120));
                controller.close();
            },
        });
        await assert.rejects(
            fetchJsonBounded('https://example.com/x', {
                maxBytes: 1024,
                fetchImpl: async () => new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } }),
            }),
            /exceeds/
        );
    });

    test('rejects non-JSON content types', async () => {
        await assert.rejects(
            fetchJsonBounded('https://example.com/x', { fetchImpl: stub(200, { 'content-type': 'text/html' }, '{}') }),
            /not application\/json/
        );
    });

    test('returns null on 404', async () => {
        const doc = await fetchJsonBounded('https://example.com/x', { fetchImpl: stub(404, {}, '') });
        assert.strictEqual(doc, null);
    });

    test('times out on a stalled server and reports a generic error', async () => {
        const server = http.createServer(() => { /* never respond */ });
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        const url = `http://127.0.0.1:${server.address().port}/doc.json`;
        const start = Date.now();
        try {
            await assert.rejects(fetchJsonBounded(url, { timeoutMs: 300 }), (e) => e.message === `Failed to fetch ${url}`);
            assert.ok(Date.now() - start < 2000, 'timeout not enforced');
        } finally {
            server.closeAllConnections?.();
            await new Promise((resolve) => server.close(resolve));
        }
    });

    test('real redirects are rejected by the default fetch', async () => {
        const server = http.createServer((req, res) => {
            res.writeHead(302, { Location: 'http://127.0.0.1:9/evil' });
            res.end();
        });
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        const url = `http://127.0.0.1:${server.address().port}/doc.json`;
        try {
            await assert.rejects(fetchJsonBounded(url, {}), /Failed to fetch|Redirect rejected/);
        } finally {
            await new Promise((resolve) => server.close(resolve));
        }
    });
});
