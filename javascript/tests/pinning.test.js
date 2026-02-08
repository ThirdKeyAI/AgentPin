/**
 * Tests for TOFU key pinning.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { KeyPinStore, PinningResult, checkPinning } from '../src/pinning.js';

function makeTestJwk(kid, x) {
    return {
        kid,
        kty: 'EC',
        crv: 'P-256',
        x,
        y: 'test-y',
        use: 'sig',
    };
}

describe('KeyPinStore', () => {
    test('first use pins key', () => {
        const store = new KeyPinStore();
        const jwk = makeTestJwk('key-1', 'x-value-1');
        const result = store.checkAndPin('example.com', jwk);
        assert.strictEqual(result, PinningResult.FIRST_USE);

        const result2 = store.checkAndPin('example.com', jwk);
        assert.strictEqual(result2, PinningResult.MATCHED);
    });

    test('key change detected', () => {
        const store = new KeyPinStore();
        const jwk1 = makeTestJwk('key-1', 'x-value-1');
        store.checkAndPin('example.com', jwk1);

        const jwk2 = makeTestJwk('key-2', 'x-value-2');
        const result = store.checkAndPin('example.com', jwk2);
        assert.strictEqual(result, PinningResult.CHANGED);
    });

    test('addKey allows rotation', () => {
        const store = new KeyPinStore();
        const jwk1 = makeTestJwk('key-1', 'x-value-1');
        store.checkAndPin('example.com', jwk1);

        const jwk2 = makeTestJwk('key-2', 'x-value-2');
        store.addKey('example.com', jwk2);

        assert.strictEqual(store.checkAndPin('example.com', jwk1), PinningResult.MATCHED);
        assert.strictEqual(store.checkAndPin('example.com', jwk2), PinningResult.MATCHED);
    });

    test('JSON roundtrip', () => {
        const store = new KeyPinStore();
        const jwk = makeTestJwk('key-1', 'x-value-1');
        store.checkAndPin('example.com', jwk);

        const json = store.toJson();
        const store2 = KeyPinStore.fromJson(json);
        assert.ok(store2.getDomain('example.com'));
        assert.strictEqual(store2.getDomain('example.com').pinned_keys.length, 1);
    });

    test('different domains are independent', () => {
        const store = new KeyPinStore();
        const jwk1 = makeTestJwk('key-1', 'x-value-1');
        const jwk2 = makeTestJwk('key-2', 'x-value-2');

        store.checkAndPin('a.com', jwk1);
        store.checkAndPin('b.com', jwk2);

        assert.strictEqual(store.checkAndPin('a.com', jwk1), PinningResult.MATCHED);
        assert.strictEqual(store.checkAndPin('b.com', jwk2), PinningResult.MATCHED);
        assert.strictEqual(store.checkAndPin('a.com', jwk2), PinningResult.CHANGED);
    });
});

describe('checkPinning', () => {
    test('throws on key change', () => {
        const store = new KeyPinStore();
        const jwk1 = makeTestJwk('key-1', 'x-value-1');
        store.checkAndPin('example.com', jwk1);

        const jwk2 = makeTestJwk('key-2', 'x-value-2');
        assert.throws(() => checkPinning(store, 'example.com', jwk2), /changed/i);
    });
});
