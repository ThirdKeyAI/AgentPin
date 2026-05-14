/**
 * Tests for DNS TXT cross-verification (v0.3.0).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    generateKeyPair,
    pemToJwk,
    jwkThumbprint,
    parseTxtRecord,
    verifyDnsMatch,
    txtRecordName,
    EntityType,
} from '../src/index.js';

function makeDiscovery(jwks) {
    return {
        agentpin_version: '0.3',
        entity: 'example.com',
        entity_type: EntityType.MAKER,
        public_keys: jwks,
        agents: [],
        max_delegation_depth: 0,
        updated_at: '2026-05-01T00:00:00Z',
    };
}

describe('parseTxtRecord', () => {
    it('parses a full record', () => {
        const r = parseTxtRecord('v=agentpin1; kid=acme-2026-04; fp=sha256:abcd1234');
        assert.equal(r.version, 'agentpin1');
        assert.equal(r.kid, 'acme-2026-04');
        assert.equal(r.fingerprint, 'sha256:abcd1234');
    });

    it('parses a minimal record', () => {
        const r = parseTxtRecord('v=agentpin1;fp=sha256:abc');
        assert.equal(r.version, 'agentpin1');
        assert.equal(r.kid, null);
        assert.equal(r.fingerprint, 'sha256:abc');
    });

    it('lowercases the fingerprint', () => {
        const r = parseTxtRecord('v=agentpin1; fp=SHA256:ABCDEF');
        assert.equal(r.fingerprint, 'sha256:abcdef');
    });

    it('tolerates whitespace and unsorted fields', () => {
        const r = parseTxtRecord('  fp = sha256:beef ;  v = agentpin1  ');
        assert.equal(r.version, 'agentpin1');
        assert.equal(r.fingerprint, 'sha256:beef');
    });

    it('ignores unknown fields for forward compat', () => {
        const r = parseTxtRecord('v=agentpin1; fp=sha256:abc; future=ignoreme');
        assert.equal(r.fingerprint, 'sha256:abc');
    });

    it('rejects missing v', () => {
        assert.throws(() => parseTxtRecord('fp=sha256:abc'));
    });

    it('rejects missing fp', () => {
        assert.throws(() => parseTxtRecord('v=agentpin1'));
    });

    it('rejects unsupported version', () => {
        assert.throws(() => parseTxtRecord('v=agentpin99; fp=sha256:abc'));
    });

    it('rejects fingerprint without sha256: prefix', () => {
        assert.throws(() => parseTxtRecord('v=agentpin1; fp=abc'));
    });

    it('rejects field without =', () => {
        assert.throws(() => parseTxtRecord('v=agentpin1; broken'));
    });

    it('rejects SchemaPin-format records', () => {
        // Sanity check: must not accidentally accept SchemaPin's TXT format.
        assert.throws(() => parseTxtRecord('v=schemapin1; fp=sha256:abc'));
    });
});

describe('verifyDnsMatch', () => {
    function fingerprintForKey(jwk) {
        const t = jwkThumbprint(jwk).toLowerCase();
        return t.startsWith('sha256:') ? t : `sha256:${t}`;
    }

    it('matches when TXT fp equals the key thumbprint', () => {
        const { publicKeyPem } = generateKeyPair();
        const jwk = pemToJwk(publicKeyPem, 'kid-1');
        const doc = makeDiscovery([jwk]);
        const txt = { kid: null, fingerprint: fingerprintForKey(jwk) };
        verifyDnsMatch(doc, txt);
    });

    it('matches one of multiple discovery keys', () => {
        const { publicKeyPem: pk1 } = generateKeyPair();
        const { publicKeyPem: pk2 } = generateKeyPair();
        const jwk1 = pemToJwk(pk1, 'kid-a');
        const jwk2 = pemToJwk(pk2, 'kid-b');
        const doc = makeDiscovery([jwk1, jwk2]);
        const txt = { kid: 'kid-b', fingerprint: fingerprintForKey(jwk2) };
        verifyDnsMatch(doc, txt);
    });

    it('fails when kid in TXT does not match the discovery key', () => {
        const { publicKeyPem } = generateKeyPair();
        const jwk = pemToJwk(publicKeyPem, 'kid-real');
        const doc = makeDiscovery([jwk]);
        const txt = { kid: 'kid-different', fingerprint: fingerprintForKey(jwk) };
        assert.throws(() => verifyDnsMatch(doc, txt));
    });

    it('fails on fingerprint mismatch', () => {
        const { publicKeyPem } = generateKeyPair();
        const jwk = pemToJwk(publicKeyPem, 'kid-1');
        const doc = makeDiscovery([jwk]);
        const txt = {
            kid: null,
            fingerprint: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        };
        assert.throws(() => verifyDnsMatch(doc, txt));
    });
});

describe('txtRecordName', () => {
    it('strips trailing dot', () => {
        assert.equal(txtRecordName('example.com'), '_agentpin.example.com');
        assert.equal(txtRecordName('example.com.'), '_agentpin.example.com');
    });
});
