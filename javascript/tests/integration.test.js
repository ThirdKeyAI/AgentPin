/**
 * End-to-end integration tests for AgentPin.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
    generateKeyPair,
    generateKeyId,
    pemToJwk,
    issueCredential,
    decodeJwtUnverified,
    verifyJwt,
    verifyCredentialOffline,
    defaultVerifierConfig,
    buildDiscoveryDocument,
    validateDiscoveryDocument,
    findKeyByKid,
    findAgentById,
    buildRevocationDocument,
    addRevokedKey,
    checkRevocation,
    KeyPinStore,
    PinningResult,
    checkPinning,
    createChallenge,
    createResponse,
    verifyResponseWithNonceStore,
    InMemoryNonceStore,
    httpExtractCredential,
    httpFormatAuthorizationHeader,
    mcpExtractCredential,
    mcpFormatMetaField,
    wsExtractCredential,
    wsFormatAuthMessage,
    grpcExtractCredential,
    grpcFormatMetadataValue,
    prepareRotation,
    applyRotation,
    completeRotation,
    AgentPinError,
} from '../src/index.js';

function makeTestSetup() {
    const { privateKeyPem, publicKeyPem } = generateKeyPair();
    const kid = generateKeyId(publicKeyPem);
    const jwk = pemToJwk(publicKeyPem, kid);
    const agentId = 'urn:agentpin:example.com:test-agent';
    const doc = buildDiscoveryDocument(
        'example.com',
        'maker',
        [jwk],
        [
            {
                agent_id: agentId,
                name: 'Test Agent',
                capabilities: ['read:*', 'write:report'],
                status: 'active',
                credential_ttl_max: 3600,
            },
        ],
        2,
        '2026-01-01T00:00:00Z'
    );
    return { privateKeyPem, publicKeyPem, kid, agentId, doc };
}

describe('Maker-Deployer Flow', () => {
    it('should issue, decode, verify, and validate a credential end-to-end', () => {
        const { privateKeyPem, publicKeyPem, kid, agentId, doc } = makeTestSetup();

        // Issue a credential
        const jwtStr = issueCredential(
            privateKeyPem,
            kid,
            'example.com',
            agentId,
            'verifier.com',
            ['read:data', 'write:report'],
            null,
            null,
            3600
        );
        assert.ok(jwtStr);
        assert.equal(jwtStr.split('.').length, 3);

        // Decode unverified to inspect
        const { header, payload } = decodeJwtUnverified(jwtStr);
        assert.equal(header.alg, 'ES256');
        assert.equal(header.typ, 'agentpin-credential+jwt');
        assert.equal(header.kid, kid);
        assert.equal(payload.iss, 'example.com');
        assert.equal(payload.sub, agentId);

        // Verify signature
        const verified = verifyJwt(jwtStr, publicKeyPem);
        assert.equal(verified.header.kid, kid);
        assert.equal(verified.payload.iss, 'example.com');

        // Full offline verification
        const pinStore = new KeyPinStore();
        const config = defaultVerifierConfig();
        const result = verifyCredentialOffline(
            jwtStr,
            doc,
            null,
            pinStore,
            'verifier.com',
            config
        );
        assert.ok(result.valid, `Expected valid, got: ${result.error_message}`);
        assert.equal(result.agent_id, agentId);
        assert.equal(result.issuer, 'example.com');
    });
});

describe('Revocation Flow', () => {
    it('should detect a revoked key during verification', () => {
        const { privateKeyPem, publicKeyPem, kid, agentId, doc } = makeTestSetup();

        const jwtStr = issueCredential(
            privateKeyPem,
            kid,
            'example.com',
            agentId,
            null,
            ['read:data'],
            null,
            null,
            3600
        );

        const { header, payload } = decodeJwtUnverified(jwtStr);

        // Clean revocation: should pass
        const revDoc = buildRevocationDocument('example.com');
        checkRevocation(revDoc, payload.jti, agentId, kid); // no error

        // Add revoked key
        addRevokedKey(revDoc, kid, 'key_compromise');

        // Now checkRevocation should fail
        assert.throws(
            () => checkRevocation(revDoc, payload.jti, agentId, kid),
            AgentPinError
        );

        // Full offline verification should also fail
        const pinStore = new KeyPinStore();
        const config = defaultVerifierConfig();
        const vresult = verifyCredentialOffline(
            jwtStr,
            doc,
            revDoc,
            pinStore,
            null,
            config
        );
        assert.equal(vresult.valid, false);
    });
});

describe('Mutual Verification with Nonce Store', () => {
    it('should prevent nonce replay', () => {
        const { privateKeyPem, publicKeyPem } = generateKeyPair();

        const store = new InMemoryNonceStore();
        const challenge = createChallenge();
        const response = createResponse(challenge, privateKeyPem, 'test-key');

        // First verification should succeed
        const valid = verifyResponseWithNonceStore(
            response,
            challenge,
            publicKeyPem,
            store
        );
        assert.ok(valid);

        // Second verification with same nonce should fail (replay)
        assert.throws(
            () =>
                verifyResponseWithNonceStore(
                    response,
                    challenge,
                    publicKeyPem,
                    store
                ),
            /already been used/
        );
    });
});

describe('Transport Roundtrip', () => {
    it('should format and extract credentials across all transports', () => {
        const { privateKeyPem, publicKeyPem } = generateKeyPair();
        const kid = generateKeyId(publicKeyPem);

        const jwtStr = issueCredential(
            privateKeyPem,
            kid,
            'example.com',
            'urn:agentpin:example.com:test-agent',
            null,
            ['read:data'],
            null,
            null,
            3600
        );

        // HTTP roundtrip
        const httpHeader = httpFormatAuthorizationHeader(jwtStr);
        const httpExtracted = httpExtractCredential(httpHeader);
        assert.equal(httpExtracted, jwtStr);

        // MCP roundtrip
        const mcpMeta = mcpFormatMetaField(jwtStr);
        const mcpExtracted = mcpExtractCredential(mcpMeta);
        assert.equal(mcpExtracted, jwtStr);

        // WebSocket roundtrip
        const wsMsg = wsFormatAuthMessage(jwtStr);
        const wsExtracted = wsExtractCredential(wsMsg);
        assert.equal(wsExtracted, jwtStr);

        // gRPC roundtrip
        const grpcVal = grpcFormatMetadataValue(jwtStr);
        const grpcExtracted = grpcExtractCredential(grpcVal);
        assert.equal(grpcExtracted, jwtStr);
    });
});

describe('Key Rotation Lifecycle', () => {
    it('should add new key, then remove old key and record revocation', () => {
        const { publicKeyPem } = generateKeyPair();
        const oldKid = generateKeyId(publicKeyPem);
        const oldJwk = pemToJwk(publicKeyPem, oldKid);

        const doc = buildDiscoveryDocument(
            'example.com',
            'maker',
            [oldJwk],
            [],
            2,
            '2026-01-01T00:00:00Z'
        );
        assert.equal(doc.public_keys.length, 1);

        // Prepare rotation
        const plan = prepareRotation(oldKid);
        assert.notEqual(plan.newKid, oldKid);

        // Apply rotation: both keys should be present
        applyRotation(doc, plan);
        assert.equal(doc.public_keys.length, 2);
        const kids = doc.public_keys.map((k) => k.kid);
        assert.ok(kids.includes(oldKid));
        assert.ok(kids.includes(plan.newKid));

        // Complete rotation: old key removed, added to revocation
        const revDoc = buildRevocationDocument('example.com');
        completeRotation(doc, revDoc, oldKid, 'superseded');

        assert.equal(doc.public_keys.length, 1);
        assert.equal(doc.public_keys[0].kid, plan.newKid);
        assert.equal(revDoc.revoked_keys.length, 1);
        assert.equal(revDoc.revoked_keys[0].kid, oldKid);
        assert.equal(revDoc.revoked_keys[0].reason, 'superseded');
    });
});

describe('Pinning Flow', () => {
    it('should pin on first use, match on second, error on different key', () => {
        const { publicKeyPem: pub1 } = generateKeyPair();
        const kid1 = generateKeyId(pub1);
        const jwk1 = pemToJwk(pub1, kid1);

        const store = new KeyPinStore();

        // First verification pins the key
        const result1 = checkPinning(store, 'example.com', jwk1);
        assert.equal(result1, PinningResult.FIRST_USE);

        // Same key succeeds
        const result2 = checkPinning(store, 'example.com', jwk1);
        assert.equal(result2, PinningResult.MATCHED);

        // Different key triggers error
        const { publicKeyPem: pub2 } = generateKeyPair();
        const kid2 = generateKeyId(pub2);
        const jwk2 = pemToJwk(pub2, kid2);

        assert.throws(
            () => checkPinning(store, 'example.com', jwk2),
            AgentPinError
        );
    });
});
