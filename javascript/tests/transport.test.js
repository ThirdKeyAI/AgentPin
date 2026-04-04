/**
 * Tests for transport binding helpers.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
    httpExtractCredential,
    httpFormatAuthorizationHeader,
    mcpExtractCredential,
    mcpFormatMetaField,
    wsExtractCredential,
    wsFormatAuthMessage,
    grpcExtractCredential,
    grpcFormatMetadataValue,
    GRPC_METADATA_KEY,
} from '../src/transport.js';

const TEST_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';

describe('HTTP transport', () => {
    test('extract valid credential', () => {
        const jwt = httpExtractCredential('AgentPin ' + TEST_JWT);
        assert.strictEqual(jwt, TEST_JWT);
    });

    test('reject missing prefix', () => {
        assert.throws(
            () => httpExtractCredential('Bearer ' + TEST_JWT),
            /Missing 'AgentPin ' prefix/
        );
    });

    test('reject empty credential after prefix', () => {
        assert.throws(
            () => httpExtractCredential('AgentPin '),
            /Empty credential/
        );
    });

    test('format roundtrip', () => {
        const header = httpFormatAuthorizationHeader(TEST_JWT);
        const extracted = httpExtractCredential(header);
        assert.strictEqual(extracted, TEST_JWT);
    });
});

describe('MCP transport', () => {
    test('extract valid credential', () => {
        const jwt = mcpExtractCredential({ agentpin_credential: TEST_JWT });
        assert.strictEqual(jwt, TEST_JWT);
    });

    test('reject missing field', () => {
        assert.throws(
            () => mcpExtractCredential({}),
            /Missing 'agentpin_credential'/
        );
    });

    test('reject non-string field', () => {
        assert.throws(
            () => mcpExtractCredential({ agentpin_credential: 42 }),
            /not a string/
        );
    });

    test('format roundtrip', () => {
        const meta = mcpFormatMetaField(TEST_JWT);
        const extracted = mcpExtractCredential(meta);
        assert.strictEqual(extracted, TEST_JWT);
    });
});

describe('WebSocket transport', () => {
    test('extract valid credential', () => {
        const msg = JSON.stringify({ type: 'agentpin-auth', credential: TEST_JWT });
        const jwt = wsExtractCredential(msg);
        assert.strictEqual(jwt, TEST_JWT);
    });

    test('reject invalid JSON', () => {
        assert.throws(
            () => wsExtractCredential('not json'),
            /Invalid JSON/
        );
    });

    test('reject wrong type', () => {
        const msg = JSON.stringify({ type: 'other', credential: TEST_JWT });
        assert.throws(
            () => wsExtractCredential(msg),
            /Expected type 'agentpin-auth'/
        );
    });

    test('reject missing credential field', () => {
        const msg = JSON.stringify({ type: 'agentpin-auth' });
        assert.throws(
            () => wsExtractCredential(msg),
            /Missing or non-string 'credential'/
        );
    });

    test('format roundtrip', () => {
        const msg = wsFormatAuthMessage(TEST_JWT);
        const extracted = wsExtractCredential(msg);
        assert.strictEqual(extracted, TEST_JWT);
    });
});

describe('gRPC transport', () => {
    test('metadata key is correct', () => {
        assert.strictEqual(GRPC_METADATA_KEY, 'agentpin-credential');
    });

    test('extract valid credential', () => {
        const jwt = grpcExtractCredential(TEST_JWT);
        assert.strictEqual(jwt, TEST_JWT);
    });

    test('reject empty value', () => {
        assert.throws(
            () => grpcExtractCredential(''),
            /Empty gRPC metadata/
        );
    });

    test('reject null value', () => {
        assert.throws(
            () => grpcExtractCredential(null),
            /Empty gRPC metadata/
        );
    });

    test('format roundtrip', () => {
        const val = grpcFormatMetadataValue(TEST_JWT);
        const extracted = grpcExtractCredential(val);
        assert.strictEqual(extracted, TEST_JWT);
    });
});
