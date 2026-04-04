/**
 * Transport binding helpers for AgentPin (spec Section 13).
 */

import { AgentPinError, ErrorCode } from './types.js';

// --- HTTP ---
const HTTP_PREFIX = 'AgentPin ';

/**
 * Extract a credential JWT from an HTTP Authorization header value.
 * @param {string} headerValue
 * @returns {string} The JWT credential
 * @throws {AgentPinError} if the header is malformed
 */
export function httpExtractCredential(headerValue) {
    if (!headerValue.startsWith(HTTP_PREFIX)) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, "Missing 'AgentPin ' prefix in Authorization header");
    }
    const jwt = headerValue.slice(HTTP_PREFIX.length);
    if (!jwt) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, 'Empty credential in Authorization header');
    }
    return jwt;
}

/**
 * Format a JWT into an HTTP Authorization header value.
 * @param {string} jwt
 * @returns {string}
 */
export function httpFormatAuthorizationHeader(jwt) {
    return `AgentPin ${jwt}`;
}

// --- MCP ---
const MCP_FIELD = 'agentpin_credential';

/**
 * Extract a credential JWT from MCP metadata.
 * @param {object} meta
 * @returns {string} The JWT credential
 * @throws {AgentPinError} if the field is missing or not a string
 */
export function mcpExtractCredential(meta) {
    if (!(MCP_FIELD in meta)) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `Missing '${MCP_FIELD}' field in MCP metadata`);
    }
    const value = meta[MCP_FIELD];
    if (typeof value !== 'string') {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `'${MCP_FIELD}' field is not a string`);
    }
    return value;
}

/**
 * Format a JWT into an MCP metadata field.
 * @param {string} jwt
 * @returns {object}
 */
export function mcpFormatMetaField(jwt) {
    return { [MCP_FIELD]: jwt };
}

// --- WebSocket ---
const WS_AUTH_TYPE = 'agentpin-auth';

/**
 * Extract a credential JWT from a WebSocket auth message (JSON string).
 * @param {string} message - JSON-encoded message
 * @returns {string} The JWT credential
 * @throws {AgentPinError} if the message is malformed
 */
export function wsExtractCredential(message) {
    let parsed;
    try {
        parsed = JSON.parse(message);
    } catch (e) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `Invalid JSON: ${e.message}`);
    }
    if (parsed.type !== WS_AUTH_TYPE) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `Expected type '${WS_AUTH_TYPE}', got '${parsed.type}'`);
    }
    if (typeof parsed.credential !== 'string') {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, "Missing or non-string 'credential' field");
    }
    return parsed.credential;
}

/**
 * Format a JWT into a WebSocket auth message (JSON string).
 * @param {string} jwt
 * @returns {string} JSON-encoded message
 */
export function wsFormatAuthMessage(jwt) {
    return JSON.stringify({ type: WS_AUTH_TYPE, credential: jwt });
}

// --- gRPC ---

/** The gRPC metadata key for AgentPin credentials. */
export const GRPC_METADATA_KEY = 'agentpin-credential';

/**
 * Extract a credential JWT from a gRPC metadata value.
 * @param {string} metadataValue
 * @returns {string} The JWT credential
 * @throws {AgentPinError} if the value is empty
 */
export function grpcExtractCredential(metadataValue) {
    if (!metadataValue) {
        throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, 'Empty gRPC metadata value');
    }
    return metadataValue;
}

/**
 * Format a JWT into a gRPC metadata value.
 * @param {string} jwt
 * @returns {string}
 */
export function grpcFormatMetadataValue(jwt) {
    return jwt;
}
