/**
 * AgentPin type constants and enums.
 */

/** Entity types for discovery documents. */
export const EntityType = Object.freeze({
    MAKER: 'maker',
    DEPLOYER: 'deployer',
    BOTH: 'both',
});

/** Agent status values. */
export const AgentStatus = Object.freeze({
    ACTIVE: 'active',
    SUSPENDED: 'suspended',
    DEPRECATED: 'deprecated',
});

/** Delegation role values. */
export const DelegationRole = Object.freeze({
    MAKER: 'maker',
    DEPLOYER: 'deployer',
});

/** Revocation reason values (snake_case to match Rust serde output). */
export const RevocationReason = Object.freeze({
    KEY_COMPROMISE: 'key_compromise',
    AFFILIATION_CHANGED: 'affiliation_changed',
    SUPERSEDED: 'superseded',
    CESSATION_OF_OPERATION: 'cessation_of_operation',
    PRIVILEGE_WITHDRAWN: 'privilege_withdrawn',
    POLICY_VIOLATION: 'policy_violation',
});

/** Data classification levels (ordered from least to most sensitive). */
export const DataClassification = Object.freeze({
    PUBLIC: 'public',
    INTERNAL: 'internal',
    CONFIDENTIAL: 'confidential',
    RESTRICTED: 'restricted',
});

/** Numeric ordering for DataClassification comparisons. */
export const DATA_CLASSIFICATION_ORDER = Object.freeze({
    'public': 0,
    'internal': 1,
    'confidential': 2,
    'restricted': 3,
});

/** Trust levels for pinned keys. */
export const TrustLevel = Object.freeze({
    TOFU: 'tofu',
    VERIFIED: 'verified',
    PINNED: 'pinned',
});

/** Error codes from spec section 6.7. */
export const ErrorCode = Object.freeze({
    SIGNATURE_INVALID: 'SIGNATURE_INVALID',
    KEY_NOT_FOUND: 'KEY_NOT_FOUND',
    KEY_EXPIRED: 'KEY_EXPIRED',
    KEY_REVOKED: 'KEY_REVOKED',
    CREDENTIAL_EXPIRED: 'CREDENTIAL_EXPIRED',
    CREDENTIAL_REVOKED: 'CREDENTIAL_REVOKED',
    AGENT_NOT_FOUND: 'AGENT_NOT_FOUND',
    AGENT_INACTIVE: 'AGENT_INACTIVE',
    CAPABILITY_EXCEEDED: 'CAPABILITY_EXCEEDED',
    CONSTRAINT_VIOLATION: 'CONSTRAINT_VIOLATION',
    DELEGATION_INVALID: 'DELEGATION_INVALID',
    DELEGATION_DEPTH_EXCEEDED: 'DELEGATION_DEPTH_EXCEEDED',
    DISCOVERY_FETCH_FAILED: 'DISCOVERY_FETCH_FAILED',
    DISCOVERY_INVALID: 'DISCOVERY_INVALID',
    DOMAIN_MISMATCH: 'DOMAIN_MISMATCH',
    AUDIENCE_MISMATCH: 'AUDIENCE_MISMATCH',
    ALGORITHM_REJECTED: 'ALGORITHM_REJECTED',
    KEY_PIN_MISMATCH: 'KEY_PIN_MISMATCH',
});

/** AgentPin-specific error class. */
export class AgentPinError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'AgentPinError';
        this.code = code;
    }
}
