/**
 * AgentPin: Domain-anchored cryptographic identity protocol for AI agents.
 */

export {
    generateKeyPair,
    signData,
    verifySignature,
    generateKeyId,
    sha256Hash,
    sha256Hex,
} from './crypto.js';

export {
    pemToJwk,
    jwkToPem,
    jwkThumbprint,
} from './jwk.js';

export {
    base64urlEncode,
    base64urlDecode,
    encodeJwt,
    decodeJwtUnverified,
    verifyJwt,
} from './jwt.js';

export {
    EntityType,
    AgentStatus,
    DelegationRole,
    RevocationReason,
    DataClassification,
    DATA_CLASSIFICATION_ORDER,
    TrustLevel,
    ErrorCode,
    AgentPinError,
} from './types.js';

export {
    Capability,
    capabilitiesSubset,
    capabilitiesHash,
} from './capability.js';

export {
    parseRateLimit,
    domainPatternMatches,
    constraintsSubsetOf,
} from './constraint.js';

export {
    issueCredential,
    validateCredentialAgainstDiscovery,
} from './credential.js';

export {
    buildDiscoveryDocument,
    validateDiscoveryDocument,
    findKeyByKid,
    findAgentById,
    fetchDiscoveryDocument,
} from './discovery.js';

export {
    buildRevocationDocument,
    addRevokedCredential,
    addRevokedAgent,
    addRevokedKey,
    checkRevocation,
    fetchRevocationDocument,
} from './revocation.js';

export {
    KeyPinStore,
    PinningResult,
    checkPinning,
} from './pinning.js';

export {
    canonicalAttestationInput,
    createAttestation,
    verifyAttestation,
    verifyChainDepth,
} from './delegation.js';

export {
    createChallenge,
    createResponse,
    verifyResponse,
} from './mutual.js';

export {
    defaultVerifierConfig,
    verifyCredentialOffline,
    verifyCredential,
} from './verification.js';

export const version = '0.1.0';
