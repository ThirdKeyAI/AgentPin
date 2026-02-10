"""AgentPin type constants, enums, and error classes."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class EntityType(str, Enum):
    MAKER = "maker"
    DEPLOYER = "deployer"
    BOTH = "both"


class AgentStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEPRECATED = "deprecated"


class DelegationRole(str, Enum):
    MAKER = "maker"
    DEPLOYER = "deployer"


class RevocationReason(str, Enum):
    KEY_COMPROMISE = "key_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    POLICY_VIOLATION = "policy_violation"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


DATA_CLASSIFICATION_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


class TrustLevel(str, Enum):
    TOFU = "tofu"
    VERIFIED = "verified"
    PINNED = "pinned"


class ErrorCode(str, Enum):
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    KEY_EXPIRED = "KEY_EXPIRED"
    KEY_REVOKED = "KEY_REVOKED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    AGENT_INACTIVE = "AGENT_INACTIVE"
    CAPABILITY_EXCEEDED = "CAPABILITY_EXCEEDED"
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"
    DELEGATION_INVALID = "DELEGATION_INVALID"
    DELEGATION_DEPTH_EXCEEDED = "DELEGATION_DEPTH_EXCEEDED"
    DISCOVERY_FETCH_FAILED = "DISCOVERY_FETCH_FAILED"
    DISCOVERY_INVALID = "DISCOVERY_INVALID"
    DOMAIN_MISMATCH = "DOMAIN_MISMATCH"
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"
    ALGORITHM_REJECTED = "ALGORITHM_REJECTED"
    KEY_PIN_MISMATCH = "KEY_PIN_MISMATCH"


class AgentPinError(Exception):
    """AgentPin-specific error with an error code."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class ValidHours:
    start: str
    end: str
    timezone: str


@dataclass
class Constraints:
    allowed_domains: Optional[List[str]] = None
    denied_domains: Optional[List[str]] = None
    rate_limit: Optional[str] = None
    data_classification_max: Optional[str] = None
    ip_allowlist: Optional[List[str]] = None
    valid_hours: Optional[ValidHours] = None


@dataclass
class JwtHeader:
    alg: str
    typ: str
    kid: str


@dataclass
class JwtPayload:
    iss: str
    sub: str
    iat: int
    exp: int
    jti: str
    agentpin_version: str
    capabilities: List[str]
    aud: Optional[str] = None
    nbf: Optional[int] = None
    constraints: Optional[Constraints] = None
    delegation_chain: Optional[list] = None
    nonce: Optional[str] = None


@dataclass
class DelegationAttestation:
    domain: str
    role: str
    agent_id: str
    kid: str
    attestation: str


@dataclass
class Jwk:
    kid: str
    kty: str
    crv: str
    x: str
    y: str
    use: str = "sig"
    key_ops: Optional[List[str]] = None
    exp: Optional[str] = None


@dataclass
class AgentDeclaration:
    agent_id: str
    name: str
    capabilities: List[str]
    status: str
    agent_type: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    constraints: Optional[dict] = None
    maker_attestation: Optional[str] = None
    credential_ttl_max: Optional[int] = None
    directory_listing: Optional[bool] = None


@dataclass
class DiscoveryDocument:
    agentpin_version: str
    entity: str
    entity_type: str
    public_keys: List[dict]
    agents: List[dict]
    max_delegation_depth: int
    updated_at: str
    revocation_endpoint: Optional[str] = None
    policy_url: Optional[str] = None
    schemapin_endpoint: Optional[str] = None


@dataclass
class RevocationDocument:
    agentpin_version: str
    entity: str
    updated_at: str
    revoked_credentials: List[dict] = field(default_factory=list)
    revoked_agents: List[dict] = field(default_factory=list)
    revoked_keys: List[dict] = field(default_factory=list)


@dataclass
class PinnedKey:
    kid: str
    public_key_hash: str
    first_seen: str
    last_seen: str
    trust_level: str


@dataclass
class PinnedDomain:
    domain: str
    pinned_keys: List[PinnedKey] = field(default_factory=list)


@dataclass
class Challenge:
    type: str
    nonce: str
    timestamp: str
    verifier_credential: Optional[str] = None


@dataclass
class Response:
    type: str
    nonce: str
    signature: str
    kid: str


@dataclass
class VerificationResult:
    valid: bool
    agent_id: Optional[str] = None
    issuer: Optional[str] = None
    capabilities: Optional[List[str]] = None
    constraints: Optional[dict] = None
    delegation_verified: Optional[bool] = None
    delegation_chain: Optional[list] = None
    key_pinning: Optional[dict] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


@dataclass
class VerifierConfig:
    clock_skew_secs: int = 60
    max_ttl_secs: int = 86400
