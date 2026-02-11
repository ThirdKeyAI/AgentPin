"""AgentPin: Domain-anchored cryptographic identity protocol for AI agents."""

from .capability import (
    Capability,
    capabilities_hash,
    capabilities_subset,
)
from .constraint import (
    constraints_subset_of,
    domain_pattern_matches,
    parse_rate_limit,
)
from .credential import (
    issue_credential,
    validate_credential_against_discovery,
)
from .crypto import (
    generate_key_id,
    generate_key_pair,
    sha256_hash,
    sha256_hex,
    sign_data,
    verify_signature,
)
from .delegation import (
    canonical_attestation_input,
    create_attestation,
    verify_attestation,
    verify_chain_depth,
)
from .discovery import (
    build_discovery_document,
    fetch_discovery_document,
    find_agent_by_id,
    find_key_by_kid,
    validate_discovery_document,
)
from .jwk import (
    jwk_thumbprint,
    jwk_to_pem,
    pem_to_jwk,
)
from .jwt import (
    base64url_decode,
    base64url_encode,
    decode_jwt_unverified,
    encode_jwt,
    verify_jwt,
)
from .mutual import (
    create_challenge,
    create_response,
    verify_response,
)
from .pinning import (
    KeyPinStore,
    PinningResult,
    check_pinning,
)
from .revocation import (
    add_revoked_agent,
    add_revoked_credential,
    add_revoked_key,
    build_revocation_document,
    check_revocation,
    fetch_revocation_document,
)
from .types import (
    DATA_CLASSIFICATION_ORDER,
    AgentPinError,
    AgentStatus,
    DataClassification,
    DelegationRole,
    EntityType,
    ErrorCode,
    RevocationReason,
    TrustLevel,
    VerificationResult,
    VerifierConfig,
)
from .verification import (
    verify_credential,
    verify_credential_offline,
)
from .bundle import (
    create_trust_bundle,
    find_bundle_discovery,
    find_bundle_revocation,
    load_trust_bundle,
    save_trust_bundle,
    verify_credential_with_bundle,
)

__version__ = "0.2.0"

__all__ = [
    # Types
    "EntityType",
    "AgentStatus",
    "DelegationRole",
    "RevocationReason",
    "DataClassification",
    "DATA_CLASSIFICATION_ORDER",
    "TrustLevel",
    "ErrorCode",
    "AgentPinError",
    "VerificationResult",
    "VerifierConfig",
    # Crypto
    "generate_key_pair",
    "sign_data",
    "verify_signature",
    "generate_key_id",
    "sha256_hash",
    "sha256_hex",
    # JWK
    "pem_to_jwk",
    "jwk_to_pem",
    "jwk_thumbprint",
    # JWT
    "base64url_encode",
    "base64url_decode",
    "encode_jwt",
    "decode_jwt_unverified",
    "verify_jwt",
    # Capability
    "Capability",
    "capabilities_subset",
    "capabilities_hash",
    # Constraint
    "parse_rate_limit",
    "domain_pattern_matches",
    "constraints_subset_of",
    # Credential
    "issue_credential",
    "validate_credential_against_discovery",
    # Discovery
    "build_discovery_document",
    "validate_discovery_document",
    "find_key_by_kid",
    "find_agent_by_id",
    "fetch_discovery_document",
    # Revocation
    "build_revocation_document",
    "add_revoked_credential",
    "add_revoked_agent",
    "add_revoked_key",
    "check_revocation",
    "fetch_revocation_document",
    # Pinning
    "KeyPinStore",
    "PinningResult",
    "check_pinning",
    # Delegation
    "canonical_attestation_input",
    "create_attestation",
    "verify_attestation",
    "verify_chain_depth",
    # Mutual
    "create_challenge",
    "create_response",
    "verify_response",
    # Verification
    "verify_credential_offline",
    "verify_credential",
    # Bundle
    "create_trust_bundle",
    "find_bundle_discovery",
    "find_bundle_revocation",
    "load_trust_bundle",
    "save_trust_bundle",
    "verify_credential_with_bundle",
]
