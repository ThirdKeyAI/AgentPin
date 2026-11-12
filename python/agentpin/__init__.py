"""AgentPin: Domain-anchored cryptographic identity protocol for AI agents."""

from .a2a import (
    agent_card_signing_input,
    build_and_sign_agent_card,
    build_unsigned_agent_card,
    canonicalize_for_signing,
    capability_to_skill,
    extension_key_thumbprint,
    sign_agent_card,
    verify_agentpin_extension,
)
from .bundle import (
    bundle_signing_input,
    check_bundle_expiry,
    create_trust_bundle,
    find_bundle_discovery,
    find_bundle_revocation,
    load_trust_bundle,
    save_trust_bundle,
    sign_trust_bundle,
    verify_credential_with_bundle,
    verify_trust_bundle,
)
from .capability import (
    CORE_ACTIONS,
    Capability,
    capabilities_hash,
    capabilities_subset,
    validate_capability,
)
from .constraint import (
    constraints_subset_of,
    domain_pattern_matches,
    merge_constraints,
    parse_rate_limit,
)
from .credential import (
    issue_bound_credential,
    issue_credential,
    validate_credential_against_discovery,
)
from .crypto import (
    CTX_AGENTCARD,
    CTX_ATTESTATION,
    CTX_BUNDLE,
    CTX_RESPONSE,
    CTX_REVOCATION,
    domain_separated_input,
    generate_key_id,
    generate_key_pair,
    sha256_hash,
    sha256_hex,
    sign_data,
    sign_with_context,
    verify_signature,
    verify_with_context,
)
from .delegation import (
    canonical_attestation_input,
    create_attestation,
    verify_attestation,
    verify_chain_depth,
)
from .discovery import (
    AllowedDomains,
    build_discovery_document,
    fetch_discovery_document,
    find_agent_by_id,
    find_key_by_kid,
    validate_discovery_document,
)
from .dns import (
    fetch_dns_txt,
    parse_txt_record,
    txt_record_name,
    verify_dns_match,
)
from .domain import (
    default_revocation_endpoint,
    https_url_host,
    normalize_domain,
    validate_https_url_for_domain,
)
from .httpsig import (
    Component,
    HttpRequest,
    HttpResponse,
    ParsedSignature,
    SignatureFields,
    SignatureParams,
    content_digest,
    content_digest_matches,
    parse_signatures,
)
from .jwk import (
    jwk_thumbprint,
    jwk_to_pem,
    pem_to_jwk,
)
from .jwt import (
    CREDENTIAL_VERSION,
    MalformedCredentialError,
    base64url_decode,
    base64url_encode,
    decode_jwt_unverified,
    encode_jwt,
    validate_claims,
    verify_jwt,
)
from .mutual import (
    NONCE_EXPIRY_SECS,
    create_challenge,
    create_response,
    response_signing_input,
    validate_nonce,
    verify_response,
    verify_response_with_nonce_store,
)
from .net import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TIMEOUT_SECS,
    FetchedResponse,
    fetch_bounded,
    fetch_json_bounded,
    is_non_public,
)
from .nonce import (
    InMemoryNonceStore,
    NonceStore,
)
from .pinning import (
    KeyPinStore,
    PinningResult,
    check_pinning,
    check_pinning_set,
)
from .resolver_a2a import (
    A2aAgentCardResolver,
)
from .resolver_local import (
    LocalAgentCardStore,
    card_endpoint_host,
    card_key_published_in,
    derive_discovery_from_card,
)
from .resolver_wba import (
    CachingDirectoryResolver,
    DirectoryFetchOptions,
    fetch_directory,
)
from .revocation import (
    add_revoked_agent,
    add_revoked_credential,
    add_revoked_key,
    build_revocation_document,
    check_revocation,
    check_revocation_freshness,
    fetch_revocation_document,
    fetch_revocation_document_if_present,
    revocation_signing_input,
    sign_revocation_document,
    verify_revocation_document,
)
from .rotation import (
    apply_rotation,
    complete_rotation,
    prepare_rotation,
)
from .transport import (
    AUTH_TYPE,
    FIELD_NAME,
    GRPC_METADATA_KEY,
    grpc_extract_credential,
    grpc_format_metadata_value,
    http_extract_credential,
    http_format_authorization_header,
    mcp_extract_credential,
    mcp_format_meta_field,
    ws_extract_credential,
    ws_format_auth_message,
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
    DEFAULT_CREDENTIAL_TTL_MAX,
    check_key_usable,
    verify_credential,
    verify_credential_offline,
    verify_credential_with_resolver,
)
from .wba import (
    DIRECTORY_MEDIA_TYPE,
    DIRECTORY_PATH,
    DIRECTORY_TAG,
    MAX_DIRECTORY_KEYS,
    MAX_VALIDITY_SECS,
    BindingFailure,
    BoundAgent,
    Directory,
    DirectoryKeyStore,
    KeyLookup,
    SignedHeaders,
    SignOptions,
    VerifiedAgent,
    VerifyOptions,
    WbaOutcome,
    check_binding,
    find_key,
    generate_signing_key,
    load_signing_key,
    normalize_signature_agent,
    request_credential,
    sign_directory_response,
    sign_request,
    signing_key_to_pem,
    thumbprint,
    verify_bound_request,
    verify_directory_response,
    verify_request,
    well_known_directory,
)
from .wba import (
    TAG as WBA_TAG,
)
from .wba import (
    Jwk as WbaJwk,
)
from .wba import (
    PrivateKey as WbaPrivateKey,
)
from .wba import (
    PublicKey as WbaPublicKey,
)

__version__ = "0.3.0"

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
    "domain_separated_input",
    "sign_with_context",
    "verify_with_context",
    "CTX_RESPONSE",
    "CTX_ATTESTATION",
    "CTX_AGENTCARD",
    "CTX_REVOCATION",
    "CTX_BUNDLE",
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
    "validate_claims",
    "MalformedCredentialError",
    "CREDENTIAL_VERSION",
    # Capability
    "Capability",
    "capabilities_subset",
    "capabilities_hash",
    "validate_capability",
    "CORE_ACTIONS",
    # Constraint
    "parse_rate_limit",
    "domain_pattern_matches",
    "constraints_subset_of",
    "merge_constraints",
    # Credential
    "issue_credential",
    "issue_bound_credential",
    "validate_credential_against_discovery",
    # Discovery
    "build_discovery_document",
    "validate_discovery_document",
    "find_key_by_kid",
    "find_agent_by_id",
    "fetch_discovery_document",
    "AllowedDomains",
    # A2A AgentCard (v0.3.0)
    "agent_card_signing_input",
    "build_and_sign_agent_card",
    "build_unsigned_agent_card",
    "canonicalize_for_signing",
    "capability_to_skill",
    "extension_key_thumbprint",
    "sign_agent_card",
    "verify_agentpin_extension",
    # Domain normalization
    "normalize_domain",
    "https_url_host",
    "validate_https_url_for_domain",
    "default_revocation_endpoint",
    # DNS TXT (v0.3.0)
    "fetch_dns_txt",
    "parse_txt_record",
    "txt_record_name",
    "verify_dns_match",
    # Resolvers (v0.3.0)
    "LocalAgentCardStore",
    "A2aAgentCardResolver",
    "card_endpoint_host",
    "card_key_published_in",
    "derive_discovery_from_card",
    # Revocation
    "build_revocation_document",
    "add_revoked_credential",
    "add_revoked_agent",
    "add_revoked_key",
    "check_revocation",
    "fetch_revocation_document",
    "fetch_revocation_document_if_present",
    "revocation_signing_input",
    "sign_revocation_document",
    "verify_revocation_document",
    "check_revocation_freshness",
    # Network
    "fetch_json_bounded",
    "fetch_bounded",
    "FetchedResponse",
    "is_non_public",
    "DEFAULT_TIMEOUT_SECS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    # Pinning
    "KeyPinStore",
    "PinningResult",
    "check_pinning",
    "check_pinning_set",
    # Delegation
    "canonical_attestation_input",
    "create_attestation",
    "verify_attestation",
    "verify_chain_depth",
    # Mutual
    "create_challenge",
    "create_response",
    "verify_response",
    "verify_response_with_nonce_store",
    "validate_nonce",
    "response_signing_input",
    "NONCE_EXPIRY_SECS",
    # Nonce
    "NonceStore",
    "InMemoryNonceStore",
    # Rotation
    "prepare_rotation",
    "apply_rotation",
    "complete_rotation",
    # Transport
    "http_extract_credential",
    "http_format_authorization_header",
    "FIELD_NAME",
    "mcp_extract_credential",
    "mcp_format_meta_field",
    "AUTH_TYPE",
    "ws_extract_credential",
    "ws_format_auth_message",
    "GRPC_METADATA_KEY",
    "grpc_extract_credential",
    "grpc_format_metadata_value",
    # Verification
    "verify_credential_offline",
    "verify_credential",
    "verify_credential_with_resolver",
    "check_key_usable",
    "DEFAULT_CREDENTIAL_TTL_MAX",
    # Bundle
    "create_trust_bundle",
    "find_bundle_discovery",
    "find_bundle_revocation",
    "load_trust_bundle",
    "save_trust_bundle",
    "verify_credential_with_bundle",
    "bundle_signing_input",
    "sign_trust_bundle",
    "verify_trust_bundle",
    "check_bundle_expiry",
    # HTTP Message Signatures (RFC 9421)
    "Component",
    "HttpRequest",
    "HttpResponse",
    "ParsedSignature",
    "SignatureFields",
    "SignatureParams",
    "parse_signatures",
    "content_digest",
    "content_digest_matches",
    # Web Bot Auth (v0.4.0)
    "WBA_TAG",
    "DIRECTORY_TAG",
    "DIRECTORY_PATH",
    "DIRECTORY_MEDIA_TYPE",
    "MAX_DIRECTORY_KEYS",
    "MAX_VALIDITY_SECS",
    "WbaPrivateKey",
    "WbaPublicKey",
    "WbaJwk",
    "Directory",
    "DirectoryKeyStore",
    "KeyLookup",
    "SignOptions",
    "SignedHeaders",
    "VerifyOptions",
    "VerifiedAgent",
    "WbaOutcome",
    "BoundAgent",
    "BindingFailure",
    "generate_signing_key",
    "load_signing_key",
    "signing_key_to_pem",
    "thumbprint",
    "find_key",
    "normalize_signature_agent",
    "well_known_directory",
    "sign_request",
    "verify_request",
    "sign_directory_response",
    "verify_directory_response",
    "request_credential",
    "check_binding",
    "verify_bound_request",
    "DirectoryFetchOptions",
    "CachingDirectoryResolver",
    "fetch_directory",
]
