use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::credential::validate_credential_against_discovery;
use crate::discovery::{find_agent_by_id, find_key_by_kid, validate_discovery_document};
use crate::domain::normalize_domain;
use crate::error::{Error, ErrorCode};
use crate::jwk::jwk_to_verifying_key;
use crate::jwt;
use crate::pinning::{check_pinning, KeyPinStore, PinningResult};
use crate::resolver::DiscoveryResolver;
use crate::revocation::check_revocation;
use crate::types::capability::Capability;
use crate::types::constraint::{merge_constraints, Constraints};
use crate::types::discovery::{AgentStatus, DiscoveryDocument};
use crate::types::revocation::RevocationDocument;

/// Configuration for the verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Clock skew tolerance in seconds (default: 60)
    pub clock_skew_secs: i64,
    /// Maximum credential lifetime in seconds (default: 86400)
    pub max_ttl_secs: i64,
    /// When true, capabilities are validated against the taxonomy (default: false)
    pub strict_capabilities: bool,
    /// When true, an unsigned revocation document is rejected (default:
    /// false). Signed documents are always verified when a signature is
    /// present.
    pub require_signed_revocation: bool,
    /// When set, a revocation document whose `updated_at` is older than
    /// this many seconds (or unparsable) is rejected (default: `None`).
    pub revocation_max_age_secs: Option<i64>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            clock_skew_secs: 60,
            max_ttl_secs: 86400,
            strict_capabilities: false,
            require_signed_revocation: false,
            revocation_max_age_secs: None,
        }
    }
}

/// Structured verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<Capability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_chain: Option<Vec<DelegationChainEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pinning: Option<KeyPinningStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChainEntry {
    pub domain: String,
    pub role: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPinningStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
}

impl VerificationResult {
    fn success(
        agent_id: &str,
        issuer: &str,
        capabilities: Vec<Capability>,
        constraints: Option<Constraints>,
        pin_status: KeyPinningStatus,
    ) -> Self {
        Self {
            valid: true,
            agent_id: Some(agent_id.to_string()),
            issuer: Some(issuer.to_string()),
            capabilities: Some(capabilities),
            constraints,
            delegation_verified: None,
            delegation_chain: None,
            key_pinning: Some(pin_status),
            error_code: None,
            error_message: None,
            warnings: vec![],
        }
    }

    fn failure(code: ErrorCode, message: &str) -> Self {
        Self {
            valid: false,
            agent_id: None,
            issuer: None,
            capabilities: None,
            constraints: None,
            delegation_verified: None,
            delegation_chain: None,
            key_pinning: None,
            error_code: Some(code),
            error_message: Some(message.to_string()),
            warnings: vec![],
        }
    }
}

/// Map a decode error to a verification failure: claim-shape problems are
/// MALFORMED_CREDENTIAL, everything else (structure, alg, typ) is
/// ALGORITHM_REJECTED as before.
fn parse_failure(e: Error) -> VerificationResult {
    match e {
        Error::MalformedCredential(msg) => {
            VerificationResult::failure(ErrorCode::MalformedCredential, &msg)
        }
        other => VerificationResult::failure(
            ErrorCode::AlgorithmRejected,
            &format!("JWT parse failed: {}", other),
        ),
    }
}

/// Default `credential_ttl_max` when an agent declaration omits it (spec §4.5).
pub const DEFAULT_CREDENTIAL_TTL_MAX: u64 = 86400;

/// Verify a credential offline using caller-provided documents.
/// Implements the 12-step verification flow from the spec.
pub fn verify_credential_offline(
    credential_jwt: &str,
    discovery: &DiscoveryDocument,
    revocation: Option<&RevocationDocument>,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
) -> VerificationResult {
    // Step 1: Parse JWT (validates alg == ES256 and typ == agentpin-credential+jwt,
    // then claim shape — AP-5 / AP-18)
    let (header, payload, _sig) = match jwt::decode_jwt_unverified(credential_jwt) {
        Ok(parts) => parts,
        Err(e) => return parse_failure(e),
    };

    // Normalize the issuer domain before it is used as a lookup key anywhere
    // (pin store, entity comparison, resolver paths/URLs) — AP-3.
    let issuer = match normalize_domain(&payload.iss) {
        Ok(d) => d,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryInvalid,
                &format!("Invalid issuer domain: {}", e),
            )
        }
    };

    // Step 2: Check temporal validity
    let now = Utc::now().timestamp();
    let skew = config.clock_skew_secs;

    if payload.iat > now + skew {
        return VerificationResult::failure(
            ErrorCode::CredentialExpired,
            "Credential issued in the future",
        );
    }
    if payload.exp <= now - skew {
        return VerificationResult::failure(ErrorCode::CredentialExpired, "Credential has expired");
    }
    if let Some(nbf) = payload.nbf {
        if nbf > now + skew {
            return VerificationResult::failure(
                ErrorCode::CredentialExpired,
                "Credential not yet valid (nbf)",
            );
        }
    }

    // Check max TTL. Claims were validated non-negative with exp > iat, so
    // the subtraction cannot wrap; use checked arithmetic anyway (AP-14).
    let lifetime = match payload.exp.checked_sub(payload.iat) {
        Some(l) if l > 0 => l,
        _ => {
            return VerificationResult::failure(
                ErrorCode::MalformedCredential,
                "exp must be greater than iat",
            )
        }
    };
    if lifetime > config.max_ttl_secs {
        return VerificationResult::failure(
            ErrorCode::CredentialExpired,
            &format!(
                "Credential lifetime {} exceeds max TTL {}",
                lifetime, config.max_ttl_secs
            ),
        );
    }

    // Step 3: Validate discovery document (entity matches iss)
    if let Err(e) = validate_discovery_document(discovery, &issuer) {
        return VerificationResult::failure(
            ErrorCode::DiscoveryInvalid,
            &format!("Discovery validation failed: {}", e),
        );
    }

    // Step 4: Resolve public key by kid
    let jwk = match find_key_by_kid(discovery, &header.kid) {
        Some(k) => k,
        None => {
            return VerificationResult::failure(
                ErrorCode::KeyNotFound,
                &format!("Key '{}' not found in discovery document", header.kid),
            )
        }
    };

    // Check key expiration
    if let Some(ref exp_str) = jwk.exp {
        if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
            if exp_dt.timestamp() < now - skew {
                return VerificationResult::failure(
                    ErrorCode::KeyExpired,
                    &format!("Key '{}' has expired", header.kid),
                );
            }
        }
    }

    // Convert JWK to verifying key
    let verifying_key = match jwk_to_verifying_key(jwk) {
        Ok(vk) => vk,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::KeyNotFound,
                &format!("Invalid key format for '{}': {}", header.kid, e),
            )
        }
    };

    // Step 5: Verify JWT signature
    if jwt::verify_jwt(credential_jwt, &verifying_key).is_err() {
        return VerificationResult::failure(
            ErrorCode::SignatureInvalid,
            &format!("JWT signature verification failed for kid '{}'", header.kid),
        );
    }

    // Step 6: Check revocation. The document must belong to this issuer and,
    // when signed, verify under a discovery key (design issue 3).
    if let Some(rev_doc) = revocation {
        if let Err(e) = crate::revocation::verify_revocation_document(rev_doc, discovery) {
            return VerificationResult::failure(
                ErrorCode::DiscoveryInvalid,
                &format!("Revocation document invalid: {}", e),
            );
        }
        if config.require_signed_revocation && rev_doc.signature.is_none() {
            return VerificationResult::failure(
                ErrorCode::DiscoveryInvalid,
                "Revocation document is not signed",
            );
        }
        if let Some(max_age) = config.revocation_max_age_secs {
            if let Err(e) = crate::revocation::check_revocation_freshness(rev_doc, max_age) {
                return VerificationResult::failure(
                    ErrorCode::DiscoveryInvalid,
                    &format!("Revocation document invalid: {}", e),
                );
            }
        }
        if let Err(e) = check_revocation(rev_doc, &payload.jti, &payload.sub, &header.kid) {
            let code = match &e {
                Error::Verification { code, .. } => *code,
                _ => ErrorCode::CredentialRevoked,
            };
            return VerificationResult::failure(code, &e.to_string());
        }
    }

    // Step 7: Validate agent status
    let agent = match find_agent_by_id(discovery, &payload.sub) {
        Some(a) => a,
        None => {
            return VerificationResult::failure(
                ErrorCode::AgentNotFound,
                &format!("Agent '{}' not found in discovery document", payload.sub),
            )
        }
    };

    if agent.status != AgentStatus::Active {
        return VerificationResult::failure(
            ErrorCode::AgentInactive,
            &format!("Agent '{}' status is {:?}", payload.sub, agent.status),
        );
    }

    // Spec §5.7: exp - iat MUST NOT exceed the agent's credential_ttl_max
    // (default 86400 when omitted) — AP-14.
    let ttl_max = agent
        .credential_ttl_max
        .unwrap_or(DEFAULT_CREDENTIAL_TTL_MAX);
    if u64::try_from(lifetime).map_or(true, |l| l > ttl_max) {
        return VerificationResult::failure(
            ErrorCode::CredentialExpired,
            &format!(
                "Credential lifetime {} exceeds agent credential_ttl_max {}",
                lifetime, ttl_max
            ),
        );
    }

    // Step 8: Validate capabilities
    if let Err(e) =
        validate_credential_against_discovery(&payload.capabilities, &agent.capabilities)
    {
        return VerificationResult::failure(ErrorCode::CapabilityExceeded, &e.to_string());
    }

    // Step 9: Validate constraints and compute the effective (merged) set the
    // consumer must enforce: discovery defaults narrowed by the credential
    // (AP-15).
    let effective_constraints =
        match merge_constraints(agent.constraints.as_ref(), payload.constraints.as_ref()) {
            Ok(merged) => merged,
            Err(reason) => {
                return VerificationResult::failure(
                    ErrorCode::ConstraintViolation,
                    &format!(
                        "Credential constraints are less restrictive than discovery defaults: {}",
                        reason
                    ),
                )
            }
        };

    // Step 10: Validate delegation chain (if present) — signature verification
    // requires fetching each domain's discovery doc, which is only available
    // in online mode. In offline mode we note presence but can't verify.
    let mut result = VerificationResult::success(
        &payload.sub,
        &issuer,
        payload.capabilities.clone(),
        effective_constraints,
        KeyPinningStatus {
            status: "unknown".to_string(),
            first_seen: None,
        },
    );

    if let Some(ref chain) = payload.delegation_chain {
        let entries: Vec<DelegationChainEntry> = chain
            .iter()
            .map(|att| DelegationChainEntry {
                domain: att.domain.clone(),
                role: serde_json::to_string(&att.role)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                verified: false, // Offline mode can't verify delegation signatures
            })
            .collect();
        result.delegation_chain = Some(entries);
        result.delegation_verified = Some(false);
        result
            .warnings
            .push("Delegation chain present but not verified in offline mode".to_string());
    }

    // Step 11: TOFU key pinning
    match check_pinning(pin_store, &issuer, jwk) {
        Ok(PinningResult::FirstUse) => {
            result.key_pinning = Some(KeyPinningStatus {
                status: "first_use".to_string(),
                first_seen: Some(Utc::now().to_rfc3339()),
            });
        }
        Ok(PinningResult::Matched) => {
            let first_seen = pin_store
                .get_domain(&issuer)
                .and_then(|d| d.pinned_keys.first())
                .map(|pk| pk.first_seen.clone());
            result.key_pinning = Some(KeyPinningStatus {
                status: "pinned".to_string(),
                first_seen,
            });
        }
        Ok(PinningResult::Changed) | Err(_) => {
            return VerificationResult::failure(
                ErrorCode::KeyPinMismatch,
                &format!("Key for '{}' has changed since last pinned", issuer),
            );
        }
    }

    // Step 12: Check audience
    if let Some(aud) = audience {
        if let Some(ref cred_aud) = payload.aud {
            if cred_aud != "*" && cred_aud != aud {
                return VerificationResult::failure(
                    ErrorCode::AudienceMismatch,
                    &format!(
                        "Credential audience '{}' does not match verifier '{}'",
                        cred_aud, aud
                    ),
                );
            }
        }
    }

    result
}

/// Verify a credential using a sync [`DiscoveryResolver`].
///
/// This function extracts the issuer domain from the JWT, uses the resolver to
/// obtain the discovery and revocation documents, then delegates to
/// [`verify_credential_offline`].
pub fn verify_credential_with_resolver(
    credential_jwt: &str,
    resolver: &dyn DiscoveryResolver,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
) -> VerificationResult {
    let (_header, payload, _sig) = match jwt::decode_jwt_unverified(credential_jwt) {
        Ok(parts) => parts,
        Err(e) => return parse_failure(e),
    };

    let issuer = match normalize_domain(&payload.iss) {
        Ok(d) => d,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryInvalid,
                &format!("Invalid issuer domain: {}", e),
            )
        }
    };

    let discovery = match resolver.resolve_discovery(&issuer) {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to resolve discovery document: {}", e),
            )
        }
    };

    let revocation = match resolver.resolve_revocation(&issuer, &discovery) {
        Ok(doc) => doc,
        Err(_) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                "Revocation document unreachable (fail-closed)",
            );
        }
    };

    verify_credential_offline(
        credential_jwt,
        &discovery,
        revocation.as_ref(),
        pin_store,
        audience,
        config,
    )
}

/// Verify a credential using an [`AsyncDiscoveryResolver`].
#[cfg(feature = "fetch")]
pub async fn verify_credential_with_async_resolver(
    credential_jwt: &str,
    resolver: &dyn crate::resolver::AsyncDiscoveryResolver,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
) -> VerificationResult {
    let (_header, payload, _sig) = match jwt::decode_jwt_unverified(credential_jwt) {
        Ok(parts) => parts,
        Err(e) => return parse_failure(e),
    };

    let issuer = match normalize_domain(&payload.iss) {
        Ok(d) => d,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryInvalid,
                &format!("Invalid issuer domain: {}", e),
            )
        }
    };

    let discovery = match resolver.resolve_discovery(&issuer).await {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to resolve discovery document: {}", e),
            )
        }
    };

    let revocation = match resolver.resolve_revocation(&issuer, &discovery).await {
        Ok(doc) => doc,
        Err(_) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                "Revocation document unreachable (fail-closed)",
            );
        }
    };

    verify_credential_offline(
        credential_jwt,
        &discovery,
        revocation.as_ref(),
        pin_store,
        audience,
        config,
    )
}

/// Online verification that fetches discovery/revocation documents.
///
/// This delegates to [`verify_credential_with_async_resolver`] using
/// [`WellKnownResolver`](crate::resolver::WellKnownResolver).
#[cfg(feature = "fetch")]
pub async fn verify_credential(
    credential_jwt: &str,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
) -> VerificationResult {
    verify_credential_with_async_resolver(
        credential_jwt,
        &crate::resolver::WellKnownResolver,
        pin_store,
        audience,
        config,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::issue_credential;
    use crate::crypto;
    use crate::discovery::build_discovery_document;
    use crate::jwk::verifying_key_to_jwk;
    use crate::revocation::{add_revoked_agent, add_revoked_credential, build_revocation_document};
    use crate::types::capability::Capability;
    use crate::types::constraint::{Constraints, DataClassification};
    use crate::types::discovery::{AgentDeclaration, AgentStatus, EntityType};

    struct TestFixture {
        jwt: String,
        discovery: DiscoveryDocument,
        revocation: RevocationDocument,
        pin_store: KeyPinStore,
        config: VerifierConfig,
        private_key_pem: String,
    }

    fn setup() -> TestFixture {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let jwk = verifying_key_to_jwk(&vk, "test-2026-01");

        let discovery = build_discovery_document(
            "example.com",
            EntityType::Maker,
            vec![jwk],
            vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:agent".to_string(),
                agent_type: None,
                name: "Test Agent".to_string(),
                description: None,
                version: None,
                capabilities: vec![Capability::from("read:*"), Capability::from("write:report")],
                constraints: Some(Constraints {
                    data_classification_max: Some(DataClassification::Confidential),
                    rate_limit: Some("100/hour".to_string()),
                    ..Default::default()
                }),
                maker_attestation: None,
                credential_ttl_max: Some(3600),
                status: AgentStatus::Active,
                directory_listing: None,
            }],
            2,
            "2026-01-15T00:00:00Z",
        );

        let jwt = issue_credential(
            &sk,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![
                Capability::from("read:data"),
                Capability::from("write:report"),
            ],
            Some(Constraints {
                data_classification_max: Some(DataClassification::Internal),
                rate_limit: Some("50/hour".to_string()),
                ..Default::default()
            }),
            None,
            3600,
        )
        .unwrap();

        let revocation = build_revocation_document("example.com");

        TestFixture {
            jwt,
            discovery,
            revocation,
            pin_store: KeyPinStore::new(),
            config: VerifierConfig::default(),
            private_key_pem: kp.private_key_pem.clone(),
        }
    }

    #[test]
    fn test_happy_path_verification() {
        let mut f = setup();
        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(result.valid, "Expected valid, got: {:?}", result);
        assert_eq!(
            result.agent_id,
            Some("urn:agentpin:example.com:agent".to_string())
        );
        assert_eq!(result.issuer, Some("example.com".to_string()));
    }

    #[test]
    fn test_expired_credential() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let jwk = verifying_key_to_jwk(&vk, "test-2026-01");

        let discovery = build_discovery_document(
            "example.com",
            EntityType::Maker,
            vec![jwk],
            vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:agent".to_string(),
                agent_type: None,
                name: "Test".to_string(),
                description: None,
                version: None,
                capabilities: vec![Capability::from("read:*")],
                constraints: None,
                maker_attestation: None,
                credential_ttl_max: Some(86400),
                status: AgentStatus::Active,
                directory_listing: None,
            }],
            2,
            "2026-01-15T00:00:00Z",
        );

        // Issue a credential with timestamps in the past
        let header = crate::types::credential::JwtHeader {
            alg: "ES256".to_string(),
            typ: "agentpin-credential+jwt".to_string(),
            kid: "test-2026-01".to_string(),
        };
        let payload = crate::types::credential::JwtPayload {
            iss: "example.com".to_string(),
            sub: "urn:agentpin:example.com:agent".to_string(),
            aud: None,
            iat: 1000000,
            exp: 1003600, // Long expired
            nbf: None,
            jti: "expired-jti".to_string(),
            agentpin_version: "0.1".to_string(),
            capabilities: vec![Capability::from("read:data")],
            constraints: None,
            delegation_chain: None,
            nonce: None,
        };
        let jwt_str = jwt::encode_jwt(&header, &payload, &sk).unwrap();

        let mut pin_store = KeyPinStore::new();
        let config = VerifierConfig::default();
        let result =
            verify_credential_offline(&jwt_str, &discovery, None, &mut pin_store, None, &config);
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::CredentialExpired));
    }

    #[test]
    fn test_wrong_algorithm_rejected() {
        // Manually craft a JWT with wrong alg by encoding directly
        let result = verify_credential_offline(
            "invalid.jwt.token",
            &setup().discovery,
            None,
            &mut KeyPinStore::new(),
            None,
            &VerifierConfig::default(),
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::AlgorithmRejected));
    }

    #[test]
    fn test_credential_revoked() {
        let mut f = setup();
        // Parse the JWT to get the jti
        let (_, payload, _) = jwt::decode_jwt_unverified(&f.jwt).unwrap();
        add_revoked_credential(
            &mut f.revocation,
            &payload.jti,
            crate::types::revocation::RevocationReason::KeyCompromise,
        );

        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::CredentialRevoked));
    }

    #[test]
    fn test_agent_revoked() {
        let mut f = setup();
        add_revoked_agent(
            &mut f.revocation,
            "urn:agentpin:example.com:agent",
            crate::types::revocation::RevocationReason::PrivilegeWithdrawn,
        );

        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(!result.valid);
    }

    #[test]
    fn test_inactive_agent() {
        let mut f = setup();
        f.discovery.agents[0].status = AgentStatus::Suspended;

        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::AgentInactive));
    }

    #[test]
    fn test_capability_exceeded() {
        let mut f = setup();
        // Remove all capabilities from discovery
        f.discovery.agents[0].capabilities = vec![Capability::from("read:limited")];

        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::CapabilityExceeded));
    }

    #[test]
    fn test_audience_mismatch() {
        let mut f = setup();
        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("wrong-verifier.com"),
            &f.config,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::AudienceMismatch));
    }

    #[test]
    fn test_key_pin_change_rejected() {
        let mut f = setup();
        // First verification pins the key
        let result1 = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(result1.valid);

        // Now change the key in the discovery document
        let kp2 = crypto::generate_key_pair().unwrap();
        let vk2 = crypto::load_verifying_key(&kp2.public_key_pem).unwrap();
        let jwk2 = verifying_key_to_jwk(&vk2, "test-2026-01");
        f.discovery.public_keys = vec![jwk2];

        // Reissue credential with new key
        let sk2 = crypto::load_signing_key(&kp2.private_key_pem).unwrap();
        let jwt2 = issue_credential(
            &sk2,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            None,
            None,
            3600,
        )
        .unwrap();

        let result2 = verify_credential_offline(
            &jwt2,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(!result2.valid);
        assert_eq!(result2.error_code, Some(ErrorCode::KeyPinMismatch));
    }

    #[test]
    fn test_verify_with_trust_bundle_resolver() {
        let f = setup();
        let bundle = crate::types::bundle::TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![f.discovery.clone()],
            revocations: vec![f.revocation.clone()],
            expires_at: None,
            kid: None,
            signature: None,
        };
        let resolver = crate::resolver::TrustBundleResolver::new(&bundle);
        let mut pin_store = KeyPinStore::new();
        let config = VerifierConfig::default();

        let result = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut pin_store,
            Some("verifier.com"),
            &config,
        );
        assert!(result.valid, "Expected valid, got: {:?}", result);
        assert_eq!(
            result.agent_id,
            Some("urn:agentpin:example.com:agent".to_string())
        );
    }

    #[test]
    fn test_verify_with_resolver_missing_domain() {
        let f = setup();
        let bundle = crate::types::bundle::TrustBundle::new("2026-02-10T00:00:00Z");
        let resolver = crate::resolver::TrustBundleResolver::new(&bundle);
        let mut pin_store = KeyPinStore::new();
        let config = VerifierConfig::default();

        let result = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut pin_store,
            Some("verifier.com"),
            &config,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::DiscoveryFetchFailed));
    }

    #[test]
    fn test_domain_mismatch() {
        let mut f = setup();
        f.discovery.entity = "other.com".to_string();

        let result = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            None,
            &f.config,
        );
        assert!(!result.valid);
        assert_eq!(result.error_code, Some(ErrorCode::DiscoveryInvalid));
    }

    /// AP-3: a case variant of a pinned issuer must hit the existing pin,
    /// not create a fresh first-use entry under a different key.
    #[test]
    fn test_case_variant_iss_hits_existing_pin() {
        let mut f = setup();
        let r1 = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(r1.valid, "{:?}", r1);

        // Attacker controlling the host publishes a doc for "EXAMPLE.COM"
        // with their own key and issues credentials with iss "EXAMPLE.COM".
        let kp2 = crypto::generate_key_pair().unwrap();
        let sk2 = crypto::load_signing_key(&kp2.private_key_pem).unwrap();
        let vk2 = crypto::load_verifying_key(&kp2.public_key_pem).unwrap();
        let mut evil_doc = f.discovery.clone();
        evil_doc.entity = "EXAMPLE.COM".to_string();
        evil_doc.public_keys = vec![verifying_key_to_jwk(&vk2, "evil-key")];
        let evil_jwt = issue_credential(
            &sk2,
            "evil-key",
            "EXAMPLE.COM",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            None,
            None,
            3600,
        )
        .unwrap();
        let r2 = verify_credential_offline(
            &evil_jwt,
            &evil_doc,
            None,
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(!r2.valid);
        assert_eq!(r2.error_code, Some(ErrorCode::KeyPinMismatch));
        // Only one pin entry exists, under the normalized name.
        assert!(f.pin_store.get_domain("example.com").is_some());
        assert_eq!(
            f.pin_store
                .get_domain("example.com")
                .unwrap()
                .pinned_keys
                .len(),
            1
        );
    }

    /// AP-3: issuer and entity are compared after normalization, so a
    /// trailing dot or different case on either side is not a mismatch.
    #[test]
    fn test_issuer_entity_compared_normalized() {
        let mut f = setup();
        f.discovery.entity = "Example.COM.".to_string();
        let r = verify_credential_offline(
            &f.jwt,
            &f.discovery,
            Some(&f.revocation),
            &mut f.pin_store,
            Some("verifier.com"),
            &f.config,
        );
        assert!(r.valid, "{:?}", r);
        assert_eq!(r.issuer.as_deref(), Some("example.com"));
    }

    /// AP-10 / AP-12: an iss that is not a bare hostname is rejected before
    /// it can reach a file path, URL or pin store.
    #[test]
    fn test_non_hostname_iss_rejected() {
        let f = setup();
        for bad_iss in [
            "127.0.0.1:8443",
            "../../tmp/x",
            "/srv/uploads/x",
            "example.com/path",
            "user@example.com",
        ] {
            let kp = crypto::generate_key_pair().unwrap();
            let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
            let jwt = issue_credential(
                &sk,
                "test-2026-01",
                bad_iss,
                "urn:agentpin:example.com:agent",
                None,
                vec![Capability::from("read:data")],
                None,
                None,
                3600,
            )
            .unwrap();
            let r = verify_credential_offline(
                &jwt,
                &f.discovery,
                None,
                &mut KeyPinStore::new(),
                None,
                &f.config,
            );
            assert!(!r.valid);
            assert_eq!(
                r.error_code,
                Some(ErrorCode::DiscoveryInvalid),
                "iss={}",
                bad_iss
            );
            let r = verify_credential_with_resolver(
                &jwt,
                &crate::resolver::LocalFileResolver::new(std::path::Path::new("/"), None),
                &mut KeyPinStore::new(),
                None,
                &f.config,
            );
            assert_eq!(
                r.error_code,
                Some(ErrorCode::DiscoveryInvalid),
                "iss={}",
                bad_iss
            );
        }
    }

    /// Design issue 3: a revocation document for another entity, a badly
    /// signed one, an unsigned one under require_signed_revocation, or a
    /// stale one under revocation_max_age_secs all fail closed.
    #[test]
    fn test_revocation_document_validation() {
        let f = setup();
        let run = |f: &TestFixture, rev: &RevocationDocument, cfg: &VerifierConfig| {
            verify_credential_offline(
                &f.jwt,
                &f.discovery,
                Some(rev),
                &mut KeyPinStore::new(),
                Some("verifier.com"),
                cfg,
            )
        };
        let mut foreign = f.revocation.clone();
        foreign.entity = "other.com".to_string();
        let r = run(&f, &foreign, &VerifierConfig::default());
        assert_eq!(r.error_code, Some(ErrorCode::DiscoveryInvalid));

        let strict = VerifierConfig {
            require_signed_revocation: true,
            ..Default::default()
        };
        let unsigned = f.revocation.clone();
        let r = run(&f, &unsigned, &strict);
        assert_eq!(r.error_code, Some(ErrorCode::DiscoveryInvalid));

        // Signed with the discovery key: accepted under strict config.
        let sk = crypto::load_signing_key(&f.private_key_pem).unwrap();
        let mut signed = f.revocation.clone();
        crate::revocation::sign_revocation_document(&mut signed, &sk, "test-2026-01").unwrap();
        let r = run(&f, &signed, &strict);
        assert!(r.valid, "{:?}", r);

        // Tampered after signing: rejected even without strict config.
        let mut tampered = signed.clone();
        tampered.updated_at = "2030-01-01T00:00:00Z".to_string();
        let r = run(&f, &tampered, &VerifierConfig::default());
        assert_eq!(r.error_code, Some(ErrorCode::DiscoveryInvalid));

        let aged = VerifierConfig {
            revocation_max_age_secs: Some(60),
            ..Default::default()
        };
        let mut stale = f.revocation.clone();
        stale.updated_at = (Utc::now() - chrono::Duration::seconds(3600)).to_rfc3339();
        let r = run(&f, &stale, &aged);
        assert_eq!(r.error_code, Some(ErrorCode::DiscoveryInvalid));
        let fresh = f.revocation.clone();
        let r = run(&f, &fresh, &aged);
        assert!(r.valid, "{:?}", r);
    }

    fn raw_credential(sk: &p256::ecdsa::SigningKey, payload_json: &str) -> String {
        let header = jwt::base64url_encode(
            br#"{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"test-2026-01"}"#,
        );
        let signing_input = format!(
            "{}.{}",
            header,
            jwt::base64url_encode(payload_json.as_bytes())
        );
        let sig = crypto::sign_bytes(sk, signing_input.as_bytes());
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig).unwrap();
        format!("{}.{}", signing_input, jwt::base64url_encode(&der))
    }

    /// AP-5 / AP-14 / AP-18: credentials with a missing, string or negative
    /// exp/iat, or exp <= iat, fail with MALFORMED_CREDENTIAL even when
    /// correctly signed, and a huge-TTL credential with i64::MIN iat does
    /// not bypass the max-TTL cap.
    #[test]
    fn test_malformed_claims_rejected() {
        let f = setup();
        let sk = crypto::load_signing_key(&f.private_key_pem).unwrap();
        let now = Utc::now().timestamp();
        let base = r#""iss":"example.com","sub":"urn:agentpin:example.com:agent","jti":"j","agentpin_version":"0.1","capabilities":["read:data"]"#;
        let cases = [
            format!("{{{},\"iat\":{}}}", base, now),
            format!("{{{},\"iat\":{},\"exp\":\"never\"}}", base, now),
            format!(
                "{{{},\"iat\":-9223372036854775808,\"exp\":{}}}",
                base,
                now + 315360000
            ),
            format!("{{{},\"iat\":{},\"exp\":{}}}", base, now, now),
        ];
        for payload in cases {
            let jwt = raw_credential(&sk, &payload);
            let r = verify_credential_offline(
                &jwt,
                &f.discovery,
                None,
                &mut KeyPinStore::new(),
                None,
                &VerifierConfig::default(),
            );
            assert!(!r.valid, "{}", payload);
            assert_eq!(
                r.error_code,
                Some(ErrorCode::MalformedCredential),
                "{}",
                payload
            );
        }
    }

    /// AP-14: the agent's declared credential_ttl_max is enforced
    /// (default 86400 when omitted).
    #[test]
    fn test_credential_ttl_max_enforced() {
        let mut f = setup();
        f.discovery.agents[0].credential_ttl_max = Some(600);
        let sk = crypto::load_signing_key(&f.private_key_pem).unwrap();
        let long = issue_credential(
            &sk,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            None,
            None,
            3600,
        )
        .unwrap();
        let r = verify_credential_offline(
            &long,
            &f.discovery,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &f.config,
        );
        assert_eq!(r.error_code, Some(ErrorCode::CredentialExpired));
        assert!(r.error_message.unwrap().contains("credential_ttl_max"));

        let short = issue_credential(
            &sk,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            None,
            None,
            600,
        )
        .unwrap();
        let r = verify_credential_offline(
            &short,
            &f.discovery,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &f.config,
        );
        assert!(r.valid, "{:?}", r);

        // Omitted credential_ttl_max defaults to 86400: a 2-day credential fails
        // even when the verifier's own cap is raised.
        f.discovery.agents[0].credential_ttl_max = None;
        let two_days = issue_credential(
            &sk,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            None,
            None,
            172800,
        )
        .unwrap();
        let lax = VerifierConfig {
            max_ttl_secs: 10 * 86400,
            ..Default::default()
        };
        let r = verify_credential_offline(
            &two_days,
            &f.discovery,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &lax,
        );
        assert_eq!(r.error_code, Some(ErrorCode::CredentialExpired));
    }

    /// AP-15: a credential that omits constraints inherits the discovery
    /// declaration's constraints in the result instead of reporting none.
    #[test]
    fn test_omitted_constraints_inherit_discovery_defaults() {
        let mut f = setup();
        f.discovery.agents[0].constraints = Some(Constraints {
            allowed_domains: Some(vec!["*.client-corp.com".to_string()]),
            rate_limit: Some("100/hour".to_string()),
            ..Default::default()
        });
        let sk = crypto::load_signing_key(&f.private_key_pem).unwrap();
        let jwt = issue_credential(
            &sk,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            None,
            None,
            3600,
        )
        .unwrap();
        let r = verify_credential_offline(
            &jwt,
            &f.discovery,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &f.config,
        );
        assert!(r.valid, "{:?}", r);
        let c = r
            .constraints
            .expect("effective constraints must be present");
        assert_eq!(
            c.allowed_domains,
            Some(vec!["*.client-corp.com".to_string()])
        );
        assert_eq!(c.rate_limit.as_deref(), Some("100/hour"));

        // A credential that tries to widen allowed_domains is rejected.
        let wide = issue_credential(
            &sk,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            vec![Capability::from("read:data")],
            Some(Constraints {
                allowed_domains: Some(vec!["evil.com".to_string()]),
                ..Default::default()
            }),
            None,
            3600,
        )
        .unwrap();
        let r = verify_credential_offline(
            &wide,
            &f.discovery,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &f.config,
        );
        assert_eq!(r.error_code, Some(ErrorCode::ConstraintViolation));
    }

    #[test]
    fn test_wildcard_audience_accepted() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let jwk = verifying_key_to_jwk(&vk, "test-key");

        let discovery = build_discovery_document(
            "example.com",
            EntityType::Maker,
            vec![jwk],
            vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:agent".to_string(),
                agent_type: None,
                name: "Test".to_string(),
                description: None,
                version: None,
                capabilities: vec![Capability::from("read:*")],
                constraints: None,
                maker_attestation: None,
                credential_ttl_max: Some(3600),
                status: AgentStatus::Active,
                directory_listing: None,
            }],
            2,
            "2026-01-15T00:00:00Z",
        );

        // Issue with wildcard audience
        let jwt_str = issue_credential(
            &sk,
            "test-key",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("*"),
            vec![Capability::from("read:data")],
            None,
            None,
            3600,
        )
        .unwrap();

        let mut pin_store = KeyPinStore::new();
        let result = verify_credential_offline(
            &jwt_str,
            &discovery,
            None,
            &mut pin_store,
            Some("any-verifier.com"),
            &VerifierConfig::default(),
        );
        assert!(result.valid, "Wildcard audience should be accepted");
    }
}
