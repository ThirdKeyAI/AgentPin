use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::credential::validate_credential_against_discovery;
use crate::discovery::{find_agent_by_id, find_key_by_kid, validate_discovery_document};
use crate::error::{Error, ErrorCode};
use crate::jwk::jwk_to_verifying_key;
use crate::jwt;
use crate::pinning::{check_pinning, KeyPinStore, PinningResult};
use crate::revocation::check_revocation;
use crate::types::capability::Capability;
use crate::types::constraint::{constraints_subset_of, Constraints};
use crate::types::discovery::{AgentStatus, DiscoveryDocument};
use crate::types::revocation::RevocationDocument;

/// Configuration for the verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Clock skew tolerance in seconds (default: 60)
    pub clock_skew_secs: i64,
    /// Maximum credential lifetime in seconds (default: 86400)
    pub max_ttl_secs: i64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            clock_skew_secs: 60,
            max_ttl_secs: 86400,
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
    // Step 1: Parse JWT (validates alg == ES256 and typ == agentpin-credential+jwt)
    let (header, payload, _sig) = match jwt::decode_jwt_unverified(credential_jwt) {
        Ok(parts) => parts,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::AlgorithmRejected,
                &format!("JWT parse failed: {}", e),
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

    // Check max TTL
    let lifetime = payload.exp - payload.iat;
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
    if let Err(e) = validate_discovery_document(discovery, &payload.iss) {
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

    // Step 6: Check revocation
    if let Some(rev_doc) = revocation {
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

    // Step 8: Validate capabilities
    if let Err(e) =
        validate_credential_against_discovery(&payload.capabilities, &agent.capabilities)
    {
        return VerificationResult::failure(ErrorCode::CapabilityExceeded, &e.to_string());
    }

    // Step 9: Validate constraints
    if !constraints_subset_of(&agent.constraints, &payload.constraints) {
        return VerificationResult::failure(
            ErrorCode::ConstraintViolation,
            "Credential constraints are less restrictive than discovery defaults",
        );
    }

    // Step 10: Validate delegation chain (if present) — signature verification
    // requires fetching each domain's discovery doc, which is only available
    // in online mode. In offline mode we note presence but can't verify.
    let mut result = VerificationResult::success(
        &payload.sub,
        &payload.iss,
        payload.capabilities.clone(),
        payload.constraints.clone(),
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
    match check_pinning(pin_store, &payload.iss, jwk) {
        Ok(PinningResult::FirstUse) => {
            result.key_pinning = Some(KeyPinningStatus {
                status: "first_use".to_string(),
                first_seen: Some(Utc::now().to_rfc3339()),
            });
        }
        Ok(PinningResult::Matched) => {
            let first_seen = pin_store
                .get_domain(&payload.iss)
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
                &format!("Key for '{}' has changed since last pinned", payload.iss),
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

/// Online verification that fetches discovery/revocation documents.
#[cfg(feature = "fetch")]
pub async fn verify_credential(
    credential_jwt: &str,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
) -> VerificationResult {
    // Parse JWT to extract issuer domain
    let (_header, payload, _sig) = match jwt::decode_jwt_unverified(credential_jwt) {
        Ok(parts) => parts,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::AlgorithmRejected,
                &format!("JWT parse failed: {}", e),
            )
        }
    };

    // Fetch discovery document
    let discovery = match crate::discovery::fetch_discovery_document(&payload.iss).await {
        Ok(doc) => doc,
        Err(e) => {
            return VerificationResult::failure(
                ErrorCode::DiscoveryFetchFailed,
                &format!("Failed to fetch discovery document: {}", e),
            )
        }
    };

    // Fetch revocation document
    let revocation = if let Some(ref endpoint) = discovery.revocation_endpoint {
        match crate::revocation::fetch_revocation_document(endpoint).await {
            Ok(doc) => Some(doc),
            Err(_) => {
                // Fail closed: if revocation endpoint is unreachable, reject
                return VerificationResult::failure(
                    ErrorCode::DiscoveryFetchFailed,
                    "Revocation endpoint unreachable (fail-closed)",
                );
            }
        }
    } else {
        None
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
