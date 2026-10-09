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
    /// When true (default), a credential carrying a `delegation_chain` is
    /// rejected with DELEGATION_INVALID unless every attestation in the
    /// chain was cryptographically verified against the attester's
    /// discovery document (spec §6.1 step 10 / §6.4). Set to false only to
    /// accept unverified chains, which are then reported with
    /// `delegation_verified: false` and a warning (AP-2, design issue 10).
    pub require_delegation_verification: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            clock_skew_secs: 60,
            max_ttl_secs: 86400,
            strict_capabilities: false,
            require_signed_revocation: false,
            revocation_max_age_secs: None,
            require_delegation_verification: true,
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
///
/// Without a resolver for the attesters' discovery documents a
/// `delegation_chain` cannot be verified; under the default
/// `require_delegation_verification = true` such a credential is rejected.
/// Use [`verify_credential_offline_with_chain_resolver`] to supply the
/// attesters' documents (for example from a [`crate::resolver::TrustBundleResolver`]).
pub fn verify_credential_offline(
    credential_jwt: &str,
    discovery: &DiscoveryDocument,
    revocation: Option<&RevocationDocument>,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
) -> VerificationResult {
    verify_credential_core(
        credential_jwt,
        discovery,
        revocation,
        pin_store,
        audience,
        config,
        None,
    )
}

/// [`verify_credential_offline`] with a resolver used only to fetch the
/// discovery documents of delegation-chain attesters.
pub fn verify_credential_offline_with_chain_resolver(
    credential_jwt: &str,
    discovery: &DiscoveryDocument,
    revocation: Option<&RevocationDocument>,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
    chain_resolver: &dyn DiscoveryResolver,
) -> VerificationResult {
    verify_credential_core(
        credential_jwt,
        discovery,
        revocation,
        pin_store,
        audience,
        config,
        Some(chain_resolver),
    )
}

/// Error type for chain verification: the code and message of the failure
/// result to return (kept small so clippy's result_large_err is happy).
type ChainFailure = (ErrorCode, String);

fn delegation_failure(message: String) -> ChainFailure {
    (ErrorCode::DelegationInvalid, message)
}

/// Spec §6.4: verify every attestation in `chain` against its attester's
/// discovery document, check Maker/Deployer scope narrowing, and enforce
/// the minimum `max_delegation_depth` across all participants.
fn verify_delegation_chain(
    chain: &[crate::types::credential::DelegationAttestation],
    issuer: &str,
    payload: &crate::types::credential::JwtPayload,
    discovery: &DiscoveryDocument,
    resolver: &dyn DiscoveryResolver,
    now: i64,
    skew: i64,
) -> Result<Vec<DelegationChainEntry>, ChainFailure> {
    use crate::delegation::{role_str, verify_attestation, verify_chain_depth};
    use crate::types::capability::capabilities_subset;

    let mut depths = vec![discovery.max_delegation_depth];
    let mut entries = Vec::with_capacity(chain.len());
    for att in chain {
        let domain = normalize_domain(&att.domain).map_err(|e| {
            delegation_failure(format!("Delegation attester domain invalid: {}", e))
        })?;
        let doc = resolver.resolve_discovery(&domain).map_err(|e| {
            delegation_failure(format!(
                "Cannot resolve discovery document for delegation attester '{}': {}",
                domain, e
            ))
        })?;
        validate_discovery_document(&doc, &domain).map_err(|e| {
            delegation_failure(format!(
                "Discovery document for delegation attester '{}' invalid: {}",
                domain, e
            ))
        })?;
        let jwk = find_key_by_kid(&doc, &att.kid).ok_or_else(|| {
            delegation_failure(format!(
                "Delegation attester '{}' has no key '{}'",
                domain, att.kid
            ))
        })?;
        check_key_usable(jwk, now, skew).map_err(|e| {
            delegation_failure(format!(
                "Delegation attester '{}' key '{}' unusable: {}",
                domain, att.kid, e
            ))
        })?;
        let vk = jwk_to_verifying_key(jwk).map_err(|e| {
            delegation_failure(format!(
                "Delegation attester '{}' key '{}' invalid: {}",
                domain, att.kid, e
            ))
        })?;
        verify_attestation(att, &vk, issuer, &payload.sub, &payload.capabilities)
            .map_err(|e| delegation_failure(e.to_string()))?;

        // Scope narrowing (spec §10.3): when the attester declares the
        // attested agent, it must be active and the credential capabilities
        // must be within what the attester declared for it.
        if let Some(agent) = find_agent_by_id(&doc, &att.agent_id) {
            if agent.status != AgentStatus::Active {
                return Err(delegation_failure(format!(
                    "Delegation attester '{}' declares agent '{}' as {:?}",
                    domain, att.agent_id, agent.status
                )));
            }
            if !capabilities_subset(&agent.capabilities, &payload.capabilities) {
                return Err(delegation_failure(format!(
                    "Credential capabilities exceed those declared by delegation attester '{}' for '{}'",
                    domain, att.agent_id
                )));
            }
        }

        depths.push(doc.max_delegation_depth);
        entries.push(DelegationChainEntry {
            domain: domain.clone(),
            role: role_str(&att.role).to_string(),
            verified: true,
        });
    }
    verify_chain_depth(chain.len(), &depths).map_err(|e| match e {
        Error::Verification { code, message } => (code, message),
        other => delegation_failure(other.to_string()),
    })?;
    Ok(entries)
}

/// Reject keys that are expired, not marked for signature use, or whose
/// `key_ops` exclude `verify` (spec §4.4; AP-20, AP-21).
pub fn check_key_usable(jwk: &crate::jwk::Jwk, now: i64, skew: i64) -> Result<(), Error> {
    if let Some(ref exp_str) = jwk.exp {
        let exp_dt =
            chrono::DateTime::parse_from_rfc3339(exp_str).map_err(|_| Error::Verification {
                code: ErrorCode::KeyExpired,
                message: format!("Key '{}' has an unparsable exp '{}'", jwk.kid, exp_str),
            })?;
        if exp_dt.timestamp() < now - skew {
            return Err(Error::Verification {
                code: ErrorCode::KeyExpired,
                message: format!("Key '{}' has expired", jwk.kid),
            });
        }
    }
    if jwk.use_ != "sig" {
        return Err(Error::Verification {
            code: ErrorCode::KeyNotFound,
            message: format!(
                "Key '{}' is not a signature key (use = '{}')",
                jwk.kid, jwk.use_
            ),
        });
    }
    if let Some(ops) = &jwk.key_ops {
        if !ops.iter().any(|op| op == "verify") {
            return Err(Error::Verification {
                code: ErrorCode::KeyNotFound,
                message: format!("Key '{}' key_ops do not permit verify", jwk.kid),
            });
        }
    }
    Ok(())
}

fn verify_credential_core(
    credential_jwt: &str,
    discovery: &DiscoveryDocument,
    revocation: Option<&RevocationDocument>,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    config: &VerifierConfig,
    chain_resolver: Option<&dyn DiscoveryResolver>,
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

    // Check key expiration and usage (an unparsable exp is a failure, not a
    // pass — AP-20; use/key_ops enforced — AP-21)
    if let Err(e) = check_key_usable(jwk, now, skew) {
        let (code, message) = match e {
            Error::Verification { code, message } => (code, message),
            other => (ErrorCode::KeyNotFound, other.to_string()),
        };
        return VerificationResult::failure(code, &message);
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

    // Step 10: Validate delegation chain (if present). Every attestation is
    // verified against its attester's discovery document (spec §6.4); a
    // chain that cannot be verified fails closed unless the verifier opted
    // out via require_delegation_verification (AP-2).
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
        if !chain.is_empty() {
            match chain_resolver {
                Some(resolver) => {
                    match verify_delegation_chain(
                        chain, &issuer, &payload, discovery, resolver, now, skew,
                    ) {
                        Ok(entries) => {
                            result.delegation_chain = Some(entries);
                            result.delegation_verified = Some(true);
                        }
                        Err((code, message)) => return VerificationResult::failure(code, &message),
                    }
                }
                None if config.require_delegation_verification => {
                    return VerificationResult::failure(
                        ErrorCode::DelegationInvalid,
                        "Delegation chain present but no resolver is available to verify it",
                    );
                }
                None => {
                    let entries: Vec<DelegationChainEntry> = chain
                        .iter()
                        .map(|att| DelegationChainEntry {
                            domain: att.domain.clone(),
                            role: crate::delegation::role_str(&att.role).to_string(),
                            verified: false,
                        })
                        .collect();
                    result.delegation_chain = Some(entries);
                    result.delegation_verified = Some(false);
                    result.warnings.push(
                        "Delegation chain present but not verified (require_delegation_verification is false)"
                            .to_string(),
                    );
                }
            }
        }
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

    verify_credential_core(
        credential_jwt,
        &discovery,
        revocation.as_ref(),
        pin_store,
        audience,
        config,
        Some(resolver),
    )
}

/// Pre-resolved discovery documents for delegation attesters, used by the
/// async entry point which cannot call an async resolver from the sync core.
struct PreResolved(std::collections::HashMap<String, DiscoveryDocument>);

impl DiscoveryResolver for PreResolved {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        let key = normalize_domain(domain).unwrap_or_else(|_| domain.to_string());
        self.0
            .get(&key)
            .cloned()
            .ok_or_else(|| Error::Discovery(format!("Domain '{}' not pre-resolved", domain)))
    }
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

    // Pre-resolve the discovery documents of every delegation attester so
    // the chain can be verified by the sync core (AP-2).
    let mut chain_docs = std::collections::HashMap::new();
    if let Some(ref chain) = payload.delegation_chain {
        for att in chain {
            let domain = match normalize_domain(&att.domain) {
                Ok(d) => d,
                Err(e) => {
                    return VerificationResult::failure(
                        ErrorCode::DelegationInvalid,
                        &format!("Delegation attester domain invalid: {}", e),
                    )
                }
            };
            if chain_docs.contains_key(&domain) {
                continue;
            }
            match resolver.resolve_discovery(&domain).await {
                Ok(doc) => {
                    chain_docs.insert(domain, doc);
                }
                Err(e) => {
                    return VerificationResult::failure(
                        ErrorCode::DelegationInvalid,
                        &format!(
                            "Cannot resolve discovery document for delegation attester '{}': {}",
                            domain, e
                        ),
                    )
                }
            }
        }
    }
    let pre = PreResolved(chain_docs);

    verify_credential_core(
        credential_jwt,
        &discovery,
        revocation.as_ref(),
        pin_store,
        audience,
        config,
        Some(&pre),
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

    /// Maker (maker.com) + Deployer (example.com) fixture with a valid
    /// delegation chain, exposed through a TrustBundleResolver.
    struct DelegationFixture {
        jwt: String,
        deployer_doc: DiscoveryDocument,
        maker_doc: DiscoveryDocument,
        deployer_sk: p256::ecdsa::SigningKey,
        maker_sk: p256::ecdsa::SigningKey,
        caps: Vec<Capability>,
    }

    fn delegation_fixture() -> DelegationFixture {
        use crate::delegation::create_attestation;
        use crate::types::credential::DelegationRole;

        let maker_kp = crypto::generate_key_pair().unwrap();
        let maker_sk = crypto::load_signing_key(&maker_kp.private_key_pem).unwrap();
        let maker_vk = crypto::load_verifying_key(&maker_kp.public_key_pem).unwrap();
        let maker_doc = build_discovery_document(
            "maker.com",
            EntityType::Maker,
            vec![verifying_key_to_jwk(&maker_vk, "maker-2026-01")],
            vec![AgentDeclaration {
                agent_id: "urn:agentpin:maker.com:agent-type".to_string(),
                agent_type: None,
                name: "Agent Type".to_string(),
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

        let deployer_kp = crypto::generate_key_pair().unwrap();
        let deployer_sk = crypto::load_signing_key(&deployer_kp.private_key_pem).unwrap();
        let deployer_vk = crypto::load_verifying_key(&deployer_kp.public_key_pem).unwrap();
        let deployer_doc = build_discovery_document(
            "example.com",
            EntityType::Deployer,
            vec![verifying_key_to_jwk(&deployer_vk, "deployer-2026-01")],
            vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:agent".to_string(),
                agent_type: Some("urn:agentpin:maker.com:agent-type".to_string()),
                name: "Deployed Agent".to_string(),
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

        let caps = vec![Capability::from("read:data")];
        let att = create_attestation(
            &maker_sk,
            "maker-2026-01",
            "maker.com",
            DelegationRole::Maker,
            "urn:agentpin:maker.com:agent-type",
            "example.com",
            "urn:agentpin:example.com:agent",
            &caps,
        )
        .unwrap();
        let jwt = issue_credential(
            &deployer_sk,
            "deployer-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            caps.clone(),
            None,
            Some(vec![att]),
            3600,
        )
        .unwrap();
        DelegationFixture {
            jwt,
            deployer_doc,
            maker_doc,
            deployer_sk,
            maker_sk,
            caps,
        }
    }

    fn bundle_resolver(docs: Vec<DiscoveryDocument>) -> crate::resolver::TrustBundleResolver {
        let mut bundle = crate::types::bundle::TrustBundle::new("2026-02-10T00:00:00Z");
        bundle.documents = docs;
        crate::resolver::TrustBundleResolver::new(&bundle)
    }

    /// AP-2: a genuine chain verifies end to end and is reported as verified.
    #[test]
    fn test_delegation_chain_verified() {
        let f = delegation_fixture();
        let resolver = bundle_resolver(vec![f.deployer_doc.clone(), f.maker_doc.clone()]);
        let r = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &VerifierConfig::default(),
        );
        assert!(r.valid, "{:?}", r);
        assert_eq!(r.delegation_verified, Some(true));
        let chain = r.delegation_chain.unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain[0].verified);
        assert_eq!(chain[0].domain, "maker.com");
        assert_eq!(chain[0].role, "maker");
        assert!(r.warnings.is_empty());
    }

    /// AP-2: a fabricated attestation is rejected with DELEGATION_INVALID
    /// instead of being reported alongside valid: true.
    #[test]
    fn test_forged_delegation_chain_rejected() {
        let f = delegation_fixture();
        let forged = issue_credential(
            &f.deployer_sk,
            "deployer-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            Some("verifier.com"),
            f.caps.clone(),
            None,
            Some(vec![crate::types::credential::DelegationAttestation {
                domain: "maker.com".to_string(),
                role: crate::types::credential::DelegationRole::Maker,
                agent_id: "urn:agentpin:maker.com:agent-type".to_string(),
                kid: "maker-2026-01".to_string(),
                attestation: "AAAA".to_string(),
                exp: None,
            }]),
            3600,
        )
        .unwrap();
        let resolver = bundle_resolver(vec![f.deployer_doc.clone(), f.maker_doc.clone()]);
        let r = verify_credential_with_resolver(
            &forged,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &VerifierConfig::default(),
        );
        assert!(!r.valid);
        assert_eq!(r.error_code, Some(ErrorCode::DelegationInvalid));

        // Offline with no way to resolve the attester: fail closed by default.
        let r = verify_credential_offline(
            &f.jwt,
            &f.deployer_doc,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &VerifierConfig::default(),
        );
        assert!(!r.valid);
        assert_eq!(r.error_code, Some(ErrorCode::DelegationInvalid));

        // Explicit opt-out: accepted but clearly marked unverified.
        let lax = VerifierConfig {
            require_delegation_verification: false,
            ..Default::default()
        };
        let r = verify_credential_offline(
            &f.jwt,
            &f.deployer_doc,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &lax,
        );
        assert!(r.valid, "{:?}", r);
        assert_eq!(r.delegation_verified, Some(false));
        assert!(!r.warnings.is_empty());

        // Offline with a chain resolver works too.
        let resolver = bundle_resolver(vec![f.maker_doc.clone()]);
        let r = verify_credential_offline_with_chain_resolver(
            &f.jwt,
            &f.deployer_doc,
            None,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &VerifierConfig::default(),
            &resolver,
        );
        assert!(r.valid, "{:?}", r);
        assert_eq!(r.delegation_verified, Some(true));
    }

    /// AP-2: unknown attester kid, unresolvable attester, exceeded depth and
    /// capability widening beyond the attester's declaration all fail.
    #[test]
    fn test_delegation_chain_failure_modes() {
        let f = delegation_fixture();
        let cfg = VerifierConfig::default();

        // Attester unresolvable.
        let resolver = bundle_resolver(vec![f.deployer_doc.clone()]);
        let r = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &cfg,
        );
        assert_eq!(r.error_code, Some(ErrorCode::DelegationInvalid));

        // Attester key rotated away (kid unknown).
        let mut no_key = f.maker_doc.clone();
        no_key.public_keys[0].kid = "maker-2026-02".to_string();
        let resolver = bundle_resolver(vec![f.deployer_doc.clone(), no_key]);
        let r = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &cfg,
        );
        assert_eq!(r.error_code, Some(ErrorCode::DelegationInvalid));

        // Depth: the maker allows no delegation.
        let mut shallow = f.maker_doc.clone();
        shallow.max_delegation_depth = 0;
        let resolver = bundle_resolver(vec![f.deployer_doc.clone(), shallow]);
        let r = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &cfg,
        );
        assert_eq!(r.error_code, Some(ErrorCode::DelegationDepthExceeded));

        // Scope narrowing: the maker attests to caps it never declared.
        let mut narrow_maker = f.maker_doc.clone();
        narrow_maker.agents[0].capabilities = vec![Capability::from("read:public")];
        let resolver = bundle_resolver(vec![f.deployer_doc.clone(), narrow_maker]);
        let r = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &cfg,
        );
        assert_eq!(r.error_code, Some(ErrorCode::DelegationInvalid));
        assert!(r.error_message.unwrap().contains("exceed"));

        // Attester declares the agent inactive.
        let mut suspended = f.maker_doc.clone();
        suspended.agents[0].status = AgentStatus::Suspended;
        let resolver = bundle_resolver(vec![f.deployer_doc.clone(), suspended]);
        let r = verify_credential_with_resolver(
            &f.jwt,
            &resolver,
            &mut KeyPinStore::new(),
            Some("verifier.com"),
            &cfg,
        );
        assert_eq!(r.error_code, Some(ErrorCode::DelegationInvalid));

        // The maker key is still usable for its own credentials.
        let _ = &f.maker_sk;
    }

    /// AP-20 / AP-21: a key with an unparsable exp, use != sig, or key_ops
    /// without verify is rejected.
    #[test]
    fn test_key_metadata_enforced() {
        let f = setup();
        let run = |doc: &DiscoveryDocument| {
            verify_credential_offline(
                &f.jwt,
                doc,
                None,
                &mut KeyPinStore::new(),
                Some("verifier.com"),
                &f.config,
            )
        };
        let mut bad_exp = f.discovery.clone();
        bad_exp.public_keys[0].exp = Some("expired".to_string());
        assert_eq!(run(&bad_exp).error_code, Some(ErrorCode::KeyExpired));
        let mut past = f.discovery.clone();
        past.public_keys[0].exp = Some("2020-01-01T00:00:00Z".to_string());
        assert_eq!(run(&past).error_code, Some(ErrorCode::KeyExpired));
        let mut enc = f.discovery.clone();
        enc.public_keys[0].use_ = "enc".to_string();
        assert_eq!(run(&enc).error_code, Some(ErrorCode::KeyNotFound));
        let mut ops = f.discovery.clone();
        ops.public_keys[0].key_ops = Some(vec!["sign".to_string()]);
        assert_eq!(run(&ops).error_code, Some(ErrorCode::KeyNotFound));
        let mut future = f.discovery.clone();
        future.public_keys[0].exp = Some("2099-01-01T00:00:00Z".to_string());
        assert!(run(&future).valid);
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
