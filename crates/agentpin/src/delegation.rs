//! Delegation attestations (spec §5.6 / §6.4).
//!
//! An attestation is an ECDSA signature over the domain-separated structure
//!
//! ```text
//! "agentpin-attestation-v1" 0x00
//!     len(domain) domain  len(role) role  len(agent_id) agent_id
//!     len(delegatee_domain) delegatee_domain
//!     len(delegatee_agent_id) delegatee_agent_id
//!     len(capabilities_hash) capabilities_hash
//!     len(kid) kid  len(exp) exp
//! ```
//!
//! `kid` binds the attestation to the attesting key so it cannot be replayed
//! across a key rotation; `exp` (decimal Unix seconds, empty when absent)
//! bounds its lifetime. The context label keeps attestation signatures
//! disjoint from credential, challenge-response and AgentCard signatures.

use chrono::Utc;
use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::crypto::{self, CTX_ATTESTATION};
use crate::domain::normalize_domain;
use crate::error::{Error, ErrorCode};
use crate::types::capability::{capabilities_hash, Capability};
use crate::types::credential::{DelegationAttestation, DelegationRole};

/// Wire string for a delegation role.
pub fn role_str(role: &DelegationRole) -> &'static str {
    match role {
        DelegationRole::Maker => "maker",
        DelegationRole::Deployer => "deployer",
    }
}

/// Create the canonical (domain-separated) attestation signing input.
#[allow(clippy::too_many_arguments)]
pub fn canonical_attestation_input(
    domain: &str,
    role: &DelegationRole,
    agent_id: &str,
    delegatee_domain: &str,
    delegatee_agent_id: &str,
    capabilities: &[Capability],
    kid: &str,
    exp: Option<i64>,
) -> Vec<u8> {
    let cap_hash = capabilities_hash(capabilities);
    let exp_str = exp.map(|e| e.to_string()).unwrap_or_default();
    // Domains are compared in normalized form everywhere else (AP-3), so the
    // signed input uses the normalized form too; invalid names are signed
    // verbatim and can never match a normalized issuer.
    let domain = normalize_domain(domain).unwrap_or_else(|_| domain.to_string());
    let delegatee_domain =
        normalize_domain(delegatee_domain).unwrap_or_else(|_| delegatee_domain.to_string());
    crypto::domain_separated_input(
        CTX_ATTESTATION,
        &[
            domain.as_bytes(),
            role_str(role).as_bytes(),
            agent_id.as_bytes(),
            delegatee_domain.as_bytes(),
            delegatee_agent_id.as_bytes(),
            cap_hash.as_bytes(),
            kid.as_bytes(),
            exp_str.as_bytes(),
        ],
    )
}

/// Create a delegation attestation signed by the attesting entity, without
/// an expiry.
#[allow(clippy::too_many_arguments)]
pub fn create_attestation(
    signing_key: &SigningKey,
    kid: &str,
    domain: &str,
    role: DelegationRole,
    agent_id: &str,
    delegatee_domain: &str,
    delegatee_agent_id: &str,
    capabilities: &[Capability],
) -> Result<DelegationAttestation, Error> {
    create_attestation_with_expiry(
        signing_key,
        kid,
        domain,
        role,
        agent_id,
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
        None,
    )
}

/// Create a delegation attestation with an optional expiry (Unix seconds).
#[allow(clippy::too_many_arguments)]
pub fn create_attestation_with_expiry(
    signing_key: &SigningKey,
    kid: &str,
    domain: &str,
    role: DelegationRole,
    agent_id: &str,
    delegatee_domain: &str,
    delegatee_agent_id: &str,
    capabilities: &[Capability],
    exp: Option<i64>,
) -> Result<DelegationAttestation, Error> {
    let input = canonical_attestation_input(
        domain,
        &role,
        agent_id,
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
        kid,
        exp,
    );
    let signature = crypto::sign_bytes(signing_key, &input);

    Ok(DelegationAttestation {
        domain: domain.to_string(),
        role,
        agent_id: agent_id.to_string(),
        kid: kid.to_string(),
        attestation: signature,
        exp,
    })
}

/// Verify a single delegation attestation signature (and its expiry, when
/// present).
pub fn verify_attestation(
    attestation: &DelegationAttestation,
    verifying_key: &VerifyingKey,
    delegatee_domain: &str,
    delegatee_agent_id: &str,
    capabilities: &[Capability],
) -> Result<(), Error> {
    if let Some(exp) = attestation.exp {
        if exp < Utc::now().timestamp() {
            return Err(Error::Verification {
                code: ErrorCode::DelegationInvalid,
                message: format!(
                    "Delegation attestation from {} has expired",
                    attestation.domain
                ),
            });
        }
    }

    let input = canonical_attestation_input(
        &attestation.domain,
        &attestation.role,
        &attestation.agent_id,
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
        &attestation.kid,
        attestation.exp,
    );

    let valid = crypto::verify_bytes(verifying_key, &input, &attestation.attestation)?;
    if !valid {
        return Err(Error::Verification {
            code: ErrorCode::DelegationInvalid,
            message: format!(
                "Delegation attestation from {} failed signature verification",
                attestation.domain
            ),
        });
    }
    Ok(())
}

/// Verify the depth of a delegation chain does not exceed the minimum max_delegation_depth.
pub fn verify_chain_depth(chain_len: usize, max_depths: &[u8]) -> Result<(), Error> {
    let min_depth = max_depths.iter().copied().min().unwrap_or(0) as usize;
    if chain_len > min_depth {
        return Err(Error::Verification {
            code: ErrorCode::DelegationDepthExceeded,
            message: format!(
                "Delegation chain depth {} exceeds minimum max_delegation_depth {}",
                chain_len, min_depth
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn keys() -> (SigningKey, VerifyingKey) {
        let kp = crypto::generate_key_pair().unwrap();
        (
            crypto::load_signing_key(&kp.private_key_pem).unwrap(),
            crypto::load_verifying_key(&kp.public_key_pem).unwrap(),
        )
    }

    #[test]
    fn test_create_and_verify_attestation() {
        let (sk, vk) = keys();
        let caps = vec![
            Capability::from("read:data"),
            Capability::from("write:report"),
        ];

        let att = create_attestation(
            &sk,
            "maker-2026-01",
            "maker.com",
            DelegationRole::Maker,
            "urn:agentpin:maker.com:agent-type",
            "deployer.com",
            "urn:agentpin:deployer.com:instance",
            &caps,
        )
        .unwrap();

        assert_eq!(att.domain, "maker.com");
        assert_eq!(att.role, DelegationRole::Maker);
        assert_eq!(att.exp, None);

        assert!(verify_attestation(
            &att,
            &vk,
            "deployer.com",
            "urn:agentpin:deployer.com:instance",
            &caps
        )
        .is_ok());
    }

    #[test]
    fn test_verify_attestation_wrong_key() {
        let (sk1, _) = keys();
        let (_, vk2) = keys();
        let caps = vec![Capability::from("read:data")];
        let att = create_attestation(
            &sk1,
            "kid",
            "domain",
            DelegationRole::Maker,
            "agent",
            "delegatee",
            "delegatee-agent",
            &caps,
        )
        .unwrap();
        assert!(verify_attestation(&att, &vk2, "delegatee", "delegatee-agent", &caps).is_err());
    }

    #[test]
    fn test_verify_attestation_wrong_capabilities() {
        let (sk, vk) = keys();
        let caps = vec![Capability::from("read:data")];
        let wrong_caps = vec![Capability::from("write:data")];
        let att = create_attestation(
            &sk,
            "kid",
            "domain",
            DelegationRole::Maker,
            "agent",
            "delegatee",
            "delegatee-agent",
            &caps,
        )
        .unwrap();
        assert!(
            verify_attestation(&att, &vk, "delegatee", "delegatee-agent", &wrong_caps).is_err()
        );
    }

    /// Design issue 7: the attestation is bound to the attesting `kid`, so
    /// re-labelling it under a different key id breaks the signature.
    #[test]
    fn test_attestation_bound_to_kid() {
        let (sk, vk) = keys();
        let caps = vec![Capability::from("read:data")];
        let mut att = create_attestation(
            &sk,
            "kid-1",
            "maker.com",
            DelegationRole::Maker,
            "agent",
            "deployer.com",
            "delegatee-agent",
            &caps,
        )
        .unwrap();
        att.kid = "kid-2".to_string();
        assert!(verify_attestation(&att, &vk, "deployer.com", "delegatee-agent", &caps).is_err());
    }

    /// Design issue 7: expired attestations are rejected; the expiry is
    /// covered by the signature.
    #[test]
    fn test_attestation_expiry() {
        let (sk, vk) = keys();
        let caps = vec![Capability::from("read:data")];
        let now = Utc::now().timestamp();
        let fresh = create_attestation_with_expiry(
            &sk,
            "kid",
            "maker.com",
            DelegationRole::Maker,
            "agent",
            "deployer.com",
            "delegatee-agent",
            &caps,
            Some(now + 3600),
        )
        .unwrap();
        assert!(verify_attestation(&fresh, &vk, "deployer.com", "delegatee-agent", &caps).is_ok());

        let expired = create_attestation_with_expiry(
            &sk,
            "kid",
            "maker.com",
            DelegationRole::Maker,
            "agent",
            "deployer.com",
            "delegatee-agent",
            &caps,
            Some(now - 10),
        )
        .unwrap();
        assert!(
            verify_attestation(&expired, &vk, "deployer.com", "delegatee-agent", &caps).is_err()
        );

        // Stripping the expiry from a signed attestation breaks the signature.
        let mut stripped = fresh.clone();
        stripped.exp = None;
        assert!(
            verify_attestation(&stripped, &vk, "deployer.com", "delegatee-agent", &caps).is_err()
        );
    }

    /// AP-1: an attestation signature is not a raw signature over the legacy
    /// `|`-joined string, and a legacy-format signature does not verify.
    #[test]
    fn test_attestation_is_domain_separated() {
        let (sk, vk) = keys();
        let caps = vec![Capability::from("read:data")];
        let legacy = format!(
            "maker.com|maker|agent|deployer.com|delegatee-agent|{}",
            capabilities_hash(&caps)
        );
        let legacy_sig = crypto::sign_bytes(&sk, legacy.as_bytes());
        let legacy_att = DelegationAttestation {
            domain: "maker.com".to_string(),
            role: DelegationRole::Maker,
            agent_id: "agent".to_string(),
            kid: "kid".to_string(),
            attestation: legacy_sig,
            exp: None,
        };
        assert!(
            verify_attestation(&legacy_att, &vk, "deployer.com", "delegatee-agent", &caps).is_err()
        );
    }

    #[test]
    fn test_verify_chain_depth() {
        assert!(verify_chain_depth(1, &[2, 3]).is_ok());
        assert!(verify_chain_depth(2, &[2, 3]).is_ok());
        assert!(verify_chain_depth(3, &[2, 3]).is_err());
        assert!(verify_chain_depth(1, &[]).is_err());
    }
}
