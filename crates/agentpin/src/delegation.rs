use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::crypto;
use crate::error::{Error, ErrorCode};
use crate::types::capability::{capabilities_hash, Capability};
use crate::types::credential::{DelegationAttestation, DelegationRole};

/// Create the canonical attestation input string.
/// Format: `{domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{capabilities_hash}`
pub fn canonical_attestation_input(
    domain: &str,
    role: &DelegationRole,
    agent_id: &str,
    delegatee_domain: &str,
    delegatee_agent_id: &str,
    capabilities: &[Capability],
) -> String {
    let role_str = match role {
        DelegationRole::Maker => "maker",
        DelegationRole::Deployer => "deployer",
    };
    let cap_hash = capabilities_hash(capabilities);
    format!(
        "{}|{}|{}|{}|{}|{}",
        domain, role_str, agent_id, delegatee_domain, delegatee_agent_id, cap_hash
    )
}

/// Create a delegation attestation signed by the attesting entity.
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
    let input = canonical_attestation_input(
        domain,
        &role,
        agent_id,
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
    );
    let signature = crypto::sign_bytes(signing_key, input.as_bytes());

    Ok(DelegationAttestation {
        domain: domain.to_string(),
        role,
        agent_id: agent_id.to_string(),
        kid: kid.to_string(),
        attestation: signature,
    })
}

/// Verify a single delegation attestation signature.
pub fn verify_attestation(
    attestation: &DelegationAttestation,
    verifying_key: &VerifyingKey,
    delegatee_domain: &str,
    delegatee_agent_id: &str,
    capabilities: &[Capability],
) -> Result<(), Error> {
    let input = canonical_attestation_input(
        &attestation.domain,
        &attestation.role,
        &attestation.agent_id,
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
    );

    let valid = crypto::verify_bytes(verifying_key, input.as_bytes(), &attestation.attestation)?;
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

    #[test]
    fn test_create_and_verify_attestation() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

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

        // Verify should succeed
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
        let kp1 = crypto::generate_key_pair().unwrap();
        let kp2 = crypto::generate_key_pair().unwrap();
        let sk1 = crypto::load_signing_key(&kp1.private_key_pem).unwrap();
        let vk2 = crypto::load_verifying_key(&kp2.public_key_pem).unwrap();

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
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

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

        // Wrong capabilities should fail
        assert!(
            verify_attestation(&att, &vk, "delegatee", "delegatee-agent", &wrong_caps).is_err()
        );
    }

    #[test]
    fn test_verify_chain_depth() {
        assert!(verify_chain_depth(1, &[2, 3]).is_ok());
        assert!(verify_chain_depth(2, &[2, 3]).is_ok());
        assert!(verify_chain_depth(3, &[2, 3]).is_err());
    }
}
