use chrono::Utc;
use p256::ecdsa::SigningKey;
use uuid::Uuid;

use crate::error::Error;
use crate::jwt;
use crate::types::capability::Capability;
use crate::types::constraint::Constraints;
use crate::types::credential::{DelegationAttestation, JwtHeader, JwtPayload};

/// Issue a new agent credential JWT.
#[allow(clippy::too_many_arguments)]
pub fn issue_credential(
    signing_key: &SigningKey,
    kid: &str,
    issuer: &str,
    agent_id: &str,
    audience: Option<&str>,
    capabilities: Vec<Capability>,
    constraints: Option<Constraints>,
    delegation_chain: Option<Vec<DelegationAttestation>>,
    ttl_secs: u64,
) -> Result<String, Error> {
    let now = Utc::now().timestamp();

    let header = JwtHeader {
        alg: "ES256".to_string(),
        typ: "agentpin-credential+jwt".to_string(),
        kid: kid.to_string(),
    };

    let payload = JwtPayload {
        iss: issuer.to_string(),
        sub: agent_id.to_string(),
        aud: audience.map(|a| a.to_string()),
        iat: now,
        exp: now + ttl_secs as i64,
        nbf: None,
        jti: Uuid::new_v4().to_string(),
        agentpin_version: "0.1".to_string(),
        capabilities,
        constraints,
        delegation_chain,
        nonce: None,
    };

    jwt::encode_jwt(&header, &payload, signing_key)
}

/// Validate that credential capabilities are a subset of discovery agent capabilities.
pub fn validate_credential_against_discovery(
    credential_caps: &[Capability],
    discovery_caps: &[Capability],
) -> Result<(), Error> {
    use crate::types::capability::capabilities_subset;
    if !capabilities_subset(discovery_caps, credential_caps) {
        return Err(Error::Verification {
            code: crate::error::ErrorCode::CapabilityExceeded,
            message: "Credential capabilities exceed discovery document".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn test_issue_credential() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let jwt_str = issue_credential(
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

        // Should verify
        let (header, payload) = jwt::verify_jwt(&jwt_str, &vk).unwrap();
        assert_eq!(header.kid, "test-2026-01");
        assert_eq!(payload.iss, "example.com");
        assert_eq!(payload.sub, "urn:agentpin:example.com:agent");
        assert_eq!(payload.aud, Some("verifier.com".to_string()));
        assert_eq!(payload.agentpin_version, "0.1");
        assert!(payload.exp > payload.iat);
    }

    #[test]
    fn test_validate_capabilities_ok() {
        let disc_caps = vec![Capability::from("read:*"), Capability::from("write:report")];
        let cred_caps = vec![Capability::from("read:data")];
        assert!(validate_credential_against_discovery(&cred_caps, &disc_caps).is_ok());
    }

    #[test]
    fn test_validate_capabilities_exceeded() {
        let disc_caps = vec![Capability::from("read:data")];
        let cred_caps = vec![Capability::from("delete:data")];
        assert!(validate_credential_against_discovery(&cred_caps, &disc_caps).is_err());
    }
}
