use serde::{Deserialize, Serialize};

use super::capability::Capability;
use super::constraint::Constraints;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtPayload {
    pub iss: String,
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    pub jti: String,
    pub agentpin_version: String,
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_chain: Option<Vec<DelegationAttestation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationAttestation {
    pub domain: String,
    pub role: DelegationRole,
    pub agent_id: String,
    pub kid: String,
    pub attestation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DelegationRole {
    Maker,
    Deployer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_header_serde() {
        let header = JwtHeader {
            alg: "ES256".to_string(),
            typ: "agentpin-credential+jwt".to_string(),
            kid: "test-2026-01".to_string(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let h2: JwtHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(header, h2);
    }

    #[test]
    fn test_jwt_payload_serde_roundtrip() {
        let payload = JwtPayload {
            iss: "example.com".to_string(),
            sub: "urn:agentpin:example.com:agent".to_string(),
            aud: Some("verifier.com".to_string()),
            iat: 1738300800,
            exp: 1738304400,
            nbf: None,
            jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            agentpin_version: "0.1".to_string(),
            capabilities: vec![Capability::from("read:data")],
            constraints: None,
            delegation_chain: Some(vec![DelegationAttestation {
                domain: "maker.com".to_string(),
                role: DelegationRole::Maker,
                agent_id: "urn:agentpin:maker.com:agent-type".to_string(),
                kid: "maker-2026-01".to_string(),
                attestation: "MEUCIQD7y2F8...".to_string(),
            }]),
            nonce: None,
        };
        let json = serde_json::to_string_pretty(&payload).unwrap();
        let p2: JwtPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, p2);
    }

    #[test]
    fn test_delegation_role_serde() {
        assert_eq!(
            serde_json::to_string(&DelegationRole::Maker).unwrap(),
            "\"maker\""
        );
        assert_eq!(
            serde_json::to_string(&DelegationRole::Deployer).unwrap(),
            "\"deployer\""
        );
    }
}
