use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationDocument {
    pub agentpin_version: String,
    pub entity: String,
    pub updated_at: String,
    #[serde(default)]
    pub revoked_credentials: Vec<RevokedCredential>,
    #[serde(default)]
    pub revoked_agents: Vec<RevokedAgent>,
    #[serde(default)]
    pub revoked_keys: Vec<RevokedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedCredential {
    pub jti: String,
    pub revoked_at: String,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedAgent {
    pub agent_id: String,
    pub revoked_at: String,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedKey {
    pub kid: String,
    pub revoked_at: String,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    KeyCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    PrivilegeWithdrawn,
    PolicyViolation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_document_serde_roundtrip() {
        let doc = RevocationDocument {
            agentpin_version: "0.1".to_string(),
            entity: "example.com".to_string(),
            updated_at: "2026-01-30T00:00:00Z".to_string(),
            revoked_credentials: vec![RevokedCredential {
                jti: "test-jti-123".to_string(),
                revoked_at: "2026-01-30T00:00:00Z".to_string(),
                reason: RevocationReason::KeyCompromise,
            }],
            revoked_agents: vec![],
            revoked_keys: vec![RevokedKey {
                kid: "old-key-01".to_string(),
                revoked_at: "2026-01-30T00:00:00Z".to_string(),
                reason: RevocationReason::Superseded,
            }],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let doc2: RevocationDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, doc2);
    }

    #[test]
    fn test_revocation_reason_serde() {
        assert_eq!(
            serde_json::to_string(&RevocationReason::KeyCompromise).unwrap(),
            "\"key_compromise\""
        );
        assert_eq!(
            serde_json::to_string(&RevocationReason::CessationOfOperation).unwrap(),
            "\"cessation_of_operation\""
        );
    }
}
