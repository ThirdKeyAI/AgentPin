use serde::{Deserialize, Serialize};

use super::capability::Capability;
use super::constraint::Constraints;
use crate::jwk::Jwk;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryDocument {
    pub agentpin_version: String,
    pub entity: String,
    pub entity_type: EntityType,
    pub public_keys: Vec<Jwk>,
    pub agents: Vec<AgentDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schemapin_endpoint: Option<String>,
    pub max_delegation_depth: u8,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityType {
    Maker,
    Deployer,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDeclaration {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maker_attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ttl_max: Option<u64>,
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Suspended,
    Deprecated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_document_serde_roundtrip() {
        let doc = DiscoveryDocument {
            agentpin_version: "0.1".to_string(),
            entity: "example.com".to_string(),
            entity_type: EntityType::Maker,
            public_keys: vec![],
            agents: vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:test-agent".to_string(),
                agent_type: None,
                name: "Test Agent".to_string(),
                description: Some("A test agent".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: vec![Capability::from("read:*")],
                constraints: None,
                maker_attestation: None,
                credential_ttl_max: Some(3600),
                status: AgentStatus::Active,
            }],
            revocation_endpoint: Some(
                "https://example.com/.well-known/agent-identity-revocations.json".to_string(),
            ),
            policy_url: None,
            schemapin_endpoint: None,
            max_delegation_depth: 2,
            updated_at: "2026-01-15T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string_pretty(&doc).unwrap();
        let doc2: DiscoveryDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, doc2);
    }

    #[test]
    fn test_entity_type_serde() {
        assert_eq!(
            serde_json::to_string(&EntityType::Maker).unwrap(),
            "\"maker\""
        );
        assert_eq!(
            serde_json::to_string(&EntityType::Deployer).unwrap(),
            "\"deployer\""
        );
        assert_eq!(
            serde_json::to_string(&EntityType::Both).unwrap(),
            "\"both\""
        );
    }

    #[test]
    fn test_agent_status_serde() {
        assert_eq!(
            serde_json::to_string(&AgentStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&AgentStatus::Suspended).unwrap(),
            "\"suspended\""
        );
    }
}
