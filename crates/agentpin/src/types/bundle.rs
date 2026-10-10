use serde::{Deserialize, Serialize};

use super::discovery::DiscoveryDocument;
use super::revocation::RevocationDocument;

/// A pre-shared collection of discovery and revocation documents.
///
/// Trust bundles allow verification in environments where the standard
/// `.well-known` HTTP discovery is unavailable (air-gapped networks,
/// CI pipelines, enterprise-internal agents, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustBundle {
    pub agentpin_bundle_version: String,
    pub created_at: String,
    pub documents: Vec<DiscoveryDocument>,
    #[serde(default)]
    pub revocations: Vec<RevocationDocument>,
    /// Optional expiry (RFC 3339). A bundle past its expiry is rejected by
    /// [`crate::bundle::verify_trust_bundle`] (design issue 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Optional `kid` of the key that signed this bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Optional standard-base64 DER signature over the domain-separated
    /// canonical JSON of the bundle with `signature` cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl TrustBundle {
    /// Create a new empty trust bundle.
    pub fn new(created_at: &str) -> Self {
        Self {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: created_at.to_string(),
            documents: vec![],
            revocations: vec![],
            expires_at: None,
            kid: None,
            signature: None,
        }
    }

    /// Find a discovery document by domain (entity field), compared in
    /// normalized form.
    pub fn find_discovery(&self, domain: &str) -> Option<&DiscoveryDocument> {
        let key = bundle_key(domain);
        self.documents.iter().find(|d| bundle_key(&d.entity) == key)
    }

    /// Find a revocation document by domain (entity field), compared in
    /// normalized form.
    pub fn find_revocation(&self, domain: &str) -> Option<&RevocationDocument> {
        let key = bundle_key(domain);
        self.revocations
            .iter()
            .find(|r| bundle_key(&r.entity) == key)
    }
}

fn bundle_key(entity: &str) -> String {
    crate::domain::normalize_domain(entity).unwrap_or_else(|_| entity.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::capability::Capability;
    use crate::types::discovery::{AgentDeclaration, AgentStatus, EntityType};

    fn make_test_bundle() -> TrustBundle {
        let doc = DiscoveryDocument {
            agentpin_version: "0.1".to_string(),
            entity: "example.com".to_string(),
            entity_type: EntityType::Maker,
            public_keys: vec![],
            agents: vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:agent".to_string(),
                agent_type: None,
                name: "Test Agent".to_string(),
                description: None,
                version: None,
                capabilities: vec![Capability::from("read:*")],
                constraints: None,
                maker_attestation: None,
                credential_ttl_max: Some(3600),
                status: AgentStatus::Active,
                directory_listing: None,
            }],
            revocation_endpoint: None,
            policy_url: None,
            schemapin_endpoint: None,
            a2a_endpoint: None,
            max_delegation_depth: 2,
            updated_at: "2026-01-15T00:00:00Z".to_string(),
        };

        TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![doc],
            revocations: vec![],
            expires_at: None,
            kid: None,
            signature: None,
        }
    }

    #[test]
    fn test_trust_bundle_serde_roundtrip() {
        let bundle = make_test_bundle();
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let bundle2: TrustBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, bundle2);
    }

    #[test]
    fn test_find_discovery() {
        let bundle = make_test_bundle();
        assert!(bundle.find_discovery("example.com").is_some());
        assert!(bundle.find_discovery("other.com").is_none());
    }

    #[test]
    fn test_find_revocation() {
        let bundle = make_test_bundle();
        assert!(bundle.find_revocation("example.com").is_none());
    }

    #[test]
    fn test_new_bundle() {
        let bundle = TrustBundle::new("2026-02-10T00:00:00Z");
        assert_eq!(bundle.agentpin_bundle_version, "0.1");
        assert!(bundle.documents.is_empty());
        assert!(bundle.revocations.is_empty());
    }
}
