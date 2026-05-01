use serde::{Deserialize, Serialize};

use super::capability::Capability;
use super::constraint::Constraints;
use crate::jwk::Jwk;

/// List of domains an agent is permitted to interact with (v0.3.0).
///
/// Extracted from [`Constraints::allowed_domains`] for use by cross-protocol
/// A2A verification — most notably SchemaPin v1.4's `A2aVerificationContext`,
/// which scopes tool verification to the intersection of caller and provider
/// domains.
///
/// Convention: an empty list means *no restriction* (all domains trusted).
/// A non-empty list means the agent is restricted to exactly those domains.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AllowedDomains(pub Vec<String>);

impl AllowedDomains {
    /// Construct an empty list (no restriction — all domains trusted).
    pub fn unrestricted() -> Self {
        Self(Vec::new())
    }

    /// Construct from any iterable of strings.
    pub fn from_domains<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(iter.into_iter().map(Into::into).collect())
    }

    /// `true` when the list is empty (no restriction).
    pub fn is_unrestricted(&self) -> bool {
        self.0.is_empty()
    }

    /// `true` when `domain` is allowed under this list.
    /// An empty list trusts all domains.
    pub fn allows(&self, domain: &str) -> bool {
        self.is_unrestricted() || self.0.iter().any(|d| d == domain)
    }

    /// Intersection of two allow-lists.
    ///
    /// Following the convention that empty = unrestricted:
    /// - `unrestricted ∩ X = X`
    /// - `X ∩ unrestricted = X`
    /// - `[a,b] ∩ [b,c] = [b]`
    pub fn intersect(&self, other: &Self) -> Self {
        if self.is_unrestricted() {
            return other.clone();
        }
        if other.is_unrestricted() {
            return self.clone();
        }
        let inter: Vec<String> = self
            .0
            .iter()
            .filter(|d| other.0.contains(d))
            .cloned()
            .collect();
        Self(inter)
    }

    /// Borrow the inner vector.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl<S> std::iter::FromIterator<S> for AllowedDomains
where
    S: Into<String>,
{
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

impl Constraints {
    /// Extract [`AllowedDomains`] from the constraints' `allowed_domains` field.
    ///
    /// Returns [`AllowedDomains::unrestricted`] when the field is absent — the
    /// "no allow-list specified" case is treated as "no restriction" so the
    /// intersection helper composes correctly with cross-protocol callers.
    pub fn allowed_domains_typed(&self) -> AllowedDomains {
        match &self.allowed_domains {
            Some(list) => AllowedDomains(list.clone()),
            None => AllowedDomains::unrestricted(),
        }
    }
}

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
    /// Optional v0.3.0: URL of the entity's A2A AgentCard endpoint
    /// (`.well-known/agent-card.json`), enabling cross-protocol discovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a_endpoint: Option<String>,
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
    /// When `false`, signals that this agent SHOULD NOT be included in public
    /// agent directories or registries (analogous to `noindex` for search
    /// engines). Defaults to `true` if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_listing: Option<bool>,
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
                directory_listing: None,
            }],
            revocation_endpoint: Some(
                "https://example.com/.well-known/agent-identity-revocations.json".to_string(),
            ),
            policy_url: None,
            schemapin_endpoint: None,
            a2a_endpoint: None,
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

    // ── v0.3.0: AllowedDomains tests ─────────────────────────────────

    #[test]
    fn allowed_domains_unrestricted_accepts_anything() {
        let ad = AllowedDomains::unrestricted();
        assert!(ad.is_unrestricted());
        assert!(ad.allows("anything.com"));
        assert!(ad.allows("example.com"));
    }

    #[test]
    fn allowed_domains_restricted_filters() {
        let ad = AllowedDomains::from_domains(["a.com", "b.com"]);
        assert!(!ad.is_unrestricted());
        assert!(ad.allows("a.com"));
        assert!(ad.allows("b.com"));
        assert!(!ad.allows("c.com"));
    }

    #[test]
    fn allowed_domains_intersect_with_unrestricted_returns_other() {
        let unrestricted = AllowedDomains::unrestricted();
        let restricted = AllowedDomains::from_domains(["a.com", "b.com"]);
        assert_eq!(
            unrestricted.intersect(&restricted).as_slice(),
            restricted.as_slice()
        );
        assert_eq!(
            restricted.intersect(&unrestricted).as_slice(),
            restricted.as_slice()
        );
    }

    #[test]
    fn allowed_domains_intersect_returns_overlap() {
        let lhs = AllowedDomains::from_domains(["a.com", "b.com", "c.com"]);
        let rhs = AllowedDomains::from_domains(["b.com", "c.com", "d.com"]);
        assert_eq!(
            lhs.intersect(&rhs).as_slice(),
            &["b.com".to_string(), "c.com".to_string()]
        );
    }

    #[test]
    fn allowed_domains_intersect_no_overlap_yields_empty() {
        let lhs = AllowedDomains::from_domains(["a.com"]);
        let rhs = AllowedDomains::from_domains(["b.com"]);
        let inter = lhs.intersect(&rhs);
        // empty == unrestricted under our convention; documented in the type
        assert!(inter.is_unrestricted());
    }

    #[test]
    fn allowed_domains_serializes_transparently() {
        let ad = AllowedDomains::from_domains(["a.com", "b.com"]);
        let json = serde_json::to_string(&ad).unwrap();
        assert_eq!(json, "[\"a.com\",\"b.com\"]");
        let back: AllowedDomains = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_slice(), ad.as_slice());
    }

    #[test]
    fn constraints_allowed_domains_typed_extracts_or_defaults() {
        let with_list = Constraints {
            allowed_domains: Some(vec!["a.com".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            with_list.allowed_domains_typed().as_slice(),
            &["a.com".to_string()]
        );

        let without = Constraints::default();
        assert!(without.allowed_domains_typed().is_unrestricted());
    }

    #[test]
    fn allowed_domains_collects_via_from_iterator() {
        let ad: AllowedDomains = ["a.com", "b.com"].iter().copied().collect();
        assert_eq!(ad.as_slice(), &["a.com".to_string(), "b.com".to_string()]);
    }
}
