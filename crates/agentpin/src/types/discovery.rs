use serde::{Deserialize, Serialize};

use super::capability::Capability;
use super::constraint::Constraints;
use crate::jwk::Jwk;

/// List of domains an agent is permitted to interact with (v0.3.0, made a
/// proper tri-state in v0.4 — AP-6).
///
/// Extracted from [`Constraints::allowed_domains`] for use by cross-protocol
/// A2A verification — most notably SchemaPin v1.4's `A2aVerificationContext`,
/// which scopes tool verification to the intersection of caller and provider
/// domains.
///
/// Wire form: an absent `allowed_domains` field is [`Unrestricted`]; a
/// present list (including the empty list) is [`Restricted`]. "No
/// restriction" and "restricted to nothing" are therefore distinct, so the
/// intersection of two disjoint allow-lists is `Restricted([])` — which
/// allows nothing — and can never be re-interpreted as unrestricted.
///
/// [`Unrestricted`]: AllowedDomains::Unrestricted
/// [`Restricted`]: AllowedDomains::Restricted
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Option<Vec<String>>", into = "Option<Vec<String>>")]
pub enum AllowedDomains {
    /// No restriction: every domain is allowed.
    #[default]
    Unrestricted,
    /// Only domains matching one of the listed literals or `*.` patterns
    /// (spec §5.5) are allowed. An empty list allows nothing.
    Restricted(Vec<String>),
}

impl From<Option<Vec<String>>> for AllowedDomains {
    fn from(value: Option<Vec<String>>) -> Self {
        match value {
            None => AllowedDomains::Unrestricted,
            Some(list) => AllowedDomains::Restricted(list),
        }
    }
}

impl From<AllowedDomains> for Option<Vec<String>> {
    fn from(value: AllowedDomains) -> Self {
        match value {
            AllowedDomains::Unrestricted => None,
            AllowedDomains::Restricted(list) => Some(list),
        }
    }
}

impl AllowedDomains {
    /// No restriction — all domains trusted.
    pub fn unrestricted() -> Self {
        Self::Unrestricted
    }

    /// Construct a restricted list from any iterable of strings. An empty
    /// iterable yields `Restricted([])`, which allows nothing.
    pub fn from_domains<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Restricted(iter.into_iter().map(Into::into).collect())
    }

    /// `true` when there is no restriction.
    pub fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted)
    }

    /// `true` when `domain` is allowed under this list. Patterns use the
    /// §5.5 `*.` wildcard rules; `Restricted([])` allows nothing.
    pub fn allows(&self, domain: &str) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Restricted(list) => list
                .iter()
                .any(|pattern| super::constraint::domain_pattern_matches(pattern, domain)),
        }
    }

    /// Intersection of two allow-lists.
    ///
    /// - `Unrestricted ∩ X = X`
    /// - `X ∩ Unrestricted = X`
    /// - `Restricted(a) ∩ Restricted(b)` = the entries of either list that
    ///   are allowed by the other (so `*.corp.com ∩ api.corp.com` =
    ///   `api.corp.com`); when the lists are disjoint the result is
    ///   `Restricted([])`, which allows nothing.
    pub fn intersect(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unrestricted, x) | (x, Self::Unrestricted) => x.clone(),
            (Self::Restricted(a), Self::Restricted(b)) => {
                let mut out: Vec<String> = Vec::new();
                for d in a.iter().filter(|d| other.allows(d)) {
                    if !out.contains(d) {
                        out.push(d.clone());
                    }
                }
                for d in b.iter().filter(|d| self.allows(d)) {
                    if !out.contains(d) {
                        out.push(d.clone());
                    }
                }
                Self::Restricted(out)
            }
        }
    }

    /// Borrow the restricted list; empty for `Unrestricted`. Use
    /// [`is_unrestricted`](Self::is_unrestricted) to tell the two apart.
    pub fn as_slice(&self) -> &[String] {
        match self {
            Self::Unrestricted => &[],
            Self::Restricted(list) => list,
        }
    }
}

impl<S> std::iter::FromIterator<S> for AllowedDomains
where
    S: Into<String>,
{
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self::from_domains(iter)
    }
}

impl Constraints {
    /// Extract [`AllowedDomains`] from the constraints' `allowed_domains` field.
    ///
    /// Returns [`AllowedDomains::Unrestricted`] when the field is absent and
    /// `Restricted(list)` (including the empty list) when it is present.
    pub fn allowed_domains_typed(&self) -> AllowedDomains {
        match &self.allowed_domains {
            Some(list) => AllowedDomains::Restricted(list.clone()),
            None => AllowedDomains::Unrestricted,
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

    /// AP-6: disjoint allow-lists intersect to "restricted to nothing", which
    /// allows nothing and is never re-interpreted as unrestricted.
    #[test]
    fn allowed_domains_intersect_no_overlap_allows_nothing() {
        let lhs = AllowedDomains::from_domains(["a.com"]);
        let rhs = AllowedDomains::from_domains(["b.com"]);
        let inter = lhs.intersect(&rhs);
        assert!(!inter.is_unrestricted());
        assert_eq!(inter, AllowedDomains::Restricted(vec![]));
        assert!(!inter.allows("a.com"));
        assert!(!inter.allows("anything.com"));
        assert!(!AllowedDomains::from_domains(Vec::<String>::new()).allows("x.com"));
    }

    /// AP-6: `allows` and `intersect` use the §5.5 pattern rules.
    #[test]
    fn allowed_domains_pattern_matching() {
        let wild = AllowedDomains::from_domains(["*.corp.com"]);
        assert!(wild.allows("api.corp.com"));
        assert!(!wild.allows("corp.com"));
        assert!(!wild.allows("evil-corp.com"));
        let literal = AllowedDomains::from_domains(["api.corp.com"]);
        assert_eq!(
            wild.intersect(&literal),
            AllowedDomains::from_domains(["api.corp.com"])
        );
        assert_eq!(
            literal.intersect(&wild),
            AllowedDomains::from_domains(["api.corp.com"])
        );
    }

    /// AP-6: wire form — absent is unrestricted, `[]` is restricted to nothing.
    #[test]
    fn allowed_domains_wire_form() {
        let ad = AllowedDomains::from_domains(["a.com", "b.com"]);
        let json = serde_json::to_string(&ad).unwrap();
        assert_eq!(json, "[\"a.com\",\"b.com\"]");
        let back: AllowedDomains = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ad);

        let empty: AllowedDomains = serde_json::from_str("[]").unwrap();
        assert_eq!(empty, AllowedDomains::Restricted(vec![]));
        assert_eq!(serde_json::to_string(&empty).unwrap(), "[]");

        let none: AllowedDomains = serde_json::from_str("null").unwrap();
        assert!(none.is_unrestricted());
        assert_eq!(
            serde_json::to_string(&AllowedDomains::Unrestricted).unwrap(),
            "null"
        );

        // Constraints: Some([]) is restricted to nothing, None is unrestricted.
        let restricted_to_nothing = Constraints {
            allowed_domains: Some(vec![]),
            ..Default::default()
        };
        assert!(!restricted_to_nothing
            .allowed_domains_typed()
            .is_unrestricted());
        assert!(Constraints::default()
            .allowed_domains_typed()
            .is_unrestricted());
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
