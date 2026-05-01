//! [`LocalAgentCardStore`] — in-memory A2A AgentCard store (v0.3.0).
//!
//! For agents that do not serve HTTP themselves (CLI tools, daemon processes,
//! external agents pushed into a coordinator at registration time), the
//! coordinator can keep their AgentCards in memory and resolve them via
//! [`DiscoveryResolver`] without making any network calls.
//!
//! This supports Symbiont v1.7.0's push-based external-agent registration
//! flow, where a coordinator receives the AgentCard JSON inline rather than
//! fetching it from a `.well-known` endpoint.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::a2a::verify_agentpin_extension;
use crate::error::Error;
use crate::resolver::DiscoveryResolver;
use crate::types::a2a::A2aAgentCard;
use crate::types::discovery::DiscoveryDocument;
use crate::types::revocation::RevocationDocument;

/// In-memory store of pre-registered A2A AgentCards keyed by their AgentPin
/// discovery domain.
///
/// Cards are added via [`register`](Self::register) (after their AgentPin
/// extension signature is verified) and looked up via the
/// [`DiscoveryResolver`] trait — see [`A2aAgentCardStore::resolve_card`] for
/// raw card access.
///
/// Pair with [`crate::resolver::ChainResolver`] to fall back to HTTP fetches
/// for domains that aren't pre-registered.
pub struct LocalAgentCardStore {
    /// `agentpin_endpoint -> (card, derived_discovery_doc)`. We pre-derive the
    /// discovery doc at registration time so [`DiscoveryResolver`] is cheap.
    inner: Mutex<HashMap<String, StoredCard>>,
}

struct StoredCard {
    card: A2aAgentCard,
    discovery: DiscoveryDocument,
}

impl LocalAgentCardStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register an AgentCard for the domain implied by its agentpin endpoint.
    ///
    /// Verifies the AgentPin extension signature before storing. The card is
    /// keyed by its `agentpin_endpoint` host so [`resolve_discovery`] /
    /// [`resolve_revocation`] can find it later.
    ///
    /// Re-registering an existing domain replaces the prior entry — useful
    /// for handling key rotations on long-lived coordinators.
    pub fn register(&self, card: A2aAgentCard) -> Result<(), Error> {
        verify_agentpin_extension(&card)?;
        let domain = card_endpoint_host(&card)?;
        let discovery = derive_discovery_from_card(&card)?;
        let stored = StoredCard {
            card: card.clone(),
            discovery,
        };
        self.inner
            .lock()
            .map_err(|e| Error::Discovery(format!("LocalAgentCardStore mutex poisoned: {e}")))?
            .insert(domain, stored);
        Ok(())
    }

    /// Number of registered AgentCards.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// `true` when no AgentCards are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the raw [`A2aAgentCard`] for a given domain, if registered.
    pub fn resolve_card(&self, domain: &str) -> Option<A2aAgentCard> {
        self.inner
            .lock()
            .ok()
            .and_then(|m| m.get(domain).map(|s| s.card.clone()))
    }

    /// Drop a registered AgentCard. Returns `true` when one was removed.
    pub fn remove(&self, domain: &str) -> bool {
        self.inner
            .lock()
            .map(|mut m| m.remove(domain).is_some())
            .unwrap_or(false)
    }
}

impl Default for LocalAgentCardStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryResolver for LocalAgentCardStore {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        let map = self
            .inner
            .lock()
            .map_err(|e| Error::Discovery(format!("LocalAgentCardStore mutex poisoned: {e}")))?;
        map.get(domain).map(|s| s.discovery.clone()).ok_or_else(|| {
            Error::Discovery(format!("Domain '{}' not in LocalAgentCardStore", domain))
        })
    }

    fn resolve_revocation(
        &self,
        _domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        // The store doesn't carry revocation data. Pair with `ChainResolver`
        // and a HTTP / file resolver for revocation fallback.
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the host portion of the AgentCard's agentpin endpoint URL.
///
/// `https://example.com/.well-known/agent-identity.json` -> `example.com`.
pub(crate) fn card_endpoint_host(card: &A2aAgentCard) -> Result<String, Error> {
    let ext = card
        .agentpin
        .as_ref()
        .ok_or_else(|| Error::Discovery("AgentCard has no agentpin extension".to_string()))?;
    let url = url::Url::parse(&ext.agentpin_endpoint)
        .map_err(|e| Error::Discovery(format!("Invalid agentpin_endpoint URL: {e}")))?;
    url.host_str()
        .map(|h| h.to_string())
        .ok_or_else(|| Error::Discovery("agentpin_endpoint URL has no host".to_string()))
}

/// Derive a minimal [`DiscoveryDocument`] from an A2A AgentCard.
///
/// The card's [`AgentpinExtension::public_key_jwk`] becomes the sole entry in
/// `public_keys`; the card's name/description/version/capabilities become a
/// single [`AgentDeclaration`]. This lets the rest of the AgentPin verification
/// stack (TOFU pinning, revocation checking, capability validation) run
/// against AgentCards exactly the way it runs against fetched discovery docs.
pub(crate) fn derive_discovery_from_card(card: &A2aAgentCard) -> Result<DiscoveryDocument, Error> {
    use crate::types::discovery::{AgentDeclaration, AgentStatus, EntityType};

    let extension = card
        .agentpin
        .as_ref()
        .ok_or_else(|| Error::Discovery("AgentCard has no agentpin extension".to_string()))?;
    let domain = card_endpoint_host(card)?;

    // Reverse-engineer the capability list from skill IDs (built by
    // capability_to_skill on the issuer side).
    let capabilities = card
        .skills
        .iter()
        .map(|s| crate::types::capability::Capability::from(s.id.as_str()))
        .collect();

    let constraints = if card.capabilities.allowed_domains.is_unrestricted() {
        None
    } else {
        Some(crate::types::constraint::Constraints {
            allowed_domains: Some(card.capabilities.allowed_domains.0.clone()),
            ..Default::default()
        })
    };

    let agent_id = format!("urn:agentpin:{}:{}", domain, slug(&card.name));

    let declaration = AgentDeclaration {
        agent_id,
        agent_type: None,
        name: card.name.clone(),
        description: card.description.clone(),
        version: card.version.clone(),
        capabilities,
        constraints,
        maker_attestation: None,
        credential_ttl_max: None,
        status: AgentStatus::Active,
        directory_listing: None,
    };

    Ok(DiscoveryDocument {
        agentpin_version: "0.3".to_string(),
        entity: domain,
        entity_type: EntityType::Both,
        public_keys: vec![extension.public_key_jwk.clone()],
        agents: vec![declaration],
        revocation_endpoint: None,
        policy_url: None,
        schemapin_endpoint: None,
        a2a_endpoint: Some(extension.agentpin_endpoint.clone()),
        max_delegation_depth: 0,
        updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

fn slug(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::A2aAgentCardBuilder;
    use crate::crypto::generate_key_pair;
    use crate::types::capability::Capability;
    use crate::types::constraint::Constraints;
    use crate::types::discovery::{AgentDeclaration, AgentStatus};

    fn declaration() -> AgentDeclaration {
        AgentDeclaration {
            agent_id: "urn:agentpin:example.com:tester".to_string(),
            agent_type: None,
            name: "Tester".to_string(),
            description: Some("Test agent".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec![Capability::from("read:*")],
            constraints: Some(Constraints {
                allowed_domains: Some(vec!["partner.com".to_string()]),
                ..Default::default()
            }),
            maker_attestation: None,
            credential_ttl_max: Some(3600),
            status: AgentStatus::Active,
            directory_listing: None,
        }
    }

    fn signed_card() -> A2aAgentCard {
        let kp = generate_key_pair().unwrap();
        let decl = declaration();
        A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap()
    }

    #[test]
    fn register_then_resolve() {
        let store = LocalAgentCardStore::new();
        store.register(signed_card()).unwrap();
        assert_eq!(store.len(), 1);
        let doc = store.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.entity, "example.com");
        assert_eq!(doc.public_keys.len(), 1);
        assert_eq!(doc.agents.len(), 1);
        assert_eq!(doc.agents[0].name, "Tester");
    }

    #[test]
    fn register_propagates_signature_failure() {
        let mut card = signed_card();
        card.url = "https://attacker.example/agent".to_string(); // tampered
        let store = LocalAgentCardStore::new();
        assert!(store.register(card).is_err());
        assert!(store.is_empty());
    }

    #[test]
    fn resolve_discovery_missing_returns_err() {
        let store = LocalAgentCardStore::new();
        assert!(store.resolve_discovery("missing.com").is_err());
    }

    #[test]
    fn re_register_replaces_prior_entry() {
        let store = LocalAgentCardStore::new();
        store.register(signed_card()).unwrap();
        store.register(signed_card()).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn remove_drops_entry() {
        let store = LocalAgentCardStore::new();
        store.register(signed_card()).unwrap();
        assert!(store.remove("example.com"));
        assert!(store.is_empty());
        assert!(!store.remove("example.com"));
    }

    #[test]
    fn resolve_card_returns_clone() {
        let store = LocalAgentCardStore::new();
        store.register(signed_card()).unwrap();
        let card = store.resolve_card("example.com").unwrap();
        assert_eq!(card.name, "Tester");
    }

    #[test]
    fn allowed_domains_propagate_into_derived_doc() {
        let store = LocalAgentCardStore::new();
        store.register(signed_card()).unwrap();
        let doc = store.resolve_discovery("example.com").unwrap();
        let constraints = doc.agents[0].constraints.as_ref().unwrap();
        assert_eq!(
            constraints.allowed_domains.as_ref().unwrap(),
            &vec!["partner.com".to_string()]
        );
    }

    #[test]
    fn revocation_lookup_returns_none() {
        let store = LocalAgentCardStore::new();
        store.register(signed_card()).unwrap();
        let doc = store.resolve_discovery("example.com").unwrap();
        let rev = store.resolve_revocation("example.com", &doc).unwrap();
        assert!(rev.is_none());
    }
}
