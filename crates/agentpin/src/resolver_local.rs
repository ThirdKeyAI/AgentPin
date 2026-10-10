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
//!
//! ## Trust anchor (spec §4.10.4 step 5)
//!
//! An AgentCard is self-certifying: the only key that verifies it is the one
//! inside its own extension. Verifying the signature therefore proves
//! nothing about *which domain* the card speaks for. The store requires a
//! trust anchor at construction (AP-4, design issue 9):
//!
//! - [`with_trusted_thumbprints`](LocalAgentCardStore::with_trusted_thumbprints):
//!   an allowlist of JWK thumbprints the operator has verified out of band;
//! - [`with_resolver`](LocalAgentCardStore::with_resolver): the card key must
//!   appear, by thumbprint, in the authoritative discovery document of the
//!   endpoint's domain;
//! - [`unanchored`](LocalAgentCardStore::unanchored): explicit opt-out for
//!   callers whose registration channel already establishes provenance.
//!
//! [`new`](LocalAgentCardStore::new) creates a store with an empty allowlist,
//! which refuses every registration until a thumbprint is trusted.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::a2a::{extension_key_thumbprint, verify_agentpin_extension};
use crate::error::Error;
use crate::jwk::jwk_thumbprint;
use crate::resolver::DiscoveryResolver;
use crate::types::a2a::A2aAgentCard;
use crate::types::discovery::DiscoveryDocument;
use crate::types::revocation::RevocationDocument;

/// How a [`LocalAgentCardStore`] decides whether a card's key may speak for
/// its endpoint domain.
enum TrustAnchor {
    /// Only keys whose RFC 7638 thumbprint is in the set.
    Thumbprints(HashSet<String>),
    /// Only keys published in the domain's authoritative discovery document.
    Resolver(Arc<dyn DiscoveryResolver>),
    /// No check: the caller vouches for the registration channel.
    Unanchored,
}

/// In-memory store of pre-registered A2A AgentCards keyed by their AgentPin
/// discovery domain.
///
/// Cards are added via [`register`](Self::register) (after their AgentPin
/// extension signature is verified and the trust anchor accepts the key)
/// and looked up via the [`DiscoveryResolver`] trait — see
/// [`A2aAgentCardStore::resolve_card`] for raw card access.
///
/// Pair with [`crate::resolver::ChainResolver`] to fall back to HTTP fetches
/// for domains that aren't pre-registered.
pub struct LocalAgentCardStore {
    /// `domain -> (card, derived_discovery_doc)`. We pre-derive the
    /// discovery doc at registration time so [`DiscoveryResolver`] is cheap.
    inner: Mutex<HashMap<String, StoredCard>>,
    anchor: Mutex<TrustAnchor>,
}

struct StoredCard {
    card: A2aAgentCard,
    discovery: DiscoveryDocument,
}

impl LocalAgentCardStore {
    /// Construct an empty store with an empty thumbprint allowlist. Every
    /// registration is refused until [`trust_thumbprint`](Self::trust_thumbprint)
    /// is called; see the module docs for the other anchors.
    pub fn new() -> Self {
        Self::with_anchor(TrustAnchor::Thumbprints(HashSet::new()))
    }

    /// Construct a store that accepts only cards whose extension key has one
    /// of the given RFC 7638 thumbprints (hex).
    pub fn with_trusted_thumbprints<I, S>(thumbprints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::with_anchor(TrustAnchor::Thumbprints(
            thumbprints.into_iter().map(Into::into).collect(),
        ))
    }

    /// Construct a store that accepts only cards whose extension key is
    /// published in the authoritative discovery document for the card's
    /// endpoint domain, as resolved by `resolver` (spec §4.10.4 step 5).
    pub fn with_resolver(resolver: Arc<dyn DiscoveryResolver>) -> Self {
        Self::with_anchor(TrustAnchor::Resolver(resolver))
    }

    /// Construct a store with no trust anchor.
    ///
    /// Use only when the channel that delivers cards to `register` already
    /// authenticates the registrant for the domain it claims (an
    /// authenticated coordinator API, an operator-controlled config file).
    /// This is the "documented substitute provenance check" spec §4.10.4
    /// allows; without such a channel, anyone who can call `register` can
    /// assert any domain.
    pub fn unanchored() -> Self {
        Self::with_anchor(TrustAnchor::Unanchored)
    }

    fn with_anchor(anchor: TrustAnchor) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            anchor: Mutex::new(anchor),
        }
    }

    /// Add a trusted key thumbprint. Only meaningful for allowlist-anchored
    /// stores (including those from [`new`](Self::new)).
    pub fn trust_thumbprint(&self, thumbprint: impl Into<String>) -> Result<(), Error> {
        let mut anchor = self
            .anchor
            .lock()
            .map_err(|e| Error::Discovery(format!("LocalAgentCardStore mutex poisoned: {e}")))?;
        match &mut *anchor {
            TrustAnchor::Thumbprints(set) => {
                set.insert(thumbprint.into());
                Ok(())
            }
            _ => Err(Error::Discovery(
                "LocalAgentCardStore is not anchored on a thumbprint allowlist".to_string(),
            )),
        }
    }

    /// Check the trust anchor for `card` registered under `domain`.
    fn check_anchor(&self, card: &A2aAgentCard, domain: &str) -> Result<(), Error> {
        let ext = card
            .agentpin
            .as_ref()
            .ok_or_else(|| Error::Discovery("AgentCard has no agentpin extension".to_string()))?;
        let thumbprint = extension_key_thumbprint(ext);
        let anchor = self
            .anchor
            .lock()
            .map_err(|e| Error::Discovery(format!("LocalAgentCardStore mutex poisoned: {e}")))?;
        match &*anchor {
            TrustAnchor::Unanchored => Ok(()),
            TrustAnchor::Thumbprints(set) => {
                if set.contains(&thumbprint) {
                    Ok(())
                } else {
                    Err(Error::Discovery(format!(
                        "AgentCard key {} is not a trusted thumbprint for domain '{}'",
                        thumbprint, domain
                    )))
                }
            }
            TrustAnchor::Resolver(resolver) => {
                let doc = resolver.resolve_discovery(domain)?;
                if card_key_published_in(&doc, card) {
                    Ok(())
                } else {
                    Err(Error::Discovery(format!(
                        "AgentCard key {} is not published in the discovery document for '{}'",
                        thumbprint, domain
                    )))
                }
            }
        }
    }

    /// Register an AgentCard for the domain implied by its agentpin endpoint.
    ///
    /// Verifies the AgentPin extension signature, then requires the trust
    /// anchor to accept the card key for the endpoint's domain, before
    /// storing. The card is keyed by its (normalized) `agentpin_endpoint`
    /// host so [`resolve_discovery`] / [`resolve_revocation`] can find it.
    ///
    /// Re-registering an existing domain replaces the prior entry — useful
    /// for handling key rotations on long-lived coordinators.
    pub fn register(&self, card: A2aAgentCard) -> Result<(), Error> {
        verify_agentpin_extension(&card)?;
        let domain = card_endpoint_host(&card)?;
        self.check_anchor(&card, &domain)?;
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

    /// [`register`](Self::register), additionally requiring the card's
    /// endpoint host to equal `expected_domain` (normalized). Use this when
    /// the registration channel tells you which domain the registrant is
    /// allowed to speak for.
    pub fn register_for_domain(
        &self,
        card: A2aAgentCard,
        expected_domain: &str,
    ) -> Result<(), Error> {
        let expected = crate::domain::normalize_domain(expected_domain)?;
        let host = card_endpoint_host(&card)?;
        if host != expected {
            return Err(Error::Verification {
                code: crate::error::ErrorCode::DomainMismatch,
                message: format!(
                    "AgentCard agentpin_endpoint host '{}' does not match expected domain '{}'",
                    host, expected
                ),
            });
        }
        self.register(card)
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
            .and_then(|m| m.get(&store_key(domain)).map(|s| s.card.clone()))
    }

    /// Drop a registered AgentCard. Returns `true` when one was removed.
    pub fn remove(&self, domain: &str) -> bool {
        self.inner
            .lock()
            .map(|mut m| m.remove(&store_key(domain)).is_some())
            .unwrap_or(false)
    }
}

/// `true` when the card's extension key appears, by RFC 7638 thumbprint, in
/// `doc.public_keys` (spec §4.10.4 step 5).
pub fn card_key_published_in(doc: &DiscoveryDocument, card: &A2aAgentCard) -> bool {
    match card.agentpin.as_ref() {
        None => false,
        Some(ext) => {
            let tp = extension_key_thumbprint(ext);
            doc.public_keys.iter().any(|k| jwk_thumbprint(k) == tp)
        }
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
        map.get(&store_key(domain))
            .map(|s| s.discovery.clone())
            .ok_or_else(|| {
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
///
/// The endpoint must be an `https` URL with a domain host and no userinfo,
/// port or fragment; the returned host is normalized (AP-3, AP-12).
pub fn card_endpoint_host(card: &A2aAgentCard) -> Result<String, Error> {
    let ext = card
        .agentpin
        .as_ref()
        .ok_or_else(|| Error::Discovery("AgentCard has no agentpin extension".to_string()))?;
    crate::domain::https_url_host(&ext.agentpin_endpoint)
        .map_err(|e| Error::Discovery(format!("Invalid agentpin_endpoint URL: {}", e)))
}

/// Normalized store key for a domain (raw string when not a valid hostname,
/// which can never match a registered card).
fn store_key(domain: &str) -> String {
    crate::domain::normalize_domain(domain).unwrap_or_else(|_| domain.to_string())
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
            allowed_domains: Some(card.capabilities.allowed_domains.as_slice().to_vec()),
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
        agentpin_version: "0.1".to_string(),
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

    fn signed_card_with_key() -> (A2aAgentCard, crate::crypto::KeyPair) {
        let kp = generate_key_pair().unwrap();
        let decl = declaration();
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();
        (card, kp)
    }

    fn signed_card() -> A2aAgentCard {
        signed_card_with_key().0
    }

    /// A store that trusts exactly the key inside `card`.
    fn store_trusting(card: &A2aAgentCard) -> LocalAgentCardStore {
        let tp = crate::a2a::extension_key_thumbprint(card.agentpin.as_ref().unwrap());
        LocalAgentCardStore::with_trusted_thumbprints([tp])
    }

    /// AP-4 / design 9: a store with no trusted key refuses every
    /// registration, so "whoever can call register asserts any domain" is no
    /// longer the trust model.
    #[test]
    fn default_store_refuses_registration() {
        let store = LocalAgentCardStore::new();
        let err = store.register(signed_card()).unwrap_err().to_string();
        assert!(err.contains("not a trusted thumbprint"), "{}", err);
        assert!(store.is_empty());
    }

    /// AP-4: the self-signed card of an attacker that claims bank.example as
    /// its endpoint is refused by a thumbprint-anchored store and by a
    /// resolver-anchored store whose discovery document for bank.example
    /// does not publish the attacker's key.
    #[test]
    fn foreign_domain_claim_is_refused() {
        let kp = generate_key_pair().unwrap();
        let decl = declaration();
        let evil = A2aAgentCardBuilder::from_declaration("https://attacker.example/agent", &decl)
            .agentpin_endpoint("https://bank.example/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();

        // Allowlist anchored on some other key.
        let other = signed_card();
        let store = store_trusting(&other);
        assert!(store.register(evil.clone()).is_err());
        assert!(store.resolve_card("bank.example").is_none());

        // Resolver anchored: bank.example publishes a different key.
        let bank_kp = generate_key_pair().unwrap();
        let bank_vk = crate::crypto::load_verifying_key(&bank_kp.public_key_pem).unwrap();
        let bank_doc = crate::discovery::build_discovery_document(
            "bank.example",
            crate::types::discovery::EntityType::Deployer,
            vec![crate::jwk::verifying_key_to_jwk(&bank_vk, "bank-1")],
            vec![],
            0,
            "2026-01-15T00:00:00Z",
        );
        let mut bundle = crate::types::bundle::TrustBundle::new("2026-01-15T00:00:00Z");
        bundle.documents.push(bank_doc);
        let resolver = std::sync::Arc::new(crate::resolver::TrustBundleResolver::new(&bundle));
        let store = LocalAgentCardStore::with_resolver(resolver);
        let err = store.register(evil).unwrap_err().to_string();
        assert!(err.contains("not published"), "{}", err);
        assert!(store.is_empty());
    }

    /// Spec §4.10.4 step 5: a resolver-anchored store accepts a card whose
    /// key is published in the domain's discovery document.
    #[test]
    fn resolver_anchor_accepts_published_key() {
        let (card, kp) = signed_card_with_key();
        let vk = crate::crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let doc = crate::discovery::build_discovery_document(
            "example.com",
            crate::types::discovery::EntityType::Both,
            vec![crate::jwk::verifying_key_to_jwk(&vk, "kid-1")],
            vec![],
            0,
            "2026-01-15T00:00:00Z",
        );
        assert!(card_key_published_in(&doc, &card));
        let mut bundle = crate::types::bundle::TrustBundle::new("2026-01-15T00:00:00Z");
        bundle.documents.push(doc);
        let resolver = std::sync::Arc::new(crate::resolver::TrustBundleResolver::new(&bundle));
        let store = LocalAgentCardStore::with_resolver(resolver);
        store.register(card).unwrap();
        assert_eq!(store.len(), 1);
    }

    /// register_for_domain binds the registration to the domain the channel
    /// authenticated.
    #[test]
    fn register_for_domain_requires_matching_host() {
        let card = signed_card();
        let store = store_trusting(&card);
        assert!(store
            .register_for_domain(card.clone(), "other.com")
            .is_err());
        assert!(store.is_empty());
        store.register_for_domain(card, "EXAMPLE.com.").unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn trust_thumbprint_enables_registration() {
        let card = signed_card();
        let store = LocalAgentCardStore::new();
        assert!(store.register(card.clone()).is_err());
        store
            .trust_thumbprint(crate::a2a::extension_key_thumbprint(
                card.agentpin.as_ref().unwrap(),
            ))
            .unwrap();
        store.register(card).unwrap();
        assert!(LocalAgentCardStore::unanchored()
            .trust_thumbprint("x")
            .is_err());
    }

    #[test]
    fn unanchored_store_accepts_any_verified_card() {
        let store = LocalAgentCardStore::unanchored();
        store.register(signed_card()).unwrap();
        assert_eq!(store.len(), 1);
    }

    /// Regression test for AP-9: card-derived discovery documents must carry
    /// the wire protocol version ("0.1") so that the standard verifier
    /// accepts them. Before the fix they were stamped "0.3" and every
    /// credential resolved through the store failed with DISCOVERY_INVALID.
    #[test]
    fn credential_verifies_through_card_derived_discovery() {
        use crate::credential::issue_credential;
        use crate::crypto::load_signing_key;
        use crate::pinning::KeyPinStore;
        use crate::verification::{verify_credential_with_resolver, VerifierConfig};

        let (card, kp) = signed_card_with_key();
        let store = store_trusting(&card);
        store.register(card).unwrap();

        let doc = store.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.agentpin_version, "0.1");

        let sk = load_signing_key(&kp.private_key_pem).unwrap();
        let jwt = issue_credential(
            &sk,
            "kid-1",
            "example.com",
            "urn:agentpin:example.com:tester",
            None,
            vec![Capability::from("read:data")],
            None,
            None,
            3600,
        )
        .unwrap();

        let mut pin_store = KeyPinStore::new();
        let result = verify_credential_with_resolver(
            &jwt,
            &store,
            &mut pin_store,
            None,
            &VerifierConfig::default(),
        );
        assert!(result.valid, "expected valid, got {:?}", result);
        assert_eq!(result.issuer.as_deref(), Some("example.com"));
        assert_eq!(
            result.agent_id.as_deref(),
            Some("urn:agentpin:example.com:tester")
        );
    }

    #[test]
    fn register_then_resolve() {
        let card = signed_card();
        let store = store_trusting(&card);
        store.register(card).unwrap();
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
        let store = store_trusting(&card);
        assert!(store.register(card).is_err());
        assert!(store.is_empty());
    }

    /// AP-12: the agentpin_endpoint must be https with a domain host.
    #[test]
    fn register_rejects_non_https_or_ip_endpoint() {
        let kp = generate_key_pair().unwrap();
        let decl = declaration();
        for bad in [
            "http://example.com/.well-known/agent-identity.json",
            "https://127.0.0.1/.well-known/agent-identity.json",
            "https://example.com:8443/.well-known/agent-identity.json",
            "https://user@example.com/.well-known/agent-identity.json",
        ] {
            let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
                .agentpin_endpoint(bad)
                .sign(&kp.private_key_pem, "kid-1")
                .unwrap();
            let store = LocalAgentCardStore::unanchored();
            assert!(store.register(card).is_err(), "endpoint {:?} accepted", bad);
        }
    }

    /// AP-3: store lookups are case-insensitive.
    #[test]
    fn resolve_discovery_normalizes_lookup() {
        let store = LocalAgentCardStore::unanchored();
        store.register(signed_card()).unwrap();
        assert!(store.resolve_discovery("EXAMPLE.COM.").is_ok());
        assert!(store.resolve_card("Example.com").is_some());
    }

    #[test]
    fn resolve_discovery_missing_returns_err() {
        let store = LocalAgentCardStore::new();
        assert!(store.resolve_discovery("missing.com").is_err());
    }

    #[test]
    fn re_register_replaces_prior_entry() {
        let store = LocalAgentCardStore::unanchored();
        store.register(signed_card()).unwrap();
        store.register(signed_card()).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn remove_drops_entry() {
        let store = LocalAgentCardStore::unanchored();
        store.register(signed_card()).unwrap();
        assert!(store.remove("example.com"));
        assert!(store.is_empty());
        assert!(!store.remove("example.com"));
    }

    #[test]
    fn resolve_card_returns_clone() {
        let store = LocalAgentCardStore::unanchored();
        store.register(signed_card()).unwrap();
        let card = store.resolve_card("example.com").unwrap();
        assert_eq!(card.name, "Tester");
    }

    #[test]
    fn allowed_domains_propagate_into_derived_doc() {
        let store = LocalAgentCardStore::unanchored();
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
        let store = LocalAgentCardStore::unanchored();
        store.register(signed_card()).unwrap();
        let doc = store.resolve_discovery("example.com").unwrap();
        let rev = store.resolve_revocation("example.com", &doc).unwrap();
        assert!(rev.is_none());
    }
}
