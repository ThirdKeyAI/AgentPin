//! A2A AgentCard signing and verification (v0.3.0, hardened in v0.4).
//!
//! This module turns an AgentPin [`AgentDeclaration`] into a signed A2A
//! [`A2aAgentCard`] via [`A2aAgentCardBuilder`], and verifies a received
//! AgentCard's [`AgentpinExtension`] payload via [`verify_agentpin_extension`].
//!
//! ## Signature canonicalization
//!
//! The detached ECDSA P-256 signature inside an [`AgentpinExtension`] covers
//! the **domain-separated canonical bytes of the AgentCard including the
//! extension's `agentpin_endpoint` and `public_key_jwk`** (but not the
//! `signature` field itself):
//!
//! 1. Take the AgentCard you intend to publish.
//! 2. Replace its `agentpin` field with
//!    `{"agentpin_endpoint": ..., "public_key_jwk": ...}` (no `signature`).
//! 3. Serialize it as sorted-key, compact JSON (unknown fields included
//!    verbatim).
//! 4. Prefix the context label `agentpin-agentcard-v1` and a length prefix
//!    (see [`crate::crypto::domain_separated_input`]).
//! 5. Sign those bytes with ECDSA P-256.
//!
//! The verifier reproduces steps 1-4 from the received card and checks the
//! signature against the JWK in the extension. The signature therefore
//! covers every field of the card: `name`, `url`, `capabilities`, `skills`,
//! any upstream A2A fields, **and** the extension's `agentpin_endpoint` and
//! `public_key_jwk`. Rewriting the endpoint to point at another domain
//! breaks the signature (AP-4), and the context label keeps card signatures
//! disjoint from credential, attestation and challenge-response signatures
//! (AP-1).

use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use serde::Serialize;

use crate::crypto;
use crate::error::Error;
use crate::jwk::{jwk_thumbprint, pem_to_jwk};
use crate::types::a2a::{
    capability_to_skill, A2aAgentCapabilities, A2aAgentCard, A2aAgentSkill, AgentpinExtension,
};
use crate::types::discovery::{AgentDeclaration, AllowedDomains};

/// Derive the public-key PEM from a private-key PEM (P-256).
fn derive_public_pem(private_key_pem: &str) -> Result<String, Error> {
    let secret = p256::SecretKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| Error::Ecdsa(e.to_string()))?;
    let public = secret.public_key();
    public
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| Error::Ecdsa(e.to_string()))
}

/// Builder that turns an AgentPin [`AgentDeclaration`] into a signed A2A
/// [`A2aAgentCard`].
///
/// Minimal usage:
///
/// ```ignore
/// let card = A2aAgentCardBuilder::from_declaration(
///     "https://example.com/agent",
///     &declaration,
/// )
/// .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
/// .sign(&private_key_pem, "kid-1")?;
/// ```
pub struct A2aAgentCardBuilder<'a> {
    url: String,
    declaration: &'a AgentDeclaration,
    agentpin_endpoint: Option<String>,
    skill_overrides: Vec<A2aAgentSkill>,
    streaming: bool,
    push_notifications: bool,
    extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<'a> A2aAgentCardBuilder<'a> {
    /// Start a builder seeded from an [`AgentDeclaration`].
    ///
    /// The capability list is mapped 1:1 to A2A skills via
    /// [`capability_to_skill`]; the `allowed_domains` constraint is mapped to
    /// [`A2aAgentCapabilities::allowed_domains`].
    pub fn from_declaration(url: impl Into<String>, declaration: &'a AgentDeclaration) -> Self {
        Self {
            url: url.into(),
            declaration,
            agentpin_endpoint: None,
            skill_overrides: Vec::new(),
            streaming: false,
            push_notifications: false,
            extra: std::collections::BTreeMap::new(),
        }
    }

    /// Attach an upstream A2A field (e.g. `provider`, `documentationUrl`)
    /// that AgentPin does not model. It is preserved verbatim and covered by
    /// the signature (AP-17).
    pub fn extra_field(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Set the AgentPin discovery endpoint URL written into the extension.
    pub fn agentpin_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.agentpin_endpoint = Some(endpoint.into());
        self
    }

    /// Replace the auto-generated skill list with caller-supplied entries.
    /// Useful when callers want richer names or descriptions than the raw
    /// capability strings provide.
    pub fn with_skill_overrides(mut self, skills: Vec<A2aAgentSkill>) -> Self {
        self.skill_overrides = skills;
        self
    }

    /// Mark the agent as supporting streaming responses.
    pub fn streaming(mut self, value: bool) -> Self {
        self.streaming = value;
        self
    }

    /// Mark the agent as emitting push notifications.
    pub fn push_notifications(mut self, value: bool) -> Self {
        self.push_notifications = value;
        self
    }

    /// Construct an unsigned [`A2aAgentCard`] (extension absent).
    ///
    /// Useful for testing the structural mapping without performing crypto.
    pub fn build_unsigned(&self) -> A2aAgentCard {
        let skills = if self.skill_overrides.is_empty() {
            self.declaration
                .capabilities
                .iter()
                .map(capability_to_skill)
                .collect()
        } else {
            self.skill_overrides.clone()
        };

        let allowed_domains = self
            .declaration
            .constraints
            .as_ref()
            .map(|c| c.allowed_domains_typed())
            .unwrap_or_else(AllowedDomains::unrestricted);

        A2aAgentCard {
            name: self.declaration.name.clone(),
            description: self.declaration.description.clone(),
            version: self.declaration.version.clone(),
            url: self.url.clone(),
            capabilities: A2aAgentCapabilities {
                streaming: self.streaming,
                push_notifications: self.push_notifications,
                allowed_domains,
                extra: Default::default(),
            },
            skills,
            agentpin: None,
            extra: self.extra.clone(),
        }
    }

    /// Sign the AgentCard with the given ECDSA P-256 private key (PEM).
    ///
    /// Requires [`agentpin_endpoint`](Self::agentpin_endpoint) to have been
    /// set, otherwise returns [`Error::Validation`].
    pub fn sign(&self, private_key_pem: &str, kid: &str) -> Result<A2aAgentCard, Error> {
        let endpoint = self.agentpin_endpoint.clone().ok_or_else(|| {
            Error::Discovery(
                "A2aAgentCardBuilder::sign requires agentpin_endpoint to be set".to_string(),
            )
        })?;

        let public_key_pem = derive_public_pem(private_key_pem)?;
        let public_key_jwk = pem_to_jwk(&public_key_pem, kid)?;

        // Build the unsigned card; sign over its domain-separated canonical
        // bytes with the endpoint and JWK included.
        let mut card = self.build_unsigned();
        let input = agent_card_signing_input_for(&card, &endpoint, &public_key_jwk)?;
        let signing_key = crypto::load_signing_key(private_key_pem)?;
        let signature_b64 = crypto::sign_bytes(&signing_key, &input);

        card.agentpin = Some(AgentpinExtension {
            agentpin_endpoint: endpoint,
            public_key_jwk,
            signature: signature_b64,
        });
        Ok(card)
    }
}

/// Verify the [`AgentpinExtension`] of an A2A AgentCard.
///
/// Returns `Ok(())` when:
/// 1. The extension is present.
/// 2. The detached signature verifies against `public_key_jwk` over the
///    canonicalised bytes of the AgentCard with the extension cleared.
///
/// The caller still has to verify the JWK chains back to a trusted AgentPin
/// discovery document — this function only proves the AgentCard hasn't been
/// tampered with relative to the key inside its own extension. Pair it with
/// [`crate::resolver_a2a::A2aAgentCardResolver`] for the full chain.
pub fn verify_agentpin_extension(card: &A2aAgentCard) -> Result<(), Error> {
    let extension = card
        .agentpin
        .as_ref()
        .ok_or_else(|| Error::Discovery("AgentCard has no agentpin extension".to_string()))?;

    // Reconstruct the canonical signing input: card with the extension's
    // endpoint and JWK included and its signature cleared.
    let input = agent_card_signing_input(card)?;

    let verifying_key = crate::jwk::jwk_to_verifying_key(&extension.public_key_jwk)?;
    let valid = crypto::verify_bytes(&verifying_key, &input, &extension.signature)?;
    if !valid {
        return Err(Error::Discovery(
            "A2A AgentCard signature did not verify against extension JWK".to_string(),
        ));
    }
    Ok(())
}

/// Compute the JWK thumbprint (key id) of the public key in an
/// [`AgentpinExtension`]. Convenience wrapper used by resolvers when they
/// need to match the card's key against a discovery document.
pub fn extension_key_thumbprint(ext: &AgentpinExtension) -> String {
    jwk_thumbprint(&ext.public_key_jwk)
}

// ---------------------------------------------------------------------------
// Canonicalisation
// ---------------------------------------------------------------------------

/// Produce the full signing input for a signed [`A2aAgentCard`], using the
/// `agentpin_endpoint` and `public_key_jwk` from its own extension.
///
/// Returns the domain-separated bytes that `agentpin.signature` must verify
/// against. Exposed so cross-language conformance tests can compare the
/// exact bytes.
pub fn agent_card_signing_input(card: &A2aAgentCard) -> Result<Vec<u8>, Error> {
    let extension = card
        .agentpin
        .as_ref()
        .ok_or_else(|| Error::Discovery("AgentCard has no agentpin extension".to_string()))?;
    agent_card_signing_input_for(
        card,
        &extension.agentpin_endpoint,
        &extension.public_key_jwk,
    )
}

/// Produce the signing input for `card` as if it carried an extension with
/// the given endpoint and JWK (and no signature).
fn agent_card_signing_input_for(
    card: &A2aAgentCard,
    agentpin_endpoint: &str,
    public_key_jwk: &crate::jwk::Jwk,
) -> Result<Vec<u8>, Error> {
    let mut value: serde_json::Value = serde_json::to_value(card)?;
    let ext = serde_json::json!({
        "agentpin_endpoint": agentpin_endpoint,
        "public_key_jwk": serde_json::to_value(public_key_jwk)?,
    });
    match value.as_object_mut() {
        Some(map) => {
            map.insert("agentpin".to_string(), ext);
        }
        None => {
            return Err(Error::Discovery(
                "AgentCard did not serialize to a JSON object".to_string(),
            ))
        }
    }
    let canonical = canonicalize_json(&value)?;
    Ok(crypto::domain_separated_input(
        crypto::CTX_AGENTCARD,
        &[&canonical],
    ))
}

/// Canonical JSON bytes: sorted keys at every depth, compact separators.
pub fn canonicalize_json(value: &serde_json::Value) -> Result<Vec<u8>, Error> {
    let canonical = sorted_canonical(value);
    serde_json::to_vec(&canonical).map_err(Error::from)
}

/// Recursively rebuild a [`serde_json::Value`] with object keys sorted.
fn sorted_canonical(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut sorted = serde_json::Map::new();
            for (k, v) in entries {
                sorted.insert(k.clone(), sorted_canonical(v));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(sorted_canonical).collect())
        }
        other => other.clone(),
    }
}

// Trick to silence the `unused` lint on the trait import when only used in
// tests below — the public API does not need it.
#[allow(dead_code)]
fn _serialize_marker<T: Serialize>(_: &T) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_key_pair, KeyPair};
    use crate::types::capability::Capability;
    use crate::types::constraint::Constraints;
    use crate::types::discovery::{AgentDeclaration, AgentStatus};

    fn declaration_with_caps(caps: Vec<&str>, allowed: Option<Vec<&str>>) -> AgentDeclaration {
        AgentDeclaration {
            agent_id: "urn:agentpin:example.com:test".to_string(),
            agent_type: None,
            name: "Test Agent".to_string(),
            description: Some("test".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: caps.into_iter().map(Capability::from).collect(),
            constraints: allowed.map(|d| Constraints {
                allowed_domains: Some(d.into_iter().map(String::from).collect()),
                ..Default::default()
            }),
            maker_attestation: None,
            credential_ttl_max: Some(3600),
            status: AgentStatus::Active,
            directory_listing: None,
        }
    }

    fn keypair() -> KeyPair {
        generate_key_pair().unwrap()
    }

    #[test]
    fn build_unsigned_maps_capabilities_to_skills() {
        let decl = declaration_with_caps(vec!["read:customers", "write:invoices"], None);
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .build_unsigned();
        assert_eq!(card.skills.len(), 2);
        assert_eq!(card.skills[0].id, "read:customers");
        assert_eq!(card.skills[1].id, "write:invoices");
        assert!(card.agentpin.is_none(), "unsigned card has no extension");
    }

    #[test]
    fn build_unsigned_maps_allowed_domains() {
        let decl = declaration_with_caps(vec!["read:*"], Some(vec!["a.com", "b.com"]));
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .build_unsigned();
        assert_eq!(
            card.capabilities.allowed_domains.as_slice(),
            &["a.com".to_string(), "b.com".to_string()]
        );
    }

    #[test]
    fn build_unsigned_treats_missing_constraints_as_unrestricted() {
        let decl = declaration_with_caps(vec!["read:*"], None);
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .build_unsigned();
        assert!(card.capabilities.allowed_domains.is_unrestricted());
    }

    #[test]
    fn sign_requires_agentpin_endpoint() {
        let decl = declaration_with_caps(vec!["read:*"], None);
        let kp = keypair();
        let result = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .sign(&kp.private_key_pem, "kid-1");
        assert!(matches!(result, Err(Error::Discovery(_))));
    }

    #[test]
    fn signed_card_round_trips_and_verifies() {
        let decl = declaration_with_caps(
            vec!["read:customers", "write:invoices"],
            Some(vec!["partner.com"]),
        );
        let kp = keypair();
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .streaming(true)
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();

        // Card carries the extension and verifies cleanly.
        assert!(card.agentpin.is_some());
        verify_agentpin_extension(&card).unwrap();

        // Round-trip through JSON and re-verify.
        let json = serde_json::to_string(&card).unwrap();
        let parsed: A2aAgentCard = serde_json::from_str(&json).unwrap();
        verify_agentpin_extension(&parsed).unwrap();
    }

    #[test]
    fn verify_fails_when_extension_missing() {
        let decl = declaration_with_caps(vec!["read:*"], None);
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .build_unsigned();
        let err = verify_agentpin_extension(&card).unwrap_err();
        assert!(matches!(err, Error::Discovery(_)));
    }

    #[test]
    fn verify_fails_when_card_tampered() {
        let decl = declaration_with_caps(vec!["read:customers"], None);
        let kp = keypair();
        let mut card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();

        // Tamper with the URL — signature should now fail.
        card.url = "https://attacker.example/agent".to_string();
        let err = verify_agentpin_extension(&card).unwrap_err();
        assert!(matches!(err, Error::Discovery(_)));
    }

    /// AP-4: the signature covers `agentpin_endpoint`, so re-pointing a
    /// legitimately signed card at another domain's discovery endpoint
    /// breaks verification.
    #[test]
    fn verify_fails_when_agentpin_endpoint_rewritten() {
        let decl = declaration_with_caps(vec!["read:customers"], None);
        let kp = keypair();
        let mut card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();
        card.agentpin.as_mut().unwrap().agentpin_endpoint =
            "https://bank.example/.well-known/agent-identity.json".to_string();
        assert!(matches!(
            verify_agentpin_extension(&card),
            Err(Error::Discovery(_))
        ));
    }

    /// AP-4: the signature covers the extension JWK metadata (kid etc.).
    #[test]
    fn verify_fails_when_extension_jwk_kid_rewritten() {
        let decl = declaration_with_caps(vec!["read:customers"], None);
        let kp = keypair();
        let mut card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();
        card.agentpin.as_mut().unwrap().public_key_jwk.kid = "kid-2".to_string();
        assert!(verify_agentpin_extension(&card).is_err());
    }

    /// AP-1: the card signature is domain separated — it is not a raw
    /// signature over the canonical JSON, and a raw signature over the
    /// legacy (extension-cleared) canonical bytes does not verify.
    #[test]
    fn card_signature_is_domain_separated() {
        let decl = declaration_with_caps(vec!["read:customers"], None);
        let kp = keypair();
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();
        let input = agent_card_signing_input(&card).unwrap();
        assert!(input.starts_with(b"agentpin-agentcard-v1\0"));
        let sig = &card.agentpin.as_ref().unwrap().signature;
        // The raw canonical JSON (without the context prefix) is not what was signed.
        let canonical = &input[crypto::CTX_AGENTCARD.len() + 1 + 4..];
        assert!(!crypto::verify_signature(&kp.public_key_pem, canonical, sig).unwrap());

        // Legacy format: signature over the card with the extension cleared.
        let mut legacy_card = card.clone();
        legacy_card.agentpin = None;
        let legacy_bytes = canonicalize_json(&serde_json::to_value(&legacy_card).unwrap()).unwrap();
        let legacy_sig = crypto::sign_data(&kp.private_key_pem, &legacy_bytes).unwrap();
        let mut forged = card.clone();
        forged.agentpin.as_mut().unwrap().signature = legacy_sig;
        assert!(verify_agentpin_extension(&forged).is_err());
    }

    /// AP-17: upstream fields are part of the signed bytes — a card signed
    /// with them verifies after a JSON round trip, and adding, removing or
    /// changing one afterwards breaks the signature.
    #[test]
    fn unknown_fields_are_covered_by_signature() {
        let decl = declaration_with_caps(vec!["read:customers"], None);
        let kp = keypair();
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .extra_field("provider", serde_json::json!({"organization": "Example"}))
            .extra_field(
                "documentationUrl",
                serde_json::json!("https://example.com/docs"),
            )
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();
        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("documentationUrl"));
        let parsed: A2aAgentCard = serde_json::from_str(&json).unwrap();
        verify_agentpin_extension(&parsed).unwrap();

        let mut changed = parsed.clone();
        changed.extra.insert(
            "documentationUrl".to_string(),
            serde_json::json!("https://evil.example/docs"),
        );
        assert!(verify_agentpin_extension(&changed).is_err());
        let mut added = parsed.clone();
        added
            .extra
            .insert("securitySchemes".to_string(), serde_json::json!({"x": 1}));
        assert!(verify_agentpin_extension(&added).is_err());
        let mut removed = parsed.clone();
        removed.extra.remove("provider");
        assert!(verify_agentpin_extension(&removed).is_err());
    }

    #[test]
    fn extension_key_thumbprint_matches_jwk_thumbprint() {
        let decl = declaration_with_caps(vec!["read:*"], None);
        let kp = keypair();
        let card = A2aAgentCardBuilder::from_declaration("https://example.com/agent", &decl)
            .agentpin_endpoint("https://example.com/.well-known/agent-identity.json")
            .sign(&kp.private_key_pem, "kid-1")
            .unwrap();
        let ext = card.agentpin.as_ref().unwrap();
        let from_helper = extension_key_thumbprint(ext);
        let direct = jwk_thumbprint(&ext.public_key_jwk);
        assert_eq!(from_helper, direct);
    }
}
