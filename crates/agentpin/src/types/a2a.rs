//! A2A AgentCard extension types (v0.3.0).
//!
//! AgentPin extends the [Google A2A](https://github.com/google-a2a/A2A) AgentCard
//! format with cryptographic identity verification. The `AgentpinExtension`
//! payload carries the AgentPin endpoint URL, the entity's public key in JWK
//! form, and a detached ECDSA signature over the rest of the AgentCard so
//! verifiers can confirm an AgentCard came from the entity that owns the
//! AgentPin discovery domain.
//!
//! These types are structural only — the signing and verification logic live
//! in [`crate::a2a`]. Resolution from a network endpoint or an in-memory store
//! lives in [`crate::resolver_a2a`] and [`crate::resolver_local`].
//!
//! ## Why an inline definition (not the upstream `a2a-types` crate)?
//!
//! The upstream A2A spec is still draft. Embedding the minimal subset we need
//! (`AgentCard`, `AgentSkill`, `AgentCapabilities`) inline keeps AgentPin from
//! pinning an external version that's likely to churn. When the upstream crate
//! stabilises, this module can re-export from it without changing the public
//! surface here.

use serde::{Deserialize, Serialize};

use crate::jwk::Jwk;

use super::capability::Capability;
use super::discovery::AllowedDomains;

// ---------------------------------------------------------------------------
// Minimal A2A AgentCard subset (inline; upstream `a2a-types` candidate)
// ---------------------------------------------------------------------------

/// Minimal A2A `AgentCard` representation.
///
/// Only the fields AgentPin needs to populate or read are exposed. Additional
/// upstream fields can be carried verbatim via the catch-all `extensions` map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct A2aAgentCard {
    /// Human-readable agent name (matches AgentPin `AgentDeclaration.name`).
    pub name: String,
    /// Free-form description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Semver string for the agent (matches AgentPin `AgentDeclaration.version`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Public URL where the agent receives A2A traffic.
    pub url: String,
    /// Capabilities advertised under the A2A `AgentCapabilities` shape.
    pub capabilities: A2aAgentCapabilities,
    /// Skills exposed under the A2A `AgentSkill` shape — one per AgentPin
    /// [`Capability`] in the source `AgentDeclaration`.
    pub skills: Vec<A2aAgentSkill>,
    /// AgentPin extension payload — present when this AgentCard is signed and
    /// resolvable via the AgentPin protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agentpin: Option<AgentpinExtension>,
}

/// Minimal A2A `AgentCapabilities` representation.
///
/// AgentPin populates `allowed_domains` from the source [`crate::types::constraint::Constraints`]
/// so A2A peers can scope tool verification (SchemaPin v1.4 `A2aVerificationContext`)
/// against the same allow-list AgentPin already enforces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct A2aAgentCapabilities {
    /// Whether the agent supports streaming responses.
    #[serde(default)]
    pub streaming: bool,
    /// Whether the agent emits push notifications.
    #[serde(default, rename = "pushNotifications")]
    pub push_notifications: bool,
    /// AgentPin v0.3.0 extension: domains this agent is permitted to interact
    /// with. Populated from `Constraints.allowed_domains`.
    /// Empty list = no restriction (all domains trusted).
    #[serde(default, skip_serializing_if = "AllowedDomains::is_unrestricted")]
    pub allowed_domains: AllowedDomains,
}

/// Minimal A2A `AgentSkill` representation.
///
/// AgentPin's [`Capability`] strings (e.g. `read:customers/*`) map to the A2A
/// `id`. Free-form `name` and `description` carry over from the source
/// declaration when present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct A2aAgentSkill {
    /// Stable identifier — equal to the AgentPin [`Capability`] verb-resource string.
    pub id: String,
    /// Human-readable skill name. AgentPin defaults to the capability id when
    /// no name is supplied at builder time.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// AgentPin extension payload
// ---------------------------------------------------------------------------

/// AgentPin extension carried inside an A2A AgentCard's `agentpin` field.
///
/// The signature is a detached ECDSA P-256 signature over the canonical bytes
/// of the rest of the AgentCard (everything *except* this `AgentpinExtension`
/// itself — the canonical input is computed by serialising the card with the
/// extension field cleared). Verifiers reconstruct that canonical input and
/// check the signature against `public_key_jwk`.
///
/// Use [`crate::a2a::A2aAgentCardBuilder`] to construct + sign one and
/// [`crate::a2a::verify_agentpin_extension`] to verify one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentpinExtension {
    /// URL of the entity's `.well-known/agent-identity.json` discovery document.
    pub agentpin_endpoint: String,
    /// Public key (JWK form) used to sign the AgentCard.
    pub public_key_jwk: Jwk,
    /// Detached ECDSA P-256 signature, base64url-encoded.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Capability mapping helpers (AgentDeclaration -> A2A skill list)
// ---------------------------------------------------------------------------

/// Map an AgentPin [`Capability`] to a minimal [`A2aAgentSkill`].
///
/// The capability string itself (`verb:resource`) becomes both the skill `id`
/// and the default `name`. Callers that want richer names/descriptions should
/// use [`crate::a2a::A2aAgentCardBuilder::with_skill_overrides`].
pub fn capability_to_skill(cap: &Capability) -> A2aAgentSkill {
    let id = cap.0.clone();
    A2aAgentSkill {
        id: id.clone(),
        name: id,
        description: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_maps_to_skill() {
        let cap = Capability::from("read:customers/*");
        let skill = capability_to_skill(&cap);
        assert_eq!(skill.id, "read:customers/*");
        assert_eq!(skill.name, "read:customers/*");
        assert_eq!(skill.description, None);
    }

    #[test]
    fn allowed_domains_serializes_omits_when_empty() {
        let caps = A2aAgentCapabilities::default();
        let json = serde_json::to_string(&caps).unwrap();
        assert!(!json.contains("allowed_domains"), "got: {json}");
    }

    #[test]
    fn allowed_domains_serializes_when_populated() {
        let caps = A2aAgentCapabilities {
            allowed_domains: AllowedDomains::from_domains(["a.com", "b.com"]),
            ..Default::default()
        };
        let json = serde_json::to_string(&caps).unwrap();
        assert!(
            json.contains("\"allowed_domains\":[\"a.com\",\"b.com\"]"),
            "got: {json}"
        );
    }

    #[test]
    fn agentpin_extension_roundtrips() {
        let ext = AgentpinExtension {
            agentpin_endpoint: "https://example.com/.well-known/agent-identity.json".to_string(),
            public_key_jwk: Jwk {
                kid: "kid-1".to_string(),
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: "x".to_string(),
                y: "y".to_string(),
                use_: "sig".to_string(),
                key_ops: None,
                exp: None,
            },
            signature: "sig".to_string(),
        };
        let json = serde_json::to_string(&ext).unwrap();
        let back: AgentpinExtension = serde_json::from_str(&json).unwrap();
        assert_eq!(ext, back);
    }
}
