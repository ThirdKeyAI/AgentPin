package types

// A2A AgentCard extension types (v0.3.0).
//
// AgentPin extends the Google A2A AgentCard format with cryptographic
// identity verification. The AgentpinExtension payload carries the AgentPin
// endpoint URL, the entity's public key in JWK form, and a detached ECDSA
// signature over the rest of the AgentCard.
//
// Mirrors the Rust agentpin::types::a2a module — the wire format is
// byte-identical so cards signed in any of Rust/JS/Python/Go verify in the
// others.

// A2aAgentCard is the minimal subset of the A2A AgentCard that AgentPin
// populates or reads. Additional upstream fields are not modeled here while
// the A2A spec is still draft; once it stabilises this can be re-exported
// from an upstream a2a-types package.
type A2aAgentCard struct {
	Name         string               `json:"name"`
	Description  string               `json:"description,omitempty"`
	Version      string               `json:"version,omitempty"`
	URL          string               `json:"url"`
	Capabilities A2aAgentCapabilities `json:"capabilities"`
	Skills       []A2aAgentSkill      `json:"skills"`
	// Agentpin is the AgentPin extension payload. Present when the card is
	// signed and resolvable via the AgentPin protocol.
	Agentpin *AgentpinExtension `json:"agentpin,omitempty"`
}

// A2aAgentCapabilities mirrors the A2A "AgentCapabilities" shape with one
// AgentPin-specific addition: AllowedDomains, propagated from the source
// Constraints so cross-protocol A2A peers can scope tool verification.
type A2aAgentCapabilities struct {
	Streaming         bool `json:"streaming"`
	PushNotifications bool `json:"pushNotifications"`
	// AllowedDomains is omitted (rather than emitted as `null` or `[]`) when
	// the agent is unrestricted, matching the Rust SDK's serde behaviour and
	// the "empty list = unrestricted" convention.
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

// A2aAgentSkill mirrors the A2A "AgentSkill" shape. AgentPin's Capability
// strings (e.g. "read:customers/*") map directly to the skill `id`.
type A2aAgentSkill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// AgentpinExtension is the AgentPin extension carried inside an A2A
// AgentCard's `agentpin` field.
//
// The signature is a detached ECDSA P-256 signature over the canonical bytes
// of the AgentCard with this extension field cleared. Verifiers reconstruct
// that canonical input and check the signature against PublicKeyJWK.
type AgentpinExtension struct {
	AgentpinEndpoint string `json:"agentpin_endpoint"`
	PublicKeyJWK     JWK    `json:"public_key_jwk"`
	Signature        string `json:"signature"`
}

// CapabilityToSkill maps an AgentPin Capability to a minimal A2aAgentSkill.
// The capability string itself becomes both the skill `id` and the default
// `name`.
func CapabilityToSkill(cap Capability) A2aAgentSkill {
	id := string(cap)
	return A2aAgentSkill{ID: id, Name: id}
}
