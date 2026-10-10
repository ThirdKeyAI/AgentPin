package types

import "encoding/json"

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
// populates or reads. Every other upstream field (provider,
// securitySchemes, documentationUrl, ...) is carried verbatim in Extra and
// included in the signed canonical bytes, as spec §4.10.1 requires (AP-17),
// so a field a third party appends after signing breaks the signature.
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
	// Extra holds upstream A2A fields not modeled above, preserved verbatim
	// and covered by the AgentCard signature.
	Extra map[string]json.RawMessage `json:"-"`
}

type a2aAgentCardKnown A2aAgentCard

var a2aKnownKeys = map[string]bool{
	"name": true, "description": true, "version": true, "url": true,
	"capabilities": true, "skills": true, "agentpin": true,
}

// MarshalJSON emits the modeled fields plus every Extra field.
func (c A2aAgentCard) MarshalJSON() ([]byte, error) {
	known := a2aAgentCardKnown(c)
	known.Extra = nil
	base, err := json.Marshal(known)
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return base, nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(base, &out); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if !a2aKnownKeys[k] {
			out[k] = v
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads the modeled fields and keeps every unknown field in
// Extra.
func (c *A2aAgentCard) UnmarshalJSON(data []byte) error {
	var known a2aAgentCardKnown
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	known.Extra = nil
	for k, v := range all {
		if !a2aKnownKeys[k] {
			if known.Extra == nil {
				known.Extra = map[string]json.RawMessage{}
			}
			known.Extra[k] = v
		}
	}
	*c = A2aAgentCard(known)
	return nil
}

// A2aAgentCapabilities mirrors the A2A "AgentCapabilities" shape with one
// AgentPin-specific addition: AllowedDomains, propagated from the source
// Constraints so cross-protocol A2A peers can scope tool verification.
type A2aAgentCapabilities struct {
	Streaming         bool `json:"streaming"`
	PushNotifications bool `json:"pushNotifications"`
	// AllowedDomains is omitted when nil (unrestricted) and emitted whenever
	// non-nil, including as `[]` (restricted to nothing) — AP-6.
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// Extra holds unmodeled fields, preserved verbatim and signed.
	Extra map[string]json.RawMessage `json:"-"`
}

var capabilitiesKnownKeys = map[string]bool{"streaming": true, "pushNotifications": true, "allowed_domains": true}

// MarshalJSON emits allowed_domains whenever it is non-nil, including when
// empty, so "restricted to nothing" survives a round trip.
func (c A2aAgentCapabilities) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{
		"streaming":         c.Streaming,
		"pushNotifications": c.PushNotifications,
	}
	if c.AllowedDomains != nil {
		out["allowed_domains"] = c.AllowedDomains
	}
	for k, v := range c.Extra {
		if !capabilitiesKnownKeys[k] {
			out[k] = v
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON keeps unknown fields in Extra.
func (c *A2aAgentCapabilities) UnmarshalJSON(data []byte) error {
	type plain A2aAgentCapabilities
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	extra, err := unknownFields(data, capabilitiesKnownKeys)
	if err != nil {
		return err
	}
	p.Extra = extra
	*c = A2aAgentCapabilities(p)
	return nil
}

// unknownFields returns the members of the JSON object data whose keys are
// not in known, or nil when there are none.
func unknownFields(data []byte, known map[string]bool) (map[string]json.RawMessage, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	var extra map[string]json.RawMessage
	for k, v := range all {
		if !known[k] {
			if extra == nil {
				extra = map[string]json.RawMessage{}
			}
			extra[k] = v
		}
	}
	return extra, nil
}

// A2aAgentSkill mirrors the A2A "AgentSkill" shape. AgentPin's Capability
// strings (e.g. "read:customers/*") map directly to the skill `id`.
type A2aAgentSkill struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Extra holds unmodeled fields (tags, examples, ...), preserved verbatim
	// and signed.
	Extra map[string]json.RawMessage `json:"-"`
}

var skillKnownKeys = map[string]bool{"id": true, "name": true, "description": true}

// MarshalJSON emits the modeled fields plus every Extra field.
func (s A2aAgentSkill) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{"id": s.ID, "name": s.Name}
	if s.Description != "" {
		out["description"] = s.Description
	}
	for k, v := range s.Extra {
		if !skillKnownKeys[k] {
			out[k] = v
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON keeps unknown fields in Extra.
func (s *A2aAgentSkill) UnmarshalJSON(data []byte) error {
	type plain A2aAgentSkill
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	extra, err := unknownFields(data, skillKnownKeys)
	if err != nil {
		return err
	}
	p.Extra = extra
	*s = A2aAgentSkill(p)
	return nil
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
