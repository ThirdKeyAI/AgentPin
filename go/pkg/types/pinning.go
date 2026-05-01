package types

// TrustLevel describes how a pinned key was vetted.
type TrustLevel string

const (
	TrustTOFU     TrustLevel = "tofu"
	TrustVerified TrustLevel = "verified"
	TrustPinned   TrustLevel = "pinned"
)

// PinnedKey represents one TOFU-pinned key for a domain.
type PinnedKey struct {
	Kid           string     `json:"kid"`
	PublicKeyHash string     `json:"public_key_hash"`
	FirstSeen     string     `json:"first_seen"`
	LastSeen      string     `json:"last_seen"`
	TrustLevel    TrustLevel `json:"trust_level"`
}

// PinnedDomain holds all pinned keys for a single domain.
type PinnedDomain struct {
	Domain     string      `json:"domain"`
	PinnedKeys []PinnedKey `json:"pinned_keys"`
}
