package types

import "github.com/ThirdKeyAi/agentpin/go/pkg/domain"

func bundleKey(entity string) string {
	if n, err := domain.Normalize(entity); err == nil {
		return n
	}
	return entity
}

// TrustBundle is a pre-shared collection of discovery and revocation
// documents for offline / air-gapped verification.
type TrustBundle struct {
	AgentpinBundleVersion string               `json:"agentpin_bundle_version"`
	CreatedAt             string               `json:"created_at"`
	Documents             []DiscoveryDocument  `json:"documents"`
	Revocations           []RevocationDocument `json:"revocations"`
	// ExpiresAt is an optional RFC 3339 expiry (design issue 5).
	ExpiresAt string `json:"expires_at,omitempty"`
	// Kid identifies the key that signed this bundle (optional).
	Kid string `json:"kid,omitempty"`
	// Signature is a standard-base64 DER signature over the domain-separated
	// canonical JSON of the bundle with Signature cleared (optional).
	Signature string `json:"signature,omitempty"`
}

// FindDiscovery returns the first discovery document whose entity matches
// domain, or nil.
func (b *TrustBundle) FindDiscovery(domainName string) *DiscoveryDocument {
	key := bundleKey(domainName)
	for i := range b.Documents {
		if bundleKey(b.Documents[i].Entity) == key {
			return &b.Documents[i]
		}
	}
	return nil
}

// FindRevocation returns the first revocation document whose entity matches
// domain, or nil.
func (b *TrustBundle) FindRevocation(domainName string) *RevocationDocument {
	key := bundleKey(domainName)
	for i := range b.Revocations {
		if bundleKey(b.Revocations[i].Entity) == key {
			return &b.Revocations[i]
		}
	}
	return nil
}
