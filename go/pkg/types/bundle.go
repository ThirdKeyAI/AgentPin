package types

// TrustBundle is a pre-shared collection of discovery and revocation
// documents for offline / air-gapped verification.
type TrustBundle struct {
	AgentpinBundleVersion string               `json:"agentpin_bundle_version"`
	CreatedAt             string               `json:"created_at"`
	Documents             []DiscoveryDocument  `json:"documents"`
	Revocations           []RevocationDocument `json:"revocations"`
}

// FindDiscovery returns the first discovery document whose entity matches
// domain, or nil.
func (b *TrustBundle) FindDiscovery(domain string) *DiscoveryDocument {
	for i := range b.Documents {
		if b.Documents[i].Entity == domain {
			return &b.Documents[i]
		}
	}
	return nil
}

// FindRevocation returns the first revocation document whose entity matches
// domain, or nil.
func (b *TrustBundle) FindRevocation(domain string) *RevocationDocument {
	for i := range b.Revocations {
		if b.Revocations[i].Entity == domain {
			return &b.Revocations[i]
		}
	}
	return nil
}
