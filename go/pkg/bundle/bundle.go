// Package bundle provides helpers for constructing and querying AgentPin
// trust bundles for offline / air-gapped verification.
package bundle

import (
	"github.com/ThirdKeyAi/agentpin/go/internal/version"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// NewTrustBundle creates an empty trust bundle with the given creation
// timestamp.
func NewTrustBundle(createdAt string) types.TrustBundle {
	return types.TrustBundle{
		AgentpinBundleVersion: version.BundleVersion,
		CreatedAt:             createdAt,
		Documents:             []types.DiscoveryDocument{},
		Revocations:           []types.RevocationDocument{},
	}
}

// FindBundleDiscovery returns the first discovery document in b matching domain.
func FindBundleDiscovery(b *types.TrustBundle, domain string) *types.DiscoveryDocument {
	return b.FindDiscovery(domain)
}

// FindBundleRevocation returns the first revocation document in b matching domain.
func FindBundleRevocation(b *types.TrustBundle, domain string) *types.RevocationDocument {
	return b.FindRevocation(domain)
}
