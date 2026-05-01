// Package resolver provides discovery / revocation resolution strategies
// (well-known HTTPS, local file, trust bundle, chain).
package resolver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// DiscoveryResolver resolves discovery and revocation documents for a
// domain. Implementations may fetch from HTTPS, the local filesystem, a
// pre-loaded trust bundle, or anything else.
type DiscoveryResolver interface {
	ResolveDiscovery(domain string) (*types.DiscoveryDocument, error)
	ResolveRevocation(domain string, discovery *types.DiscoveryDocument) (*types.RevocationDocument, error)
}

// WellKnownResolver fetches documents from the standard `.well-known` HTTPS
// endpoint.
type WellKnownResolver struct {
	Client *http.Client
}

// NewWellKnownResolver returns a resolver using the default HTTP client.
func NewWellKnownResolver() *WellKnownResolver { return &WellKnownResolver{} }

// ResolveDiscovery implements DiscoveryResolver.
func (r *WellKnownResolver) ResolveDiscovery(domain string) (*types.DiscoveryDocument, error) {
	return discovery.FetchDiscoveryDocument(r.Client, domain)
}

// ResolveRevocation implements DiscoveryResolver.
func (r *WellKnownResolver) ResolveRevocation(_ string, doc *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	if doc == nil || doc.RevocationEndpoint == "" {
		return nil, nil
	}
	return revocation.FetchRevocationDocument(r.Client, doc.RevocationEndpoint)
}

// LocalFileResolver reads discovery documents from a local directory in
// `{domain}.json` form, and (optionally) revocation documents from
// `{domain}.revocations.json`.
type LocalFileResolver struct {
	DiscoveryDir  string
	RevocationDir string
}

// NewLocalFileResolver returns a resolver rooted at discoveryDir. If
// revocationDir is empty, revocations are read from discoveryDir.
func NewLocalFileResolver(discoveryDir, revocationDir string) *LocalFileResolver {
	return &LocalFileResolver{DiscoveryDir: discoveryDir, RevocationDir: revocationDir}
}

// ResolveDiscovery implements DiscoveryResolver.
func (r *LocalFileResolver) ResolveDiscovery(domain string) (*types.DiscoveryDocument, error) {
	path := filepath.Join(r.DiscoveryDir, domain+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var doc types.DiscoveryDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// ResolveRevocation implements DiscoveryResolver.
func (r *LocalFileResolver) ResolveRevocation(domain string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	dir := r.RevocationDir
	if dir == "" {
		dir = r.DiscoveryDir
	}
	path := filepath.Join(dir, domain+".revocations.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	var doc types.RevocationDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// TrustBundleResolver resolves documents from a pre-loaded TrustBundle.
type TrustBundleResolver struct {
	discovery   map[string]*types.DiscoveryDocument
	revocations map[string]*types.RevocationDocument
}

// NewTrustBundleResolver indexes b by entity for O(1) lookup.
func NewTrustBundleResolver(b *types.TrustBundle) *TrustBundleResolver {
	r := &TrustBundleResolver{
		discovery:   make(map[string]*types.DiscoveryDocument, len(b.Documents)),
		revocations: make(map[string]*types.RevocationDocument, len(b.Revocations)),
	}
	for i := range b.Documents {
		d := b.Documents[i]
		r.discovery[d.Entity] = &d
	}
	for i := range b.Revocations {
		rev := b.Revocations[i]
		r.revocations[rev.Entity] = &rev
	}
	return r
}

// TrustBundleResolverFromJSON builds a TrustBundleResolver from a JSON-encoded
// TrustBundle.
func TrustBundleResolverFromJSON(data []byte) (*TrustBundleResolver, error) {
	var b types.TrustBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return NewTrustBundleResolver(&b), nil
}

// ResolveDiscovery implements DiscoveryResolver.
func (r *TrustBundleResolver) ResolveDiscovery(domain string) (*types.DiscoveryDocument, error) {
	d, ok := r.discovery[domain]
	if !ok {
		return nil, fmt.Errorf("domain '%s' not in trust bundle", domain)
	}
	cp := *d
	return &cp, nil
}

// ResolveRevocation implements DiscoveryResolver.
func (r *TrustBundleResolver) ResolveRevocation(domain string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	rev, ok := r.revocations[domain]
	if !ok {
		return nil, nil
	}
	cp := *rev
	return &cp, nil
}

// ChainResolver tries a sequence of resolvers in order until one succeeds.
type ChainResolver struct {
	Resolvers []DiscoveryResolver
}

// NewChainResolver builds a ChainResolver from a slice of resolvers.
func NewChainResolver(resolvers []DiscoveryResolver) *ChainResolver {
	return &ChainResolver{Resolvers: resolvers}
}

// ResolveDiscovery implements DiscoveryResolver.
func (r *ChainResolver) ResolveDiscovery(domain string) (*types.DiscoveryDocument, error) {
	var lastErr error = errors.New("no resolvers configured")
	for _, sub := range r.Resolvers {
		doc, err := sub.ResolveDiscovery(domain)
		if err == nil {
			return doc, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ResolveRevocation implements DiscoveryResolver.
func (r *ChainResolver) ResolveRevocation(domain string, doc *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	for _, sub := range r.Resolvers {
		rev, err := sub.ResolveRevocation(domain, doc)
		if err != nil {
			continue
		}
		if rev != nil {
			return rev, nil
		}
	}
	return nil, nil
}
