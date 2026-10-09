// Package resolver provides discovery / revocation resolution strategies
// (well-known HTTPS, local file, trust bundle, chain).
package resolver

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/bundle"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
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
func (r *WellKnownResolver) ResolveRevocation(domainName string, doc *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	if doc != nil && doc.RevocationEndpoint != "" {
		// The endpoint is attacker-publishable; never fetch anything but
		// https on the issuer's own host (AP-12). An explicitly declared
		// endpoint fails closed on any error, including 404.
		if err := domain.ValidateHTTPSURLForDomain(doc.RevocationEndpoint, domainName); err != nil {
			return nil, err
		}
		return revocation.FetchRevocationDocument(r.Client, doc.RevocationEndpoint)
	}
	// Spec §8.1: assume the default endpoint when none is declared. A 404
	// there means the issuer publishes no revocations; any other failure
	// still fails closed (design issue 3).
	normalized, err := domain.Normalize(domainName)
	if err != nil {
		return nil, err
	}
	return revocation.FetchRevocationDocumentIfPresent(r.Client, domain.DefaultRevocationEndpoint(normalized))
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

// readContained resolves "{domain}{suffix}" inside dir, refusing anything
// that is not a normalized hostname and anything whose resolved path escapes
// dir (AP-10). Returns (nil, nil) when the file does not exist and a generic
// error (no OS error text, no path) on any other failure.
func readContained(dir, rawDomain, suffix string) ([]byte, error) {
	domainName, err := domain.Normalize(rawDomain)
	if err != nil {
		return nil, err
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.New("discovery directory is not accessible")
	}
	path := filepath.Join(base, domainName+suffix)
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("document path for domain '%s' escapes the discovery directory", domainName)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		resolvedBase, berr := filepath.EvalSymlinks(base)
		if berr != nil {
			return nil, errors.New("discovery directory is not accessible")
		}
		relResolved, rerr := filepath.Rel(resolvedBase, resolved)
		if rerr != nil || relResolved == ".." || strings.HasPrefix(relResolved, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("document path for domain '%s' escapes the discovery directory", domainName)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else {
		return nil, fmt.Errorf("cannot read document for domain '%s'", domainName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read document for domain '%s'", domainName)
	}
	return data, nil
}

// ResolveDiscovery implements DiscoveryResolver.
func (r *LocalFileResolver) ResolveDiscovery(domainName string) (*types.DiscoveryDocument, error) {
	data, err := readContained(r.DiscoveryDir, domainName, ".json")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no discovery document for domain '%s'", domainName)
	}
	var doc types.DiscoveryDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// ResolveRevocation implements DiscoveryResolver.
func (r *LocalFileResolver) ResolveRevocation(domainName string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	dir := r.RevocationDir
	if dir == "" {
		dir = r.DiscoveryDir
	}
	data, err := readContained(dir, domainName, ".revocations.json")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
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
		r.discovery[bundleKey(d.Entity)] = &d
	}
	for i := range b.Revocations {
		rev := b.Revocations[i]
		r.revocations[bundleKey(rev.Entity)] = &rev
	}
	return r
}

// bundleKey is the normalized domain when the entity is a valid hostname,
// the raw string otherwise (such entries can never match a normalized iss).
func bundleKey(entity string) string {
	if n, err := domain.Normalize(entity); err == nil {
		return n
	}
	return entity
}

// TrustBundleResolverFromJSON builds a TrustBundleResolver from a JSON-encoded
// TrustBundle. The bundle is rejected when its expires_at has passed; its
// signature, if any, is not checked — use TrustBundleResolverFromSignedJSON
// for that.
func TrustBundleResolverFromJSON(data []byte) (*TrustBundleResolver, error) {
	var b types.TrustBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if err := bundle.CheckBundleExpiry(&b); err != nil {
		return nil, err
	}
	return NewTrustBundleResolver(&b), nil
}

// TrustBundleResolverFromSignedJSON builds a resolver from a signed
// TrustBundle, requiring a valid signature under pub and an unexpired
// expires_at (design issue 5).
func TrustBundleResolverFromSignedJSON(data []byte, pub *ecdsa.PublicKey) (*TrustBundleResolver, error) {
	var b types.TrustBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if err := bundle.VerifyTrustBundle(&b, pub); err != nil {
		return nil, err
	}
	return NewTrustBundleResolver(&b), nil
}

// ResolveDiscovery implements DiscoveryResolver.
func (r *TrustBundleResolver) ResolveDiscovery(domainName string) (*types.DiscoveryDocument, error) {
	d, ok := r.discovery[bundleKey(domainName)]
	if !ok {
		return nil, fmt.Errorf("domain '%s' not in trust bundle", domainName)
	}
	cp := *d
	return &cp, nil
}

// ResolveRevocation implements DiscoveryResolver.
func (r *TrustBundleResolver) ResolveRevocation(domainName string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	rev, ok := r.revocations[bundleKey(domainName)]
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
