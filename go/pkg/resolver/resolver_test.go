package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"errors"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"strings"
)

func makeDiscovery(domain string) types.DiscoveryDocument {
	return discovery.BuildDiscoveryDocument(
		domain,
		types.EntityMaker,
		[]types.JWK{{Kid: "test-key", Kty: "EC", Crv: "P-256", X: "x", Y: "y", Use: "sig"}},
		nil,
		2,
		"2026-01-15T00:00:00Z",
	)
}

func TestTrustBundleResolverHit(t *testing.T) {
	b := types.TrustBundle{
		AgentpinBundleVersion: "0.1",
		Documents:             []types.DiscoveryDocument{makeDiscovery("example.com")},
	}
	r := NewTrustBundleResolver(&b)
	d, err := r.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Entity != "example.com" {
		t.Fatal("entity wrong")
	}
}

func TestTrustBundleResolverMiss(t *testing.T) {
	r := NewTrustBundleResolver(&types.TrustBundle{})
	if _, err := r.ResolveDiscovery("missing.com"); err == nil {
		t.Fatal("expected error")
	}
}

func TestTrustBundleResolverRevocation(t *testing.T) {
	rev := revocation.BuildRevocationDocument("example.com")
	b := types.TrustBundle{
		AgentpinBundleVersion: "0.1",
		Documents:             []types.DiscoveryDocument{makeDiscovery("example.com")},
		Revocations:           []types.RevocationDocument{rev},
	}
	r := NewTrustBundleResolver(&b)
	d, _ := r.ResolveDiscovery("example.com")
	got, err := r.ResolveRevocation("example.com", d)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected revocation document")
	}
}

func TestTrustBundleResolverFromJSON(t *testing.T) {
	b := types.TrustBundle{
		AgentpinBundleVersion: "0.1",
		Documents:             []types.DiscoveryDocument{makeDiscovery("example.com")},
	}
	data, _ := json.Marshal(b)
	r, err := TrustBundleResolverFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveDiscovery("example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestLocalFileResolver(t *testing.T) {
	dir := t.TempDir()
	d := makeDiscovery("local.example.com")
	data, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "local.example.com.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewLocalFileResolver(dir, "")
	got, err := r.ResolveDiscovery("local.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Entity != "local.example.com" {
		t.Fatal("entity wrong")
	}
}

func TestLocalFileResolverMissing(t *testing.T) {
	r := NewLocalFileResolver(t.TempDir(), "")
	if _, err := r.ResolveDiscovery("missing.com"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLocalFileResolverRevocation(t *testing.T) {
	dir := t.TempDir()
	d := makeDiscovery("local.example.com")
	rev := revocation.BuildRevocationDocument("local.example.com")
	dData, _ := json.Marshal(d)
	rData, _ := json.Marshal(rev)
	_ = os.WriteFile(filepath.Join(dir, "local.example.com.json"), dData, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "local.example.com.revocations.json"), rData, 0o644)
	r := NewLocalFileResolver(dir, "")
	got, err := r.ResolveRevocation("local.example.com", &d)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected revocation")
	}
}

func TestChainResolverFirstWins(t *testing.T) {
	a := &TrustBundleResolver{discovery: map[string]*types.DiscoveryDocument{}}
	d := makeDiscovery("a.com")
	a.discovery["a.com"] = &d
	b := &TrustBundleResolver{discovery: map[string]*types.DiscoveryDocument{}}
	chain := NewChainResolver([]DiscoveryResolver{a, b})
	if _, err := chain.ResolveDiscovery("a.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.ResolveDiscovery("c.com"); err == nil {
		t.Fatal("expected miss")
	}
}

func TestChainResolverFallthrough(t *testing.T) {
	empty := &TrustBundleResolver{discovery: map[string]*types.DiscoveryDocument{}}
	d := makeDiscovery("example.com")
	with := &TrustBundleResolver{discovery: map[string]*types.DiscoveryDocument{"example.com": &d}}
	chain := NewChainResolver([]DiscoveryResolver{empty, with})
	if _, err := chain.ResolveDiscovery("example.com"); err != nil {
		t.Fatal(err)
	}
}

// AP-10: an untrusted domain string can never escape the discovery
// directory, and errors never echo OS error text or paths.
func TestLocalFileResolverRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewLocalFileResolver(dir, "")
	rel := "../" + filepath.Base(outside) + "/x"
	for _, bad := range []string{filepath.Join(outside, "x"), rel, "..", "../x", "a/../../x", `x\..\y`} {
		_, err := r.ResolveDiscovery(bad)
		if err == nil {
			t.Fatalf("%q resolved", bad)
		}
		if strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), dir) {
			t.Fatalf("error leaks OS detail or path: %v", err)
		}
	}
	_, err := r.ResolveDiscovery("missing.com")
	if err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "no such file") {
		t.Fatalf("missing-document error should be generic: %v", err)
	}
}

// AP-3: file and bundle lookups use the normalized domain.
func TestResolversNormalizeLookups(t *testing.T) {
	dir := t.TempDir()
	doc := discovery.BuildDiscoveryDocument("local.example.com", types.EntityMaker,
		[]types.JWK{{Kid: "k", Kty: "EC", Crv: "P-256", X: "x", Y: "y", Use: "sig"}}, nil, 2, "2026-01-15T00:00:00Z")
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "local.example.com.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalFileResolver(dir, "").ResolveDiscovery("LOCAL.Example.COM."); err != nil {
		t.Fatalf("file lookup not normalized: %v", err)
	}
	bdoc := discovery.BuildDiscoveryDocument("Example.COM", types.EntityMaker,
		[]types.JWK{{Kid: "k", Kty: "EC", Crv: "P-256", X: "x", Y: "y", Use: "sig"}}, nil, 2, "2026-01-15T00:00:00Z")
	b := types.TrustBundle{AgentpinBundleVersion: "0.1", Documents: []types.DiscoveryDocument{bdoc}}
	tb := NewTrustBundleResolver(&b)
	if _, err := tb.ResolveDiscovery("example.com"); err != nil {
		t.Fatalf("bundle lookup not normalized: %v", err)
	}
	if _, err := tb.ResolveDiscovery("EXAMPLE.COM."); err != nil {
		t.Fatalf("bundle lookup not normalized: %v", err)
	}
}

type failingRevocation struct{}

func (failingRevocation) ResolveDiscovery(d string) (*types.DiscoveryDocument, error) {
	return nil, errors.New("no discovery for " + d)
}

func (failingRevocation) ResolveRevocation(string, *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	return nil, errors.New("revocation source unreachable")
}

// AP-11: a failing revocation source inside a chain fails closed unless a
// later resolver actually produces a document.
func TestChainResolverRevocationFailClosed(t *testing.T) {
	doc := discovery.BuildDiscoveryDocument("example.com", types.EntityMaker,
		[]types.JWK{{Kid: "k", Kty: "EC", Crv: "P-256", X: "x", Y: "y", Use: "sig"}}, nil, 2, "2026-01-15T00:00:00Z")
	empty := NewTrustBundleResolver(&types.TrustBundle{AgentpinBundleVersion: "0.1"})
	chain := NewChainResolver([]DiscoveryResolver{failingRevocation{}, empty})
	if _, err := chain.ResolveRevocation("example.com", &doc); err == nil {
		t.Fatal("failing source with no later data must fail closed")
	}
	rev := revocation.BuildRevocationDocument("example.com")
	withRev := NewTrustBundleResolver(&types.TrustBundle{AgentpinBundleVersion: "0.1",
		Documents: []types.DiscoveryDocument{doc}, Revocations: []types.RevocationDocument{rev}})
	chain = NewChainResolver([]DiscoveryResolver{failingRevocation{}, withRev})
	got, err := chain.ResolveRevocation("example.com", &doc)
	if err != nil || got == nil {
		t.Fatalf("later data must win: %v %v", got, err)
	}
	chain = NewChainResolver([]DiscoveryResolver{empty})
	if got, err := chain.ResolveRevocation("example.com", &doc); err != nil || got != nil {
		t.Fatalf("no failures and no data is still nil: %v %v", got, err)
	}
}
