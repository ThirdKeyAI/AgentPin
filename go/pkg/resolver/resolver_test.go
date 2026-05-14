package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
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
