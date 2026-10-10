package resolver

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"strings"
)

func signedCard(t *testing.T) types.A2aAgentCard {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	decl := &types.AgentDeclaration{
		AgentID:      "urn:agentpin:example.com:tester",
		Name:         "Tester",
		Description:  "Test agent",
		Version:      "1.0.0",
		Capabilities: []types.Capability{"read:*"},
		Constraints:  &types.Constraints{AllowedDomains: []string{"partner.com"}},
		Status:       types.AgentActive,
	}
	card, err := a2a.BuildAndSignAgentCard(
		"https://example.com/agent",
		decl,
		kp.PrivateKeyPEM, "kid-1",
		"https://example.com/.well-known/agent-identity.json",
		a2a.BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func TestCardEndpointHost(t *testing.T) {
	card := signedCard(t)
	host, err := CardEndpointHost(&card)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" {
		t.Fatalf("got %q", host)
	}
}

func TestCardEndpointHostWithoutExtension(t *testing.T) {
	card := types.A2aAgentCard{Name: "x"}
	if _, err := CardEndpointHost(&card); err == nil {
		t.Fatal("expected error for card without extension")
	}
}

func TestDeriveDiscoveryFromCard(t *testing.T) {
	card := signedCard(t)
	doc, err := DeriveDiscoveryFromCard(&card)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Entity != "example.com" {
		t.Fatalf("entity %q", doc.Entity)
	}
	if len(doc.PublicKeys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.PublicKeys))
	}
	if len(doc.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(doc.Agents))
	}
	if doc.Agents[0].Name != "Tester" {
		t.Fatalf("name %q", doc.Agents[0].Name)
	}
	if doc.A2aEndpoint != "https://example.com/.well-known/agent-identity.json" {
		t.Fatalf("a2a_endpoint %q", doc.A2aEndpoint)
	}
	if doc.Agents[0].Constraints == nil || len(doc.Agents[0].Constraints.AllowedDomains) != 1 {
		t.Fatalf("missing constraints")
	}
}

func TestLocalAgentCardStoreRegisterThenResolve(t *testing.T) {
	store := NewUnanchoredLocalAgentCardStore()
	if err := store.Register(signedCard(t)); err != nil {
		t.Fatal(err)
	}
	if store.Len() != 1 {
		t.Fatalf("len=%d", store.Len())
	}
	doc, err := store.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Entity != "example.com" {
		t.Fatalf("entity %q", doc.Entity)
	}
}

func TestLocalAgentCardStoreRegisterPropagatesSignatureFailure(t *testing.T) {
	card := signedCard(t)
	card.URL = "https://attacker.example/agent" // tamper
	store := NewUnanchoredLocalAgentCardStore()
	if err := store.Register(card); err == nil {
		t.Fatal("expected signature failure")
	}
	if !store.IsEmpty() {
		t.Fatal("store should be empty after failed register")
	}
}

func TestLocalAgentCardStoreResolveMissing(t *testing.T) {
	store := NewUnanchoredLocalAgentCardStore()
	if _, err := store.ResolveDiscovery("missing.com"); err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestLocalAgentCardStoreReRegisterReplaces(t *testing.T) {
	store := NewUnanchoredLocalAgentCardStore()
	if err := store.Register(signedCard(t)); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(signedCard(t)); err != nil {
		t.Fatal(err)
	}
	if store.Len() != 1 {
		t.Fatalf("expected re-register to replace, len=%d", store.Len())
	}
}

func TestLocalAgentCardStoreRemove(t *testing.T) {
	store := NewUnanchoredLocalAgentCardStore()
	_ = store.Register(signedCard(t))
	if !store.Remove("example.com") {
		t.Fatal("expected remove to return true")
	}
	if !store.IsEmpty() {
		t.Fatal("store should be empty")
	}
	if store.Remove("example.com") {
		t.Fatal("expected second remove to return false")
	}
}

func TestLocalAgentCardStoreResolveCard(t *testing.T) {
	store := NewUnanchoredLocalAgentCardStore()
	_ = store.Register(signedCard(t))
	card, ok := store.ResolveCard("example.com")
	if !ok || card.Name != "Tester" {
		t.Fatalf("unexpected: ok=%v card=%+v", ok, card)
	}
}

func TestLocalAgentCardStoreResolveRevocationReturnsNil(t *testing.T) {
	store := NewUnanchoredLocalAgentCardStore()
	_ = store.Register(signedCard(t))
	doc, _ := store.ResolveDiscovery("example.com")
	rev, err := store.ResolveRevocation("example.com", doc)
	if err != nil || rev != nil {
		t.Fatalf("expected nil rev, got rev=%v err=%v", rev, err)
	}
}

// AP-12: the agentpin_endpoint must be https with a domain host.
func TestRegisterRejectsNonHTTPSOrIPEndpoint(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	decl := &types.AgentDeclaration{AgentID: "urn:agentpin:example.com:tester", Name: "Tester",
		Capabilities: []types.Capability{"read:*"}, Status: types.AgentActive}
	for _, bad := range []string{
		"http://example.com/.well-known/agent-identity.json",
		"https://127.0.0.1/.well-known/agent-identity.json",
		"https://example.com:8443/.well-known/agent-identity.json",
		"https://user@example.com/.well-known/agent-identity.json",
	} {
		card, err := a2a.BuildAndSignAgentCard("https://example.com/agent", decl, kp.PrivateKeyPEM, "kid-1", bad, a2a.BuildOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := NewUnanchoredLocalAgentCardStore().Register(card); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
}

// AP-3: store lookups are case-insensitive.
func TestLocalAgentCardStoreNormalizesLookup(t *testing.T) {
	s := NewUnanchoredLocalAgentCardStore()
	if err := s.Register(signedCard(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveDiscovery("EXAMPLE.COM."); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveCard("Example.com"); !ok {
		t.Fatal("ResolveCard must normalize")
	}
}

func storeTrusting(card types.A2aAgentCard) *LocalAgentCardStore {
	return NewLocalAgentCardStoreWithThumbprints([]string{a2a.ExtensionKeyThumbprint(card.Agentpin)})
}

// AP-4 / design 9: a store with no trusted key refuses every registration.
func TestDefaultStoreRefusesRegistration(t *testing.T) {
	s := NewLocalAgentCardStore()
	err := s.Register(signedCard(t))
	if err == nil || !strings.Contains(err.Error(), "not a trusted thumbprint") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if !s.IsEmpty() {
		t.Fatal("nothing should be stored")
	}
}

// AP-4: an attacker's self-signed card claiming bank.example is refused by a
// thumbprint-anchored store and by a resolver-anchored store whose
// discovery document for bank.example publishes a different key.
func TestForeignDomainClaimIsRefused(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	decl := &types.AgentDeclaration{AgentID: "urn:agentpin:example.com:tester", Name: "Tester",
		Capabilities: []types.Capability{"read:*"}, Status: types.AgentActive}
	evil, err := a2a.BuildAndSignAgentCard("https://attacker.example/agent", decl, kp.PrivateKeyPEM, "kid-1",
		"https://bank.example/.well-known/agent-identity.json", a2a.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := storeTrusting(signedCard(t)).Register(evil); err == nil {
		t.Fatal("allowlist store must refuse an untrusted key")
	}
	bankKP, _ := crypto.GenerateKeyPair()
	bankPub, _ := crypto.LoadPublicKey(bankKP.PublicKeyPEM)
	bankDoc := discovery.BuildDiscoveryDocument("bank.example", types.EntityDeployer,
		[]types.JWK{jwk.VerifyingKeyToJWK(bankPub, "bank-1")}, nil, 0, "2026-01-15T00:00:00Z")
	b := types.TrustBundle{AgentpinBundleVersion: "0.1", Documents: []types.DiscoveryDocument{bankDoc}}
	s := NewLocalAgentCardStoreWithResolver(NewTrustBundleResolver(&b))
	err = s.Register(evil)
	if err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("resolver store must refuse an unpublished key, got %v", err)
	}
	if !s.IsEmpty() {
		t.Fatal("nothing should be stored")
	}
}

// Spec §4.10.4 step 5: a resolver-anchored store accepts a published key.
func TestResolverAnchorAcceptsPublishedKey(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	decl := &types.AgentDeclaration{AgentID: "urn:agentpin:example.com:tester", Name: "Tester",
		Capabilities: []types.Capability{"read:*"}, Status: types.AgentActive}
	card, _ := a2a.BuildAndSignAgentCard("https://example.com/agent", decl, kp.PrivateKeyPEM, "kid-1",
		"https://example.com/.well-known/agent-identity.json", a2a.BuildOptions{})
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	doc := discovery.BuildDiscoveryDocument("example.com", types.EntityBoth,
		[]types.JWK{jwk.VerifyingKeyToJWK(pub, "kid-1")}, nil, 0, "2026-01-15T00:00:00Z")
	if !CardKeyPublishedIn(&doc, &card) {
		t.Fatal("CardKeyPublishedIn should be true")
	}
	b := types.TrustBundle{AgentpinBundleVersion: "0.1", Documents: []types.DiscoveryDocument{doc}}
	s := NewLocalAgentCardStoreWithResolver(NewTrustBundleResolver(&b))
	if err := s.Register(card); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatal("card should be stored")
	}
}

func TestRegisterForDomainRequiresMatchingHost(t *testing.T) {
	card := signedCard(t)
	s := storeTrusting(card)
	if err := s.RegisterForDomain(card, "other.com"); err == nil {
		t.Fatal("mismatched domain must be refused")
	}
	if err := s.RegisterForDomain(card, "EXAMPLE.com."); err != nil {
		t.Fatal(err)
	}
}

func TestTrustThumbprintEnablesRegistration(t *testing.T) {
	card := signedCard(t)
	s := NewLocalAgentCardStore()
	if err := s.Register(card); err == nil {
		t.Fatal("empty allowlist must refuse")
	}
	if err := s.TrustThumbprint(a2a.ExtensionKeyThumbprint(card.Agentpin)); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(card); err != nil {
		t.Fatal(err)
	}
	if err := NewUnanchoredLocalAgentCardStore().TrustThumbprint("x"); err == nil {
		t.Fatal("unanchored store has no allowlist")
	}
}
