package resolver

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
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
	store := NewLocalAgentCardStore()
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
	store := NewLocalAgentCardStore()
	if err := store.Register(card); err == nil {
		t.Fatal("expected signature failure")
	}
	if !store.IsEmpty() {
		t.Fatal("store should be empty after failed register")
	}
}

func TestLocalAgentCardStoreResolveMissing(t *testing.T) {
	store := NewLocalAgentCardStore()
	if _, err := store.ResolveDiscovery("missing.com"); err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestLocalAgentCardStoreReRegisterReplaces(t *testing.T) {
	store := NewLocalAgentCardStore()
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
	store := NewLocalAgentCardStore()
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
	store := NewLocalAgentCardStore()
	_ = store.Register(signedCard(t))
	card, ok := store.ResolveCard("example.com")
	if !ok || card.Name != "Tester" {
		t.Fatalf("unexpected: ok=%v card=%+v", ok, card)
	}
}

func TestLocalAgentCardStoreResolveRevocationReturnsNil(t *testing.T) {
	store := NewLocalAgentCardStore()
	_ = store.Register(signedCard(t))
	doc, _ := store.ResolveDiscovery("example.com")
	rev, err := store.ResolveRevocation("example.com", doc)
	if err != nil || rev != nil {
		t.Fatalf("expected nil rev, got rev=%v err=%v", rev, err)
	}
}
