package verification

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// TestCredentialVerifiesThroughCardDerivedDiscovery is the AP-9 regression
// test: a credential signed with the key inside a registered AgentCard must
// verify through the LocalAgentCardStore. Before the fix the derived
// discovery document carried agentpin_version "0.3" and every verification
// through the store failed with DISCOVERY_INVALID.
func TestCredentialVerifiesThroughCardDerivedDiscovery(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	decl := &types.AgentDeclaration{
		AgentID:      "urn:agentpin:example.com:tester",
		Name:         "Tester",
		Capabilities: []types.Capability{"read:*"},
		Status:       types.AgentActive,
	}
	card, err := a2a.BuildAndSignAgentCard(
		"https://example.com/agent", decl, kp.PrivateKeyPEM, "kid-1",
		"https://example.com/.well-known/agent-identity.json", a2a.BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	store := resolver.NewLocalAgentCardStore()
	if err := store.Register(card); err != nil {
		t.Fatal(err)
	}
	doc, err := store.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if doc.AgentpinVersion != "0.1" {
		t.Fatalf("derived doc version = %q, want 0.1", doc.AgentpinVersion)
	}

	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	jwtStr, err := credential.IssueCredential(
		priv, "kid-1", "example.com", "urn:agentpin:example.com:tester", "",
		[]types.Capability{"read:data"}, nil, nil, 3600,
	)
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyCredentialWithResolver(jwtStr, store, pinning.NewKeyPinStore(), "", DefaultVerifierConfig())
	if !r.Valid {
		t.Fatalf("expected valid through card-derived discovery, got %+v", r)
	}
	if r.AgentID != "urn:agentpin:example.com:tester" {
		t.Fatalf("agent_id = %s", r.AgentID)
	}
}
