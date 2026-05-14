package a2a

import (
	"encoding/json"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func declaration(caps []string, allowed []string) *types.AgentDeclaration {
	capabilities := make([]types.Capability, 0, len(caps))
	for _, c := range caps {
		capabilities = append(capabilities, types.Capability(c))
	}
	decl := &types.AgentDeclaration{
		AgentID:      "urn:agentpin:example.com:test",
		Name:         "Test Agent",
		Description:  "test",
		Version:      "1.0.0",
		Capabilities: capabilities,
		Status:       types.AgentActive,
	}
	if allowed != nil {
		decl.Constraints = &types.Constraints{AllowedDomains: allowed}
	}
	return decl
}

func TestCapabilityToSkillMapsStrings(t *testing.T) {
	skill := types.CapabilityToSkill(types.Capability("read:customers/*"))
	if skill.ID != "read:customers/*" || skill.Name != "read:customers/*" {
		t.Fatalf("unexpected skill: %+v", skill)
	}
}

func TestBuildUnsignedAgentCardMapsCapabilities(t *testing.T) {
	card := BuildUnsignedAgentCard("https://example.com/agent",
		declaration([]string{"read:customers", "write:invoices"}, nil),
		BuildOptions{})
	if len(card.Skills) != 2 {
		t.Fatalf("want 2 skills, got %d", len(card.Skills))
	}
	if card.Skills[0].ID != "read:customers" || card.Skills[1].ID != "write:invoices" {
		t.Fatalf("skill IDs wrong: %+v", card.Skills)
	}
	if card.Agentpin != nil {
		t.Fatalf("unsigned card should have no agentpin extension")
	}
}

func TestBuildUnsignedAgentCardMapsAllowedDomains(t *testing.T) {
	card := BuildUnsignedAgentCard("https://example.com/agent",
		declaration([]string{"read:*"}, []string{"a.com", "b.com"}),
		BuildOptions{})
	if got, want := card.Capabilities.AllowedDomains, []string{"a.com", "b.com"}; !equalSlices(got, want) {
		t.Fatalf("allowed_domains wrong: %v", got)
	}
}

func TestBuildUnsignedAgentCardOmitsAllowedDomainsWhenUnrestricted(t *testing.T) {
	card := BuildUnsignedAgentCard("https://example.com/agent",
		declaration([]string{"read:*"}, nil), BuildOptions{})
	if card.Capabilities.AllowedDomains != nil {
		t.Fatalf("expected unrestricted allowed_domains, got %v", card.Capabilities.AllowedDomains)
	}
}

func TestSignRequiresAgentpinEndpoint(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := BuildUnsignedAgentCard("https://example.com/agent", declaration([]string{"read:*"}, nil), BuildOptions{})
	if _, err := SignAgentCard(unsigned, kp.PrivateKeyPEM, "kid-1", ""); err == nil {
		t.Fatal("expected error when agentpin endpoint is empty")
	}
}

func TestSignedCardRoundTripsAndVerifies(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	card, err := BuildAndSignAgentCard(
		"https://example.com/agent",
		declaration([]string{"read:customers", "write:invoices"}, []string{"partner.com"}),
		kp.PrivateKeyPEM, "kid-1",
		"https://example.com/.well-known/agent-identity.json",
		BuildOptions{Streaming: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if card.Agentpin == nil {
		t.Fatal("expected signed card to have agentpin extension")
	}
	if err := VerifyAgentpinExtension(&card); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	raw, err := json.Marshal(&card)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip types.A2aAgentCard
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgentpinExtension(&roundtrip); err != nil {
		t.Fatalf("verify after roundtrip failed: %v", err)
	}
}

func TestVerifyFailsWhenExtensionMissing(t *testing.T) {
	card := BuildUnsignedAgentCard("https://example.com/agent", declaration([]string{"read:*"}, nil), BuildOptions{})
	if err := VerifyAgentpinExtension(&card); err == nil {
		t.Fatal("expected error for card without extension")
	}
}

func TestVerifyFailsWhenCardTampered(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	card, err := BuildAndSignAgentCard(
		"https://example.com/agent",
		declaration([]string{"read:customers"}, nil),
		kp.PrivateKeyPEM, "kid-1",
		"https://example.com/.well-known/agent-identity.json",
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	card.URL = "https://attacker.example/agent"
	if err := VerifyAgentpinExtension(&card); err == nil {
		t.Fatal("expected verify failure on tampered card")
	}
}

func TestExtensionKeyThumbprintMatchesJWKThumbprint(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	card, err := BuildAndSignAgentCard(
		"https://example.com/agent",
		declaration([]string{"read:*"}, nil),
		kp.PrivateKeyPEM, "kid-1",
		"https://example.com/.well-known/agent-identity.json",
		BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	got := ExtensionKeyThumbprint(card.Agentpin)
	want := jwk.JWKThumbprint(&card.Agentpin.PublicKeyJWK)
	if got != want {
		t.Fatalf("thumbprint mismatch: got=%s want=%s", got, want)
	}
}

func TestCanonicalizeSortsKeysAndDropsNullishOmitempty(t *testing.T) {
	value := map[string]interface{}{"b": 1.0, "a": map[string]interface{}{"d": 4.0, "c": 3.0}}
	out, err := CanonicalizeForSigning(value)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"c":3,"d":4},"b":1}`
	if string(out) != want {
		t.Fatalf("canonical mismatch: got=%s want=%s", out, want)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
