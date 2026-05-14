package discovery

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func makeDoc() types.DiscoveryDocument {
	return BuildDiscoveryDocument(
		"example.com",
		types.EntityMaker,
		[]types.JWK{{Kid: "example-2026-01", Kty: "EC", Crv: "P-256", X: "x", Y: "y", Use: "sig"}},
		[]types.AgentDeclaration{
			{
				AgentID:      "urn:agentpin:example.com:agent",
				Name:         "Test Agent",
				Capabilities: []types.Capability{"read:*"},
				Status:       types.AgentActive,
			},
		},
		2,
		"2026-01-15T00:00:00Z",
	)
}

func TestValidateDiscoveryDocument(t *testing.T) {
	d := makeDoc()
	if err := ValidateDiscoveryDocument(&d, "example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDomainMismatch(t *testing.T) {
	d := makeDoc()
	err := ValidateDiscoveryDocument(&d, "other.com")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	ve, ok := types.AsVerificationError(err)
	if !ok || ve.Code != types.ErrDomainMismatch {
		t.Fatalf("expected DomainMismatch, got %v", err)
	}
}

func TestFindKeyByKid(t *testing.T) {
	d := makeDoc()
	if FindKeyByKid(&d, "example-2026-01") == nil {
		t.Fatal("hit expected")
	}
	if FindKeyByKid(&d, "missing") != nil {
		t.Fatal("miss expected")
	}
}

func TestFindAgentByID(t *testing.T) {
	d := makeDoc()
	if FindAgentByID(&d, "urn:agentpin:example.com:agent") == nil {
		t.Fatal("hit expected")
	}
	if FindAgentByID(&d, "urn:agentpin:example.com:other") != nil {
		t.Fatal("miss expected")
	}
}

func TestBuildDiscoveryDocumentRevocationEndpoint(t *testing.T) {
	d := makeDoc()
	want := "https://example.com/.well-known/agent-identity-revocations.json"
	if d.RevocationEndpoint != want {
		t.Fatalf("RevocationEndpoint = %s, want %s", d.RevocationEndpoint, want)
	}
}

func TestRejectMaxDelegationDepthOver3(t *testing.T) {
	d := makeDoc()
	d.MaxDelegationDepth = 4
	if err := ValidateDiscoveryDocument(&d, "example.com"); err == nil {
		t.Fatal("max_delegation_depth > 3 should be rejected")
	}
}

func TestRejectEmptyKeys(t *testing.T) {
	d := makeDoc()
	d.PublicKeys = nil
	if err := ValidateDiscoveryDocument(&d, "example.com"); err == nil {
		t.Fatal("empty keys should be rejected")
	}
}
