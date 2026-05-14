package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEntityTypeJSON(t *testing.T) {
	cases := []struct {
		v    EntityType
		want string
	}{
		{EntityMaker, `"maker"`},
		{EntityDeployer, `"deployer"`},
		{EntityBoth, `"both"`},
	}
	for _, tc := range cases {
		got, _ := json.Marshal(tc.v)
		if string(got) != tc.want {
			t.Errorf("EntityType %q = %s, want %s", tc.v, got, tc.want)
		}
	}
}

func TestAgentStatusJSON(t *testing.T) {
	got, _ := json.Marshal(AgentActive)
	if string(got) != `"active"` {
		t.Fatalf("AgentActive = %s", got)
	}
}

func TestDiscoveryDocumentJSONRoundTrip(t *testing.T) {
	ttl := uint64(3600)
	doc := DiscoveryDocument{
		AgentpinVersion: "0.1",
		Entity:          "example.com",
		EntityType:      EntityMaker,
		PublicKeys:      []JWK{},
		Agents: []AgentDeclaration{
			{
				AgentID:          "urn:agentpin:example.com:test-agent",
				Name:             "Test Agent",
				Description:      "A test agent",
				Capabilities:     []Capability{"read:*"},
				Status:           AgentActive,
				CredentialTTLMax: &ttl,
			},
		},
		RevocationEndpoint: "https://example.com/.well-known/agent-identity-revocations.json",
		MaxDelegationDepth: 2,
		UpdatedAt:          "2026-01-15T00:00:00Z",
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"entity":"example.com"`) {
		t.Fatalf("missing entity field in JSON: %s", data)
	}
	var doc2 DiscoveryDocument
	if err := json.Unmarshal(data, &doc2); err != nil {
		t.Fatal(err)
	}
	if doc2.Entity != doc.Entity || doc2.EntityType != doc.EntityType {
		t.Fatal("roundtrip mismatch")
	}
}
