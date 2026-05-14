package types

import (
	"encoding/json"
	"testing"
)

func TestBundleFindHelpers(t *testing.T) {
	b := TrustBundle{
		AgentpinBundleVersion: "0.1",
		CreatedAt:             "2026-02-10T00:00:00Z",
		Documents: []DiscoveryDocument{
			{
				Entity:             "example.com",
				AgentpinVersion:    "0.1",
				EntityType:         EntityMaker,
				MaxDelegationDepth: 2,
				PublicKeys:         []JWK{{Kid: "k", Kty: "EC", Crv: "P-256"}},
				Agents:             []AgentDeclaration{},
				UpdatedAt:          "x",
			},
		},
		Revocations: []RevocationDocument{},
	}
	if b.FindDiscovery("example.com") == nil {
		t.Fatal("FindDiscovery hit expected")
	}
	if b.FindDiscovery("missing.com") != nil {
		t.Fatal("FindDiscovery miss expected")
	}
	if b.FindRevocation("example.com") != nil {
		t.Fatal("FindRevocation should be nil")
	}
}

func TestBundleJSONRoundTrip(t *testing.T) {
	b := TrustBundle{
		AgentpinBundleVersion: "0.1",
		CreatedAt:             "2026-02-10T00:00:00Z",
		Documents:             []DiscoveryDocument{},
		Revocations:           []RevocationDocument{},
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var b2 TrustBundle
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatal(err)
	}
	if b2.AgentpinBundleVersion != "0.1" {
		t.Fatal("bundle version mismatch")
	}
}
