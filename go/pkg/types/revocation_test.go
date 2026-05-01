package types

import (
	"encoding/json"
	"testing"
)

func TestRevocationReasonJSON(t *testing.T) {
	got, _ := json.Marshal(ReasonKeyCompromise)
	if string(got) != `"key_compromise"` {
		t.Fatalf("ReasonKeyCompromise = %s", got)
	}
	got, _ = json.Marshal(ReasonCessationOfOperation)
	if string(got) != `"cessation_of_operation"` {
		t.Fatalf("ReasonCessationOfOperation = %s", got)
	}
}

func TestRevocationDocumentRoundTrip(t *testing.T) {
	doc := RevocationDocument{
		AgentpinVersion: "0.1",
		Entity:          "example.com",
		UpdatedAt:       "2026-01-30T00:00:00Z",
		RevokedCredentials: []RevokedCredential{
			{Jti: "jti-1", RevokedAt: "2026-01-30T00:00:00Z", Reason: ReasonKeyCompromise},
		},
		RevokedAgents: []RevokedAgent{},
		RevokedKeys: []RevokedKey{
			{Kid: "old-key", RevokedAt: "2026-01-30T00:00:00Z", Reason: ReasonSuperseded},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var doc2 RevocationDocument
	if err := json.Unmarshal(data, &doc2); err != nil {
		t.Fatal(err)
	}
	if len(doc2.RevokedCredentials) != 1 || doc2.RevokedCredentials[0].Jti != "jti-1" {
		t.Fatal("roundtrip mismatch")
	}
}
