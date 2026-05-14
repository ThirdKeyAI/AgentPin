package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChallengeJSON(t *testing.T) {
	c := Challenge{
		Type:               "agentpin-challenge",
		Nonce:              "abc",
		Timestamp:          "2026-01-30T00:00:00Z",
		VerifierCredential: "eyJ...",
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"type":"agentpin-challenge"`) {
		t.Fatalf("expected type field, got %s", data)
	}
	var c2 Challenge
	if err := json.Unmarshal(data, &c2); err != nil {
		t.Fatal(err)
	}
	if c2 != c {
		t.Fatal("roundtrip mismatch")
	}
}

func TestResponseJSON(t *testing.T) {
	r := Response{Type: "agentpin-response", Nonce: "abc", Signature: "sig", Kid: "k"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Response
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2 != r {
		t.Fatal("roundtrip mismatch")
	}
}
