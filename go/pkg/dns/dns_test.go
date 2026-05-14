package dns

import (
	"strings"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func discoveryDoc(jwks []types.JWK) *types.DiscoveryDocument {
	return &types.DiscoveryDocument{
		AgentpinVersion:    "0.3",
		Entity:             "example.com",
		EntityType:         types.EntityMaker,
		PublicKeys:         jwks,
		MaxDelegationDepth: 0,
		UpdatedAt:          "2026-05-01T00:00:00Z",
	}
}

func TestParseFullRecord(t *testing.T) {
	r, err := ParseTxtRecord("v=agentpin1; kid=acme-2026-04; fp=sha256:abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "agentpin1" || r.Kid != "acme-2026-04" || r.Fingerprint != "sha256:abcd1234" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestParseMinimalRecord(t *testing.T) {
	r, err := ParseTxtRecord("v=agentpin1;fp=sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kid != "" || r.Fingerprint != "sha256:abc" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestParseLowercasesFingerprint(t *testing.T) {
	r, err := ParseTxtRecord("v=agentpin1; fp=SHA256:ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != "sha256:abcdef" {
		t.Fatalf("expected lowercased fp, got %q", r.Fingerprint)
	}
}

func TestParseToleratesWhitespaceAndOrder(t *testing.T) {
	r, err := ParseTxtRecord("  fp = sha256:beef ;  v = agentpin1  ")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != "sha256:beef" || r.Version != "agentpin1" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestParseIgnoresUnknownFields(t *testing.T) {
	r, err := ParseTxtRecord("v=agentpin1; fp=sha256:abc; future=ignoreme")
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != "sha256:abc" {
		t.Fatalf("unexpected: %+v", r)
	}
}

func TestParseFailures(t *testing.T) {
	cases := []string{
		"fp=sha256:abc",               // missing v
		"v=agentpin1",                 // missing fp
		"v=agentpin99; fp=sha256:abc", // bad version
		"v=agentpin1; fp=abc",         // bad fp prefix
		"v=agentpin1; broken",         // missing '='
		"v=schemapin1; fp=sha256:abc", // SchemaPin format
	}
	for _, c := range cases {
		if _, err := ParseTxtRecord(c); err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

func fpFor(j types.JWK) string {
	t := strings.ToLower(jwk.JWKThumbprint(&j))
	if !strings.HasPrefix(t, "sha256:") {
		t = "sha256:" + t
	}
	return t
}

func TestVerifyMatchAgainstSingleKey(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	j, err := jwk.PEMToJWK(kp.PublicKeyPEM, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDnsMatch(discoveryDoc([]types.JWK{j}),
		&TxtRecord{Fingerprint: fpFor(j)}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMatchAgainstOneOfMultipleKeys(t *testing.T) {
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	j1, _ := jwk.PEMToJWK(kp1.PublicKeyPEM, "kid-a")
	j2, _ := jwk.PEMToJWK(kp2.PublicKeyPEM, "kid-b")
	doc := discoveryDoc([]types.JWK{j1, j2})
	if err := VerifyDnsMatch(doc, &TxtRecord{Kid: "kid-b", Fingerprint: fpFor(j2)}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyKidMismatchFailsEvenWhenFpMatches(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	j, _ := jwk.PEMToJWK(kp.PublicKeyPEM, "kid-real")
	doc := discoveryDoc([]types.JWK{j})
	if err := VerifyDnsMatch(doc, &TxtRecord{Kid: "kid-different", Fingerprint: fpFor(j)}); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifyFingerprintMismatch(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	j, _ := jwk.PEMToJWK(kp.PublicKeyPEM, "kid-1")
	doc := discoveryDoc([]types.JWK{j})
	if err := VerifyDnsMatch(doc, &TxtRecord{
		Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestTxtRecordNameStripsTrailingDot(t *testing.T) {
	if got := TxtRecordName("example.com"); got != "_agentpin.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := TxtRecordName("example.com."); got != "_agentpin.example.com" {
		t.Fatalf("got %q", got)
	}
}
