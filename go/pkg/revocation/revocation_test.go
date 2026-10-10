package revocation

import (
	"testing"

	"encoding/json"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"time"
)

func TestBuildAndAddRevocations(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	if d.Entity != "example.com" {
		t.Fatal("entity")
	}
	if len(d.RevokedCredentials) != 0 {
		t.Fatal("should start empty")
	}
	AddRevokedCredential(&d, "jti-1", types.ReasonKeyCompromise)
	AddRevokedAgent(&d, "agent-1", types.ReasonPolicyViolation)
	AddRevokedKey(&d, "kid-1", types.ReasonSuperseded)
	if len(d.RevokedCredentials) != 1 || len(d.RevokedAgents) != 1 || len(d.RevokedKeys) != 1 {
		t.Fatal("expected 1 each")
	}
}

func TestCheckRevocationClean(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	if err := CheckRevocation(&d, "j", "a", "k"); err != nil {
		t.Fatalf("clean check should pass: %v", err)
	}
}

func TestCheckRevocationCredentialRevoked(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	AddRevokedCredential(&d, "jti-bad", types.ReasonKeyCompromise)
	err := CheckRevocation(&d, "jti-bad", "a", "k")
	if err == nil {
		t.Fatal("revoked jti should fail")
	}
	ve, ok := types.AsVerificationError(err)
	if !ok || ve.Code != types.ErrCredentialRevoked {
		t.Fatalf("expected CredentialRevoked, got %v", err)
	}
}

func TestCheckRevocationAgentRevoked(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	AddRevokedAgent(&d, "bad-agent", types.ReasonPrivilegeWithdrawn)
	if err := CheckRevocation(&d, "j", "bad-agent", "k"); err == nil {
		t.Fatal("revoked agent should fail")
	}
}

func TestCheckRevocationKeyRevoked(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	AddRevokedKey(&d, "bad-key", types.ReasonSuperseded)
	if err := CheckRevocation(&d, "j", "a", "bad-key"); err == nil {
		t.Fatal("revoked key should fail")
	}
}

func discoveryWith(t *testing.T, j types.JWK, entity string) *types.DiscoveryDocument {
	t.Helper()
	return &types.DiscoveryDocument{
		AgentpinVersion: "0.1", Entity: entity, EntityType: types.EntityMaker,
		PublicKeys: []types.JWK{j}, MaxDelegationDepth: 2, UpdatedAt: "2026-01-15T00:00:00Z",
	}
}

// Design issue 3: signed revocation documents verify under the discovery
// key; tampering, wrong kid and foreign entities are rejected.
func TestSignedRevocationDocument(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	j, _ := jwk.PEMToJWK(kp.PublicKeyPEM, "k1")
	disc := discoveryWith(t, j, "example.com")

	doc := BuildRevocationDocument("example.com")
	AddRevokedKey(&doc, "old", types.ReasonSuperseded)
	if err := VerifyRevocationDocument(&doc, disc); err != nil {
		t.Fatalf("unsigned document should be accepted: %v", err)
	}
	if err := SignRevocationDocument(&doc, priv, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationDocument(&doc, disc); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(doc)
	var parsed types.RevocationDocument
	_ = json.Unmarshal(data, &parsed)
	if err := VerifyRevocationDocument(&parsed, disc); err != nil {
		t.Fatal(err)
	}
	tampered := doc
	tampered.RevokedKeys = nil
	if err := VerifyRevocationDocument(&tampered, disc); err == nil {
		t.Fatal("tampered document must fail")
	}
	wrongKid := doc
	wrongKid.Kid = "other"
	if err := VerifyRevocationDocument(&wrongKid, disc); err == nil {
		t.Fatal("unknown kid must fail")
	}
	foreign := BuildRevocationDocument("other.com")
	if err := VerifyRevocationDocument(&foreign, disc); err == nil {
		t.Fatal("foreign entity must fail")
	}
	variant := BuildRevocationDocument("EXAMPLE.com.")
	if err := VerifyRevocationDocument(&variant, disc); err != nil {
		t.Fatalf("normalized entity should match: %v", err)
	}
}

// Design issue 3: stale or unparsable updated_at is rejected.
func TestRevocationFreshness(t *testing.T) {
	doc := BuildRevocationDocument("example.com")
	if err := CheckRevocationFreshness(&doc, 3600); err != nil {
		t.Fatal(err)
	}
	doc.UpdatedAt = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	if err := CheckRevocationFreshness(&doc, 3600); err == nil {
		t.Fatal("stale document must fail")
	}
	doc.UpdatedAt = "yesterday"
	if err := CheckRevocationFreshness(&doc, 3600); err == nil {
		t.Fatal("unparsable updated_at must fail")
	}
}
