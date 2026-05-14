package credential

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func TestIssueCredential(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)

	cred, err := IssueCredential(
		priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com",
		[]types.Capability{"read:data"},
		nil, nil, 3600,
	)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := jwt.VerifyJWT(cred, pub)
	if err != nil {
		t.Fatal(err)
	}
	if header.Kid != "test-2026-01" {
		t.Fatalf("kid: %s", header.Kid)
	}
	if payload.Iss != "example.com" || payload.Sub != "urn:agentpin:example.com:agent" {
		t.Fatal("iss/sub mismatch")
	}
	if payload.Aud != "verifier.com" || payload.AgentpinVersion != "0.1" {
		t.Fatal("aud/version mismatch")
	}
	if payload.Exp <= payload.Iat {
		t.Fatal("exp must be > iat")
	}
}

func TestValidateCredentialAgainstDiscovery(t *testing.T) {
	disc := []types.Capability{"read:*", "write:report"}
	if err := ValidateCredentialAgainstDiscovery([]types.Capability{"read:data"}, disc); err != nil {
		t.Fatalf("subset should pass: %v", err)
	}
	if err := ValidateCredentialAgainstDiscovery([]types.Capability{"delete:data"}, []types.Capability{"read:data"}); err == nil {
		t.Fatal("delete > read should fail")
	}
}
