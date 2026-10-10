package bundle

import (
	"encoding/json"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func TestNewTrustBundle(t *testing.T) {
	b := NewTrustBundle("2026-02-10T00:00:00Z")
	if b.AgentpinBundleVersion != "0.1" {
		t.Fatal("bundle version")
	}
	if len(b.Documents) != 0 || len(b.Revocations) != 0 {
		t.Fatal("should start empty")
	}
}

func TestFindHelpers(t *testing.T) {
	b := types.TrustBundle{
		Documents: []types.DiscoveryDocument{{Entity: "example.com"}},
	}
	if FindBundleDiscovery(&b, "example.com") == nil {
		t.Fatal("hit")
	}
	if FindBundleDiscovery(&b, "missing") != nil {
		t.Fatal("miss")
	}
}

func TestBundleSerializesEmpty(t *testing.T) {
	b := NewTrustBundle("2026-02-10T00:00:00Z")
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var b2 types.TrustBundle
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatal(err)
	}
}

// Design issue 5: a signed bundle verifies, tampering and expiry fail.
func TestSignedTrustBundle(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	other, _ := crypto.GenerateKeyPair()
	otherPub, _ := crypto.LoadPublicKey(other.PublicKeyPEM)

	b := NewTrustBundle("2026-02-10T00:00:00Z")
	if err := VerifyTrustBundle(&b, pub); err == nil {
		t.Fatal("unsigned bundle must be rejected")
	}
	if err := SignTrustBundle(&b, priv, "ops-1"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTrustBundle(&b, pub); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(b)
	var parsed types.TrustBundle
	_ = json.Unmarshal(data, &parsed)
	if err := VerifyTrustBundle(&parsed, pub); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTrustBundle(&b, otherPub); err == nil {
		t.Fatal("wrong key must fail")
	}
	tampered := b
	tampered.CreatedAt = "2030-01-01T00:00:00Z"
	if err := VerifyTrustBundle(&tampered, pub); err == nil {
		t.Fatal("tampered bundle must fail")
	}
	expired := NewTrustBundle("2026-02-10T00:00:00Z")
	expired.ExpiresAt = "2020-01-01T00:00:00Z"
	_ = SignTrustBundle(&expired, priv, "ops-1")
	if err := VerifyTrustBundle(&expired, pub); err == nil {
		t.Fatal("expired bundle must fail")
	}
}
