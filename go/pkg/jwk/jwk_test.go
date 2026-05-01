package jwk

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func TestJWKRoundTrip(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	j, err := PEMToJWK(kp.PublicKeyPEM, "test-key-01")
	if err != nil {
		t.Fatal(err)
	}
	if j.Kty != "EC" || j.Crv != "P-256" || j.Kid != "test-key-01" || j.Use != "sig" {
		t.Fatalf("JWK fields wrong: %+v", j)
	}
	pem, err := JWKToPEM(&j)
	if err != nil {
		t.Fatal(err)
	}
	if pem != kp.PublicKeyPEM {
		t.Fatalf("PEM roundtrip mismatch:\n%s\nvs\n%s", pem, kp.PublicKeyPEM)
	}
}

func TestJWKThumbprintDeterministic(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	j, _ := PEMToJWK(kp.PublicKeyPEM, "kid-1")
	t1 := JWKThumbprint(&j)
	t2 := JWKThumbprint(&j)
	if t1 != t2 {
		t.Fatal("thumbprint not deterministic")
	}
	if len(t1) != 64 {
		t.Fatalf("thumbprint length %d, want 64", len(t1))
	}
}

func TestJWKThumbprintKnownVector(t *testing.T) {
	// RFC 7638 Section 3.1 example, adapted for our hex output.
	// {"crv":"P-256","kty":"EC","x":"...","y":"..."} → SHA-256 hex.
	// Use a known fixed JWK to lock down byte-for-byte parity with Rust.
	j := types.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		Y:   "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	}
	got := JWKThumbprint(&j)
	// Computed canonical: {"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
	// SHA-256 hex (matches the AgentPin Rust SDK on the same input).
	want := "727f88fd634c0a57a1895a79d62ff4569384356d6ea447ab03cb046a6e619feb"
	if got != want {
		t.Fatalf("JWKThumbprint mismatch:\ngot  %s\nwant %s", got, want)
	}
}

func TestInvalidJWKRejected(t *testing.T) {
	j := types.JWK{Kty: "RSA", Crv: "P-256", X: "AAAA", Y: "BBBB"}
	if _, err := JWKToVerifyingKey(&j); err == nil {
		t.Fatal("invalid JWK should be rejected")
	}
}

func TestVerifyingKeyToJWKShape(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	j := VerifyingKeyToJWK(pub, "kid-1")
	if j.Kty != "EC" || j.Crv != "P-256" {
		t.Fatal("kty/crv wrong")
	}
	if len(j.KeyOps) != 1 || j.KeyOps[0] != "verify" {
		t.Fatalf("key_ops = %v", j.KeyOps)
	}
	if j.Use != "sig" {
		t.Fatal("use should be sig")
	}
}
