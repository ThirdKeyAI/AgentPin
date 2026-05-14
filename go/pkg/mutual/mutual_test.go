package mutual

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/nonce"
)

func TestChallengeResponseRoundTrip(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	c, err := CreateChallenge("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := CreateResponse(c, priv, "k")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyResponse(r, c, pub)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
}

func TestNonceIs128Bits(t *testing.T) {
	c, _ := CreateChallenge("")
	b, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	if err != nil || len(b) != 16 {
		t.Fatalf("nonce len = %d, want 16 (128 bits)", len(b))
	}
}

func TestWrongKeyRejected(t *testing.T) {
	k1, _ := crypto.GenerateKeyPair()
	k2, _ := crypto.GenerateKeyPair()
	p1, _ := crypto.LoadPrivateKey(k1.PrivateKeyPEM)
	pub2, _ := crypto.LoadPublicKey(k2.PublicKeyPEM)
	c, _ := CreateChallenge("")
	r, _ := CreateResponse(c, p1, "k")
	ok, _ := VerifyResponse(r, c, pub2)
	if ok {
		t.Fatal("wrong key should not verify")
	}
}

func TestNonceMismatchRejected(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	c, _ := CreateChallenge("")
	r, _ := CreateResponse(c, priv, "k")
	r.Nonce = "wrong"
	ok, _ := VerifyResponse(r, c, pub)
	if ok {
		t.Fatal("nonce mismatch should not verify")
	}
}

func TestExpiredNonceRejected(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	c, _ := CreateChallenge("")
	c.Timestamp = time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339)
	r, _ := CreateResponse(c, priv, "k")
	if _, err := VerifyResponse(r, c, pub); err == nil {
		t.Fatal("expired challenge should error")
	}
}

func TestNonceStoreReplayProtection(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	store := nonce.NewInMemoryStore()
	c, _ := CreateChallenge("")
	r, _ := CreateResponse(c, priv, "k")
	if _, err := VerifyResponseWithStore(r, c, pub, store); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}
	if _, err := VerifyResponseWithStore(r, c, pub, store); err == nil {
		t.Fatal("replay should be rejected")
	}
}
