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

// AP-19: nonces are single-use even without an explicit store.
func TestDefaultStoreRejectsReplay(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	c, _ := CreateChallenge("")
	r, _ := CreateResponse(c, priv, "k")
	if ok, err := VerifyResponse(r, c, pub); err != nil || !ok {
		t.Fatalf("first verify: ok=%v err=%v", ok, err)
	}
	if _, err := VerifyResponse(r, c, pub); err == nil {
		t.Fatal("replay must be rejected by the default store")
	}
}

// AP-19: a forged response must not burn the nonce for the real responder.
func TestForgedResponseDoesNotConsumeNonce(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	attacker, _ := crypto.GenerateKeyPair()
	attackerPriv, _ := crypto.LoadPrivateKey(attacker.PrivateKeyPEM)
	c, _ := CreateChallenge("")
	forged, _ := CreateResponse(c, attackerPriv, "k")
	if ok, _ := VerifyResponse(forged, c, pub); ok {
		t.Fatal("forged response must not verify")
	}
	genuine, _ := CreateResponse(c, priv, "k")
	if ok, err := VerifyResponse(genuine, c, pub); err != nil || !ok {
		t.Fatalf("genuine response after forgery: ok=%v err=%v", ok, err)
	}
}

// AP-19: an unparsable timestamp is treated as expired.
func TestMalformedTimestampRejected(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	c, _ := CreateChallenge("")
	c.Timestamp = "not-a-timestamp"
	r, _ := CreateResponse(c, priv, "k")
	if _, err := VerifyResponse(r, c, pub); err == nil {
		t.Fatal("malformed timestamp must be rejected")
	}
}

// AP-1: the responder refuses to sign anything that is not a well-formed
// 128-bit nonce, so it cannot be used as a signing oracle for a JWT.
func TestCreateResponseRejectsNonNonceChallenge(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	c, _ := CreateChallenge("")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"k"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"example.com"}`))
	c.Nonce = header + "." + payload
	if _, err := CreateResponse(c, priv, "k"); err == nil {
		t.Fatal("JWT-shaped nonce must be rejected")
	}
	c.Nonce = "AAAAAAAAAAAAAAAAAAAAAA=="
	if _, err := CreateResponse(c, priv, "k"); err == nil {
		t.Fatal("padded nonce must be rejected")
	}
	c.Nonce = "AAAAAAAAAAAAAAAAAAAAAB"
	if _, err := CreateResponse(c, priv, "k"); err == nil {
		t.Fatal("non-canonical nonce must be rejected")
	}
	c.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := CreateResponse(c, priv, "k"); err != nil {
		t.Fatalf("canonical nonce should be accepted: %v", err)
	}
}

// AP-1 / design 8: the response signature is domain separated and bound to
// the prover kid and the verifier credential.
func TestResponseSignatureIsDomainSeparated(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	c, _ := CreateChallenge("eyJ.verifier.jwt")
	r, _ := CreateResponse(c, priv, "k")
	if ok, _ := crypto.VerifyBytes(pub, []byte(c.Nonce), r.Signature); ok {
		t.Fatal("signature must not be a raw signature over the nonce")
	}
	other := *r
	other.Kid = "other"
	if ok, _ := VerifyResponse(&other, c, pub); ok {
		t.Fatal("changing kid must break the signature")
	}
	c2 := *c
	c2.VerifierCredential = "eyJ.someone.else"
	if ok, _ := VerifyResponse(r, &c2, pub); ok {
		t.Fatal("changing verifier binding must break the signature")
	}
}
