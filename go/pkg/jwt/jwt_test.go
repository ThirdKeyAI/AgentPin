package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func makeKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func makeTestJWT(t *testing.T, priv *ecdsa.PrivateKey, kid string) (string, *types.JWTHeader, *types.JWTPayload) {
	t.Helper()
	header := &types.JWTHeader{Alg: RequiredAlg, Typ: RequiredTyp, Kid: kid}
	payload := &types.JWTPayload{
		Iss:             "example.com",
		Sub:             "urn:agentpin:example.com:agent",
		Aud:             "verifier.com",
		Iat:             1738300800,
		Exp:             1738304400,
		Jti:             "test-jti-001",
		AgentpinVersion: "0.1",
		Capabilities:    []types.Capability{"read:data"},
	}
	jwt, err := EncodeJWT(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return jwt, header, payload
}

func TestJWTEncodeDecodeRoundTrip(t *testing.T) {
	priv := makeKey(t)
	pub := &priv.PublicKey
	jwt, _, _ := makeTestJWT(t, priv, "k")
	header, payload, err := VerifyJWT(jwt, pub)
	if err != nil {
		t.Fatal(err)
	}
	if header.Alg != RequiredAlg {
		t.Fatalf("alg: %s", header.Alg)
	}
	if payload.Iss != "example.com" {
		t.Fatalf("iss: %s", payload.Iss)
	}
}

func TestJWTWrongKeyRejected(t *testing.T) {
	p1 := makeKey(t)
	p2 := makeKey(t)
	jwt, _, _ := makeTestJWT(t, p1, "k")
	if _, _, err := VerifyJWT(jwt, &p2.PublicKey); err == nil {
		t.Fatal("wrong key should fail")
	}
}

// craftBadAlgJWT manually crafts a JWT with the given header alg/typ values
// to test that DecodeJWTUnverified rejects each one before any signature work.
func craftBadAlgJWT(alg, typ string) string {
	hdr, _ := json.Marshal(types.JWTHeader{Alg: alg, Typ: typ, Kid: "k"})
	pld, _ := json.Marshal(types.JWTPayload{Iss: "e.com", Sub: "s", Iat: 1, Exp: 2, Jti: "j"})
	hb := base64.RawURLEncoding.EncodeToString(hdr)
	pb := base64.RawURLEncoding.EncodeToString(pld)
	return hb + "." + pb + ".sig"
}

func TestJWTAlgorithmRejectionNone(t *testing.T) {
	_, _, _, err := DecodeJWTUnverified(craftBadAlgJWT("none", RequiredTyp))
	if err == nil {
		t.Fatal("alg=none must be rejected")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("error should mention rejection, got: %v", err)
	}
}

func TestJWTAlgorithmRejectionHS256(t *testing.T) {
	if _, _, _, err := DecodeJWTUnverified(craftBadAlgJWT("HS256", RequiredTyp)); err == nil {
		t.Fatal("alg=HS256 must be rejected")
	}
}

func TestJWTAlgorithmRejectionRS256(t *testing.T) {
	if _, _, _, err := DecodeJWTUnverified(craftBadAlgJWT("RS256", RequiredTyp)); err == nil {
		t.Fatal("alg=RS256 must be rejected")
	}
}

func TestJWTAlgorithmRejectionES384(t *testing.T) {
	if _, _, _, err := DecodeJWTUnverified(craftBadAlgJWT("ES384", RequiredTyp)); err == nil {
		t.Fatal("alg=ES384 must be rejected")
	}
}

func TestJWTAlgorithmRejectionEmpty(t *testing.T) {
	if _, _, _, err := DecodeJWTUnverified(craftBadAlgJWT("", RequiredTyp)); err == nil {
		t.Fatal("alg='' must be rejected")
	}
}

func TestJWTWrongTypRejected(t *testing.T) {
	if _, _, _, err := DecodeJWTUnverified(craftBadAlgJWT(RequiredAlg, "JWT")); err == nil {
		t.Fatal("typ=JWT must be rejected")
	}
}

func TestJWTMalformedRejected(t *testing.T) {
	if _, _, _, err := DecodeJWTUnverified("not.a.jwt.token"); err == nil {
		t.Fatal("4-part jwt should be rejected")
	}
	if _, _, _, err := DecodeJWTUnverified("only-one-part"); err == nil {
		t.Fatal("1-part jwt should be rejected")
	}
}

func TestBase64URLEncode(t *testing.T) {
	if got := Base64URLEncode([]byte("hello")); got != "aGVsbG8" {
		t.Fatalf("Base64URLEncode = %q", got)
	}
	dec, err := Base64URLDecode("aGVsbG8")
	if err != nil || string(dec) != "hello" {
		t.Fatalf("Base64URLDecode roundtrip failed: %v %s", err, dec)
	}
}
