package crypto

import (
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.PrivateKeyPEM, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("private PEM bad prefix: %q", kp.PrivateKeyPEM[:30])
	}
	if !strings.HasPrefix(kp.PublicKeyPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("public PEM bad prefix: %q", kp.PublicKeyPEM[:30])
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello agentpin")
	sig, err := SignData(kp.PrivateKeyPEM, data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifySignature(kp.PublicKeyPEM, data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature should verify")
	}
	ok, _ = VerifySignature(kp.PublicKeyPEM, []byte("wrong"), sig)
	if ok {
		t.Fatal("wrong data must not verify")
	}
}

func TestWrongKeyRejection(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	sig, _ := SignData(kp1.PrivateKeyPEM, []byte("test"))
	ok, _ := VerifySignature(kp2.PublicKeyPEM, []byte("test"), sig)
	if ok {
		t.Fatal("wrong key should not verify")
	}
}

func TestGenerateKeyID(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kid, err := GenerateKeyID(kp.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(kid) != 64 {
		t.Fatalf("kid length %d, want 64", len(kid))
	}
	kid2, _ := GenerateKeyID(kp.PublicKeyPEM)
	if kid != kid2 {
		t.Fatal("GenerateKeyID must be deterministic")
	}
}

func TestSHA256Hex(t *testing.T) {
	got := SHA256Hex([]byte("test"))
	want := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got != want {
		t.Fatalf("SHA256Hex(test) = %q, want %q", got, want)
	}
}
