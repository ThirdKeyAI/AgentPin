package delegation

import (
	"testing"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func TestCreateAndVerifyAttestation(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	caps := []types.Capability{"read:data", "write:report"}

	att, err := CreateAttestation(priv, "k", "maker.com", types.RoleMaker,
		"urn:maker:type", "deployer.com", "urn:deployer:inst", caps)
	if err != nil {
		t.Fatal(err)
	}
	if att.Domain != "maker.com" || att.Role != types.RoleMaker {
		t.Fatal("att fields wrong")
	}
	if err := VerifyAttestation(att, pub, "deployer.com", "urn:deployer:inst", caps); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyAttestationWrongKey(t *testing.T) {
	k1, _ := crypto.GenerateKeyPair()
	k2, _ := crypto.GenerateKeyPair()
	p1, _ := crypto.LoadPrivateKey(k1.PrivateKeyPEM)
	pub2, _ := crypto.LoadPublicKey(k2.PublicKeyPEM)
	caps := []types.Capability{"read:data"}
	att, _ := CreateAttestation(p1, "k", "d", types.RoleMaker, "a", "dd", "da", caps)
	if err := VerifyAttestation(att, pub2, "dd", "da", caps); err == nil {
		t.Fatal("wrong key should fail")
	}
}

func TestVerifyAttestationWrongCaps(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	caps := []types.Capability{"read:data"}
	bad := []types.Capability{"write:data"}
	att, _ := CreateAttestation(priv, "k", "d", types.RoleMaker, "a", "dd", "da", caps)
	if err := VerifyAttestation(att, pub, "dd", "da", bad); err == nil {
		t.Fatal("wrong caps should fail")
	}
}

func TestVerifyChainDepth(t *testing.T) {
	if err := VerifyChainDepth(1, []uint8{2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChainDepth(2, []uint8{2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChainDepth(3, []uint8{2, 3}); err == nil {
		t.Fatal("3 > min(2,3) should fail")
	}
}

// Design issue 7: the attestation is bound to the attesting kid.
func TestAttestationBoundToKid(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	caps := []types.Capability{"read:data"}
	att, _ := CreateAttestation(priv, "kid-1", "maker.com", types.RoleMaker, "a", "deployer.com", "da", caps)
	att.Kid = "kid-2"
	if err := VerifyAttestation(att, pub, "deployer.com", "da", caps); err == nil {
		t.Fatal("re-labelled kid must fail")
	}
}

// Design issue 7: expired attestations are rejected and exp is signed.
func TestAttestationExpiry(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	caps := []types.Capability{"read:data"}
	now := time.Now().Unix()
	future := now + 3600
	past := now - 10
	fresh, _ := CreateAttestationWithExpiry(priv, "k", "maker.com", types.RoleMaker, "a", "deployer.com", "da", caps, &future)
	if err := VerifyAttestation(fresh, pub, "deployer.com", "da", caps); err != nil {
		t.Fatalf("fresh attestation should verify: %v", err)
	}
	expired, _ := CreateAttestationWithExpiry(priv, "k", "maker.com", types.RoleMaker, "a", "deployer.com", "da", caps, &past)
	if err := VerifyAttestation(expired, pub, "deployer.com", "da", caps); err == nil {
		t.Fatal("expired attestation must fail")
	}
	stripped := *fresh
	stripped.Exp = nil
	if err := VerifyAttestation(&stripped, pub, "deployer.com", "da", caps); err == nil {
		t.Fatal("stripping exp must break the signature")
	}
}

// AP-1: a legacy '|'-joined attestation signature does not verify.
func TestLegacyAttestationFormatRejected(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	caps := []types.Capability{"read:data"}
	legacy := "maker.com|maker|a|deployer.com|da|" + types.CapabilitiesHash(caps)
	sig, _ := crypto.SignBytes(priv, []byte(legacy))
	att := &types.DelegationAttestation{Domain: "maker.com", Role: types.RoleMaker, AgentID: "a", Kid: "k", Attestation: sig}
	if err := VerifyAttestation(att, pub, "deployer.com", "da", caps); err == nil {
		t.Fatal("legacy format must be rejected")
	}
}

func TestVerifyChainDepthEmptyDepthsIsZero(t *testing.T) {
	if err := VerifyChainDepth(1, nil); err == nil {
		t.Fatal("empty depth list must mean depth 0")
	}
}
