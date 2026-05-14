package verification

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

type fixture struct {
	jwt        string
	discovery  *types.DiscoveryDocument
	revocation *types.RevocationDocument
	pinStore   *pinning.KeyPinStore
	cfg        VerifierConfig
	priv       *ecdsa.PrivateKey
}

func setup(t *testing.T) fixture {
	t.Helper()
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	j := jwk.VerifyingKeyToJWK(pub, "test-2026-01")

	conf := types.DataConfidential
	intl := types.DataInternal
	disc := discovery.BuildDiscoveryDocument(
		"example.com",
		types.EntityMaker,
		[]types.JWK{j},
		[]types.AgentDeclaration{
			{
				AgentID:      "urn:agentpin:example.com:agent",
				Name:         "Test Agent",
				Capabilities: []types.Capability{"read:*", "write:report"},
				Constraints: &types.Constraints{
					DataClassificationMax: &conf,
					RateLimit:             "100/hour",
				},
				Status: types.AgentActive,
			},
		},
		2,
		"2026-01-15T00:00:00Z",
	)

	jwtStr, err := credential.IssueCredential(
		priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com",
		[]types.Capability{"read:data", "write:report"},
		&types.Constraints{
			DataClassificationMax: &intl,
			RateLimit:             "50/hour",
		},
		nil, 3600,
	)
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.BuildRevocationDocument("example.com")
	return fixture{
		jwt:        jwtStr,
		discovery:  &disc,
		revocation: &rev,
		pinStore:   pinning.NewKeyPinStore(),
		cfg:        DefaultVerifierConfig(),
		priv:       priv,
	}
}

func TestHappyPath(t *testing.T) {
	f := setup(t)
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if !r.Valid {
		t.Fatalf("expected valid: %+v", r)
	}
	if r.AgentID != "urn:agentpin:example.com:agent" {
		t.Fatalf("agent_id: %s", r.AgentID)
	}
	if r.Issuer != "example.com" {
		t.Fatalf("issuer: %s", r.Issuer)
	}
}

func TestExpiredCredential(t *testing.T) {
	f := setup(t)
	header := &types.JWTHeader{Alg: jwt.RequiredAlg, Typ: jwt.RequiredTyp, Kid: "test-2026-01"}
	payload := &types.JWTPayload{
		Iss: "example.com", Sub: "urn:agentpin:example.com:agent",
		Iat: 1000000, Exp: 1003600,
		Jti: "expired", AgentpinVersion: "0.1",
		Capabilities: []types.Capability{"read:data"},
	}
	expired, err := jwt.EncodeJWT(header, payload, f.priv)
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyCredentialOffline(expired, f.discovery, nil, pinning.NewKeyPinStore(), "", f.cfg)
	if r.Valid {
		t.Fatal("expired credential must fail")
	}
	if r.ErrorCode != types.ErrCredentialExpired {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestWrongAlgorithmRejected(t *testing.T) {
	f := setup(t)
	r := VerifyCredentialOffline("invalid.jwt.token", f.discovery, nil, pinning.NewKeyPinStore(), "", f.cfg)
	if r.Valid {
		t.Fatal("malformed jwt should fail")
	}
	if r.ErrorCode != types.ErrAlgorithmRejected {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestCredentialRevoked(t *testing.T) {
	f := setup(t)
	_, payload, _, _ := jwt.DecodeJWTUnverified(f.jwt)
	revocation.AddRevokedCredential(f.revocation, payload.Jti, types.ReasonKeyCompromise)
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if r.Valid {
		t.Fatal("revoked should fail")
	}
	if r.ErrorCode != types.ErrCredentialRevoked {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestAgentRevoked(t *testing.T) {
	f := setup(t)
	revocation.AddRevokedAgent(f.revocation, "urn:agentpin:example.com:agent", types.ReasonPrivilegeWithdrawn)
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if r.Valid {
		t.Fatal("revoked agent should fail")
	}
}

func TestInactiveAgent(t *testing.T) {
	f := setup(t)
	f.discovery.Agents[0].Status = types.AgentSuspended
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if r.Valid {
		t.Fatal("inactive agent should fail")
	}
	if r.ErrorCode != types.ErrAgentInactive {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestCapabilityExceeded(t *testing.T) {
	f := setup(t)
	f.discovery.Agents[0].Capabilities = []types.Capability{"read:limited"}
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if r.Valid {
		t.Fatal("excess caps should fail")
	}
	if r.ErrorCode != types.ErrCapabilityExceeded {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestAudienceMismatch(t *testing.T) {
	f := setup(t)
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "wrong.com", f.cfg)
	if r.Valid {
		t.Fatal("aud mismatch should fail")
	}
	if r.ErrorCode != types.ErrAudienceMismatch {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestKeyPinChangeRejected(t *testing.T) {
	f := setup(t)
	r1 := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if !r1.Valid {
		t.Fatalf("first verify failed: %+v", r1)
	}
	// Now rotate the key in discovery + reissue with a new key.
	kp2, _ := crypto.GenerateKeyPair()
	priv2, _ := crypto.LoadPrivateKey(kp2.PrivateKeyPEM)
	pub2, _ := crypto.LoadPublicKey(kp2.PublicKeyPEM)
	f.discovery.PublicKeys = []types.JWK{jwk.VerifyingKeyToJWK(pub2, "test-2026-01")}
	jwt2, _ := credential.IssueCredential(
		priv2, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com", []types.Capability{"read:data"}, nil, nil, 3600,
	)
	r2 := VerifyCredentialOffline(jwt2, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if r2.Valid {
		t.Fatal("key rotation must fail without explicit pinning trust")
	}
	if r2.ErrorCode != types.ErrKeyPinMismatch {
		t.Fatalf("ErrorCode: %s", r2.ErrorCode)
	}
}

func TestVerifyWithTrustBundleResolver(t *testing.T) {
	f := setup(t)
	b := types.TrustBundle{
		AgentpinBundleVersion: "0.1",
		CreatedAt:             time.Now().UTC().Format(time.RFC3339),
		Documents:             []types.DiscoveryDocument{*f.discovery},
		Revocations:           []types.RevocationDocument{*f.revocation},
	}
	r := resolver.NewTrustBundleResolver(&b)
	res := VerifyCredentialWithResolver(f.jwt, r, pinning.NewKeyPinStore(), "verifier.com", f.cfg)
	if !res.Valid {
		t.Fatalf("trust bundle verify: %+v", res)
	}
	if res.AgentID != "urn:agentpin:example.com:agent" {
		t.Fatal("agent id")
	}
}

func TestVerifyResolverMissingDomain(t *testing.T) {
	f := setup(t)
	b := types.TrustBundle{AgentpinBundleVersion: "0.1"}
	r := resolver.NewTrustBundleResolver(&b)
	res := VerifyCredentialWithResolver(f.jwt, r, pinning.NewKeyPinStore(), "verifier.com", f.cfg)
	if res.Valid {
		t.Fatal("missing domain should fail")
	}
	if res.ErrorCode != types.ErrDiscoveryFetchFailed {
		t.Fatalf("ErrorCode: %s", res.ErrorCode)
	}
}

func TestDomainMismatch(t *testing.T) {
	f := setup(t)
	f.discovery.Entity = "other.com"
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "", f.cfg)
	if r.Valid {
		t.Fatal("domain mismatch should fail")
	}
	if r.ErrorCode != types.ErrDiscoveryInvalid {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

func TestWildcardAudienceAccepted(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	j := jwk.VerifyingKeyToJWK(pub, "test-key")
	disc := discovery.BuildDiscoveryDocument(
		"example.com", types.EntityMaker,
		[]types.JWK{j},
		[]types.AgentDeclaration{
			{
				AgentID: "urn:agentpin:example.com:agent",
				Name:    "T", Capabilities: []types.Capability{"read:*"},
				Status: types.AgentActive,
			},
		},
		2, "2026-01-15T00:00:00Z",
	)
	cred, err := credential.IssueCredential(
		priv, "test-key", "example.com", "urn:agentpin:example.com:agent",
		"*", []types.Capability{"read:data"}, nil, nil, 3600,
	)
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyCredentialOffline(cred, &disc, nil, pinning.NewKeyPinStore(), "any.com", DefaultVerifierConfig())
	if !r.Valid {
		t.Fatalf("wildcard aud should pass: %+v", r)
	}
}
