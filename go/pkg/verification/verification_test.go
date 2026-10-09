package verification

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"strings"
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

// AP-3: a case variant of a pinned issuer must hit the existing pin, not
// create a fresh first-use entry under a different key.
func TestCaseVariantIssHitsExistingPin(t *testing.T) {
	f := setup(t)
	if r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg); !r.Valid {
		t.Fatalf("first verify: %+v", r)
	}
	kp2, _ := crypto.GenerateKeyPair()
	priv2, _ := crypto.LoadPrivateKey(kp2.PrivateKeyPEM)
	pub2, _ := crypto.LoadPublicKey(kp2.PublicKeyPEM)
	evil := *f.discovery
	evil.Entity = "EXAMPLE.COM"
	evil.PublicKeys = []types.JWK{jwk.VerifyingKeyToJWK(pub2, "evil-key")}
	evilJWT, _ := credential.IssueCredential(priv2, "evil-key", "EXAMPLE.COM",
		"urn:agentpin:example.com:agent", "verifier.com", []types.Capability{"read:data"}, nil, nil, 3600)
	r := VerifyCredentialOffline(evilJWT, &evil, nil, f.pinStore, "verifier.com", f.cfg)
	if r.Valid || r.ErrorCode != types.ErrKeyPinMismatch {
		t.Fatalf("case-variant iss must hit the pin: %+v", r)
	}
	if pd := f.pinStore.GetDomain("example.com"); pd == nil || len(pd.PinnedKeys) != 1 {
		t.Fatalf("expected exactly one pin set under the normalized name")
	}
}

// AP-3: issuer and entity are compared after normalization.
func TestIssuerEntityComparedNormalized(t *testing.T) {
	f := setup(t)
	f.discovery.Entity = "Example.COM."
	r := VerifyCredentialOffline(f.jwt, f.discovery, f.revocation, f.pinStore, "verifier.com", f.cfg)
	if !r.Valid || r.Issuer != "example.com" {
		t.Fatalf("normalized entity comparison failed: %+v", r)
	}
}

// AP-10 / AP-12: an iss that is not a bare hostname is rejected before it
// can reach a file path, URL or pin store.
func TestNonHostnameIssRejected(t *testing.T) {
	f := setup(t)
	for _, bad := range []string{"127.0.0.1:8443", "../../tmp/x", "/srv/uploads/x", "example.com/path", "user@example.com"} {
		jwtStr, _ := credential.IssueCredential(f.priv, "test-2026-01", bad,
			"urn:agentpin:example.com:agent", "", []types.Capability{"read:data"}, nil, nil, 3600)
		r := VerifyCredentialOffline(jwtStr, f.discovery, nil, pinning.NewKeyPinStore(), "", f.cfg)
		if r.Valid || r.ErrorCode != types.ErrDiscoveryInvalid {
			t.Fatalf("iss %q: %+v", bad, r)
		}
		r = VerifyCredentialWithResolver(jwtStr, resolver.NewLocalFileResolver("/", ""), pinning.NewKeyPinStore(), "", f.cfg)
		if r.ErrorCode != types.ErrDiscoveryInvalid {
			t.Fatalf("iss %q via resolver: %+v", bad, r)
		}
	}
}

// Design issue 3: foreign, tampered, unsigned-under-strict and stale
// revocation documents fail closed.
func TestRevocationDocumentValidation(t *testing.T) {
	f := setup(t)
	run := func(rev *types.RevocationDocument, cfg VerifierConfig) Result {
		return VerifyCredentialOffline(f.jwt, f.discovery, rev, pinning.NewKeyPinStore(), "verifier.com", cfg)
	}
	foreign := *f.revocation
	foreign.Entity = "other.com"
	if r := run(&foreign, f.cfg); r.ErrorCode != types.ErrDiscoveryInvalid {
		t.Fatalf("foreign entity: %+v", r)
	}
	strict := f.cfg
	strict.RequireSignedRevocation = true
	if r := run(f.revocation, strict); r.ErrorCode != types.ErrDiscoveryInvalid {
		t.Fatalf("unsigned under strict: %+v", r)
	}
	signed := *f.revocation
	if err := revocation.SignRevocationDocument(&signed, f.priv, "test-2026-01"); err != nil {
		t.Fatal(err)
	}
	if r := run(&signed, strict); !r.Valid {
		t.Fatalf("signed under strict: %+v", r)
	}
	tampered := signed
	tampered.UpdatedAt = "2030-01-01T00:00:00Z"
	if r := run(&tampered, f.cfg); r.ErrorCode != types.ErrDiscoveryInvalid {
		t.Fatalf("tampered: %+v", r)
	}
	aged := f.cfg
	aged.RevocationMaxAgeSecs = 60
	stale := *f.revocation
	stale.UpdatedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if r := run(&stale, aged); r.ErrorCode != types.ErrDiscoveryInvalid {
		t.Fatalf("stale: %+v", r)
	}
	if r := run(f.revocation, aged); !r.Valid {
		t.Fatalf("fresh under max age: %+v", r)
	}
}

func rawCredential(t *testing.T, priv *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	header := jwt.Base64URLEncode([]byte(`{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"test-2026-01"}`))
	signingInput := header + "." + jwt.Base64URLEncode([]byte(payload))
	sigB64, err := crypto.SignBytes(priv, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(sigB64)
	return signingInput + "." + jwt.Base64URLEncode(der)
}

// AP-5 / AP-14 / AP-18: correctly signed credentials with missing, string
// or negative exp/iat, or exp <= iat, fail with MALFORMED_CREDENTIAL; an
// int64-min iat cannot wrap past the max-TTL cap.
func TestMalformedClaimsRejected(t *testing.T) {
	f := setup(t)
	now := time.Now().Unix()
	base := `"iss":"example.com","sub":"urn:agentpin:example.com:agent","jti":"j","agentpin_version":"0.1","capabilities":["read:data"]`
	cases := []string{
		fmt.Sprintf(`{%s,"iat":%d}`, base, now),
		fmt.Sprintf(`{%s,"iat":%d,"exp":"never"}`, base, now),
		fmt.Sprintf(`{%s,"iat":-9223372036854775808,"exp":%d}`, base, now+315360000),
		fmt.Sprintf(`{%s,"iat":%d,"exp":%d}`, base, now, now),
	}
	for _, payload := range cases {
		r := VerifyCredentialOffline(rawCredential(t, f.priv, payload), f.discovery, nil, pinning.NewKeyPinStore(), "", f.cfg)
		if r.Valid || r.ErrorCode != types.ErrMalformedCredential {
			t.Fatalf("payload %s: %+v", payload, r)
		}
	}
}

// AP-14: the agent's declared credential_ttl_max is enforced (default 86400).
func TestCredentialTTLMaxEnforced(t *testing.T) {
	f := setup(t)
	short := uint64(600)
	f.discovery.Agents[0].CredentialTTLMax = &short
	long, _ := credential.IssueCredential(f.priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com", []types.Capability{"read:data"}, nil, nil, 3600)
	if r := VerifyCredentialOffline(long, f.discovery, nil, pinning.NewKeyPinStore(), "verifier.com", f.cfg); r.ErrorCode != types.ErrCredentialExpired || !strings.Contains(r.ErrorMessage, "credential_ttl_max") {
		t.Fatalf("expected ttl_max rejection: %+v", r)
	}
	ok, _ := credential.IssueCredential(f.priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com", []types.Capability{"read:data"}, nil, nil, 600)
	if r := VerifyCredentialOffline(ok, f.discovery, nil, pinning.NewKeyPinStore(), "verifier.com", f.cfg); !r.Valid {
		t.Fatalf("600s credential should pass: %+v", r)
	}
	f.discovery.Agents[0].CredentialTTLMax = nil
	twoDays, _ := credential.IssueCredential(f.priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com", []types.Capability{"read:data"}, nil, nil, 172800)
	lax := f.cfg
	lax.MaxTTLSecs = 10 * 86400
	if r := VerifyCredentialOffline(twoDays, f.discovery, nil, pinning.NewKeyPinStore(), "verifier.com", lax); r.ErrorCode != types.ErrCredentialExpired {
		t.Fatalf("default ttl_max 86400 should reject: %+v", r)
	}
}

// AP-8: a revocation document that uses the wrong field names (the schema
// the old docs published) must fail closed, not be silently ignored.
func TestRevocationDocumentWithWrongFieldNamesFailsClosed(t *testing.T) {
	f := setup(t)
	_, payload, _, _ := jwt.DecodeJWTUnverified(f.jwt)
	raw := fmt.Sprintf(`{
	  "agentpin_version": "0.1",
	  "entity": "example.com",
	  "revoked_credentials": [{"id": %q, "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z"}],
	  "revoked_agents": [],
	  "revoked_keys": [{"id": "test-2026-01", "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z"}],
	  "updated_at": "2026-02-15T00:00:00Z"
	}`, payload.Jti)
	var rev types.RevocationDocument
	if err := json.Unmarshal([]byte(raw), &rev); err != nil {
		t.Fatal(err)
	}
	r := VerifyCredentialOffline(f.jwt, f.discovery, &rev, pinning.NewKeyPinStore(), "verifier.com", f.cfg)
	if r.Valid {
		t.Fatal("malformed revocation document must not be ignored")
	}
	if r.ErrorCode != types.ErrDiscoveryInvalid {
		t.Fatalf("ErrorCode: %s", r.ErrorCode)
	}
}

// AP-15: a credential that omits constraints inherits the discovery
// declaration's constraints in the result; widening is rejected.
func TestOmittedConstraintsInheritDiscoveryDefaults(t *testing.T) {
	f := setup(t)
	f.discovery.Agents[0].Constraints = &types.Constraints{AllowedDomains: []string{"*.client-corp.com"}, RateLimit: "100/hour"}
	jwtStr, _ := credential.IssueCredential(f.priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com", []types.Capability{"read:data"}, nil, nil, 3600)
	r := VerifyCredentialOffline(jwtStr, f.discovery, nil, pinning.NewKeyPinStore(), "verifier.com", f.cfg)
	if !r.Valid || r.Constraints == nil || len(r.Constraints.AllowedDomains) != 1 || r.Constraints.RateLimit != "100/hour" {
		t.Fatalf("effective constraints missing: %+v", r)
	}
	wide, _ := credential.IssueCredential(f.priv, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
		"verifier.com", []types.Capability{"read:data"}, &types.Constraints{AllowedDomains: []string{"evil.com"}}, nil, 3600)
	if r := VerifyCredentialOffline(wide, f.discovery, nil, pinning.NewKeyPinStore(), "verifier.com", f.cfg); r.ErrorCode != types.ErrConstraintViolation {
		t.Fatalf("widening must be rejected: %+v", r)
	}
}
