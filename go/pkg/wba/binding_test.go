package wba

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"github.com/ThirdKeyAi/agentpin/go/pkg/verification"
)

// End-to-end binding: an agent signs a request with its Ed25519 key and
// carries a cnf-bound AgentPin credential; the origin verifies the
// signature, the credential and the binding between them.

const bindingAgentID = "urn:agentpin:example.com:crawler"

type bindingSetup struct {
	es256     *ecdsa.PrivateKey
	kid       string
	discovery types.DiscoveryDocument
}

func newBindingSetup(t *testing.T, wba *types.WebBotAuth) *bindingSetup {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kid, err := crypto.GenerateKeyID(kp.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PEMToJWK(kp.PublicKeyPEM, kid)
	if err != nil {
		t.Fatal(err)
	}
	disc := discovery.BuildDiscoveryDocument("example.com", types.EntityMaker, []types.JWK{pub},
		[]types.AgentDeclaration{{
			AgentID: bindingAgentID, Name: "Crawler",
			Capabilities: []types.Capability{"read:*"}, Status: types.AgentActive,
		}}, 0, "2026-11-01T00:00:00Z")
	disc.RevocationEndpoint = ""
	disc.WebBotAuth = wba
	if err := discovery.ValidateDiscoveryDocument(&disc, "example.com"); err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &bindingSetup{es256: priv, kid: kid, discovery: disc}
}

func (s *bindingSetup) resolver() resolver.DiscoveryResolver {
	return resolver.NewTrustBundleResolver(&types.TrustBundle{
		AgentpinBundleVersion: "0.1",
		CreatedAt:             "2026-11-01T00:00:00Z",
		Documents:             []types.DiscoveryDocument{s.discovery},
		Revocations:           []types.RevocationDocument{revocation.BuildRevocationDocument("example.com")},
	})
}

func (s *bindingSetup) credential(t *testing.T, jkt string) string {
	t.Helper()
	caps := []types.Capability{"read:pages"}
	var jwt string
	var err error
	if jkt != "" {
		jwt, err = credential.IssueBoundCredential(s.es256, s.kid, "example.com", bindingAgentID, "", caps, nil, nil, 600, jkt)
	} else {
		jwt, err = credential.IssueCredential(s.es256, s.kid, "example.com", bindingAgentID, "", caps, nil, nil, 600)
	}
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

func boundRequest(t *testing.T, key PrivateKey, signatureAgent, jwt string, coverAuth bool) *httpsig.Request {
	t.Helper()
	req := newReq(t, "GET", "https://shop.example/products").Header("Authorization", FormatAuthorizationHeader(jwt))
	opts := DefaultSignOptions()
	if coverAuth {
		opts.Components = append(opts.Components, httpsig.NewComponent("authorization"))
	}
	h, err := SignRequest(req, key, signatureAgent, opts)
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	return req
}

func keysFor(t *testing.T, url string, key PrivateKey) *DirectoryKeyStore {
	t.Helper()
	s := NewDirectoryKeyStore()
	if err := s.Insert(url, DirectoryFromKeys(key.PublicKey())); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *bindingSetup) verify(req *httpsig.Request, keys KeyLookup) (*BoundAgent, error) {
	return VerifyBoundRequest(req, keys, s.resolver(), pinning.NewKeyPinStore(), "",
		DefaultVerifyOptions(), verification.DefaultVerifierConfig())
}

func failureKind(t *testing.T, err error) FailureKind {
	t.Helper()
	var f *BindingFailure
	if !errors.As(err, &f) {
		t.Fatalf("not a BindingFailure: %v", err)
	}
	return f.Kind
}

func TestBoundRequestVerifiesWithWellKnownDirectory(t *testing.T) {
	s := newBindingSetup(t, nil)
	key := gen(t)
	url := WellKnownDirectory("example.com")
	req := boundRequest(t, key, url, s.credential(t, Thumbprint(key.PublicKey())), true)
	bound, err := s.verify(req, keysFor(t, url, key))
	if err != nil {
		t.Fatal(err)
	}
	if bound.Agent.SignatureAgent != url || bound.Credential.AgentID != bindingAgentID {
		t.Fatalf("%+v", bound)
	}
}

func TestDiscoveryCanVouchForAHostedDirectory(t *testing.T) {
	hosted := "https://bots.provider.example/keys/example-com"
	s := newBindingSetup(t, &types.WebBotAuth{SignatureAgents: []string{hosted}})
	key := gen(t)
	jwt := s.credential(t, Thumbprint(key.PublicKey()))
	if _, err := s.verify(boundRequest(t, key, hosted, jwt, true), keysFor(t, hosted, key)); err != nil {
		t.Fatal(err)
	}
	// Listing a hosted directory replaces the well-known default.
	wk := WellKnownDirectory("example.com")
	_, err := s.verify(boundRequest(t, key, wk, jwt, true), keysFor(t, wk, key))
	if failureKind(t, err) != FailureBinding {
		t.Fatal(err)
	}
}

func TestBindingFailures(t *testing.T) {
	s := newBindingSetup(t, nil)
	key := gen(t)
	url := WellKnownDirectory("example.com")
	store := keysFor(t, url, key)
	tp := Thumbprint(key.PublicKey())
	check := func(name string, req *httpsig.Request, keys KeyLookup, want FailureKind) {
		t.Helper()
		_, err := s.verify(req, keys)
		if err == nil || failureKind(t, err) != want {
			t.Errorf("%s: got %v", name, err)
		}
	}

	check("no cnf", boundRequest(t, key, url, s.credential(t, ""), true), store, FailureBinding)
	check("cnf names another key", boundRequest(t, key, url, s.credential(t, Thumbprint(gen(t).PublicKey())), true), store, FailureBinding)
	// The credential could have been lifted from another request.
	check("authorization not covered", boundRequest(t, key, url, s.credential(t, tp), false), store, FailureBinding)
	foreign := "https://attacker.example/.well-known/http-message-signatures-directory"
	check("foreign directory", boundRequest(t, key, foreign, s.credential(t, tp), true), keysFor(t, foreign, key), FailureBinding)

	// Credential swapped after signing: the covered Authorization changed.
	req := boundRequest(t, key, url, s.credential(t, tp), true)
	for i := range req.Headers {
		if req.Headers[i].Name == "Authorization" {
			req.Headers[i].Value = FormatAuthorizationHeader(s.credential(t, tp))
		}
	}
	_, err := s.verify(req, store)
	var f *BindingFailure
	if !errors.As(err, &f) || f.Kind != FailureWBA || f.Outcome.Kind != Invalid {
		t.Errorf("swapped credential: %v", err)
	}

	// Forged credential: signed by a key the issuer does not publish.
	rogue := newBindingSetup(t, nil)
	check("forged credential", boundRequest(t, key, url, rogue.credential(t, tp), true), store, FailureCredential)
}

func TestInvalidDiscoveryWebBotAuthRejected(t *testing.T) {
	s := newBindingSetup(t, nil)
	for _, agents := range [][]string{{}, {"http://insecure.example/dir"}, make([]string, 17)} {
		for i := range agents {
			if agents[i] == "" {
				agents[i] = "https://ok.example/dir"
			}
		}
		s.discovery.WebBotAuth = &types.WebBotAuth{SignatureAgents: agents}
		if discovery.ValidateDiscoveryDocument(&s.discovery, "example.com") == nil {
			t.Errorf("%v accepted", agents)
		}
	}
}

func TestMalformedCnfRejectedAtIssuance(t *testing.T) {
	s := newBindingSetup(t, nil)
	for _, jkt := range []string{"not-a-thumbprint", rfcKeyID[:42] + "+"} {
		if _, err := credential.IssueBoundCredential(s.es256, s.kid, "example.com", bindingAgentID, "",
			[]types.Capability{"read:pages"}, nil, nil, 600, jkt); err == nil {
			t.Errorf("%q accepted", jkt)
		}
	}
}

func TestRequestCredential(t *testing.T) {
	if _, err := RequestCredential(newReq(t, "GET", "https://e.test/")); err == nil {
		t.Fatal("missing Authorization accepted")
	}
	for _, v := range []string{"Bearer x", "AgentPin "} {
		if _, err := RequestCredential(newReq(t, "GET", "https://e.test/").Header("Authorization", v)); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
	got, err := RequestCredential(newReq(t, "GET", "https://e.test/").Header("Authorization", "AgentPin a.b.c"))
	if err != nil || got != "a.b.c" {
		t.Fatal(got, err)
	}
}
