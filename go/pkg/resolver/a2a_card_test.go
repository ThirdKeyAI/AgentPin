package resolver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func signedCardForDomain(t *testing.T, domain string) types.A2aAgentCard {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	decl := &types.AgentDeclaration{
		AgentID:      "urn:agentpin:" + domain + ":test",
		Name:         "Test Agent",
		Description:  "desc",
		Version:      "1.0.0",
		Capabilities: []types.Capability{"read:*"},
		Status:       types.AgentActive,
	}
	card, err := a2a.BuildAndSignAgentCard(
		"https://"+domain+"/agent",
		decl,
		kp.PrivateKeyPEM, "kid-1",
		"https://"+domain+"/.well-known/agent-identity.json",
		a2a.BuildOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func serveCard(card types.A2aAgentCard, status int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(card)
		}
	}))
}

// resolverFor builds an A2aAgentCardResolver whose HTTP client trusts the
// given test server's TLS cert and rewrites all requests to point at it.
func resolverFor(server *httptest.Server) *A2aAgentCardResolver {
	client := server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	originalDial := transport.DialContext
	_ = originalDial
	client.Transport = &rewriteTransport{base: transport, target: server.URL}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &A2aAgentCardResolver{Client: client, SkipDiscoveryBinding: true}
}

// resolverForBound is resolverFor with discovery binding enabled.
func resolverForBound(server *httptest.Server) *A2aAgentCardResolver {
	r := resolverFor(server)
	r.SkipDiscoveryBinding = false
	return r
}

// serveCardAndDiscovery serves the card at /.well-known/agent-card.json and
// the discovery document at /.well-known/agent-identity.json.
func serveCardAndDiscovery(card types.A2aAgentCard, doc *types.DiscoveryDocument) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case A2aAgentCardPath:
			_ = json.NewEncoder(w).Encode(card)
		case "/.well-known/agent-identity.json":
			if doc == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(doc)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func signedCardWithKey(t *testing.T, domain string) (types.A2aAgentCard, *crypto.KeyPair) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	decl := &types.AgentDeclaration{AgentID: "urn:agentpin:" + domain + ":test", Name: "Test Agent",
		Capabilities: []types.Capability{"read:*"}, Status: types.AgentActive}
	card, err := a2a.BuildAndSignAgentCard("https://"+domain+"/agent", decl, kp.PrivateKeyPEM, "kid-1",
		"https://"+domain+"/.well-known/agent-identity.json", a2a.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return card, kp
}

// AP-4 / spec §4.10.4 step 5: with binding enabled the card key must be
// published in the domain's discovery document.
func TestA2aResolverDiscoveryBinding(t *testing.T) {
	card, kp := signedCardWithKey(t, "example.com")
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	published := discovery.BuildDiscoveryDocument("example.com", types.EntityBoth,
		[]types.JWK{jwk.VerifyingKeyToJWK(pub, "kid-1")}, nil, 0, "2026-01-15T00:00:00Z")
	srv := serveCardAndDiscovery(card, &published)
	defer srv.Close()
	if _, err := resolverForBound(srv).ResolveDiscovery("example.com"); err != nil {
		t.Fatalf("published key should bind: %v", err)
	}

	otherKP, _ := crypto.GenerateKeyPair()
	otherPub, _ := crypto.LoadPublicKey(otherKP.PublicKeyPEM)
	unrelated := discovery.BuildDiscoveryDocument("example.com", types.EntityBoth,
		[]types.JWK{jwk.VerifyingKeyToJWK(otherPub, "other")}, nil, 0, "2026-01-15T00:00:00Z")
	srv2 := serveCardAndDiscovery(card, &unrelated)
	defer srv2.Close()
	if _, err := resolverForBound(srv2).ResolveDiscovery("example.com"); err == nil {
		t.Fatal("card key not in discovery document must be rejected")
	}

	srv3 := serveCardAndDiscovery(card, nil)
	defer srv3.Close()
	if _, err := resolverForBound(srv3).ResolveDiscovery("example.com"); err == nil {
		t.Fatal("missing discovery document must be rejected when binding is required")
	}
}

// rewriteTransport rewrites the host of every request to the test server's
// host so resolving "https://example.com/..." actually hits the local TLS
// server.
type rewriteTransport struct {
	base   http.RoundTripper
	target string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace scheme+host with the test server's; preserve the original path.
	clone := req.Clone(req.Context())
	// httptest server URL contains scheme + host; reuse via url.Parse.
	parsed, err := req.URL.Parse(t.target + req.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	clone.URL = parsed
	clone.Host = parsed.Host
	return t.base.RoundTrip(clone)
}

func TestA2aResolverResolvesAndVerifies(t *testing.T) {
	card := signedCardForDomain(t, "example.com")
	server := serveCard(card, http.StatusOK)
	defer server.Close()
	resolver := resolverFor(server)
	doc, err := resolver.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Entity != "example.com" {
		t.Fatalf("entity %q", doc.Entity)
	}
	if got := resolver.LastCard("example.com"); got == nil || got.Name != "Test Agent" {
		t.Fatalf("last card unexpected: %+v", got)
	}
}

func TestA2aResolverRejectsHttpError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	resolver := resolverFor(server)
	if _, err := resolver.ResolveDiscovery("example.com"); err == nil {
		t.Fatal("expected HTTP 404 error")
	}
}

func TestA2aResolverRejectsTamperedCard(t *testing.T) {
	card := signedCardForDomain(t, "example.com")
	card.URL = "https://attacker.example/agent"
	server := serveCard(card, http.StatusOK)
	defer server.Close()
	resolver := resolverFor(server)
	if _, err := resolver.ResolveDiscovery("example.com"); err == nil {
		t.Fatal("expected tamper rejection")
	}
}

func TestA2aResolverRejectsEndpointHostMismatch(t *testing.T) {
	card := signedCardForDomain(t, "other.com")
	server := serveCard(card, http.StatusOK)
	defer server.Close()
	resolver := resolverFor(server)
	if _, err := resolver.ResolveDiscovery("example.com"); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestA2aResolverRevocationReturnsNil(t *testing.T) {
	card := signedCardForDomain(t, "example.com")
	server := serveCard(card, http.StatusOK)
	defer server.Close()
	resolver := resolverFor(server)
	doc, err := resolver.ResolveDiscovery("example.com")
	if err != nil {
		t.Fatal(err)
	}
	rev, err := resolver.ResolveRevocation("example.com", doc)
	if err != nil || rev != nil {
		t.Fatalf("expected nil rev, got rev=%v err=%v", rev, err)
	}
}
