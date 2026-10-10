package verification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// Cross-SDK conformance vectors shared with the Rust, JavaScript and Python
// suites (testdata/conformance/vectors.json at the repository root).

const conformanceDir = "../../../testdata/conformance"

type conformanceVectors struct {
	Credentials []struct {
		Name      string `json:"name"`
		JWT       string `json:"jwt"`
		ErrorCode string `json:"error_code"`
	} `json:"credentials"`
	CaseVariantIssuer struct {
		Issuer    string `json:"issuer"`
		ErrorCode string `json:"error_code"`
	} `json:"case_variant_issuer"`
	RevocationWrongFieldNames struct {
		Document  json.RawMessage `json:"document"`
		ErrorCode string          `json:"error_code"`
	} `json:"revocation_wrong_field_names"`
	InvalidRevocationEndpoints []string `json:"invalid_revocation_endpoints"`
	AgentCards                 []struct {
		Name  string          `json:"name"`
		Card  json.RawMessage `json:"card"`
		Valid bool            `json:"valid"`
	} `json:"agent_cards"`
	DomainSeparatedInput struct {
		Context     string   `json:"context"`
		FieldsHex   []string `json:"fields_hex"`
		ExpectedHex string   `json:"expected_hex"`
	} `json:"domain_separated_input"`
}

func loadConformance(t *testing.T) (conformanceVectors, *types.DiscoveryDocument) {
	t.Helper()
	var v conformanceVectors
	raw, err := os.ReadFile(filepath.Join(conformanceDir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	draw, err := os.ReadFile(filepath.Join(conformanceDir, "discovery.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d types.DiscoveryDocument
	if err := json.Unmarshal(draw, &d); err != nil {
		t.Fatal(err)
	}
	return v, &d
}

func TestConformance_MalformedCredentials(t *testing.T) {
	v, d := loadConformance(t)
	for _, c := range v.Credentials {
		r := VerifyCredentialOffline(c.JWT, d, nil, pinning.NewKeyPinStore(), "", DefaultVerifierConfig())
		if r.Valid || string(r.ErrorCode) != c.ErrorCode {
			t.Errorf("%s: got valid=%v code=%s, want %s", c.Name, r.Valid, r.ErrorCode, c.ErrorCode)
		}
	}
}

func TestConformance_CaseVariantIssuer(t *testing.T) {
	v, d := loadConformance(t)
	store := pinning.NewKeyPinStore()
	store.CheckAndPin("example.com", &d.PublicKeys[0])
	kp, _ := crypto.GenerateKeyPair()
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)
	evil := *d
	evil.Entity = v.CaseVariantIssuer.Issuer
	evil.PublicKeys = []types.JWK{jwk.VerifyingKeyToJWK(pub, "evil-key")}
	tok, err := credential.IssueCredential(priv, "evil-key", evil.Entity,
		"urn:agentpin:example.com:test-agent", "", []types.Capability{"read:data"}, nil, nil, 3600)
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyCredentialOffline(tok, &evil, nil, store, "", DefaultVerifierConfig())
	if r.Valid || string(r.ErrorCode) != v.CaseVariantIssuer.ErrorCode {
		t.Fatalf("got %+v", r)
	}
}

func TestConformance_RevocationWrongFieldNames(t *testing.T) {
	v, d := loadConformance(t)
	var rev types.RevocationDocument
	if err := json.Unmarshal(v.RevocationWrongFieldNames.Document, &rev); err != nil {
		return // rejected at parse time: fail closed
	}
	priv, err := crypto.LoadPrivateKey(string(mustRead(t, "example-2026-01.private.pem")))
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := credential.IssueCredential(priv, "example-2026-01", "example.com",
		"urn:agentpin:example.com:test-agent", "", []types.Capability{"read:data"}, nil, nil, 3600)
	r := VerifyCredentialOffline(tok, d, &rev, pinning.NewKeyPinStore(), "", DefaultVerifierConfig())
	if r.Valid || string(r.ErrorCode) != v.RevocationWrongFieldNames.ErrorCode {
		t.Fatalf("got %+v", r)
	}
}

func TestConformance_InvalidRevocationEndpoints(t *testing.T) {
	v, d := loadConformance(t)
	for _, u := range v.InvalidRevocationEndpoints {
		doc := *d
		doc.RevocationEndpoint = u
		if err := discovery.ValidateDiscoveryDocument(&doc, "example.com"); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestConformance_AgentCards(t *testing.T) {
	v, _ := loadConformance(t)
	for _, c := range v.AgentCards {
		var card types.A2aAgentCard
		if err := json.Unmarshal(c.Card, &card); err != nil {
			t.Fatal(err)
		}
		if got := a2a.VerifyAgentpinExtension(&card) == nil; got != c.Valid {
			t.Errorf("%s: valid=%v, want %v", c.Name, got, c.Valid)
		}
	}
}

func TestConformance_DomainSeparatedInput(t *testing.T) {
	v, _ := loadConformance(t)
	var fields [][]byte
	for _, h := range v.DomainSeparatedInput.FieldsHex {
		b, _ := hex.DecodeString(h)
		fields = append(fields, b)
	}
	want, _ := hex.DecodeString(v.DomainSeparatedInput.ExpectedHex)
	if got := crypto.DomainSeparatedInput(v.DomainSeparatedInput.Context, fields...); !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(conformanceDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
