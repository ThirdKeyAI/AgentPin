package wba

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
)

// Shared Web Bot Auth vectors (testdata/web_bot_auth/vectors.json at the
// repository root), also run by the Rust, JavaScript and Python suites.

const vectorsDir = "../../../testdata/web_bot_auth"

type vectorKey struct {
	PrivatePEM string          `json:"private_pem"`
	KeyID      string          `json:"keyid"`
	JWK        json.RawMessage `json:"jwk"`
}

type vectorRequest struct {
	Name              string      `json:"name"`
	Key               string      `json:"key"`
	Method            string      `json:"method"`
	URL               string      `json:"url"`
	SignatureAgentURL string      `json:"signature_agent_url"`
	Headers           [][2]string `json:"headers"`
	Reproducible      bool        `json:"reproducible"`
}

type wbaVectors struct {
	Keys      map[string]vectorKey `json:"keys"`
	Requests  []vectorRequest      `json:"requests"`
	Directory struct {
		Authority string      `json:"authority"`
		Body      string      `json:"body"`
		Headers   [][2]string `json:"headers"`
	} `json:"directory"`
	RFC9421B26 struct {
		Method         string      `json:"method"`
		URL            string      `json:"url"`
		Headers        [][2]string `json:"headers"`
		SignatureInput string      `json:"signature_input"`
		Signature      string      `json:"signature"`
	} `json:"rfc9421_b26"`
	QueryParam struct {
		URL    string      `json:"url"`
		Values [][3]string `json:"values"`
		Errors []string    `json:"errors"`
	} `json:"query_param"`
	ContentDigest struct {
		Body  string `json:"body"`
		Value string `json:"value"`
	} `json:"content_digest"`
}

func loadVectors(t *testing.T) wbaVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v wbaVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vectorKeyOf(t *testing.T, v wbaVectors, name string) PrivateKey {
	t.Helper()
	k, err := LoadSigningKey(v.Keys[name].PrivatePEM)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return k
}

func vectorRequestOf(t *testing.T, r vectorRequest, withSig bool) *httpsig.Request {
	t.Helper()
	req, err := httpsig.NewRequest(r.Method, r.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range r.Headers {
		if withSig || (!strings.HasPrefix(h[0], "Signature-I") && h[0] != "Signature") {
			req.Header(h[0], h[1])
		}
	}
	return req
}

func TestVectorKeyIDsMatchPEMAndJWK(t *testing.T) {
	v := loadVectors(t)
	for _, name := range []string{"ed25519", "rsa"} {
		k := v.Keys[name]
		if got := Thumbprint(vectorKeyOf(t, v, name).PublicKey()); got != k.KeyID {
			t.Errorf("%s: PEM keyid %s, want %s", name, got, k.KeyID)
		}
		j, err := parseJWK(k.JWK)
		if err != nil {
			t.Fatal(err)
		}
		if got := j.Thumbprint(); got != k.KeyID {
			t.Errorf("%s: JWK keyid %s, want %s", name, got, k.KeyID)
		}
	}
	if alg := vectorKeyOf(t, v, "rsa").Alg(); alg != httpsig.AlgRSAPSSSHA512 {
		t.Fatalf("rsa alg %s", alg)
	}
}

func TestVectorRequestsVerifyAndReproduce(t *testing.T) {
	v := loadVectors(t)
	opts := DefaultVerifyOptions()
	opts.Now = 1735689700
	opts.MaxValiditySecs = math.MaxInt64
	for _, r := range v.Requests {
		k := vectorKeyOf(t, v, r.Key)
		store := NewDirectoryKeyStore()
		if err := store.Insert(r.SignatureAgentURL, DirectoryFromKeys(k.PublicKey())); err != nil {
			t.Fatal(err)
		}
		req := vectorRequestOf(t, r, true)
		if o := VerifyRequest(req, store, opts); o.Kind != Verified {
			t.Fatalf("%s: %v", r.Name, o)
		}

		// Re-sign over the same base: Ed25519 reproduces the signature;
		// RSA-PSS is randomized, so check that ours verifies.
		parsed, err := httpsig.ParseSignatures(req.Headers)
		if err != nil {
			t.Fatal(err)
		}
		p := parsed[0].Params
		params := []httpsig.Param{
			httpsig.Created(*p.Created), httpsig.KeyID(*p.KeyID), httpsig.Alg(*p.Alg),
			httpsig.Expires(*p.Expires), httpsig.Nonce(*p.Nonce), httpsig.Tag(*p.Tag),
		}
		unsigned := vectorRequestOf(t, r, false)
		f, err := httpsig.Sign(httpsig.RequestMessage(unsigned), parsed[0].Label, parsed[0].Components, params, k)
		if err != nil {
			t.Fatal(err)
		}
		if f.SignatureInput != r.Headers[1][1] {
			t.Errorf("%s: Signature-Input\n got %s\nwant %s", r.Name, f.SignatureInput, r.Headers[1][1])
		}
		if r.Reproducible && f.Signature != r.Headers[2][1] {
			t.Errorf("%s: Signature\n got %s\nwant %s", r.Name, f.Signature, r.Headers[2][1])
		}
		ours := unsigned.Clone().Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
		if o := VerifyRequest(ours, store, opts); o.Kind != Verified {
			t.Fatalf("%s re-signed: %v", r.Name, o)
		}
	}
}

func TestVectorDirectory(t *testing.T) {
	v := loadVectors(t)
	d := v.Directory
	var headers []httpsig.Header
	for _, h := range d.Headers {
		headers = append(headers, httpsig.Header{Name: h[0], Value: h[1]})
	}
	proven, err := VerifyDirectoryResponse([]byte(d.Body), headers, d.Authority, 1735689700, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(proven.Keys) != 1 {
		t.Fatalf("proven %d keys", len(proven.Keys))
	}
	// Our serializer produces the vector body byte for byte.
	body, _ := DirectoryFromKeys(vectorKeyOf(t, v, "ed25519").PublicKey()).JSON()
	if string(body) != d.Body {
		t.Fatalf("directory body\n got %s\nwant %s", body, d.Body)
	}
}

func TestVectorRFC9421QueryParamAndDigest(t *testing.T) {
	v := loadVectors(t)
	ed := vectorKeyOf(t, v, "ed25519")
	b := v.RFC9421B26
	req, err := httpsig.NewRequest(b.Method, b.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range b.Headers {
		req.Header(h[0], h[1])
	}
	signed := req.Clone().Header("Signature-Input", b.SignatureInput).Header("Signature", b.Signature)
	parsed, err := httpsig.ParseSignatures(signed.Headers)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.Verify(httpsig.RequestMessage(signed), parsed[0], ed.PublicKey()); err != nil {
		t.Fatal(err)
	}

	q := v.QueryParam
	qreq, err := httpsig.NewRequest("GET", q.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range q.Values {
		comp := httpsig.QueryParam(c[0])
		if comp.QueryName != c[1] {
			t.Errorf("name %q encoded %q, want %q", c[0], comp.QueryName, c[1])
		}
		f, err := httpsig.Sign(httpsig.RequestMessage(qreq), "q", []httpsig.Component{comp}, nil, ed)
		if err != nil {
			t.Fatal(err)
		}
		s := qreq.Clone().Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
		ps, err := httpsig.ParseSignatures(s.Headers)
		if err != nil {
			t.Fatal(err)
		}
		base, err := ps[0].SignatureBase(httpsig.RequestMessage(s))
		if err != nil {
			t.Fatal(err)
		}
		line := `"@query-param";name="` + c[1] + `": ` + c[2] + "\n"
		if !strings.HasPrefix(base, line) {
			t.Errorf("base %q does not start with %q", base, line)
		}
	}
	for _, name := range q.Errors {
		if _, err := httpsig.Sign(httpsig.RequestMessage(qreq), "q", []httpsig.Component{httpsig.QueryParam(name)}, nil, ed); err == nil {
			t.Errorf("query param %q should fail", name)
		}
	}

	if got := httpsig.ContentDigest([]byte(v.ContentDigest.Body)); got != v.ContentDigest.Value {
		t.Fatalf("content digest %s", got)
	}
}

func TestVectorRSASigningRoundTripAndAlg(t *testing.T) {
	v := loadVectors(t)
	k := vectorKeyOf(t, v, "rsa")
	agent := "https://agent.test/.well-known/http-message-signatures-directory"
	req, _ := httpsig.NewRequest("GET", "https://origin.test/x")
	h, err := SignRequest(req, k, agent, DefaultSignOptions())
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	store := NewDirectoryKeyStore()
	if err := store.Insert(agent, DirectoryFromKeys(k.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if o := VerifyRequest(req, store, DefaultVerifyOptions()); o.Kind != Verified {
		t.Fatal(o)
	}
	// A mismatched alg parameter fails even with the right key.
	bad := req.Clone()
	for i := range bad.Headers {
		bad.Headers[i].Value = strings.ReplaceAll(bad.Headers[i].Value, "rsa-pss-sha512", "ed25519")
	}
	if o := VerifyRequest(bad, store, DefaultVerifyOptions()); o.Kind != Invalid {
		t.Fatal(o)
	}
}
