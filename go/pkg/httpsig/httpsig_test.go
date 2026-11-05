package httpsig

import (
	"errors"
	"net/http/httptest"
	"testing"
)

// RFC 9421 Appendix B.1.4 test key (test-key-ed25519).
const rfcEd25519PEM = "-----BEGIN PRIVATE KEY-----\n" +
	"MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n" +
	"-----END PRIVATE KEY-----\n"

func rfcKey(t *testing.T) PrivateKey {
	t.Helper()
	k, err := LoadPrivateKeyPEM(rfcEd25519PEM)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustRequest(t *testing.T, method, url string) *Request {
	t.Helper()
	r, err := NewRequest(method, url)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signed(t *testing.T, req *Request, f SignatureFields) (*Request, *ParsedSignature) {
	t.Helper()
	s := req.Clone().Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
	ps, err := ParseSignatures(s.Headers)
	if err != nil {
		t.Fatal(err)
	}
	return s, ps[0]
}

// RFC 9421 Appendix B.2.6: Ed25519 over the RFC test request.
func TestRFC9421B26(t *testing.T) {
	req := mustRequest(t, "POST", "https://example.com/foo?param=Value&Pet=dog").
		Header("Host", "example.com").
		Header("Date", "Tue, 20 Apr 2021 02:07:55 GMT").
		Header("Content-Type", "application/json").
		Header("Content-Length", "18")
	components := []Component{
		NewComponent("date"), NewComponent("@method"), NewComponent("@path"),
		NewComponent("@authority"), NewComponent("content-type"), NewComponent("content-length"),
	}
	f, err := Sign(RequestMessage(req), "sig-b26", components, []Param{Created(1618884473), KeyID("test-key-ed25519")}, rfcKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if want := "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"; f.Signature != want {
		t.Fatalf("signature %s", f.Signature)
	}
	if want := `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`; f.SignatureInput != want {
		t.Fatalf("signature input %s", f.SignatureInput)
	}
	s, p := signed(t, req, f)
	if err := Verify(RequestMessage(s), p, rfcKey(t).PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestTamperedComponentFails(t *testing.T) {
	req := mustRequest(t, "GET", "https://example.com/a")
	f, err := Sign(RequestMessage(req), "s", []Component{NewComponent("@authority"), NewComponent("@path")}, []Param{Created(1)}, rfcKey(t))
	if err != nil {
		t.Fatal(err)
	}
	moved := mustRequest(t, "GET", "https://example.com/b")
	s, p := signed(t, moved, f)
	if err := Verify(RequestMessage(s), p, rfcKey(t).PublicKey()); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestDerivedComponents(t *testing.T) {
	m := RequestMessage(mustRequest(t, "GET", "https://Example.COM:8443/p/q?x=1"))
	for name, want := range map[string]string{
		"@authority": "example.com:8443", "@scheme": "https", "@path": "/p/q",
		"@query": "?x=1", "@request-target": "/p/q?x=1", "@target-uri": "https://example.com:8443/p/q?x=1",
	} {
		if got, err := componentValue(m, NewComponent(name)); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	plain := RequestMessage(mustRequest(t, "GET", "https://example.com:443"))
	for name, want := range map[string]string{
		"@authority": "example.com", "@path": "/", "@query": "?", "@target-uri": "https://example.com/",
	} {
		if got, err := componentValue(plain, NewComponent(name)); err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := componentValue(plain, NewComponent("@status")); err == nil {
		t.Fatal("@status on a request must fail")
	}
	dots := RequestMessage(mustRequest(t, "GET", "https://example.com/a/./b/../c d"))
	if got, _ := componentValue(dots, NewComponent("@path")); got != "/a/c%20d" {
		t.Fatalf("@path %q", got)
	}
}

func TestCombinedFieldsAndDictionaryMembers(t *testing.T) {
	m := RequestMessage(mustRequest(t, "GET", "https://example.com").
		Header("X-A", " one ").
		Header("x-a", "two").
		Header("Sig-Agent", `a="https://a.test", b="https://b.test"`))
	if got, _ := componentValue(m, NewComponent("x-a")); got != "one, two" {
		t.Fatalf("combined %q", got)
	}
	if got, _ := componentValue(m, Keyed("sig-agent", "b")); got != `"https://b.test"` {
		t.Fatalf("member %q", got)
	}
	if _, err := componentValue(m, Keyed("sig-agent", "c")); err == nil {
		t.Fatal("missing member must fail")
	}
	if _, err := componentValue(m, NewComponent("missing")); err == nil {
		t.Fatal("missing field must fail")
	}
}

func TestRejectsBadIdentifiers(t *testing.T) {
	for _, input := range []string{
		`s=("Date");created=1`,
		`s=("date";sf);created=1`,
		`s=("date";bs);created=1`,
		`s=("date";tr);created=1`,
		`s=("@signature-params");created=1`,
		`s=("date" "date");created=1`,
		`s=("@method";key="x");created=1`,
		`s=("@query-param");created=1`,
		`s=("@method";name="x");created=1`,
		`s=("date";req=?0);created=1`,
		`s=(date);created=1`,
		`s="date"`,
	} {
		h := []Header{{"Signature-Input", input}, {"Signature", "s=:AAAA:"}}
		if _, err := ParseSignatures(h); err == nil {
			t.Errorf("%s: accepted", input)
		}
	}
	if _, err := ParseSignatures([]Header{{"Signature-Input", `s=("date");created=1`}}); err == nil {
		t.Fatal("missing Signature must fail")
	}
	if _, err := ParseSignatures([]Header{{"Signature-Input", `s=("date");created=1`}, {"Signature", `s="x"`}}); err == nil {
		t.Fatal("non-Byte-Sequence Signature must fail")
	}
	if _, err := ParseSignatures([]Header{{"Signature-Input", `s=("date");created="1"`}, {"Signature", "s=:AAAA:"}}); err == nil {
		t.Fatal("String created must fail")
	}
	if _, err := Sign(RequestMessage(mustRequest(t, "GET", "https://e.test/")), "s",
		[]Component{NewComponent("@path"), NewComponent("@path")}, nil, rfcKey(t)); err == nil {
		t.Fatal("duplicate component must fail at signing")
	}
}

func TestContentDigestRoundTrip(t *testing.T) {
	body := []byte("{\"hello\": \"world\"}\n")
	if got := ContentDigest(body); got != "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:" {
		t.Fatalf("digest %s", got)
	}
	h := []Header{{"Content-Digest", ContentDigest(body)}}
	if !ContentDigestMatches(h, body) || ContentDigestMatches(h, []byte("other")) || ContentDigestMatches(nil, body) {
		t.Fatal("ContentDigestMatches")
	}
}

// RFC 9421 §2.2.8 examples.
func TestQueryParamValues(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&dup=1&dup=2&qux=")
	m := RequestMessage(req)
	for name, want := range map[string]string{
		"var": "this%20is%20a%20big%0Amultiline%20value", "bar": "with%20plus%20whitespace",
		"façade\": ": "something", "qux": "",
	} {
		if got, err := componentValue(m, QueryParam(name)); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"dup", "missing"} {
		if _, err := componentValue(m, QueryParam(name)); err == nil {
			t.Errorf("%q must fail", name)
		}
	}
	if id, _ := QueryParam("façade\": ").Identifier(); id != `"@query-param";name="fa%C3%A7ade%22%3A%20"` {
		t.Fatalf("identifier %s", id)
	}
	f, err := Sign(m, "s", []Component{QueryParam("var"), NewComponent("@authority")}, []Param{Created(1)}, rfcKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s, p := signed(t, req, f)
	if !p.Covers(QueryParam("var")) {
		t.Fatal("does not cover @query-param")
	}
	if err := Verify(RequestMessage(s), p, rfcKey(t).PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestAlgParameterMustMatchKey(t *testing.T) {
	req := mustRequest(t, "GET", "https://example.com/")
	f, err := Sign(RequestMessage(req), "s", []Component{NewComponent("@authority")}, []Param{Alg(AlgRSAPSSSHA512)}, rfcKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s, p := signed(t, req, f)
	if Verify(RequestMessage(s), p, rfcKey(t).PublicKey()) == nil {
		t.Fatal("alg mismatch accepted")
	}
}

func TestResponseComponents(t *testing.T) {
	req := mustRequest(t, "GET", "https://dir.test/x")
	resp := &Response{Status: 200, Headers: []Header{{"Content-Digest", ContentDigest(nil)}}}
	m := ResponseMessage(resp, req)
	if got, _ := componentValue(m, NewComponent("@status")); got != "200" {
		t.Fatalf("@status %q", got)
	}
	if got, _ := componentValue(m, OfRequest("@authority")); got != "dir.test" {
		t.Fatalf("@authority;req %q", got)
	}
	if _, err := componentValue(m, NewComponent("@authority")); err == nil {
		t.Fatal("@authority on a response must fail")
	}
	if _, err := componentValue(ResponseMessage(resp, nil), OfRequest("@authority")); err == nil {
		t.Fatal("req without a request must fail")
	}
}

func TestStrictEd25519(t *testing.T) {
	// The identity point is a small-order public key: any signature with
	// R = identity and S = 0 satisfies the cofactorless equation for it.
	identity := make([]byte, 32)
	identity[0] = 1
	sig := make([]byte, 64)
	copy(sig, identity)
	if err := Ed25519PublicKey(identity).Verify([]byte("anything"), sig); err == nil {
		t.Fatal("small-order key accepted")
	}
	if !smallOrder(identity) || smallOrder(rfcKey(t).PublicKey().Ed25519) {
		t.Fatal("smallOrder")
	}
	// y = 2 is not on the curve.
	bad := make([]byte, 32)
	bad[0] = 2
	if ValidEd25519Point(bad) {
		t.Fatal("off-curve point accepted")
	}
}

func TestLoadPrivateKeyPEM(t *testing.T) {
	k := rfcKey(t)
	pem, err := MarshalPrivateKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadPrivateKeyPEM(pem)
	if err != nil || !k2.PublicKey().Equal(k.PublicKey()) {
		t.Fatal("PEM round trip")
	}
	if _, err := LoadPrivateKeyPEM("not a key"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestRequestFromHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "/p?q=1", nil)
	r.Host = "Origin.Example"
	r.Header.Add("X-A", "1")
	req, err := RequestFromHTTP(r)
	if err != nil {
		t.Fatal(err)
	}
	m := RequestMessage(req)
	if got, _ := componentValue(m, NewComponent("@target-uri")); got != "http://origin.example/p?q=1" {
		t.Fatal(got)
	}
	if got, _ := componentValue(m, NewComponent("x-a")); got != "1" {
		t.Fatal(got)
	}
}
