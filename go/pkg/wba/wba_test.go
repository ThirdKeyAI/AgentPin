package wba

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
	"github.com/ThirdKeyAi/agentpin/go/pkg/nonce"
)

const (
	rfcEd25519PEM = "-----BEGIN PRIVATE KEY-----\n" +
		"MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n" +
		"-----END PRIVATE KEY-----\n"
	rfcKeyID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
	rfcX     = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
	agentURL = "https://signature-agent.test"
)

func rfcKey(t *testing.T) PrivateKey {
	t.Helper()
	k, err := LoadSigningKey(rfcEd25519PEM)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func gen(t *testing.T) PrivateKey {
	t.Helper()
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newReq(t *testing.T, method, url string) *httpsig.Request {
	t.Helper()
	r, err := httpsig.NewRequest(method, url)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signedRequest(t *testing.T, key PrivateKey, opts SignOptions) *httpsig.Request {
	t.Helper()
	req := newReq(t, "GET", "https://origin.example/path?q=1")
	h, err := SignRequest(req, key, agentURL, opts)
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	return req
}

func storeWith(t *testing.T, key PrivateKey) *DirectoryKeyStore {
	t.Helper()
	s := NewDirectoryKeyStore()
	if err := s.Insert(agentURL, DirectoryFromKeys(key.PublicKey())); err != nil {
		t.Fatal(err)
	}
	return s
}

func expect(t *testing.T, o Outcome, kind OutcomeKind) {
	t.Helper()
	if o.Kind != kind {
		t.Fatalf("got %v, want %v", o, kind)
	}
}

func TestThumbprintMatchesDraftVector(t *testing.T) {
	k := rfcKey(t).PublicKey()
	if Thumbprint(k) != rfcKeyID {
		t.Fatal(Thumbprint(k))
	}
	j := JWKFromPublicKey(k)
	if j.X != rfcX || j.Kid != rfcKeyID {
		t.Fatalf("%+v", j)
	}
	pk, err := j.PublicKey()
	if err != nil || !pk.Equal(k) {
		t.Fatal("JWK round trip")
	}
}

// Draft Appendix E.2.1: the signer reproduces the vector byte for byte and
// the verifier accepts it.
func TestDraftE21DictionarySignatureAgent(t *testing.T) {
	req := newReq(t, "GET", "https://example.com/").Header("Signature-Agent", `agent2="https://signature-agent.test"`)
	f, err := httpsig.Sign(httpsig.RequestMessage(req), "sig2",
		[]httpsig.Component{httpsig.NewComponent("@authority"), httpsig.Keyed("signature-agent", "agent2")},
		[]httpsig.Param{
			httpsig.Created(1735689600), httpsig.KeyID(rfcKeyID), httpsig.Alg("ed25519"), httpsig.Expires(4889289600),
			httpsig.Nonce("n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="),
			httpsig.Tag(Tag),
		}, rfcKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if f.Signature != "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:" {
		t.Fatal(f.Signature)
	}
	signed := req.Clone().Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
	store := storeWith(t, rfcKey(t))
	opts := DefaultVerifyOptions()
	opts.Now = 1735689700
	opts.MaxValiditySecs = math.MaxInt64
	o := VerifyRequest(signed, store, opts)
	expect(t, o, Verified)
	if o.Agent.SignatureAgent != "https://signature-agent.test/" || o.Agent.KeyID != rfcKeyID || o.Agent.Label != "sig2" {
		t.Fatalf("%+v", o.Agent)
	}
	// The default 24 h ceiling rejects the vector's long window.
	strict := DefaultVerifyOptions()
	strict.Now = 1735689700
	expect(t, VerifyRequest(signed, store, strict), Invalid)
}

// Draft Appendix E.2.2: legacy bare-String Signature-Agent.
func TestDraftE22LegacySignatureAgent(t *testing.T) {
	req := newReq(t, "GET", "https://example.com/").
		Header("Signature-Agent", `"https://signature-agent.test"`).
		Header("Signature-Input", `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`).
		Header("Signature", "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:")
	store := storeWith(t, rfcKey(t))
	opts := DefaultVerifyOptions()
	opts.Now = 1735689700
	expect(t, VerifyRequest(req, store, opts), Verified)
	opts.AcceptLegacySignatureAgent = false
	expect(t, VerifyRequest(req, store, opts), Invalid)
}

// Draft Appendix E.2.3: signed directory response, reproduced and
// verified.
func TestDraftE23DirectoryResponse(t *testing.T) {
	body := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + rfcKeyID + `","x":"` + rfcX + `","use":"sig"}]}`
	headers, err := SignDirectoryResponse([]byte(body), "signature-agent.test", []PrivateKey{rfcKey(t)}, 1735689600, MaxValiditySecs)
	if err != nil {
		t.Fatal(err)
	}
	const digest = "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"
	if headers[0].Value != digest {
		t.Fatal(headers[0].Value)
	}
	vector := []httpsig.Header{
		{Name: "Content-Digest", Value: digest},
		{Name: "Signature-Input", Value: `binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"`},
		{Name: "Signature", Value: "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:"},
	}
	count := func(h []httpsig.Header, authority string, now int64) int {
		t.Helper()
		d, err := VerifyDirectoryResponse([]byte(body), h, authority, now, 60)
		if err != nil {
			t.Fatal(err)
		}
		return len(d.Keys)
	}
	if count(vector, "signature-agent.test", 1735689700) != 1 {
		t.Fatal("vector not proven")
	}
	// Re-served under another authority: the proof does not carry over.
	if count(vector, "evil.test", 1735689700) != 0 {
		t.Fatal("proof carried over to another authority")
	}
	// Swapped body: digest mismatch.
	if _, err := VerifyDirectoryResponse([]byte(`{"keys":[]}`), vector, "signature-agent.test", 1735689700, 60); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	// Our own signing round-trips; future-dated proofs are rejected.
	if count(headers, "signature-agent.test", 1735689700) != 1 || count(headers, "signature-agent.test", 1735680000) != 0 {
		t.Fatal("own directory signature")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	key := gen(t)
	req := signedRequest(t, key, DefaultSignOptions())
	sigs, err := httpsig.ParseSignatures(req.Headers)
	if err != nil {
		t.Fatal(err)
	}
	if *sigs[0].Params.Tag != Tag || sigs[0].Params.Nonce == nil {
		t.Fatal("tag/nonce")
	}
	o := VerifyRequest(req, storeWith(t, key), DefaultVerifyOptions())
	expect(t, o, Verified)
	if !o.Agent.Covers(httpsig.NewComponent("@method")) || !o.Agent.Covers(httpsig.NewComponent("@path")) || o.Agent.Expires-o.Agent.Created != 300 {
		t.Fatalf("%+v", o.Agent)
	}
}

func TestOutcomesDistinguishInvalidAndUnverified(t *testing.T) {
	key := gen(t)
	req := signedRequest(t, key, DefaultSignOptions())
	opts := DefaultVerifyOptions()

	expect(t, VerifyRequest(req, NewDirectoryKeyStore(), opts), Unverified)                                    // unknown directory
	expect(t, VerifyRequest(req, storeWith(t, gen(t)), opts), Unverified)                                      // key not in directory
	expect(t, VerifyRequest(newReq(t, "GET", "https://origin.example/"), storeWith(t, key), opts), Unverified) // unsigned

	old := DefaultSignOptions()
	old.Created = time.Now().Unix() - 10000
	expect(t, VerifyRequest(signedRequest(t, key, old), storeWith(t, key), opts), Invalid) // expired

	moved := req.Clone()
	moved.URL = "https://origin.example/other"
	expect(t, VerifyRequest(moved, storeWith(t, key), opts), Invalid) // path changed
}

// Key lookup is per (URL, keyid): a key published by one directory does
// not verify a request that names another (§5.4).
func TestKeyIsBoundToItsDirectory(t *testing.T) {
	key := gen(t)
	req := newReq(t, "GET", "https://origin.example/")
	h, err := SignRequest(req, key, "https://victim.example/.well-known/http-message-signatures-directory", DefaultSignOptions())
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	expect(t, VerifyRequest(req, storeWith(t, key), DefaultVerifyOptions()), Unverified)
}

func TestRejectsSignatureAgentProblems(t *testing.T) {
	key := gen(t)
	store := storeWith(t, key)
	opts := DefaultVerifyOptions()

	// Member swapped after signing: lookup happens under the new URL, so
	// with no directory there it is unverified, with the same key there
	// it is invalid.
	req := signedRequest(t, key, DefaultSignOptions())
	for i := range req.Headers {
		if req.Headers[i].Name == "Signature-Agent" {
			req.Headers[i].Value = `sig1="https://other.test"`
		}
	}
	expect(t, VerifyRequest(req, store, opts), Unverified)
	both := storeWith(t, key)
	if err := both.Insert("https://other.test", DirectoryFromKeys(key.PublicKey())); err != nil {
		t.Fatal(err)
	}
	expect(t, VerifyRequest(req, both, opts), Invalid)

	// Two covered members: ambiguous attribution.
	two := newReq(t, "GET", "https://origin.example/").Header("Signature-Agent", `a="https://a.test", b="https://b.test"`)
	now := time.Now().Unix()
	f, err := httpsig.Sign(httpsig.RequestMessage(two), "a",
		[]httpsig.Component{httpsig.NewComponent("@authority"), httpsig.Keyed("signature-agent", "a"), httpsig.Keyed("signature-agent", "b")},
		[]httpsig.Param{httpsig.Created(now), httpsig.Expires(now + 60), httpsig.KeyID(Thumbprint(key.PublicKey())), httpsig.Tag(Tag)}, key)
	if err != nil {
		t.Fatal(err)
	}
	two.Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
	expect(t, VerifyRequest(two, store, opts), Invalid)

	plain := newReq(t, "GET", "https://origin.example/")
	if _, err := SignRequest(plain, key, "http://insecure.test", DefaultSignOptions()); err == nil {
		t.Fatal("non-https Signature-Agent accepted")
	}
	long := DefaultSignOptions()
	long.ValiditySecs = MaxValiditySecs + 1
	if _, err := SignRequest(plain, key, agentURL, long); err == nil {
		t.Fatal("validity above 24 h accepted")
	}
	dup := plain.Clone().Header("Signature-Agent", `sig1="https://a.test"`)
	if _, err := SignRequest(dup, key, agentURL, DefaultSignOptions()); err == nil {
		t.Fatal("label collision accepted")
	}
}

func TestMissingParamsAndCoverage(t *testing.T) {
	key := gen(t)
	store := storeWith(t, key)
	now := time.Now().Unix()
	tp := Thumbprint(key.PublicKey())
	base := []httpsig.Component{httpsig.NewComponent("@authority"), httpsig.Keyed("signature-agent", "s")}
	cases := []struct {
		components []httpsig.Component
		params     []httpsig.Param
	}{
		{base, []httpsig.Param{httpsig.Expires(now + 60), httpsig.KeyID(tp), httpsig.Tag(Tag)}},                                                   // no created
		{base, []httpsig.Param{httpsig.Created(now), httpsig.KeyID(tp), httpsig.Tag(Tag)}},                                                        // no expires
		{base, []httpsig.Param{httpsig.Created(now), httpsig.Expires(now + 60), httpsig.Tag(Tag)}},                                                // no keyid
		{base, []httpsig.Param{httpsig.Created(now + 600), httpsig.Expires(now + 700), httpsig.KeyID(tp), httpsig.Tag(Tag)}},                      // future
		{base, []httpsig.Param{httpsig.Created(now), httpsig.Expires(now), httpsig.KeyID(tp), httpsig.Tag(Tag)}},                                  // expires == created
		{base, []httpsig.Param{httpsig.Created(now), httpsig.Expires(now + 60), httpsig.KeyID(tp), httpsig.Alg("hmac-sha256"), httpsig.Tag(Tag)}}, // alg
		{base[1:], []httpsig.Param{httpsig.Created(now), httpsig.Expires(now + 60), httpsig.KeyID(tp), httpsig.Tag(Tag)}},                         // no @authority
		{base[:1], []httpsig.Param{httpsig.Created(now), httpsig.Expires(now + 60), httpsig.KeyID(tp), httpsig.Tag(Tag)}},                         // no member
	}
	for i, c := range cases {
		req := newReq(t, "GET", "https://origin.example/").Header("Signature-Agent", `s="`+agentURL+`"`)
		f, err := httpsig.Sign(httpsig.RequestMessage(req), "s", c.components, c.params, key)
		if err != nil {
			t.Fatal(err)
		}
		req.Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
		if o := VerifyRequest(req, store, DefaultVerifyOptions()); o.Kind != Invalid {
			t.Errorf("case %d: %v", i, o)
		}
	}

	// Required components.
	req := signedRequest(t, key, DefaultSignOptions())
	opts := DefaultVerifyOptions()
	opts.RequiredComponents = []httpsig.Component{httpsig.NewComponent("authorization")}
	expect(t, VerifyRequest(req, store, opts), Invalid)

	// A signature with another tag is not a WBA signature.
	other := newReq(t, "GET", "https://origin.example/")
	f, _ := httpsig.Sign(httpsig.RequestMessage(other), "x", []httpsig.Component{httpsig.NewComponent("@authority")},
		[]httpsig.Param{httpsig.Created(now), httpsig.Tag("other")}, key)
	other.Header("Signature-Input", f.SignatureInput).Header("Signature", f.Signature)
	expect(t, VerifyRequest(other, store, DefaultVerifyOptions()), Unverified)
}

func TestLegacySigningRoundTrip(t *testing.T) {
	key := gen(t)
	opts := DefaultSignOptions()
	opts.LegacySignatureAgent = true
	req := signedRequest(t, key, opts)
	if v, _ := httpsig.CombinedField(req.Headers, "signature-agent"); !strings.HasPrefix(v, `"`) {
		t.Fatal(v)
	}
	expect(t, VerifyRequest(req, storeWith(t, key), DefaultVerifyOptions()), Verified)
	strict := DefaultVerifyOptions()
	strict.AcceptLegacySignatureAgent = false
	expect(t, VerifyRequest(req, storeWith(t, key), strict), Invalid)
	existing := newReq(t, "GET", "https://origin.example/").Header("Signature-Agent", `a="https://a.test"`)
	if _, err := SignRequest(existing, key, agentURL, opts); err == nil {
		t.Fatal("legacy with existing Signature-Agent accepted")
	}
}

func TestMemberWithParametersIsRejected(t *testing.T) {
	h := []httpsig.Header{{Name: "Signature-Agent", Value: `sig1="https://a.test";type=jwks_uri`}}
	if _, err := signatureAgentMember(h, "sig1", false); err == nil {
		t.Fatal("member with parameters accepted")
	}
}

func TestNormalizesIdentifiers(t *testing.T) {
	got, err := NormalizeSignatureAgent("HTTPS://Agent.Example:443/dir?x=1#f")
	if err != nil || got != "https://agent.example/dir" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"http://agent.example", "https://u:p@agent.example", "/relative", "https://"} {
		if _, err := NormalizeSignatureAgent(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDirectoryParseSkipsForeignKeysAndHonorsValidity(t *testing.T) {
	key := gen(t)
	j := JWKFromPublicKey(key.PublicKey())
	nbf, exp := int64(100), int64(200)
	j.Nbf, j.Exp = &nbf, &exp
	jb, _ := json.Marshal(j)
	data := `{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"},{"kty":"OKP","crv":"Ed25519","x":"short"},{"KTY":"OKP"},` + string(jb) + `]}`
	dir, err := ParseDirectory([]byte(data))
	if err != nil || len(dir.Keys) != 1 {
		t.Fatalf("%v %v", dir, err)
	}
	tp := Thumbprint(key.PublicKey())
	if _, ok := FindKey(dir, tp, 150, 0); !ok {
		t.Fatal("key not found within validity")
	}
	if _, ok := FindKey(dir, tp, 50, 0); ok {
		t.Fatal("key found before nbf")
	}
	if _, ok := FindKey(dir, tp, 250, 0); ok {
		t.Fatal("key found after exp")
	}
	many := `{"keys":[` + strings.Repeat(`{},`, MaxDirectoryKeys) + `{}]}`
	if _, err := ParseDirectory([]byte(many)); err == nil {
		t.Fatal("too many keys accepted")
	}
	for _, bad := range []string{`[]`, `{}`, `{"keys":null}`, `{"keys":{}}`, `nope`} {
		if _, err := ParseDirectory([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRSAJWKRules(t *testing.T) {
	v := loadVectors(t)
	j, err := parseJWK(v.Keys["rsa"].JWK)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.PublicKey(); err != nil {
		t.Fatal(err)
	}
	nonMinimal := j
	nonMinimal.E = "AAEAAQ" // leading zero byte
	short := j
	short.N = b64url.EncodeToString(make([]byte, 128))
	for _, bad := range []JWK{nonMinimal, short} {
		if _, err := bad.PublicKey(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestPEMRoundTrip(t *testing.T) {
	key := gen(t)
	pem, err := SigningKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadSigningKey(pem)
	if err != nil || !k2.PublicKey().Equal(key.PublicKey()) {
		t.Fatal("PEM round trip")
	}
	if _, err := LoadSigningKey("not a key"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestNonceStoreRejectsReplays(t *testing.T) {
	key := gen(t)
	store := storeWith(t, key)
	opts := DefaultVerifyOptions()
	opts.NonceStore = nonce.NewInMemoryStore()
	req := signedRequest(t, key, DefaultSignOptions())
	expect(t, VerifyRequest(req, store, opts), Verified)
	if o := VerifyRequest(req, store, opts); o.Kind != Invalid || o.Reason != "nonce replayed" {
		t.Fatal(o)
	}
	// A fresh signature is fine; one without a nonce is not.
	expect(t, VerifyRequest(signedRequest(t, key, DefaultSignOptions()), store, opts), Verified)
	noNonce := DefaultSignOptions()
	noNonce.Nonce = false
	expect(t, VerifyRequest(signedRequest(t, key, noNonce), store, opts), Invalid)
	// Forged signatures never reach the store.
	forged := signedRequest(t, key, DefaultSignOptions())
	forged.URL = "https://origin.example/elsewhere"
	if o := VerifyRequest(forged, store, opts); o.Kind != Invalid || o.Reason != "signature verification failed" {
		t.Fatal(o)
	}
	forged.URL = "https://origin.example/path?q=1"
	expect(t, VerifyRequest(forged, store, opts), Verified)
}
