// Package wba implements the Web Bot Auth (WBA) profile of RFC 9421 HTTP
// Message Signatures (draft-ietf-webbotauth-httpsig-protocol): agents sign
// requests with Ed25519 or RSASSA-PSS, name the HTTPS key directory that
// publishes the key in the Signature-Agent field, and verifiers resolve
// that directory and check the signature. The package also binds a WBA
// signature to an AgentPin identity (spec §18): the ES256 credential
// confirms the WBA key with cnf.jkt, and the issuer's discovery document
// vouches for the Signature-Agent URL.
//
// WBA uses its own keys. The ES256 credential profile is unchanged, and
// credential keys are never used to sign HTTP messages.
package wba

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/weburl"
	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
	"github.com/ThirdKeyAi/agentpin/go/pkg/nonce"
	"github.com/ThirdKeyAi/agentpin/go/pkg/sfv"
)

const (
	// Tag is the tag value of a Web Bot Auth request signature.
	Tag = "web-bot-auth"
	// DirectoryTag is the tag value of a directory response signature.
	DirectoryTag = "http-message-signatures-directory"
	// DirectoryPath is the well-known path of a key directory.
	DirectoryPath = "/.well-known/http-message-signatures-directory"
	// DirectoryMediaType is the media type a key directory is served with.
	DirectoryMediaType = "application/http-message-signatures-directory+json"
	// MaxDirectoryKeys is the most keys accepted from one directory.
	MaxDirectoryKeys = 64
	// MaxValiditySecs is the longest accepted expires - created window (24
	// hours, the draft's recommended ceiling).
	MaxValiditySecs int64 = 86400
)

// PrivateKey and PublicKey are the httpsig key types.
type (
	PrivateKey = httpsig.PrivateKey
	PublicKey  = httpsig.PublicKey
)

func wbaErr(format string, a ...any) error { return &httpsig.Error{Reason: fmt.Sprintf(format, a...)} }

var b64url = base64.RawURLEncoding

// ---------------------------------------------------------------------------
// Keys and JWKs
// ---------------------------------------------------------------------------

// GenerateSigningKey generates a new Ed25519 signing key.
func GenerateSigningKey() (PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, err
	}
	return httpsig.Ed25519PrivateKey(k), nil
}

// LoadSigningKey loads a signing key from PEM: Ed25519 or RSA (PKCS#8 or
// PKCS#1).
func LoadSigningKey(pemStr string) (PrivateKey, error) { return httpsig.LoadPrivateKeyPEM(pemStr) }

// SigningKeyToPEM encodes a signing key as PKCS#8 PEM.
func SigningKeyToPEM(k PrivateKey) (string, error) { return httpsig.MarshalPrivateKeyPEM(k) }

func rsaE(k *rsa.PublicKey) []byte { return big.NewInt(int64(k.E)).Bytes() }

// Thumbprint is the JWK SHA-256 thumbprint, base64url without padding:
// RFC 8037 for Ed25519, RFC 7638 for RSA. This is the WBA keyid.
func Thumbprint(k PublicKey) string {
	var canonical string
	if k.RSA != nil {
		canonical = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, b64url.EncodeToString(rsaE(k.RSA)), b64url.EncodeToString(k.RSA.N.Bytes()))
	} else {
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, b64url.EncodeToString(k.Ed25519))
	}
	h := sha256.Sum256([]byte(canonical))
	return b64url.EncodeToString(h[:])
}

// JWK is a directory public key: OKP/Ed25519 (RFC 8037) or RSA (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid,omitempty"`
	X   string `json:"x,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// Nbf is "not valid before" (Unix seconds).
	Nbf *int64 `json:"nbf,omitempty"`
	// Exp is "not valid after" (Unix seconds).
	Exp *int64 `json:"exp,omitempty"`
}

// JWKFromPublicKey returns the JWK for k, with kid set to its thumbprint.
func JWKFromPublicKey(k PublicKey) JWK {
	j := JWK{Kid: Thumbprint(k), Use: "sig"}
	if k.RSA != nil {
		j.Kty = "RSA"
		j.N = b64url.EncodeToString(k.RSA.N.Bytes())
		j.E = b64url.EncodeToString(rsaE(k.RSA))
	} else {
		j.Kty, j.Crv = "OKP", "Ed25519"
		j.X = b64url.EncodeToString(k.Ed25519)
	}
	return j
}

// PublicKey decodes the key. It accepts Ed25519 OKP keys and RSA keys of
// 2048 to 8192 bits with minimal encodings, and rejects everything else.
func (j JWK) PublicKey() (PublicKey, error) {
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		x, err := b64url.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize || !httpsig.ValidEd25519Point(x) {
			return PublicKey{}, httpsig.ErrInvalidKeyFormat
		}
		return httpsig.Ed25519PublicKey(x), nil
	case j.Kty == "RSA":
		n, err1 := b64url.DecodeString(j.N)
		e, err2 := b64url.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 {
			return PublicKey{}, httpsig.ErrInvalidKeyFormat
		}
		// Minimal encodings only (RFC 7518 §6.3.1), so the thumbprint is
		// well defined.
		nbits := len(n)*8 - bits.LeadingZeros8(n[0])
		if n[0] == 0 || e[0] == 0 || len(e) > 4 || nbits < 2048 || nbits > 8192 {
			return PublicKey{}, httpsig.ErrInvalidKeyFormat
		}
		return PublicKey{RSA: &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}}, nil
	}
	return PublicKey{}, httpsig.ErrInvalidKeyFormat
}

// Thumbprint is computed from the key material (never taken from kid);
// empty for keys PublicKey rejects.
func (j JWK) Thumbprint() string {
	k, err := j.PublicKey()
	if err != nil {
		return ""
	}
	return Thumbprint(k)
}

func (j JWK) usableAt(now, skew int64) bool {
	return (j.Nbf == nil || now+skew >= *j.Nbf) && (j.Exp == nil || now-skew < *j.Exp)
}

// parseJWK decodes one JWK with exact (case-sensitive) member names.
func parseJWK(raw json.RawMessage) (JWK, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return JWK{}, errors.New("not an object")
	}
	var j JWK
	str := func(name string, dst *string, required bool) error {
		v, ok := m[name]
		if !ok || string(v) == "null" {
			if required {
				return errors.New("missing " + name)
			}
			return nil
		}
		return json.Unmarshal(v, dst)
	}
	num := func(name string, dst **int64) error {
		v, ok := m[name]
		if !ok || string(v) == "null" {
			return nil
		}
		var n int64
		if err := json.Unmarshal(v, &n); err != nil {
			return err
		}
		*dst = &n
		return nil
	}
	for _, err := range []error{
		str("kty", &j.Kty, true), str("crv", &j.Crv, false), str("kid", &j.Kid, false),
		str("x", &j.X, false), str("n", &j.N, false), str("e", &j.E, false),
		str("use", &j.Use, false), str("alg", &j.Alg, false),
		num("nbf", &j.Nbf), num("exp", &j.Exp),
	} {
		if err != nil {
			return JWK{}, err
		}
	}
	return j, nil
}

// Directory is a key directory: a JWK Set of signing keys.
type Directory struct {
	Keys []JWK `json:"keys"`
}

// DirectoryFromKeys returns a directory publishing keys.
func DirectoryFromKeys(keys ...PublicKey) *Directory {
	d := &Directory{Keys: []JWK{}}
	for _, k := range keys {
		d.Keys = append(d.Keys, JWKFromPublicKey(k))
	}
	return d
}

// ParseDirectory parses a JWK Set. Entries that are not well-formed
// Ed25519 or RSA keys (EC, short RSA, bad values) are skipped; more than
// MaxDirectoryKeys entries is an error.
func ParseDirectory(data []byte) (*Directory, error) {
	var top map[string]json.RawMessage
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil ||
		string(top["keys"]) == "null" || json.Unmarshal(top["keys"], &raw) != nil {
		return nil, wbaErr("key directory is not a JWK Set")
	}
	if len(raw) > MaxDirectoryKeys {
		return nil, wbaErr("key directory has too many keys")
	}
	d := &Directory{Keys: []JWK{}}
	for _, r := range raw {
		j, err := parseJWK(r)
		if err != nil {
			continue
		}
		if _, err := j.PublicKey(); err == nil {
			d.Keys = append(d.Keys, j)
		}
	}
	return d, nil
}

func marshal(v any, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// JSON is the compact JSON body, as served.
func (d *Directory) JSON() ([]byte, error) {
	c := *d
	if c.Keys == nil {
		c.Keys = []JWK{}
	}
	return marshal(c, false)
}

// PrettyJSON is the indented JSON form.
func (d *Directory) PrettyJSON() ([]byte, error) {
	c := *d
	if c.Keys == nil {
		c.Keys = []JWK{}
	}
	return marshal(c, true)
}

// FindKey finds keyid in directory by computed thumbprint, honoring nbf
// and exp.
func FindKey(d *Directory, keyid string, now, skew int64) (PublicKey, bool) {
	for _, j := range d.Keys {
		if !j.usableAt(now, skew) {
			continue
		}
		k, err := j.PublicKey()
		if err == nil && Thumbprint(k) == keyid {
			return k, true
		}
	}
	return PublicKey{}, false
}

// ---------------------------------------------------------------------------
// Signature-Agent
// ---------------------------------------------------------------------------

// WellKnownDirectory is the well-known directory URL for domain.
func WellKnownDirectory(domain string) string { return "https://" + domain + DirectoryPath }

// NormalizeSignatureAgent normalizes a Signature-Agent URL into the
// identifier form the draft compares (§5.5): absolute https URL with a
// host, query and fragment dropped, scheme/host case and default port
// normalized, credentials refused.
func NormalizeSignatureAgent(rawURL string) (string, error) {
	s, err := weburl.NormalizeSignatureAgent(rawURL)
	if err != nil {
		return "", wbaErr("%s", err.Error())
	}
	return s, nil
}

// signatureAgentMember resolves the Signature-Agent member keyed label.
// legacy is set when the signature covers the bare "signature-agent"
// component, which is only valid for the old sf-string form of the field.
func signatureAgentMember(headers []httpsig.Header, label string, legacy bool) (string, error) {
	raw, ok := httpsig.CombinedField(headers, "signature-agent")
	if !ok {
		return "", errors.New("request has no Signature-Agent field")
	}
	var item sfv.Item
	if legacy {
		if len(raw) == 0 || raw[0] != '"' {
			return "", errors.New("Signature-Agent is a Dictionary; cover it with ;key")
		}
		it, err := sfv.ParseItem(raw)
		if err != nil {
			return "", errors.New("Signature-Agent is not a valid String")
		}
		item = it
	} else {
		dict, err := httpsig.ParseDictionaryField(headers, "signature-agent")
		if err != nil {
			return "", err
		}
		m, ok := dict.Get(label)
		if !ok {
			return "", fmt.Errorf("Signature-Agent has no member '%s'", label)
		}
		if m.Item == nil {
			return "", errors.New("Signature-Agent member is not an Item")
		}
		item = *m.Item
	}
	if len(item.Params) > 0 {
		return "", errors.New("Signature-Agent member carries parameters")
	}
	if item.Bare.Kind != sfv.String {
		return "", errors.New("Signature-Agent member is not a String")
	}
	return NormalizeSignatureAgent(item.Bare.Str)
}

// ---------------------------------------------------------------------------
// Signing requests
// ---------------------------------------------------------------------------

// SignOptions configures SignRequest. Start from DefaultSignOptions.
type SignOptions struct {
	// Label is the signature label; also the Signature-Agent member key.
	Label string
	// ValiditySecs is expires - created (1 to MaxValiditySecs).
	ValiditySecs int64
	// Components are covered in addition to @authority and the
	// Signature-Agent member. The default, @method and @path, narrows a
	// captured signature to one method and resource (§5.2). Add
	// authorization to bind an AgentPin credential.
	Components []httpsig.Component
	// Nonce adds a random 64-byte nonce parameter.
	Nonce bool
	// Created is the created timestamp; 0 uses the current time.
	Created int64
	// LegacySignatureAgent sends Signature-Agent in the legacy bare-String
	// form and covers the bare "signature-agent" component (draft Appendix
	// E.1.2). Only for verifiers that predate the Dictionary form; the
	// draft requires signers to send the Dictionary form.
	LegacySignatureAgent bool
}

// DefaultSignOptions returns label sig1, 300 s validity, @method and
// @path, and a nonce.
func DefaultSignOptions() SignOptions {
	return SignOptions{
		Label:        "sig1",
		ValiditySecs: 300,
		Components:   []httpsig.Component{httpsig.NewComponent("@method"), httpsig.NewComponent("@path")},
		Nonce:        true,
	}
}

// SignedHeaders are the header fields that carry one WBA signature.
type SignedHeaders struct {
	SignatureAgent string
	SignatureInput string
	Signature      string
}

// Headers returns the fields as header lines.
func (s SignedHeaders) Headers() []httpsig.Header {
	return []httpsig.Header{
		{Name: "Signature-Agent", Value: s.SignatureAgent},
		{Name: "Signature-Input", Value: s.SignatureInput},
		{Name: "Signature", Value: s.Signature},
	}
}

// Apply appends the three fields to req.
func (s SignedHeaders) Apply(req *httpsig.Request) {
	req.Headers = append(req.Headers, s.Headers()...)
}

func containsComponent(cs []httpsig.Component, c httpsig.Component) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

// SignRequest signs req as a Web Bot Auth agent whose key directory is
// signatureAgent (an https URL). It returns the fields to append; req is
// not modified. Any header named in opts.Components must already be on
// req.
func SignRequest(req *httpsig.Request, key PrivateKey, signatureAgent string, opts SignOptions) (SignedHeaders, error) {
	agentURL, err := weburl.Parse(signatureAgent)
	if err != nil || agentURL.Scheme != "https" {
		return SignedHeaders{}, wbaErr("signature_agent must be an https URL with a host")
	}
	if opts.ValiditySecs < 1 || opts.ValiditySecs > MaxValiditySecs {
		return SignedHeaders{}, wbaErr("validity_secs must be between 1 and 86400")
	}
	agent := agentURL.String()
	if !sfv.ValidString(agent) {
		return SignedHeaders{}, wbaErr("invalid Signature-Agent URL")
	}
	var field string
	var agentComponent httpsig.Component
	if opts.LegacySignatureAgent {
		if _, ok := httpsig.CombinedField(req.Headers, "signature-agent"); ok {
			return SignedHeaders{}, wbaErr("legacy Signature-Agent cannot be combined with an existing one")
		}
		field, _ = sfv.SerializeItem(sfv.Item{Bare: sfv.Str(agent)})
		agentComponent = httpsig.NewComponent("signature-agent")
	} else {
		existing, err := httpsig.ParseDictionaryField(req.Headers, "signature-agent")
		if err != nil {
			return SignedHeaders{}, err
		}
		if _, ok := existing.Get(opts.Label); ok {
			return SignedHeaders{}, wbaErr("Signature-Agent already has a member '%s'", opts.Label)
		}
		if !sfv.ValidKey(opts.Label) {
			return SignedHeaders{}, wbaErr("invalid label")
		}
		field, _ = sfv.SerializeDictionary(sfv.Dictionary{{Key: opts.Label, Value: sfv.Member{Item: &sfv.Item{Bare: sfv.Str(agent)}}}})
		agentComponent = httpsig.Keyed("signature-agent", opts.Label)
	}
	toSign := req.Clone()
	toSign.Header("Signature-Agent", field)

	components := []httpsig.Component{httpsig.NewComponent("@authority"), agentComponent}
	for _, c := range opts.Components {
		if !containsComponent(components, c) {
			components = append(components, c)
		}
	}

	created := opts.Created
	if created == 0 {
		created = time.Now().Unix()
	}
	params := []httpsig.Param{
		httpsig.Created(created),
		httpsig.KeyID(Thumbprint(key.PublicKey())),
		httpsig.Alg(key.Alg()),
		httpsig.Expires(created + opts.ValiditySecs),
	}
	if opts.Nonce {
		// 64 bytes, as in the draft's vectors; some verifiers reject other
		// lengths.
		b := make([]byte, 64)
		if _, err := rand.Read(b); err != nil {
			return SignedHeaders{}, err
		}
		params = append(params, httpsig.Nonce(base64.StdEncoding.EncodeToString(b)))
	}
	params = append(params, httpsig.Tag(Tag))

	f, err := httpsig.Sign(httpsig.RequestMessage(toSign), opts.Label, components, params, key)
	if err != nil {
		return SignedHeaders{}, err
	}
	return SignedHeaders{SignatureAgent: field, SignatureInput: f.SignatureInput, Signature: f.Signature}, nil
}

// ---------------------------------------------------------------------------
// Verifying requests
// ---------------------------------------------------------------------------

// VerifyOptions configures VerifyRequest. Start from DefaultVerifyOptions.
type VerifyOptions struct {
	// Now is the verification time (Unix seconds); 0 uses the current time.
	Now int64
	// ClockSkewSecs is the clock skew tolerance.
	ClockSkewSecs int64
	// MaxValiditySecs is the longest accepted expires - created window.
	MaxValiditySecs int64
	// AcceptLegacySignatureAgent accepts the legacy bare-String
	// Signature-Agent form (§5.2.1).
	AcceptLegacySignatureAgent bool
	// RequiredComponents must be covered by every accepted signature, in
	// addition to the protocol's own requirements.
	RequiredComponents []httpsig.Component
	// NonceStore enables replay protection: a verified signature's nonce
	// is recorded per keyid until the signature expires, and a repeat is
	// invalid. Signatures without a nonce are invalid too. Checked only
	// after the signature verifies, so forged requests cannot fill it.
	NonceStore nonce.Store
}

// DefaultVerifyOptions returns 60 s skew, a 24 h validity ceiling and
// legacy Signature-Agent accepted.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		ClockSkewSecs:              60,
		MaxValiditySecs:            MaxValiditySecs,
		AcceptLegacySignatureAgent: true,
	}
}

// VerifiedAgent is a request signature that verified against a key its
// Signature-Agent directory provides.
type VerifiedAgent struct {
	Label string
	// SignatureAgent is the normalized Signature-Agent URL: the agent's
	// identifier.
	SignatureAgent string
	// KeyID is the JWK thumbprint of the signing key.
	KeyID      string
	Created    int64
	Expires    int64
	Nonce      string
	Components []httpsig.Component
}

// Covers reports whether the signature covers c.
func (a *VerifiedAgent) Covers(c httpsig.Component) bool { return containsComponent(a.Components, c) }

// OutcomeKind is one of the three verifier outcomes the draft
// distinguishes (Appendix C.1).
type OutcomeKind int

const (
	// Unverified: not enough information to decide (no WBA signature,
	// discovery failed, or the resolved directory lacks the key).
	Unverified OutcomeKind = iota
	// Invalid: the signature, covered components, key or freshness checks
	// fail.
	Invalid
	// Verified: the signature and key material validate.
	Verified
)

func (k OutcomeKind) String() string {
	switch k {
	case Verified:
		return "verified"
	case Invalid:
		return "invalid"
	}
	return "unverified"
}

// Outcome is the result of VerifyRequest. Agent is set when Kind is
// Verified; Reason otherwise.
type Outcome struct {
	Kind   OutcomeKind
	Agent  *VerifiedAgent
	Reason string
}

func (o Outcome) String() string {
	if o.Kind == Verified {
		return "verified: " + o.Agent.SignatureAgent
	}
	return o.Kind.String() + ": " + o.Reason
}

func invalid(reason string) Outcome    { return Outcome{Kind: Invalid, Reason: reason} }
func unverified(reason string) Outcome { return Outcome{Kind: Unverified, Reason: reason} }

// KeyLookup finds keys by the (Signature-Agent URL, keyid) pair, never by
// keyid alone (§5.4). found is true when the directory at signatureAgent
// provides keyid; false with a nil error when the directory resolved
// without it; err is set when it could not be resolved.
type KeyLookup interface {
	Lookup(signatureAgent, keyid string) (key PublicKey, found bool, err error)
}

// DirectoryKeyStore is an in-memory KeyLookup built from directories the
// verifier resolved itself.
type DirectoryKeyStore struct {
	directories   map[string]*Directory
	clockSkewSecs int64
}

// NewDirectoryKeyStore returns an empty store.
func NewDirectoryKeyStore() *DirectoryKeyStore {
	return &DirectoryKeyStore{directories: map[string]*Directory{}, clockSkewSecs: 60}
}

// Insert records (or replaces) the directory resolved from signatureAgent.
func (s *DirectoryKeyStore) Insert(signatureAgent string, d *Directory) error {
	u, err := NormalizeSignatureAgent(signatureAgent)
	if err != nil {
		return err
	}
	s.directories[u] = d
	return nil
}

// Lookup implements KeyLookup.
func (s *DirectoryKeyStore) Lookup(signatureAgent, keyid string) (PublicKey, bool, error) {
	d, ok := s.directories[signatureAgent]
	if !ok {
		return PublicKey{}, false, wbaErr("directory not resolved")
	}
	k, found := FindKey(d, keyid, time.Now().Unix(), s.clockSkewSecs)
	return k, found, nil
}

// candidate is a WBA signature that passed every check except the
// cryptographic one, with the Signature-Agent URL it names.
type candidate struct {
	sig            *httpsig.ParsedSignature
	signatureAgent string
	keyid          string
}

// checkSignature runs the protocol checks on one signature (§5.2,
// §5.2.1); the error is the reason it is invalid.
func checkSignature(req *httpsig.Request, sig *httpsig.ParsedSignature, opts *VerifyOptions, now int64) (*candidate, error) {
	p := sig.Params
	switch {
	case p.Created == nil:
		return nil, errors.New("signature has no created parameter")
	case p.Expires == nil:
		return nil, errors.New("signature has no expires parameter")
	case p.KeyID == nil:
		return nil, errors.New("signature has no keyid parameter")
	}
	if p.Alg != nil && *p.Alg != httpsig.AlgEd25519 && *p.Alg != httpsig.AlgRSAPSSSHA512 {
		return nil, fmt.Errorf("unsupported alg '%s'", *p.Alg)
	}
	created, expires := *p.Created, *p.Expires
	switch {
	case created > now+opts.ClockSkewSecs:
		return nil, errors.New("signature created in the future")
	case expires <= created:
		return nil, errors.New("expires is not after created")
	case now-opts.ClockSkewSecs > expires:
		return nil, errors.New("signature expired")
	case expires-created > opts.MaxValiditySecs:
		return nil, errors.New("signature validity window too long")
	}
	if !sig.Covers(httpsig.NewComponent("@authority")) && !sig.Covers(httpsig.NewComponent("@target-uri")) {
		return nil, errors.New("signature covers neither @authority nor @target-uri")
	}
	for _, c := range opts.RequiredComponents {
		if !sig.Covers(c) {
			return nil, fmt.Errorf("signature does not cover required '%s'", c.Name)
		}
	}
	// The covered member, not the signature label, names the agent: labels
	// may be rewritten by intermediaries, member keys may not (§6.6.1).
	var members []string
	for _, c := range sig.Components {
		if c.Name == "signature-agent" && !c.Req && c.Key != "" {
			members = append(members, c.Key)
		}
	}
	var agent string
	var err error
	switch {
	case len(members) == 1:
		agent, err = signatureAgentMember(req.Headers, members[0], false)
	case len(members) == 0 && opts.AcceptLegacySignatureAgent && sig.Covers(httpsig.NewComponent("signature-agent")):
		agent, err = signatureAgentMember(req.Headers, sig.Label, true)
	case len(members) == 0:
		return nil, errors.New("signature does not cover a Signature-Agent member")
	default:
		return nil, errors.New("signature covers more than one Signature-Agent member")
	}
	if err != nil {
		return nil, err
	}
	return &candidate{sig: sig, signatureAgent: agent, keyid: *p.KeyID}, nil
}

// candidates parses and checks every WBA-tagged signature. It returns the
// candidates and the reason for the last invalid one, or a final outcome.
func candidates(req *httpsig.Request, opts *VerifyOptions, now int64) ([]*candidate, string, *Outcome) {
	sigs, err := httpsig.ParseSignatures(req.Headers)
	if err != nil {
		o := invalid(err.Error())
		return nil, "", &o
	}
	var out []*candidate
	reason := ""
	seen := false
	for _, s := range sigs {
		if s.Params.Tag == nil || *s.Params.Tag != Tag {
			continue
		}
		seen = true
		c, err := checkSignature(req, s, opts, now)
		if err != nil {
			reason = err.Error()
			continue
		}
		out = append(out, c)
	}
	if !seen {
		o := unverified("request carries no Web Bot Auth signature")
		return nil, "", &o
	}
	return out, reason, nil
}

func finish(req *httpsig.Request, c *candidate, key PublicKey, found bool, lookupErr error, opts *VerifyOptions, now int64) Outcome {
	switch {
	case lookupErr != nil:
		return unverified(fmt.Sprintf("key directory %s unavailable: %v", c.signatureAgent, lookupErr))
	case !found:
		return unverified(fmt.Sprintf("key directory %s does not provide keyid %s", c.signatureAgent, c.keyid))
	}
	if httpsig.Verify(httpsig.RequestMessage(req), c.sig, key) != nil {
		return invalid("signature verification failed")
	}
	if err := checkNonce(c, opts, now); err != nil {
		return invalid(err.Error())
	}
	a := &VerifiedAgent{
		Label:          c.sig.Label,
		SignatureAgent: c.signatureAgent,
		KeyID:          c.keyid,
		Created:        *c.sig.Params.Created,
		Expires:        *c.sig.Params.Expires,
		Components:     c.sig.Components,
	}
	if c.sig.Params.Nonce != nil {
		a.Nonce = *c.sig.Params.Nonce
	}
	return Outcome{Kind: Verified, Agent: a}
}

// checkNonce records the nonce of a verified signature in opts.NonceStore.
func checkNonce(c *candidate, opts *VerifyOptions, now int64) error {
	if opts.NonceStore == nil {
		return nil
	}
	if c.sig.Params.Nonce == nil {
		return errors.New("signature has no nonce and replay protection is on")
	}
	// Keep the nonce until the signature can no longer pass the expiry
	// check.
	ttl := *c.sig.Params.Expires + opts.ClockSkewSecs - now
	if ttl < 1 {
		ttl = 1
	}
	fresh, err := opts.NonceStore.CheckAndRecord(c.keyid+" "+*c.sig.Params.Nonce, time.Duration(ttl)*time.Second)
	if err != nil {
		return fmt.Errorf("nonce store failed: %v", err)
	}
	if !fresh {
		return errors.New("nonce replayed")
	}
	return nil
}

// VerifyRequest verifies the Web Bot Auth signatures on req. It returns
// the first signature that verifies; otherwise Invalid if any signature
// failed a check, else Unverified. Set VerifyOptions.NonceStore to reject
// replays (§5.2.3).
func VerifyRequest(req *httpsig.Request, keys KeyLookup, opts VerifyOptions) Outcome {
	now := opts.Now
	if now == 0 {
		now = time.Now().Unix()
	}
	cands, reason, final := candidates(req, &opts, now)
	if final != nil {
		return *final
	}
	var result *Outcome
	if reason != "" {
		o := invalid(reason)
		result = &o
	}
	for _, c := range cands {
		key, found, err := keys.Lookup(c.signatureAgent, c.keyid)
		o := finish(req, c, key, found, err, &opts, now)
		if o.Kind == Verified {
			return o
		}
		// Keep the more decisive failure: invalid beats unverified.
		if result == nil || result.Kind != Invalid {
			result = &o
		}
	}
	if result == nil {
		return unverified("no usable signature")
	}
	return *result
}
