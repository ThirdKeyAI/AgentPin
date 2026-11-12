// Package httpsig implements RFC 9421 HTTP Message Signatures: signature
// bases, the Signature-Input and Signature fields, and signing and
// verification with Ed25519 ("ed25519") and RSASSA-PSS SHA-512
// ("rsa-pss-sha512"). Web Bot Auth (package wba) is built on it.
//
// Supported component identifiers: @method, @target-uri, @authority,
// @scheme, @request-target, @path, @query, @query-param (with name),
// @status, and HTTP fields, with the key (Dictionary member) and req
// (related request) parameters. Identifiers carrying any other parameter
// (sf, bs, tr) are rejected rather than silently mis-serialized.
package httpsig

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ThirdKeyAi/agentpin/go/internal/weburl"
	"github.com/ThirdKeyAi/agentpin/go/pkg/sfv"
)

// Error reports an HTTP message signature that could not be parsed or
// built.
type Error struct{ Reason string }

func (e *Error) Error() string { return "HTTP signature error: " + e.Reason }

func errorf(format string, a ...any) error { return &Error{Reason: fmt.Sprintf(format, a...)} }

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

// Header is one header field line.
type Header struct {
	Name  string
	Value string
}

// Request holds the parts of an HTTP request a signature can cover.
type Request struct {
	Method string
	// URL is the absolute request URL. Derived components use its WHATWG
	// serialization (lowercase host, default port dropped, dot segments
	// removed).
	URL string
	// Headers in order; names are matched case-insensitively.
	Headers []Header
}

// NewRequest builds a request from a method and an absolute URL.
func NewRequest(method, rawURL string) (*Request, error) {
	if _, err := weburl.Parse(rawURL); err != nil {
		return nil, errorf("request URL is not an absolute URL with a host")
	}
	return &Request{Method: method, URL: rawURL}, nil
}

// RequestFromHTTP converts a net/http request. Server-side requests carry
// no absolute URL, so the scheme is https when r.TLS is set (else http)
// and the host is r.Host.
func RequestFromHTTP(r *http.Request) (*Request, error) {
	u := *r.URL
	if !u.IsAbs() {
		u.Scheme = "http"
		if r.TLS != nil {
			u.Scheme = "https"
		}
		u.Host = r.Host
	}
	req, err := NewRequest(r.Method, u.String())
	if err != nil {
		return nil, err
	}
	for name, values := range r.Header {
		for _, v := range values {
			req.Headers = append(req.Headers, Header{name, v})
		}
	}
	return req, nil
}

// Header appends a header field and returns the request.
func (r *Request) Header(name, value string) *Request {
	r.Headers = append(r.Headers, Header{name, value})
	return r
}

// Clone returns a deep copy.
func (r *Request) Clone() *Request {
	c := *r
	c.Headers = append([]Header(nil), r.Headers...)
	return &c
}

// Response holds the parts of an HTTP response a signature can cover.
type Response struct {
	Status  int
	Headers []Header
}

// Message is what a signature is computed over: a request, or a response
// with (optionally) the request that produced it, for components with the
// req parameter.
type Message struct {
	Request  *Request
	Response *Response
}

// RequestMessage wraps a request.
func RequestMessage(r *Request) Message { return Message{Request: r} }

// ResponseMessage wraps a response and its request (may be nil).
func ResponseMessage(resp *Response, req *Request) Message {
	return Message{Request: req, Response: resp}
}

func (m Message) headers() []Header {
	if m.Response != nil {
		return m.Response.Headers
	}
	return m.Request.Headers
}

// CombinedField returns every name field's value trimmed and joined with
// ", " (RFC 9421 §2.1); ok is false when the field is absent.
func CombinedField(headers []Header, name string) (string, bool) {
	var values []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			values = append(values, strings.TrimSpace(h.Value))
		}
	}
	if values == nil {
		return "", false
	}
	return strings.Join(values, ", "), true
}

// ParseDictionaryField parses the combined name field as a Structured
// Field Dictionary; an absent field is an empty Dictionary.
func ParseDictionaryField(headers []Header, name string) (sfv.Dictionary, error) {
	v, ok := CombinedField(headers, name)
	if !ok {
		return nil, nil
	}
	d, err := sfv.ParseDictionary(v)
	if err != nil {
		return nil, errorf("%s is not a valid Dictionary", name)
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// Component identifiers
// ---------------------------------------------------------------------------

// Component is a covered component identifier.
type Component struct {
	// Name is a lowercase field name or derived component name.
	Name string
	// Key covers one member of a Dictionary field.
	Key string
	// Req resolves the component against the related request.
	Req bool
	// QueryName is the encoded name parameter of @query-param.
	QueryName string
}

// NewComponent returns a plain component.
func NewComponent(name string) Component { return Component{Name: name} }

// Keyed returns a Dictionary member component, e.g. "signature-agent";key="sig1".
func Keyed(name, key string) Component { return Component{Name: name, Key: key} }

// OfRequest returns a related-request component, e.g. "@authority";req.
func OfRequest(name string) Component { return Component{Name: name, Req: true} }

// QueryParam returns a "@query-param";name="..." component. name is
// percent-encoded as RFC 9421 §2.2.8 requires.
func QueryParam(name string) Component {
	return Component{Name: "@query-param", QueryName: encodeQueryPart(name)}
}

func (c Component) item() (sfv.Item, error) {
	it := sfv.Item{Bare: sfv.Str(c.Name)}
	if c.Name == "@query-param" || c.QueryName != "" {
		it.Params.Set("name", sfv.Str(c.QueryName))
	}
	if c.Key != "" {
		it.Params.Set("key", sfv.Str(c.Key))
	}
	if c.Req {
		it.Params.Set("req", sfv.Bool(true))
	}
	if !sfv.ValidString(c.Name) || !sfv.ValidString(c.QueryName) || !sfv.ValidString(c.Key) {
		return it, errorf("value is not a valid sf-string")
	}
	return it, nil
}

// Identifier is the serialized component identifier.
func (c Component) Identifier() (string, error) {
	it, err := c.item()
	if err != nil {
		return "", err
	}
	return sfv.SerializeItem(it)
}

func componentFromItem(it sfv.Item) (Component, error) {
	if it.Bare.Kind != sfv.String {
		return Component{}, errorf("component identifier is not a String")
	}
	name := it.Bare.Str
	if name == "" || name != strings.ToLower(name) {
		return Component{}, errorf("component name '%s' must be lowercase", name)
	}
	if name == "@signature-params" {
		return Component{}, errorf("@signature-params cannot be covered")
	}
	c := Component{Name: name}
	hasName := false
	for _, p := range it.Params {
		switch {
		case p.Key == "key":
			if p.Value.Kind != sfv.String {
				return Component{}, errorf("key parameter must be a String")
			}
			if strings.HasPrefix(name, "@") {
				return Component{}, errorf("key parameter on a derived component")
			}
			if p.Value.Str == "" {
				return Component{}, errorf("key parameter is empty")
			}
			c.Key = p.Value.Str
		case p.Key == "req":
			if p.Value.Kind != sfv.Boolean || !p.Value.Bool {
				return Component{}, errorf("req parameter must be true")
			}
			c.Req = true
		case p.Key == "name" && name == "@query-param":
			if p.Value.Kind != sfv.String {
				return Component{}, errorf("name parameter must be a String")
			}
			c.QueryName = p.Value.Str
			hasName = true
		default:
			return Component{}, errorf("unsupported component parameter '%s' on '%s'", p.Key, name)
		}
	}
	if (name == "@query-param") != hasName {
		return Component{}, errorf("@query-param needs exactly one name parameter")
	}
	return c, nil
}

// encodeQueryPart percent-encodes with the application/x-www-form-urlencoded
// set, spaces as %20 (RFC 9421 §2.2.8 and its examples).
func encodeQueryPart(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '*' || c == '-' || c == '.' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// formDecode decodes one application/x-www-form-urlencoded name or value:
// '+' is a space, invalid escapes are kept, invalid UTF-8 is replaced.
func formDecode(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b = append(b, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b = append(b, byte(v))
			i += 2
		default:
			b = append(b, c)
		}
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// queryParamValue is the @query-param value: the single parameter whose
// encoded name is name. Absent or repeated parameters are errors.
func queryParamValue(query *string, name string) (string, error) {
	var found []string
	if query != nil {
		for _, pair := range strings.Split(*query, "&") {
			if pair == "" {
				continue
			}
			n, v, _ := strings.Cut(pair, "=")
			if encodeQueryPart(formDecode(n)) == name {
				found = append(found, encodeQueryPart(formDecode(v)))
			}
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", errorf("query parameter '%s' is missing", name)
	}
	return "", errorf("query parameter '%s' occurs more than once", name)
}

func componentValue(msg Message, c Component) (string, error) {
	if c.Req {
		if msg.Response == nil || msg.Request == nil {
			return "", errorf("req parameter needs a response with its request")
		}
		msg = RequestMessage(msg.Request)
	}

	if derived, ok := strings.CutPrefix(c.Name, "@"); ok {
		if derived == "status" {
			if msg.Response == nil {
				return "", errorf("@status is only valid on a response")
			}
			return strconv.Itoa(msg.Response.Status), nil
		}
		if msg.Response != nil || msg.Request == nil {
			return "", errorf("%s needs a request", c.Name)
		}
		req := msg.Request
		u, err := weburl.Parse(req.URL)
		if err != nil {
			return "", errorf("request URL is not an absolute URL with a host")
		}
		switch derived {
		case "method":
			return req.Method, nil
		case "target-uri":
			return u.String(), nil
		case "authority":
			return u.Authority(), nil
		case "scheme":
			return u.Scheme, nil
		case "request-target":
			if u.Query != nil {
				return u.Path + "?" + *u.Query, nil
			}
			return u.Path, nil
		case "path":
			return u.Path, nil
		case "query":
			if u.Query != nil {
				return "?" + *u.Query, nil
			}
			return "?", nil
		case "query-param":
			return queryParamValue(u.Query, c.QueryName)
		}
		return "", errorf("unsupported derived component %s", c.Name)
	}

	if c.Key == "" {
		v, ok := CombinedField(msg.headers(), c.Name)
		if !ok {
			return "", errorf("covered field '%s' is missing", c.Name)
		}
		return v, nil
	}
	dict, err := ParseDictionaryField(msg.headers(), c.Name)
	if err != nil {
		return "", err
	}
	m, ok := dict.Get(c.Key)
	if !ok {
		return "", errorf("'%s' has no member '%s'", c.Name, c.Key)
	}
	return sfv.SerializeList([]sfv.Member{m})
}

// ---------------------------------------------------------------------------
// Signature parameters
// ---------------------------------------------------------------------------

// Param is one @signature-params parameter, for signing. Parameters are
// written in the order given.
type Param struct {
	Name  string // created, expires, keyid, alg, nonce or tag
	Int   int64
	Value string
}

// Created returns a created parameter.
func Created(t int64) Param { return Param{Name: "created", Int: t} }

// Expires returns an expires parameter.
func Expires(t int64) Param { return Param{Name: "expires", Int: t} }

// KeyID returns a keyid parameter.
func KeyID(s string) Param { return Param{Name: "keyid", Value: s} }

// Alg returns an alg parameter.
func Alg(s string) Param { return Param{Name: "alg", Value: s} }

// Nonce returns a nonce parameter.
func Nonce(s string) Param { return Param{Name: "nonce", Value: s} }

// Tag returns a tag parameter.
func Tag(s string) Param { return Param{Name: "tag", Value: s} }

// SignatureParams are the signature parameters as received.
type SignatureParams struct {
	Created *int64
	Expires *int64
	KeyID   *string
	Alg     *string
	Nonce   *string
	Tag     *string
}

func buildInnerList(components []Component, params []Param) (sfv.InnerList, error) {
	var il sfv.InnerList
	for _, c := range components {
		it, err := c.item()
		if err != nil {
			return il, err
		}
		il.Items = append(il.Items, it)
	}
	for _, p := range params {
		var v sfv.BareItem
		switch p.Name {
		case "created", "expires":
			if p.Int > 999_999_999_999_999 || p.Int < -999_999_999_999_999 {
				return il, errorf("integer out of range")
			}
			v = sfv.Int(p.Int)
		case "keyid", "alg", "nonce", "tag":
			if !sfv.ValidString(p.Value) {
				return il, errorf("value is not a valid sf-string")
			}
			v = sfv.Str(p.Value)
		default:
			return il, errorf("unsupported signature parameter '%s'", p.Name)
		}
		if il.Params.Set(p.Name, v) {
			return il, errorf("duplicate signature parameter '%s'", p.Name)
		}
	}
	return il, nil
}

func readParams(ps sfv.Params) (SignatureParams, error) {
	var out SignatureParams
	for _, p := range ps {
		switch p.Key {
		case "created", "expires":
			if p.Value.Kind != sfv.Integer {
				return out, errorf("%s must be an Integer", p.Key)
			}
			v := p.Value.Int
			if p.Key == "created" {
				out.Created = &v
			} else {
				out.Expires = &v
			}
		case "keyid", "alg", "nonce", "tag":
			if p.Value.Kind != sfv.String {
				return out, errorf("%s must be a String", p.Key)
			}
			v := p.Value.Str
			switch p.Key {
			case "keyid":
				out.KeyID = &v
			case "alg":
				out.Alg = &v
			case "nonce":
				out.Nonce = &v
			default:
				out.Tag = &v
			}
		}
		// Unknown parameters are covered by the signature; ignore them.
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Signature base, parsing, signing, verifying
// ---------------------------------------------------------------------------

func signatureBase(msg Message, components []Component, inner sfv.InnerList) (string, error) {
	var b strings.Builder
	for _, c := range components {
		v, err := componentValue(msg, c)
		if err != nil {
			return "", err
		}
		if strings.ContainsAny(v, "\r\n") {
			return "", errorf("component value contains a line break")
		}
		id, err := c.Identifier()
		if err != nil {
			return "", err
		}
		b.WriteString(id)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	params, err := sfv.SerializeList([]sfv.Member{{Inner: &inner}})
	if err != nil {
		return "", errorf("%v", err)
	}
	b.WriteString("\"@signature-params\": ")
	b.WriteString(params)
	return b.String(), nil
}

// ParsedSignature is one signature read from Signature-Input and Signature.
type ParsedSignature struct {
	Label      string
	Components []Component
	Params     SignatureParams
	Signature  []byte
	inner      sfv.InnerList
}

// Covers reports whether the signature covers c.
func (s *ParsedSignature) Covers(c Component) bool {
	for _, x := range s.Components {
		if x == c {
			return true
		}
	}
	return false
}

// SignatureBase is the exact signature base this signature claims to cover.
func (s *ParsedSignature) SignatureBase(msg Message) (string, error) {
	return signatureBase(msg, s.Components, s.inner)
}

// ParseSignatures parses every signature carried in headers. A
// Signature-Input member without a matching Signature member, or a
// repeated component, is an error.
func ParseSignatures(headers []Header) ([]*ParsedSignature, error) {
	inputs, err := ParseDictionaryField(headers, "signature-input")
	if err != nil {
		return nil, err
	}
	sigs, err := ParseDictionaryField(headers, "signature")
	if err != nil {
		return nil, err
	}
	out := make([]*ParsedSignature, 0, len(inputs))
	for _, e := range inputs {
		if e.Value.Inner == nil {
			return nil, errorf("Signature-Input '%s' is not an Inner List", e.Key)
		}
		sm, ok := sigs.Get(e.Key)
		if !ok || sm.Item == nil {
			return nil, errorf("no Signature for label '%s'", e.Key)
		}
		if sm.Item.Bare.Kind != sfv.ByteSequence {
			return nil, errorf("Signature '%s' is not a Byte Sequence", e.Key)
		}
		ps := &ParsedSignature{Label: e.Key, Signature: sm.Item.Bare.Bytes, inner: *e.Value.Inner}
		for _, it := range e.Value.Inner.Items {
			c, err := componentFromItem(it)
			if err != nil {
				return nil, err
			}
			if ps.Covers(c) {
				return nil, errorf("component '%s' is covered twice", c.Name)
			}
			ps.Components = append(ps.Components, c)
		}
		if ps.Params, err = readParams(e.Value.Inner.Params); err != nil {
			return nil, err
		}
		out = append(out, ps)
	}
	return out, nil
}

// SignatureFields are the Signature-Input and Signature member strings for
// one signature, e.g. sig1=("@authority");created=1 and sig1=:...:. Each
// is a valid field value on its own.
type SignatureFields struct {
	SignatureInput string
	Signature      string
}

// Sign signs msg over components under label.
func Sign(msg Message, label string, components []Component, params []Param, key PrivateKey) (SignatureFields, error) {
	for i, c := range components {
		for _, d := range components[:i] {
			if c == d {
				return SignatureFields{}, errorf("component '%s' is covered twice", c.Name)
			}
		}
	}
	if !sfv.ValidKey(label) {
		return SignatureFields{}, errorf("invalid key '%s'", label)
	}
	inner, err := buildInnerList(components, params)
	if err != nil {
		return SignatureFields{}, err
	}
	base, err := signatureBase(msg, components, inner)
	if err != nil {
		return SignatureFields{}, err
	}
	sig, err := key.Sign([]byte(base))
	if err != nil {
		return SignatureFields{}, err
	}
	input, err := sfv.SerializeDictionary(sfv.Dictionary{{Key: label, Value: sfv.Member{Inner: &inner}}})
	if err != nil {
		return SignatureFields{}, errorf("%v", err)
	}
	signature, err := sfv.SerializeDictionary(sfv.Dictionary{{Key: label, Value: sfv.Member{Item: &sfv.Item{Bare: sfv.Bytes(sig)}}}})
	if err != nil {
		return SignatureFields{}, errorf("%v", err)
	}
	return SignatureFields{SignatureInput: input, Signature: signature}, nil
}

// Verify checks sig over msg with key. A present alg parameter must match
// the key type.
func Verify(msg Message, sig *ParsedSignature, key PublicKey) error {
	if sig.Params.Alg != nil && *sig.Params.Alg != key.Alg() {
		return ErrSignatureInvalid
	}
	base, err := sig.SignatureBase(msg)
	if err != nil {
		return err
	}
	return key.Verify([]byte(base), sig.Signature)
}

// ContentDigest is the Content-Digest value for body using SHA-256
// (RFC 9530).
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
}

// ContentDigestMatches reports whether the Content-Digest field in headers
// carries a sha-256 member matching body.
func ContentDigestMatches(headers []Header, body []byte) bool {
	d, err := ParseDictionaryField(headers, "content-digest")
	if err != nil {
		return false
	}
	m, ok := d.Get("sha-256")
	if !ok || m.Item == nil || m.Item.Bare.Kind != sfv.ByteSequence {
		return false
	}
	h := sha256.Sum256(body)
	return string(m.Item.Bare.Bytes) == string(h[:])
}
