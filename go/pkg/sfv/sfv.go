// Package sfv is a minimal, strict implementation of HTTP Structured Field
// Values (RFC 8941, RFC 9651): Dictionaries, Inner Lists, Items and
// Parameters with String, Token, Integer, Decimal, Boolean, Byte Sequence,
// Date and Display String bare items. Serialization is canonical, so
// values round-trip byte for byte with the other AgentPin SDKs.
package sfv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind identifies a bare item type.
type Kind int

const (
	Integer Kind = iota
	Decimal
	String
	Token
	ByteSequence
	Boolean
	Date
	DisplayString
)

// BareItem is one bare item. Int holds Integer and Date values, and
// Decimal values scaled by 1000. Str holds String, Token and Display
// String values.
type BareItem struct {
	Kind  Kind
	Int   int64
	Str   string
	Bytes []byte
	Bool  bool
}

// Int returns an Integer item.
func Int(v int64) BareItem { return BareItem{Kind: Integer, Int: v} }

// Str returns a String item.
func Str(s string) BareItem { return BareItem{Kind: String, Str: s} }

// Bytes returns a Byte Sequence item.
func Bytes(b []byte) BareItem { return BareItem{Kind: ByteSequence, Bytes: b} }

// Bool returns a Boolean item.
func Bool(v bool) BareItem { return BareItem{Kind: Boolean, Bool: v} }

// Equal reports whether two bare items have the same type and value.
func (b BareItem) Equal(o BareItem) bool {
	if b.Kind != o.Kind {
		return false
	}
	switch b.Kind {
	case Integer, Decimal, Date:
		return b.Int == o.Int
	case String, Token, DisplayString:
		return b.Str == o.Str
	case ByteSequence:
		return string(b.Bytes) == string(o.Bytes)
	default:
		return b.Bool == o.Bool
	}
}

// Param is one parameter.
type Param struct {
	Key   string
	Value BareItem
}

// Params is an ordered parameter map.
type Params []Param

// Get returns the value of key.
func (p Params) Get(key string) (BareItem, bool) {
	for _, kv := range p {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return BareItem{}, false
}

// Set replaces the value of key in place, or appends it. It reports
// whether key was already present.
func (p *Params) Set(key string, v BareItem) bool {
	for i := range *p {
		if (*p)[i].Key == key {
			(*p)[i].Value = v
			return true
		}
	}
	*p = append(*p, Param{key, v})
	return false
}

// Item is a bare item with parameters.
type Item struct {
	Bare   BareItem
	Params Params
}

// InnerList is a parenthesized list of items with parameters.
type InnerList struct {
	Items  []Item
	Params Params
}

// Member is a Dictionary or List member: exactly one of Item and Inner is
// set.
type Member struct {
	Item  *Item
	Inner *InnerList
}

// DictEntry is one Dictionary member.
type DictEntry struct {
	Key   string
	Value Member
}

// Dictionary is an ordered map of members.
type Dictionary []DictEntry

// Get returns the member named key.
func (d Dictionary) Get(key string) (Member, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return Member{}, false
}

// Set replaces the member named key in place, or appends it.
func (d *Dictionary) Set(key string, m Member) {
	for i := range *d {
		if (*d)[i].Key == key {
			(*d)[i].Value = m
			return
		}
	}
	*d = append(*d, DictEntry{key, m})
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

type parser struct {
	s string
	i int
}

func (p *parser) peek() int {
	if p.i < len(p.s) {
		return int(p.s[p.i])
	}
	return -1
}

func (p *parser) fail(what string) error {
	return fmt.Errorf("structured field: %s at offset %d", what, p.i)
}

func (p *parser) sp() {
	for p.peek() == ' ' {
		p.i++
	}
}

func (p *parser) ows() {
	for c := p.peek(); c == ' ' || c == '\t'; c = p.peek() {
		p.i++
	}
}

func (p *parser) top(f func() error) error {
	p.sp()
	if err := f(); err != nil {
		return err
	}
	p.sp()
	if p.i != len(p.s) {
		return p.fail("trailing characters")
	}
	return nil
}

// ParseDictionary parses a Dictionary field value.
func ParseDictionary(s string) (Dictionary, error) {
	p := &parser{s: s}
	var d Dictionary
	err := p.top(func() error {
		return p.commaSeparated(func() error {
			key, err := p.key()
			if err != nil {
				return err
			}
			var m Member
			if p.peek() == '=' {
				p.i++
				if m, err = p.member(); err != nil {
					return err
				}
			} else {
				params, err := p.params()
				if err != nil {
					return err
				}
				m = Member{Item: &Item{Bare: Bool(true), Params: params}}
			}
			d.Set(key, m)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// ParseList parses a List field value.
func ParseList(s string) ([]Member, error) {
	p := &parser{s: s}
	var l []Member
	err := p.top(func() error {
		return p.commaSeparated(func() error {
			m, err := p.member()
			if err == nil {
				l = append(l, m)
			}
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// ParseItem parses an Item field value.
func ParseItem(s string) (Item, error) {
	p := &parser{s: s}
	var it Item
	err := p.top(func() error {
		var err error
		it, err = p.item()
		return err
	})
	return it, err
}

func (p *parser) commaSeparated(member func() error) error {
	for p.peek() >= 0 {
		if err := member(); err != nil {
			return err
		}
		p.ows()
		if p.peek() < 0 {
			return nil
		}
		if p.peek() != ',' {
			return p.fail("expected comma")
		}
		p.i++
		p.ows()
		if p.peek() < 0 {
			return p.fail("trailing comma")
		}
	}
	return nil
}

func (p *parser) member() (Member, error) {
	if p.peek() == '(' {
		il, err := p.innerList()
		return Member{Inner: &il}, err
	}
	it, err := p.item()
	return Member{Item: &it}, err
}

func (p *parser) innerList() (InnerList, error) {
	var il InnerList
	p.i++ // '('
	for p.peek() >= 0 {
		p.sp()
		if p.peek() == ')' {
			p.i++
			params, err := p.params()
			il.Params = params
			return il, err
		}
		it, err := p.item()
		if err != nil {
			return il, err
		}
		il.Items = append(il.Items, it)
		if c := p.peek(); c >= 0 && c != ' ' && c != ')' {
			return il, p.fail("expected inner list delimiter")
		}
	}
	return il, p.fail("unterminated inner list")
}

func (p *parser) item() (Item, error) {
	b, err := p.bare()
	if err != nil {
		return Item{}, err
	}
	params, err := p.params()
	return Item{Bare: b, Params: params}, err
}

func (p *parser) params() (Params, error) {
	var ps Params
	for p.peek() == ';' {
		p.i++
		p.sp()
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		v := Bool(true)
		if p.peek() == '=' {
			p.i++
			if v, err = p.bare(); err != nil {
				return nil, err
			}
		}
		ps.Set(key, v)
	}
	return ps, nil
}

func isLCAlpha(c int) bool { return c >= 'a' && c <= 'z' }
func isDigit(c int) bool   { return c >= '0' && c <= '9' }
func isAlpha(c int) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }

func isTChar(c int) bool {
	return isAlpha(c) || isDigit(c) || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}

func isKeyStart(c int) bool { return isLCAlpha(c) || c == '*' }

func isKeyChar(c int) bool {
	return isLCAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '*' || c == '.'
}

func isTokenStart(c int) bool { return isAlpha(c) || c == '*' }
func isTokenChar(c int) bool  { return isTChar(c) || c == ':' || c == '/' }

func (p *parser) key() (string, error) {
	if !isKeyStart(p.peek()) {
		return "", p.fail("expected key")
	}
	start := p.i
	for p.i++; isKeyChar(p.peek()); p.i++ {
	}
	return p.s[start:p.i], nil
}

func (p *parser) bare() (BareItem, error) {
	c := p.peek()
	switch {
	case c == '?':
		p.i++
		switch p.peek() {
		case '0':
			p.i++
			return Bool(false), nil
		case '1':
			p.i++
			return Bool(true), nil
		}
		return BareItem{}, p.fail("expected boolean")
	case c == '"':
		s, err := p.str()
		return Str(s), err
	case c == ':':
		return p.byteSeq()
	case c == '@':
		p.i++
		n, err := p.number()
		if err != nil {
			return BareItem{}, err
		}
		if n.Kind != Integer {
			return BareItem{}, p.fail("non-integer date")
		}
		return BareItem{Kind: Date, Int: n.Int}, nil
	case c == '%':
		return p.displayString()
	case isTokenStart(c):
		start := p.i
		for p.i++; isTokenChar(p.peek()); p.i++ {
		}
		return BareItem{Kind: Token, Str: p.s[start:p.i]}, nil
	case c == '-' || isDigit(c):
		return p.number()
	}
	return BareItem{}, p.fail("expected bare item")
}

func (p *parser) str() (string, error) {
	p.i++ // '"'
	var b strings.Builder
	for p.peek() >= 0 {
		c := p.peek()
		p.i++
		switch {
		case c == '"':
			return b.String(), nil
		case c < 0x20 || c > 0x7e:
			p.i--
			return "", p.fail("invalid string character")
		case c == '\\':
			n := p.peek()
			if n != '"' && n != '\\' {
				return "", p.fail("invalid escape")
			}
			p.i++
			b.WriteByte(byte(n))
		default:
			b.WriteByte(byte(c))
		}
	}
	return "", p.fail("unterminated string")
}

func (p *parser) byteSeq() (BareItem, error) {
	p.i++ // ':'
	end := strings.IndexByte(p.s[p.i:], ':')
	if end < 0 {
		return BareItem{}, p.fail("unterminated byte sequence")
	}
	enc := p.s[p.i : p.i+end]
	p.i += end + 1
	b, err := decodeBase64(enc)
	if err != nil {
		return BareItem{}, p.fail("invalid byte sequence")
	}
	return Bytes(b), nil
}

// decodeBase64 accepts standard base64 with canonical or missing padding
// and non-zero trailing bits, and nothing else (no whitespace).
func decodeBase64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := int(s[i])
		if !(isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '=') {
			return nil, errors.New("invalid base64 character")
		}
	}
	body := strings.TrimRight(s, "=")
	if strings.Contains(body, "=") {
		return nil, errors.New("invalid padding")
	}
	if pad := len(s) - len(body); pad > 0 && (pad > 2 || len(s)%4 != 0) {
		return nil, errors.New("invalid padding")
	}
	return base64.RawStdEncoding.DecodeString(body)
}

func (p *parser) number() (BareItem, error) {
	sign := int64(1)
	if p.peek() == '-' {
		sign = -1
		p.i++
	}
	if !isDigit(p.peek()) {
		return BareItem{}, p.fail("expected digit")
	}
	var mag int64
	digits := 0
	for isDigit(p.peek()) {
		digits++
		if digits > 15 {
			return BareItem{}, p.fail("too many digits")
		}
		mag = mag*10 + int64(p.peek()-'0')
		p.i++
	}
	if p.peek() != '.' {
		return Int(sign * mag), nil
	}
	if digits > 12 {
		return BareItem{}, p.fail("too many digits before decimal point")
	}
	p.i++
	mag *= 1000
	scale := int64(100)
	for isDigit(p.peek()) {
		if scale == 0 {
			return BareItem{}, p.fail("too many digits after decimal point")
		}
		mag += int64(p.peek()-'0') * scale
		scale /= 10
		p.i++
	}
	if scale == 100 {
		return BareItem{}, p.fail("trailing decimal point")
	}
	return BareItem{Kind: Decimal, Int: sign * mag}, nil
}

func hexVal(c int) int {
	switch {
	case isDigit(c):
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return -1
}

func (p *parser) displayString() (BareItem, error) {
	p.i++ // '%'
	if p.peek() != '"' {
		return BareItem{}, p.fail("expected quote")
	}
	p.i++
	var b []byte
	for p.peek() >= 0 {
		c := p.peek()
		p.i++
		switch {
		case c == '"':
			if !utf8.Valid(b) {
				return BareItem{}, p.fail("invalid UTF-8 in display string")
			}
			return BareItem{Kind: DisplayString, Str: string(b)}, nil
		case c < 0x20 || c > 0x7e:
			p.i--
			return BareItem{}, p.fail("invalid display string character")
		case c == '%':
			hi, lo := hexVal(p.peek()), -1
			if hi >= 0 {
				p.i++
				lo = hexVal(p.peek())
			}
			if lo < 0 {
				return BareItem{}, p.fail("invalid escape")
			}
			p.i++
			b = append(b, byte(hi<<4|lo))
		default:
			b = append(b, byte(c))
		}
	}
	return BareItem{}, p.fail("unterminated display string")
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

const maxInteger = 999_999_999_999_999

// ValidKey reports whether s is a valid key.
func ValidKey(s string) bool {
	if s == "" || !isKeyStart(int(s[0])) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isKeyChar(int(s[i])) {
			return false
		}
	}
	return true
}

// ValidString reports whether s can be serialized as a String.
func ValidString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func writeKey(b *strings.Builder, k string) error {
	if !ValidKey(k) {
		return fmt.Errorf("structured field: invalid key %q", k)
	}
	b.WriteString(k)
	return nil
}

func writeBare(b *strings.Builder, v BareItem) error {
	switch v.Kind {
	case Integer:
		if v.Int > maxInteger || v.Int < -maxInteger {
			return errors.New("structured field: integer out of range")
		}
		b.WriteString(strconv.FormatInt(v.Int, 10))
	case Date:
		if v.Int > maxInteger || v.Int < -maxInteger {
			return errors.New("structured field: date out of range")
		}
		b.WriteByte('@')
		b.WriteString(strconv.FormatInt(v.Int, 10))
	case Decimal:
		if v.Int > maxInteger || v.Int < -maxInteger {
			return errors.New("structured field: decimal out of range")
		}
		writeDecimal(b, v.Int)
	case String:
		if !ValidString(v.Str) {
			return errors.New("structured field: invalid string character")
		}
		b.WriteByte('"')
		for i := 0; i < len(v.Str); i++ {
			if c := v.Str[i]; c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(v.Str[i])
		}
		b.WriteByte('"')
	case Token:
		if v.Str == "" || !isTokenStart(int(v.Str[0])) {
			return errors.New("structured field: invalid token")
		}
		for i := 1; i < len(v.Str); i++ {
			if !isTokenChar(int(v.Str[i])) {
				return errors.New("structured field: invalid token")
			}
		}
		b.WriteString(v.Str)
	case ByteSequence:
		b.WriteByte(':')
		b.WriteString(base64.StdEncoding.EncodeToString(v.Bytes))
		b.WriteByte(':')
	case Boolean:
		if v.Bool {
			b.WriteString("?1")
		} else {
			b.WriteString("?0")
		}
	case DisplayString:
		const hex = "0123456789abcdef"
		b.WriteString(`%"`)
		for i := 0; i < len(v.Str); i++ {
			c := v.Str[i]
			if c == '%' || c == '"' || c < 0x20 || c > 0x7e {
				b.WriteByte('%')
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&15])
			} else {
				b.WriteByte(c)
			}
		}
		b.WriteByte('"')
	default:
		return errors.New("structured field: unknown item kind")
	}
	return nil
}

func writeDecimal(b *strings.Builder, v int64) {
	if v == 0 {
		b.WriteString("0.0")
		return
	}
	if v < 0 {
		b.WriteByte('-')
		v = -v
	}
	ip, fp := v/1000, v%1000
	b.WriteString(strconv.FormatInt(ip, 10))
	b.WriteByte('.')
	switch {
	case fp%100 == 0:
		fmt.Fprintf(b, "%d", fp/100)
	case fp%10 == 0:
		fmt.Fprintf(b, "%02d", fp/10)
	default:
		fmt.Fprintf(b, "%03d", fp)
	}
}

func writeParams(b *strings.Builder, ps Params) error {
	for _, kv := range ps {
		b.WriteByte(';')
		if err := writeKey(b, kv.Key); err != nil {
			return err
		}
		if kv.Value.Kind == Boolean && kv.Value.Bool {
			continue
		}
		b.WriteByte('=')
		if err := writeBare(b, kv.Value); err != nil {
			return err
		}
	}
	return nil
}

func writeItem(b *strings.Builder, it Item) error {
	if err := writeBare(b, it.Bare); err != nil {
		return err
	}
	return writeParams(b, it.Params)
}

func writeInner(b *strings.Builder, il InnerList) error {
	b.WriteByte('(')
	for i, it := range il.Items {
		if i > 0 {
			b.WriteByte(' ')
		}
		if err := writeItem(b, it); err != nil {
			return err
		}
	}
	b.WriteByte(')')
	return writeParams(b, il.Params)
}

func writeMember(b *strings.Builder, m Member) error {
	switch {
	case m.Inner != nil:
		return writeInner(b, *m.Inner)
	case m.Item != nil:
		return writeItem(b, *m.Item)
	}
	return errors.New("structured field: empty member")
}

// SerializeItem serializes an Item.
func SerializeItem(it Item) (string, error) {
	var b strings.Builder
	err := writeItem(&b, it)
	return b.String(), err
}

// SerializeList serializes a List.
func SerializeList(l []Member) (string, error) {
	var b strings.Builder
	for i, m := range l {
		if i > 0 {
			b.WriteString(", ")
		}
		if err := writeMember(&b, m); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// SerializeDictionary serializes a Dictionary.
func SerializeDictionary(d Dictionary) (string, error) {
	var b strings.Builder
	for i, e := range d {
		if i > 0 {
			b.WriteString(", ")
		}
		if err := writeKey(&b, e.Key); err != nil {
			return "", err
		}
		if it := e.Value.Item; it != nil && e.Value.Inner == nil && it.Bare.Kind == Boolean && it.Bare.Bool {
			if err := writeParams(&b, it.Params); err != nil {
				return "", err
			}
			continue
		}
		b.WriteByte('=')
		if err := writeMember(&b, e.Value); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}
