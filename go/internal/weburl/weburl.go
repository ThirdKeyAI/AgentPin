// Package weburl parses absolute URLs into the serialized form the WHATWG
// URL Standard produces (lowercase scheme and host, default port dropped,
// dot segments removed, the standard percent-encode sets applied). RFC 9421
// derived components and Web Bot Auth identifiers are compared in this
// form, and the Rust SDK produces it with the `url` crate, so signers and
// verifiers in different languages see the same bytes.
package weburl

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// URL is an absolute URL split into its serialized parts.
type URL struct {
	Scheme   string // lowercase
	Userinfo string // "user:pass" as written; empty when absent
	Host     string // lowercase A-label host; IPv6 in brackets
	Port     string // empty when absent or the scheme default
	Path     string // percent-encoded, never empty for hierarchical URLs
	Query    *string
	Fragment *string
}

var hostProfile = idna.New(idna.MapForLookup(), idna.Transitional(false))

var defaultPorts = map[string]string{
	"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21",
}

// Parse parses an absolute URL with a host.
func Parse(raw string) (*URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Hostname() == "" {
		return nil, errors.New("not an absolute URL with a host")
	}
	out := &URL{Scheme: strings.ToLower(u.Scheme)}

	rest := raw[len(u.Scheme)+1:]
	if !strings.HasPrefix(rest, "//") {
		return nil, errors.New("not an absolute URL with a host")
	}
	rest = rest[2:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	rest = rest[end:]
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		info := authority[:i]
		if user, pass, _ := strings.Cut(info, ":"); user != "" || pass != "" {
			out.Userinfo = info
		}
	}

	host := u.Hostname()
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, errors.New("invalid IPv6 host")
		}
		out.Host = "[" + ip.String() + "]"
	} else if isASCII(host) {
		out.Host = strings.ToLower(host)
	} else {
		a, err := hostProfile.ToASCII(host)
		if err != nil {
			return nil, errors.New("invalid host")
		}
		out.Host = a
	}

	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, errors.New("invalid port")
		}
		p = strconv.FormatUint(n, 10)
		if defaultPorts[out.Scheme] != p {
			out.Port = p
		}
	}

	if i := strings.IndexByte(rest, '#'); i >= 0 {
		f := encode(rest[i+1:], fragmentSet)
		out.Fragment = &f
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q := encode(rest[i+1:], querySet)
		out.Query = &q
		rest = rest[:i]
	}
	out.Path = normalizePath(encode(rest, pathSet))
	return out, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Authority is the host plus a non-default port.
func (u *URL) Authority() string {
	if u.Port != "" {
		return u.Host + ":" + u.Port
	}
	return u.Host
}

// String serializes the whole URL.
func (u *URL) String() string {
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.Userinfo != "" {
		b.WriteString(u.Userinfo)
		b.WriteByte('@')
	}
	b.WriteString(u.Authority())
	b.WriteString(u.Path)
	if u.Query != nil {
		b.WriteByte('?')
		b.WriteString(*u.Query)
	}
	if u.Fragment != nil {
		b.WriteByte('#')
		b.WriteString(*u.Fragment)
	}
	return b.String()
}

// NormalizeSignatureAgent normalizes a Web Bot Auth Signature-Agent URL
// into the identifier form the draft compares (§5.5): absolute https URL
// with a host and no credentials, query and fragment dropped.
func NormalizeSignatureAgent(raw string) (string, error) {
	u, err := Parse(raw)
	if err != nil {
		return "", errors.New("Signature-Agent is not an absolute URL")
	}
	if u.Scheme != "https" {
		return "", errors.New("Signature-Agent must be an https URL with a host")
	}
	if u.Userinfo != "" {
		return "", errors.New("Signature-Agent must not carry credentials")
	}
	u.Query, u.Fragment = nil, nil
	return u.String(), nil
}

type encodeSet func(c byte) bool

func c0(c byte) bool { return c < 0x20 || c > 0x7e }

func fragmentSet(c byte) bool {
	return c0(c) || c == ' ' || c == '"' || c == '<' || c == '>' || c == '`'
}

func querySet(c byte) bool {
	return c0(c) || c == ' ' || c == '"' || c == '#' || c == '<' || c == '>' || c == '\''
}

func pathSet(c byte) bool {
	return fragmentSet(c) || c == '#' || c == '?' || c == '{' || c == '}'
}

func encode(s string, set encodeSet) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if set(c) {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isSingleDot(s string) bool { return s == "." || strings.EqualFold(s, "%2e") }

func isDoubleDot(s string) bool {
	switch strings.ToLower(s) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

// normalizePath removes dot segments the way the WHATWG path parser does.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		last := i == len(segs)-1
		switch {
		case isDoubleDot(s):
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case isSingleDot(s):
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}
