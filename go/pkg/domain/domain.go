// Package domain normalizes and validates domain names.
//
// DNS, TLS hostname matching and the HTTP Host header are case-insensitive,
// but the TOFU pin store, the discovery URL and the entity == iss
// comparison used to operate on the literal iss string, so EXAMPLE.COM,
// example.com. and the U-label/A-label forms of an IDN were distinct
// identities with independent pins (AP-3), and an iss containing a path,
// port or userinfo was interpolated unescaped into file paths and URLs
// (AP-10, AP-12). Normalize is the single choke point applied by every
// verifier, resolver and discovery validator.
package domain

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
)

var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(true),
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
)

func invalid(reason string) error {
	return fmt.Errorf("invalid domain: %s", reason)
}

// Normalize returns the canonical lowercase A-label form of a domain name.
//
// Exactly one trailing dot is removed; the name is lowercased and IDNA
// (UTS-46) mapped; anything that is not a bare hostname is rejected
// (scheme, userinfo, port, path, query, fragment, whitespace, control
// characters, IP literals, empty or over-long labels, leading/trailing
// hyphens). The result is safe as a pin-store key, file name component and
// URL host.
func Normalize(input string) (string, error) {
	if input == "" {
		return "", invalid("empty")
	}
	for _, r := range input {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", invalid("contains whitespace or control characters")
		}
		if strings.ContainsRune("/\\?#@:[]%", r) {
			return "", invalid("not a bare hostname")
		}
	}
	trimmed := strings.TrimSuffix(input, ".")
	if trimmed == "" || strings.HasSuffix(trimmed, ".") {
		return "", invalid("empty label")
	}
	ascii, err := lookupProfile.ToASCII(strings.ToLower(trimmed))
	if err != nil {
		return "", invalid(err.Error())
	}
	ascii = strings.ToLower(ascii)
	if err := validateASCIIHostname(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

func validateASCIIHostname(host string) error {
	if len(host) > maxHostnameLen {
		return invalid("hostname too long")
	}
	if net.ParseIP(host) != nil || looksLikeIPv4(host) {
		return invalid("IP literals are not allowed")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return invalid("empty label")
		}
		if len(label) > maxLabelLen {
			return invalid("label too long")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return invalid("label starts or ends with a hyphen")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return invalid("label contains characters outside [a-z0-9-]")
			}
		}
	}
	return nil
}

func looksLikeIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// HTTPSURLHost parses rawURL, requires the https scheme, no userinfo, no
// explicit port and no fragment, and returns its normalized domain host (IP
// literals are rejected).
func HTTPSURLHost(rawURL string) (string, error) {
	for _, r := range rawURL {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", errors.New("invalid URL: contains whitespace")
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("invalid URL")
	}
	if u.Scheme != "https" {
		return "", errors.New("URL must use https")
	}
	if u.User != nil {
		return "", errors.New("URL must not contain userinfo")
	}
	if u.Port() != "" {
		return "", errors.New("URL must not specify a port")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", errors.New("URL must not contain a fragment")
	}
	host := u.Hostname()
	if host == "" || strings.HasPrefix(u.Host, "[") {
		return "", errors.New("URL host must be a domain name")
	}
	return Normalize(host)
}

// ValidateHTTPSURLForDomain checks that rawURL is an https URL whose host is
// exactly domain after normalization. Used for revocation_endpoint,
// a2a_endpoint and the AgentCard agentpin_endpoint (AP-12).
func ValidateHTTPSURLForDomain(rawURL, domain string) error {
	expected, err := Normalize(domain)
	if err != nil {
		return err
	}
	host, err := HTTPSURLHost(rawURL)
	if err != nil {
		return err
	}
	if host != expected {
		return fmt.Errorf("URL host '%s' does not match domain '%s'", host, expected)
	}
	return nil
}

// DefaultRevocationEndpoint returns the spec §8.1 default revocation URL
// for domain.
func DefaultRevocationEndpoint(domain string) string {
	return "https://" + domain + "/.well-known/agent-identity-revocations.json"
}
