// Package dns implements DNS TXT cross-verification at _agentpin.{domain}
// (v0.3.0).
//
// Wire format mirrors SchemaPin's _schemapin record exactly with the version
// tag changed:
//
//	_agentpin.example.com.  3600  IN  TXT  "v=agentpin1; kid=acme-2026-04; fp=sha256:a1b2c3..."
//
// Semantics:
//   - Absent record       -> no effect (DNS TXT is purely additive)
//   - Present matching    -> verification succeeds
//   - Present mismatching / malformed -> hard failure
//
// Mismatch is fail-closed because a publisher who *intentionally* published
// a TXT record has signaled DNS is part of their trust chain.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

const (
	version  = "agentpin1"
	fpPrefix = "sha256:"
)

// TxtRecord is a parsed `_agentpin.{domain}` TXT record.
type TxtRecord struct {
	Version     string
	Kid         string // empty when unspecified
	Fingerprint string // lower-case, "sha256:<hex>"
}

// ParseTxtRecord parses a raw TXT record value such as
// "v=agentpin1; kid=acme-2026-04; fp=sha256:abcd1234".
//
// Whitespace around ';' and '=' is tolerated. Field order is not significant.
// Unknown fields are ignored for forward compatibility. Returns an error if
// the record is missing the required v or fp fields, the version is not
// agentpin1, or the fingerprint is malformed.
func ParseTxtRecord(value string) (*TxtRecord, error) {
	var ver, kid, fp string

	for _, raw := range strings.Split(value, ";") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return nil, types.NewVerificationError(
				types.ErrDiscoveryInvalid,
				fmt.Sprintf("DNS TXT field missing '=': %s", part),
			)
		}
		k := strings.ToLower(strings.TrimSpace(part[:eq]))
		v := strings.TrimSpace(part[eq+1:])
		switch k {
		case "v":
			ver = v
		case "kid":
			kid = v
		case "fp":
			fp = strings.ToLower(v)
		default:
			// Forward-compat: ignore unknown fields.
		}
	}

	if ver == "" {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"DNS TXT record missing required 'v' field",
		)
	}
	if ver != version {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("DNS TXT unsupported version: %s", ver),
		)
	}
	if fp == "" {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"DNS TXT record missing required 'fp' field",
		)
	}
	if !strings.HasPrefix(fp, fpPrefix) {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("DNS TXT 'fp' must be sha256:<hex>: %s", fp),
		)
	}
	return &TxtRecord{Version: ver, Kid: kid, Fingerprint: fp}, nil
}

// VerifyDnsMatch cross-checks a parsed TXT record against a discovery
// document. Returns nil on success or a typed VerificationError on mismatch.
//
// When the TXT specifies a kid, the matching key MUST also carry the same
// kid. Multi-key discovery documents only need one key to match.
func VerifyDnsMatch(discovery *types.DiscoveryDocument, txt *TxtRecord) error {
	if discovery == nil || txt == nil {
		return types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"verify_dns_match: nil discovery or TXT",
		)
	}
	target := strings.ToLower(txt.Fingerprint)
	for i := range discovery.PublicKeys {
		k := &discovery.PublicKeys[i]
		computed := strings.ToLower(jwk.JWKThumbprint(k))
		if !strings.HasPrefix(computed, fpPrefix) {
			computed = fpPrefix + computed
		}
		if computed != target {
			continue
		}
		if txt.Kid != "" && k.Kid != txt.Kid {
			continue
		}
		return nil
	}
	return types.NewVerificationError(
		types.ErrDiscoveryInvalid,
		fmt.Sprintf("DNS TXT fingerprint %s does not match any key in the discovery document", target),
	)
}

// TxtRecordName returns the DNS lookup name for an AgentPin domain
// ("_agentpin.{domain}", trailing dot stripped).
func TxtRecordName(domain string) string {
	return "_agentpin." + strings.TrimRight(domain, ".")
}

// LookupTxt performs the DNS TXT lookup at _agentpin.{domain} via the given
// resolver (use net.DefaultResolver for the system resolver).
//
// Returns (nil, nil) when no _agentpin record exists for the domain (or the
// resolver reports NXDOMAIN / no answer). Returns a parse error when the
// record exists but is malformed.
//
// When the resolver returns multiple TXT records at the same name, the first
// whose value contains "v=agentpin1" is used.
func LookupTxt(ctx context.Context, resolver *net.Resolver, domain string) (*TxtRecord, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	name := TxtRecordName(domain)
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || dnsErr.Err == "no such host") {
			return nil, nil
		}
		return nil, types.NewVerificationError(
			types.ErrDiscoveryFetchFailed,
			fmt.Sprintf("DNS TXT lookup failed for %s: %s", name, err),
		)
	}
	for _, value := range records {
		if strings.Contains(value, "v=agentpin1") {
			return ParseTxtRecord(value)
		}
	}
	return nil, nil
}
