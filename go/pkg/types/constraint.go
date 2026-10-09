package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// DataClassification orders allowed data sensitivity levels from least to most
// sensitive. Lower-ordinal values are less restrictive.
type DataClassification string

const (
	DataPublic       DataClassification = "public"
	DataInternal     DataClassification = "internal"
	DataConfidential DataClassification = "confidential"
	DataRestricted   DataClassification = "restricted"
)

// Order returns the comparable rank of a classification. Higher means more
// sensitive.
func (d DataClassification) Order() int {
	switch d {
	case DataPublic:
		return 0
	case DataInternal:
		return 1
	case DataConfidential:
		return 2
	case DataRestricted:
		return 3
	}
	return -1
}

// ValidHours describes a time-of-day validity window for a credential.
type ValidHours struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Timezone string `json:"timezone"`
}

// Constraints describes optional usage constraints attached to a credential
// or to a discovery agent declaration.
//
// List fields distinguish nil (absent on the wire) from an empty non-nil
// slice (present as []): an empty allowed_domains means "restricted to
// nothing", not "unrestricted" (AP-6), so the custom MarshalJSON emits
// present-but-empty lists instead of dropping them.
type Constraints struct {
	AllowedDomains        []string            `json:"allowed_domains,omitempty"`
	DeniedDomains         []string            `json:"denied_domains,omitempty"`
	RateLimit             string              `json:"rate_limit,omitempty"`
	DataClassificationMax *DataClassification `json:"data_classification_max,omitempty"`
	IPAllowlist           []string            `json:"ip_allowlist,omitempty"`
	ValidHours            *ValidHours         `json:"valid_hours,omitempty"`
}

// MarshalJSON emits list fields whenever they are non-nil, including when
// empty, so "restricted to nothing" survives a round trip.
func (c Constraints) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{}
	if c.AllowedDomains != nil {
		out["allowed_domains"] = c.AllowedDomains
	}
	if c.DeniedDomains != nil {
		out["denied_domains"] = c.DeniedDomains
	}
	if c.RateLimit != "" {
		out["rate_limit"] = c.RateLimit
	}
	if c.DataClassificationMax != nil {
		out["data_classification_max"] = *c.DataClassificationMax
	}
	if c.IPAllowlist != nil {
		out["ip_allowlist"] = c.IPAllowlist
	}
	if c.ValidHours != nil {
		out["valid_hours"] = c.ValidHours
	}
	return json.Marshal(out)
}

// ConstraintsSubsetOf reports whether a credential's constraints are equal to
// or more restrictive than the discovery declaration's constraints.
func ConstraintsSubsetOf(discovery, credential *Constraints) bool {
	_, err := MergeConstraints(discovery, credential)
	return err == nil
}

// MergeConstraints computes the effective constraints of a credential: the
// discovery declaration's defaults narrowed by whatever the credential
// declares (AP-15). Every field is compared; the credential may only narrow,
// never widen, and omitting a field inherits the discovery default instead
// of silently dropping it. An unparsable rate_limit on either side is an
// error. Returns nil when neither side declares constraints.
func MergeConstraints(discovery, credential *Constraints) (*Constraints, error) {
	switch {
	case discovery == nil && credential == nil:
		return nil, nil
	case credential == nil:
		cp := *discovery
		return &cp, nil
	case discovery == nil:
		if err := validateRateLimitField(credential.RateLimit); err != nil {
			return nil, err
		}
		cp := *credential
		return &cp, nil
	}
	merged := *discovery

	if credential.DataClassificationMax != nil {
		if discovery.DataClassificationMax != nil &&
			credential.DataClassificationMax.Order() > discovery.DataClassificationMax.Order() {
			return nil, fmt.Errorf("data_classification_max %s exceeds discovery maximum %s",
				*credential.DataClassificationMax, *discovery.DataClassificationMax)
		}
		v := *credential.DataClassificationMax
		merged.DataClassificationMax = &v
	}

	if err := validateRateLimitField(discovery.RateLimit); err != nil {
		return nil, err
	}
	if err := validateRateLimitField(credential.RateLimit); err != nil {
		return nil, err
	}
	if credential.RateLimit != "" {
		if discovery.RateLimit != "" {
			cRate, _ := parseRateLimit(credential.RateLimit)
			dRate, _ := parseRateLimit(discovery.RateLimit)
			if cRate > dRate {
				return nil, fmt.Errorf("rate_limit %s exceeds discovery limit %s", credential.RateLimit, discovery.RateLimit)
			}
		}
		merged.RateLimit = credential.RateLimit
	}

	if credential.AllowedDomains != nil {
		if discovery.AllowedDomains != nil {
			for _, cd := range credential.AllowedDomains {
				matched := false
				for _, dd := range discovery.AllowedDomains {
					if domainPatternMatches(dd, cd) {
						matched = true
						break
					}
				}
				if !matched {
					return nil, fmt.Errorf("allowed_domains entry '%s' is not covered by discovery allowed_domains", cd)
				}
			}
		}
		merged.AllowedDomains = append([]string{}, credential.AllowedDomains...)
	}

	if credential.DeniedDomains != nil {
		union := append([]string{}, discovery.DeniedDomains...)
		for _, d := range credential.DeniedDomains {
			if !containsString(union, d) {
				union = append(union, d)
			}
		}
		merged.DeniedDomains = union
	}

	if credential.IPAllowlist != nil {
		if discovery.IPAllowlist != nil {
			for _, ip := range credential.IPAllowlist {
				if !containsString(discovery.IPAllowlist, ip) {
					return nil, fmt.Errorf("ip_allowlist entry '%s' is not in discovery ip_allowlist", ip)
				}
			}
		}
		merged.IPAllowlist = append([]string{}, credential.IPAllowlist...)
	}

	if credential.ValidHours != nil {
		if discovery.ValidHours != nil {
			c, d := credential.ValidHours, discovery.ValidHours
			if c.Timezone != d.Timezone || c.Start < d.Start || c.End > d.End {
				return nil, errors.New("valid_hours widens the discovery window")
			}
		}
		v := *credential.ValidHours
		merged.ValidHours = &v
	}

	return &merged, nil
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func validateRateLimitField(rate string) error {
	if rate == "" {
		return nil
	}
	if _, ok := parseRateLimit(rate); !ok {
		return fmt.Errorf("unparsable rate_limit '%s'", rate)
	}
	return nil
}

// parseRateLimit converts a rate-limit string like "100/hour" into requests
// per hour. Malformed strings and values that would overflow yield false.
func parseRateLimit(rate string) (uint64, bool) {
	parts := strings.SplitN(rate, "/", 2)
	if len(parts) != 2 || parts[0] == "" {
		return 0, false
	}
	for i := 0; i < len(parts[0]); i++ {
		if parts[0][i] < '0' || parts[0][i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	switch parts[1] {
	case "second":
		if n > math.MaxUint64/3600 {
			return 0, false
		}
		return n * 3600, true
	case "minute":
		if n > math.MaxUint64/60 {
			return 0, false
		}
		return n * 60, true
	case "hour":
		return n, true
	}
	return 0, false
}

// DomainPatternMatches reports whether a "*.suffix" or exact-match domain
// pattern (spec §5.5) matches a domain.
func DomainPatternMatches(pattern, domain string) bool {
	return domainPatternMatches(pattern, domain)
}

// domainPatternMatches reports whether a "*.suffix" or exact-match domain
// pattern matches a domain.
func domainPatternMatches(pattern, domain string) bool {
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(domain, suffix) &&
			len(domain) > len(suffix) &&
			domain[len(domain)-len(suffix)-1] == '.'
	}
	return false
}
