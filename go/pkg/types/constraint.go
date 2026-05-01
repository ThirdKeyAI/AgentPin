package types

import (
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
type Constraints struct {
	AllowedDomains        []string            `json:"allowed_domains,omitempty"`
	DeniedDomains         []string            `json:"denied_domains,omitempty"`
	RateLimit             string              `json:"rate_limit,omitempty"`
	DataClassificationMax *DataClassification `json:"data_classification_max,omitempty"`
	IPAllowlist           []string            `json:"ip_allowlist,omitempty"`
	ValidHours            *ValidHours         `json:"valid_hours,omitempty"`
}

// ConstraintsSubsetOf reports whether a credential's constraints are equal to
// or more restrictive than the discovery declaration's constraints.
//
// nil discovery constraints permit anything; nil credential constraints inherit
// the discovery defaults.
func ConstraintsSubsetOf(discovery, credential *Constraints) bool {
	if discovery == nil {
		return true
	}
	if credential == nil {
		return true
	}

	if discovery.DataClassificationMax != nil && credential.DataClassificationMax != nil {
		if credential.DataClassificationMax.Order() > discovery.DataClassificationMax.Order() {
			return false
		}
	}

	if discovery.RateLimit != "" && credential.RateLimit != "" {
		dRate, dOK := parseRateLimit(discovery.RateLimit)
		cRate, cOK := parseRateLimit(credential.RateLimit)
		if dOK && cOK && cRate > dRate {
			return false
		}
	}

	if len(discovery.AllowedDomains) > 0 && len(credential.AllowedDomains) > 0 {
		for _, cd := range credential.AllowedDomains {
			matched := false
			for _, dd := range discovery.AllowedDomains {
				if domainPatternMatches(dd, cd) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	return true
}

// parseRateLimit converts a rate-limit string like "100/hour" into requests
// per hour.
func parseRateLimit(rate string) (uint64, bool) {
	parts := strings.SplitN(rate, "/", 2)
	if len(parts) != 2 {
		return 0, false
	}
	n, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	switch parts[1] {
	case "second":
		return n * 3600, true
	case "minute":
		return n * 60, true
	case "hour":
		return n, true
	}
	return 0, false
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
