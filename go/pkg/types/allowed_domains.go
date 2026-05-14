package types

// AllowedDomains is a helper namespace for the "allowed_domains" constraint
// treated as a typed allow-list (v0.3.0).
//
// Convention: an empty list means *unrestricted* (all domains trusted); a
// non-empty list restricts the agent to exactly those domains. Mirrors the
// AllowedDomains type in the Rust SDK.
//
// Lists are plain []string; the package exposes only static helpers so callers
// can keep using slices directly.
type AllowedDomains struct{}

// Unrestricted returns an empty (unrestricted) allow-list.
func (AllowedDomains) Unrestricted() []string {
	return nil
}

// FromDomains constructs an allow-list from a slice of strings.
func (AllowedDomains) FromDomains(domains []string) []string {
	out := make([]string, len(domains))
	copy(out, domains)
	return out
}

// IsUnrestricted reports whether the list is empty (no restriction).
func (AllowedDomains) IsUnrestricted(list []string) bool {
	return len(list) == 0
}

// Allows reports whether domain is permitted under the allow-list. An empty
// list allows everything.
func (a AllowedDomains) Allows(list []string, domain string) bool {
	if a.IsUnrestricted(list) {
		return true
	}
	for _, d := range list {
		if d == domain {
			return true
		}
	}
	return false
}

// Intersect returns the intersection of two allow-lists. Following the
// convention that empty = unrestricted: unrestricted ∩ X = X.
func (a AllowedDomains) Intersect(lhs, rhs []string) []string {
	if a.IsUnrestricted(lhs) {
		return append([]string{}, rhs...)
	}
	if a.IsUnrestricted(rhs) {
		return append([]string{}, lhs...)
	}
	rhsSet := make(map[string]struct{}, len(rhs))
	for _, d := range rhs {
		rhsSet[d] = struct{}{}
	}
	out := make([]string, 0)
	for _, d := range lhs {
		if _, ok := rhsSet[d]; ok {
			out = append(out, d)
		}
	}
	return out
}

// FromConstraints extracts the allow-list from a Constraints value. Returns
// Unrestricted() when constraints is nil or has no allowed_domains.
func (a AllowedDomains) FromConstraints(c *Constraints) []string {
	if c == nil || len(c.AllowedDomains) == 0 {
		return a.Unrestricted()
	}
	return a.FromDomains(c.AllowedDomains)
}

// AllowedDomainsHelper is the singleton instance used to access the helper
// methods, e.g. types.AllowedDomainsHelper.Intersect(a, b).
var AllowedDomainsHelper AllowedDomains
