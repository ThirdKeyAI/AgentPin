package types

// AllowedDomains is a helper namespace for the "allowed_domains" constraint
// treated as a typed allow-list (v0.3.0, made a proper tri-state in v0.4 —
// AP-6).
//
// Lists are plain []string with three states: a nil slice is *unrestricted*
// (the field is absent on the wire); a non-nil slice, including an empty
// one, is *restricted* to the listed literals and "*." patterns (spec §5.5).
// "No restriction" and "restricted to nothing" are therefore distinct: the
// intersection of two disjoint allow-lists is an empty non-nil slice, which
// allows nothing and is never re-interpreted as unrestricted.
type AllowedDomains struct{}

// Unrestricted returns the unrestricted allow-list (nil).
func (AllowedDomains) Unrestricted() []string {
	return nil
}

// FromDomains constructs a restricted allow-list from a slice of strings.
// An empty input yields an empty non-nil slice, which allows nothing.
func (AllowedDomains) FromDomains(domains []string) []string {
	out := make([]string, len(domains))
	copy(out, domains)
	return out
}

// IsUnrestricted reports whether the list places no restriction (nil).
func (AllowedDomains) IsUnrestricted(list []string) bool {
	return list == nil
}

// Allows reports whether domain is permitted under the allow-list. A nil
// list allows everything; entries are matched with the §5.5 pattern rules;
// an empty non-nil list allows nothing.
func (a AllowedDomains) Allows(list []string, domain string) bool {
	if a.IsUnrestricted(list) {
		return true
	}
	for _, pattern := range list {
		if DomainPatternMatches(pattern, domain) {
			return true
		}
	}
	return false
}

// Intersect returns the intersection of two allow-lists: unrestricted ∩ X =
// X; otherwise the entries of either list that are allowed by the other (so
// "*.corp.com" ∩ "api.corp.com" = "api.corp.com"). Disjoint lists yield an
// empty non-nil slice, which allows nothing.
func (a AllowedDomains) Intersect(lhs, rhs []string) []string {
	if a.IsUnrestricted(lhs) {
		if rhs == nil {
			return nil
		}
		return append([]string{}, rhs...)
	}
	if a.IsUnrestricted(rhs) {
		return append([]string{}, lhs...)
	}
	out := make([]string, 0)
	add := func(d string) {
		for _, x := range out {
			if x == d {
				return
			}
		}
		out = append(out, d)
	}
	for _, d := range lhs {
		if a.Allows(rhs, d) {
			add(d)
		}
	}
	for _, d := range rhs {
		if a.Allows(lhs, d) {
			add(d)
		}
	}
	return out
}

// FromConstraints extracts the allow-list from a Constraints value. Returns
// Unrestricted() when constraints is nil or allowed_domains is absent, and a
// copy of the list (including an empty one) when present.
func (a AllowedDomains) FromConstraints(c *Constraints) []string {
	if c == nil || c.AllowedDomains == nil {
		return a.Unrestricted()
	}
	return a.FromDomains(c.AllowedDomains)
}

// AllowedDomainsHelper is the singleton instance used to access the helper
// methods, e.g. types.AllowedDomainsHelper.Intersect(a, b).
var AllowedDomainsHelper AllowedDomains
