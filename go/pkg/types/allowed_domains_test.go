package types

import "testing"

func TestAllowedDomainsUnrestrictedAcceptsAnything(t *testing.T) {
	h := AllowedDomainsHelper
	ad := h.Unrestricted()
	if !h.IsUnrestricted(ad) {
		t.Fatal("expected unrestricted")
	}
	if !h.Allows(ad, "anything.com") {
		t.Fatal("unrestricted should allow everything")
	}
}

func TestAllowedDomainsRestrictedFilters(t *testing.T) {
	h := AllowedDomainsHelper
	ad := h.FromDomains([]string{"a.com", "b.com"})
	if h.IsUnrestricted(ad) {
		t.Fatal("expected restricted")
	}
	if !h.Allows(ad, "a.com") {
		t.Fatal("should allow a.com")
	}
	if h.Allows(ad, "c.com") {
		t.Fatal("should reject c.com")
	}
}

func TestAllowedDomainsIntersectWithUnrestrictedReturnsOther(t *testing.T) {
	h := AllowedDomainsHelper
	unrestricted := h.Unrestricted()
	restricted := h.FromDomains([]string{"a.com", "b.com"})
	if got := h.Intersect(unrestricted, restricted); !sliceEqual(got, restricted) {
		t.Fatalf("got %v", got)
	}
	if got := h.Intersect(restricted, unrestricted); !sliceEqual(got, restricted) {
		t.Fatalf("got %v", got)
	}
}

func TestAllowedDomainsIntersectReturnsOverlap(t *testing.T) {
	h := AllowedDomainsHelper
	lhs := h.FromDomains([]string{"a.com", "b.com", "c.com"})
	rhs := h.FromDomains([]string{"b.com", "c.com", "d.com"})
	got := h.Intersect(lhs, rhs)
	want := []string{"b.com", "c.com"}
	if !sliceEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAllowedDomainsFromConstraints(t *testing.T) {
	h := AllowedDomainsHelper
	c := &Constraints{AllowedDomains: []string{"a.com"}}
	if got := h.FromConstraints(c); !sliceEqual(got, []string{"a.com"}) {
		t.Fatalf("got %v", got)
	}
	if got := h.FromConstraints(nil); !h.IsUnrestricted(got) {
		t.Fatalf("got %v", got)
	}
	if got := h.FromConstraints(&Constraints{}); !h.IsUnrestricted(got) {
		t.Fatalf("got %v", got)
	}
	// AP-6: a present-but-empty list is restricted to nothing.
	if got := h.FromConstraints(&Constraints{AllowedDomains: []string{}}); h.IsUnrestricted(got) {
		t.Fatalf("empty list must be restricted, got %v", got)
	}
}

// AP-6: disjoint allow-lists intersect to "restricted to nothing".
func TestAllowedDomainsIntersectNoOverlapAllowsNothing(t *testing.T) {
	h := AllowedDomainsHelper
	got := h.Intersect(h.FromDomains([]string{"a.com"}), h.FromDomains([]string{"b.com"}))
	if h.IsUnrestricted(got) || len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if h.Allows(got, "a.com") || h.Allows(got, "anything.com") {
		t.Fatal("restricted-to-nothing must allow nothing")
	}
	if h.Allows(h.FromDomains(nil), "x.com") {
		t.Fatal("empty restricted list must allow nothing")
	}
}

// AP-6: Allows and Intersect use the §5.5 pattern rules.
func TestAllowedDomainsPatternMatching(t *testing.T) {
	h := AllowedDomainsHelper
	wild := h.FromDomains([]string{"*.corp.com"})
	if !h.Allows(wild, "api.corp.com") || h.Allows(wild, "corp.com") || h.Allows(wild, "evil-corp.com") {
		t.Fatal("pattern matching wrong")
	}
	literal := h.FromDomains([]string{"api.corp.com"})
	if got := h.Intersect(wild, literal); !sliceEqual(got, []string{"api.corp.com"}) {
		t.Fatalf("got %v", got)
	}
	if got := h.Intersect(literal, wild); !sliceEqual(got, []string{"api.corp.com"}) {
		t.Fatalf("got %v", got)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
