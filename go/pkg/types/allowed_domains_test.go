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
