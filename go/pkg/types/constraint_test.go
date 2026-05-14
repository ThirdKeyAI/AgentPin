package types

import (
	"encoding/json"
	"testing"
)

func TestDataClassificationOrdering(t *testing.T) {
	if DataPublic.Order() >= DataInternal.Order() {
		t.Fatal("public should be < internal")
	}
	if DataInternal.Order() >= DataConfidential.Order() {
		t.Fatal("internal should be < confidential")
	}
	if DataConfidential.Order() >= DataRestricted.Order() {
		t.Fatal("confidential should be < restricted")
	}
}

func TestParseRateLimit(t *testing.T) {
	cases := []struct {
		in  string
		out uint64
		ok  bool
	}{
		{"100/hour", 100, true},
		{"10/minute", 600, true},
		{"1/second", 3600, true},
		{"bad", 0, false},
		{"100/year", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseRateLimit(tc.in)
		if got != tc.out || ok != tc.ok {
			t.Errorf("parseRateLimit(%q) = (%d,%v), want (%d,%v)", tc.in, got, ok, tc.out, tc.ok)
		}
	}
}

func TestDomainPatternMatches(t *testing.T) {
	if !domainPatternMatches("example.com", "example.com") {
		t.Fatal("exact match")
	}
	if !domainPatternMatches("*.example.com", "sub.example.com") {
		t.Fatal("wildcard subdomain")
	}
	if domainPatternMatches("*.example.com", "example.com") {
		t.Fatal("wildcard does not match bare")
	}
	if domainPatternMatches("other.com", "example.com") {
		t.Fatal("different domains must not match")
	}
}

func TestConstraintsSubsetOf(t *testing.T) {
	conf := DataConfidential
	intl := DataInternal
	rest := DataRestricted

	disc := &Constraints{
		DataClassificationMax: &conf,
		RateLimit:             "100/hour",
	}
	credOK := &Constraints{
		DataClassificationMax: &intl,
		RateLimit:             "50/hour",
	}
	if !ConstraintsSubsetOf(disc, credOK) {
		t.Fatal("credOK should be a subset")
	}

	credBad := &Constraints{
		DataClassificationMax: &rest,
	}
	if ConstraintsSubsetOf(disc, credBad) {
		t.Fatal("restricted > confidential should fail")
	}
}

func TestConstraintsJSONRoundTrip(t *testing.T) {
	intl := DataInternal
	c := Constraints{
		AllowedDomains:        []string{"*.example.com"},
		RateLimit:             "50/hour",
		DataClassificationMax: &intl,
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var c2 Constraints
	if err := json.Unmarshal(data, &c2); err != nil {
		t.Fatal(err)
	}
	if c2.RateLimit != c.RateLimit || *c2.DataClassificationMax != *c.DataClassificationMax {
		t.Fatal("constraints roundtrip mismatch")
	}
}
