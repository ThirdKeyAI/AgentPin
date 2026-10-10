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

// AP-15: overflow and junk rate limits are rejected, never wrapped.
func TestParseRateLimitRejectsOverflowAndJunk(t *testing.T) {
	for _, in := range []string{"18446744073709551615/second", "unlimited/hour", "-5/hour", "5/day", "+5/hour"} {
		if _, ok := parseRateLimit(in); ok {
			t.Errorf("parseRateLimit(%q) accepted", in)
		}
	}
}

// AP-15: omitted credential fields inherit discovery defaults, every field
// is compared, unparsable rate limits are violations.
func TestMergeConstraints(t *testing.T) {
	conf := DataConfidential
	intl := DataInternal
	rest := DataRestricted
	disc := &Constraints{
		AllowedDomains:        []string{"*.client-corp.com"},
		DeniedDomains:         []string{"internal.client-corp.com"},
		RateLimit:             "100/hour",
		DataClassificationMax: &conf,
		IPAllowlist:           []string{"203.0.113.0/24", "198.51.100.0/24"},
		ValidHours:            &ValidHours{Start: "08:00", End: "18:00", Timezone: "UTC"},
	}
	m, err := MergeConstraints(disc, nil)
	if err != nil || m == nil || len(m.AllowedDomains) != 1 {
		t.Fatalf("omitted credential constraints must inherit: %+v %v", m, err)
	}
	m, err = MergeConstraints(disc, &Constraints{RateLimit: "1/minute", DataClassificationMax: &intl, DeniedDomains: []string{"staging.client-corp.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !sliceEqual(m.AllowedDomains, disc.AllowedDomains) || m.RateLimit != "1/minute" || *m.DataClassificationMax != DataInternal ||
		!sliceEqual(m.DeniedDomains, []string{"internal.client-corp.com", "staging.client-corp.com"}) ||
		!sliceEqual(m.IPAllowlist, disc.IPAllowlist) || m.ValidHours.Start != "08:00" {
		t.Fatalf("merge wrong: %+v", m)
	}
	widen := []*Constraints{
		{AllowedDomains: []string{"evil.com"}},
		{RateLimit: "1000/hour"},
		{RateLimit: "unlimited/hour"},
		{DataClassificationMax: &rest},
		{IPAllowlist: []string{"0.0.0.0/0"}},
		{ValidHours: &ValidHours{Start: "07:00", End: "18:00", Timezone: "UTC"}},
		{ValidHours: &ValidHours{Start: "09:00", End: "17:00", Timezone: "America/New_York"}},
	}
	for i, c := range widen {
		if _, err := MergeConstraints(disc, c); err == nil {
			t.Errorf("widen case %d accepted", i)
		}
	}
	narrow := &Constraints{AllowedDomains: []string{"api.client-corp.com"}, IPAllowlist: []string{"203.0.113.0/24"},
		ValidHours: &ValidHours{Start: "09:00", End: "17:00", Timezone: "UTC"}}
	m, err = MergeConstraints(disc, narrow)
	if err != nil || !sliceEqual(m.AllowedDomains, narrow.AllowedDomains) || m.RateLimit != "100/hour" || m.ValidHours.Start != "09:00" {
		t.Fatalf("narrow merge wrong: %+v %v", m, err)
	}
	if _, err := MergeConstraints(nil, &Constraints{RateLimit: "x/hour"}); err == nil {
		t.Fatal("unparsable credential rate_limit must fail even without discovery constraints")
	}
	if m, err := MergeConstraints(nil, nil); err != nil || m != nil {
		t.Fatal("nil/nil must be nil")
	}
}

// AP-6: an empty allowed_domains survives a JSON round trip.
func TestConstraintsEmptyAllowedDomainsRoundTrips(t *testing.T) {
	data, err := json.Marshal(Constraints{AllowedDomains: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"allowed_domains":[]}` {
		t.Fatalf("got %s", data)
	}
	var back Constraints
	_ = json.Unmarshal(data, &back)
	if back.AllowedDomains == nil || len(back.AllowedDomains) != 0 {
		t.Fatalf("round trip lost restricted-to-nothing: %+v", back)
	}
	data, _ = json.Marshal(Constraints{})
	if string(data) != `{}` {
		t.Fatalf("nil lists must be omitted, got %s", data)
	}
}
