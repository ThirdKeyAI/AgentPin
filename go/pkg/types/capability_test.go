package types

import (
	"encoding/json"
	"testing"
)

func TestCapabilityParse(t *testing.T) {
	c := Capability("read:codebase")
	if a := c.Action(); a != "read" {
		t.Fatalf("Action() = %q, want %q", a, "read")
	}
	if r := c.Resource(); r != "codebase" {
		t.Fatalf("Resource() = %q, want %q", r, "codebase")
	}
}

func TestCapabilityMatchesWildcard(t *testing.T) {
	wild := Capability("read:*")
	if !wild.Matches("read:codebase") {
		t.Fatal("read:* should match read:codebase")
	}
	if !wild.Matches("read:database") {
		t.Fatal("read:* should match read:database")
	}
	if wild.Matches("write:codebase") {
		t.Fatal("read:* should NOT match write:codebase")
	}
}

func TestCapabilityMatchesScoped(t *testing.T) {
	cap := Capability("read:codebase")
	if !cap.Matches("read:codebase.github.com/org/repo") {
		t.Fatal("scoped match expected")
	}
	if cap.Matches("read:codebase_other") {
		t.Fatal("non-dot suffix must not match")
	}
}

func TestCapabilitiesSubset(t *testing.T) {
	declared := []Capability{"read:*", "write:report"}
	requested := []Capability{"read:codebase", "write:report"}
	if !CapabilitiesSubset(declared, requested) {
		t.Fatal("requested should be a subset")
	}
	bad := []Capability{"delete:database"}
	if CapabilitiesSubset(declared, bad) {
		t.Fatal("delete:database should not be covered")
	}
}

func TestCapabilitiesHashOrderIndependent(t *testing.T) {
	a := []Capability{"read:codebase", "write:report"}
	b := []Capability{"write:report", "read:codebase"}
	if CapabilitiesHash(a) != CapabilitiesHash(b) {
		t.Fatal("CapabilitiesHash must be order-independent")
	}
}

func TestValidateCapability(t *testing.T) {
	cases := []struct {
		cap   Capability
		valid bool
	}{
		{"read:codebase", true},
		{"read:*", true},
		{"admin:*", false},
		{"admin:users", true},
		{"com.example.scan:target", true},
		{"scan:target", false},
		{"readcodebase", false},
	}
	for _, tc := range cases {
		err := ValidateCapability(tc.cap)
		got := err == nil
		if got != tc.valid {
			t.Errorf("ValidateCapability(%q) = %v, want valid=%v", tc.cap, err, tc.valid)
		}
	}
}

func TestCapabilityJSONRoundTrip(t *testing.T) {
	c := Capability("read:data")
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `"read:data"` {
		t.Fatalf("Capability JSON = %s, want \"read:data\"", data)
	}
	var c2 Capability
	if err := json.Unmarshal(data, &c2); err != nil {
		t.Fatal(err)
	}
	if c != c2 {
		t.Fatalf("roundtrip mismatch: %q != %q", c, c2)
	}
}
