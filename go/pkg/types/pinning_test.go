package types

import (
	"encoding/json"
	"testing"
)

func TestTrustLevelJSON(t *testing.T) {
	cases := []struct {
		v    TrustLevel
		want string
	}{
		{TrustTOFU, `"tofu"`},
		{TrustVerified, `"verified"`},
		{TrustPinned, `"pinned"`},
	}
	for _, tc := range cases {
		got, _ := json.Marshal(tc.v)
		if string(got) != tc.want {
			t.Errorf("%q = %s, want %s", tc.v, got, tc.want)
		}
	}
}

func TestPinnedDomainRoundTrip(t *testing.T) {
	pd := PinnedDomain{
		Domain: "example.com",
		PinnedKeys: []PinnedKey{
			{Kid: "k", PublicKeyHash: "abcd", FirstSeen: "f", LastSeen: "l", TrustLevel: TrustTOFU},
		},
	}
	data, err := json.Marshal(pd)
	if err != nil {
		t.Fatal(err)
	}
	var pd2 PinnedDomain
	if err := json.Unmarshal(data, &pd2); err != nil {
		t.Fatal(err)
	}
	if pd2.Domain != pd.Domain || pd2.PinnedKeys[0].Kid != pd.PinnedKeys[0].Kid {
		t.Fatal("roundtrip mismatch")
	}
}
