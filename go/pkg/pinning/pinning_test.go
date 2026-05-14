package pinning

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func makeJWK(kid, x string) *types.JWK {
	return &types.JWK{
		Kid: kid, Kty: "EC", Crv: "P-256",
		X: x, Y: "test-y", Use: "sig",
	}
}

func TestFirstUsePinsKey(t *testing.T) {
	store := NewKeyPinStore()
	j := makeJWK("k", "x1")
	if r := store.CheckAndPin("example.com", j); r != ResultFirstUse {
		t.Fatalf("first call should be FirstUse, got %v", r)
	}
	if r := store.CheckAndPin("example.com", j); r != ResultMatched {
		t.Fatalf("second call should be Matched, got %v", r)
	}
}

func TestKeyChangeDetected(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("example.com", makeJWK("k", "x1"))
	if r := store.CheckAndPin("example.com", makeJWK("k", "x2")); r != ResultChanged {
		t.Fatalf("changed key should be Changed, got %v", r)
	}
}

func TestAddKeyAllowsRotation(t *testing.T) {
	store := NewKeyPinStore()
	j1 := makeJWK("k1", "x1")
	j2 := makeJWK("k2", "x2")
	store.CheckAndPin("example.com", j1)
	store.AddKey("example.com", j2)
	if r := store.CheckAndPin("example.com", j2); r != ResultMatched {
		t.Fatalf("rotated key should match, got %v", r)
	}
}

func TestPinJSONRoundTrip(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("example.com", makeJWK("k", "x"))
	data, err := store.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	store2 := NewKeyPinStore()
	if err := store2.LoadFromJSON(data); err != nil {
		t.Fatal(err)
	}
	if pd := store2.GetDomain("example.com"); pd == nil || len(pd.PinnedKeys) != 1 {
		t.Fatalf("after roundtrip: %+v", pd)
	}
}

func TestCheckPinningError(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("example.com", makeJWK("k", "x1"))
	if _, err := CheckPinning(store, "example.com", makeJWK("k", "x2")); err == nil {
		t.Fatal("expected pin error")
	}
}

func TestDifferentDomainsIndependent(t *testing.T) {
	store := NewKeyPinStore()
	store.CheckAndPin("a.com", makeJWK("k", "xa"))
	store.CheckAndPin("b.com", makeJWK("k", "xb"))
	if r := store.CheckAndPin("a.com", makeJWK("k", "xb")); r != ResultChanged {
		t.Fatalf("cross-domain: got %v", r)
	}
}
