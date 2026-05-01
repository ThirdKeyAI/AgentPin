package bundle

import (
	"encoding/json"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func TestNewTrustBundle(t *testing.T) {
	b := NewTrustBundle("2026-02-10T00:00:00Z")
	if b.AgentpinBundleVersion != "0.1" {
		t.Fatal("bundle version")
	}
	if len(b.Documents) != 0 || len(b.Revocations) != 0 {
		t.Fatal("should start empty")
	}
}

func TestFindHelpers(t *testing.T) {
	b := types.TrustBundle{
		Documents: []types.DiscoveryDocument{{Entity: "example.com"}},
	}
	if FindBundleDiscovery(&b, "example.com") == nil {
		t.Fatal("hit")
	}
	if FindBundleDiscovery(&b, "missing") != nil {
		t.Fatal("miss")
	}
}

func TestBundleSerializesEmpty(t *testing.T) {
	b := NewTrustBundle("2026-02-10T00:00:00Z")
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var b2 types.TrustBundle
	if err := json.Unmarshal(data, &b2); err != nil {
		t.Fatal(err)
	}
}
