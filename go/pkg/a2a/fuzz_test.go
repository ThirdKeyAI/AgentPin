package a2a

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func FuzzAgentCardCanonicalization(f *testing.F) {
	f.Add([]byte(`{"name":"a","url":"https://example.com","capabilities":{},"skills":[{"id":"x","name":"x","tags":["t"]}],"x":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var card types.A2aAgentCard
		if json.Unmarshal(data, &card) != nil {
			return
		}
		first, err := AgentCardSigningInput(&card)
		if err != nil {
			return
		}
		// Canonicalization must be stable across a JSON round trip.
		raw, err := json.Marshal(card)
		if err != nil {
			t.Fatal(err)
		}
		var again types.A2aAgentCard
		if err := json.Unmarshal(raw, &again); err != nil {
			t.Fatal(err)
		}
		second, err := AgentCardSigningInput(&again)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("unstable canonicalization: %v\n%s\n%s", err, first, second)
		}
		_ = VerifyAgentpinExtension(&card)
	})
}
