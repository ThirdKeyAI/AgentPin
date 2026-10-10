package discovery

import (
	"encoding/json"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func FuzzDiscoveryAndRevocationJSON(f *testing.F) {
	f.Add([]byte(`{"agentpin_version":"0.1","entity":"example.com","public_keys":[],"agents":[]}`))
	f.Add([]byte(`{"entity":"example.com","revoked_credentials":[{"jti":"x"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var d types.DiscoveryDocument
		if json.Unmarshal(data, &d) == nil {
			_ = ValidateDiscoveryDocument(&d, d.Entity)
		}
		var r types.RevocationDocument
		_ = json.Unmarshal(data, &r)
	})
}
