package jwk

import (
	"encoding/json"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func FuzzJWKToVerifyingKey(f *testing.F) {
	f.Add([]byte(`{"kid":"k","kty":"EC","crv":"P-256","x":"AA","y":"AA","use":"sig"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var j types.JWK
		if json.Unmarshal(data, &j) == nil {
			_, _ = JWKToVerifyingKey(&j)
			_ = JWKThumbprint(&j)
		}
	})
}
