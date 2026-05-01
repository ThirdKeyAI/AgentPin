package types

// JWK is the AgentPin JSON Web Key representation. It mirrors the Rust
// `agentpin::jwk::Jwk` struct field-for-field so wire format is identical.
type JWK struct {
	Kid    string   `json:"kid"`
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops,omitempty"`
	Exp    string   `json:"exp,omitempty"`
}
