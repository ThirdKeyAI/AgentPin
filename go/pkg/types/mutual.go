package types

// Challenge is the AgentPin mutual-auth challenge wire payload.
type Challenge struct {
	Type               string `json:"type"`
	Nonce              string `json:"nonce"`
	Timestamp          string `json:"timestamp"`
	VerifierCredential string `json:"verifier_credential,omitempty"`
}

// Response is the AgentPin mutual-auth response wire payload.
type Response struct {
	Type      string `json:"type"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	Kid       string `json:"kid"`
}
