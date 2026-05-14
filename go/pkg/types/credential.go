package types

// DelegationRole identifies which role a delegating party plays in a chain.
type DelegationRole string

const (
	RoleMaker    DelegationRole = "maker"
	RoleDeployer DelegationRole = "deployer"
)

// DelegationAttestation is one entry in a credential's delegation chain.
type DelegationAttestation struct {
	Domain      string         `json:"domain"`
	Role        DelegationRole `json:"role"`
	AgentID     string         `json:"agent_id"`
	Kid         string         `json:"kid"`
	Attestation string         `json:"attestation"`
}

// JWTHeader is the AgentPin credential JWT header.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWTPayload is the AgentPin credential JWT body.
type JWTPayload struct {
	Iss             string                  `json:"iss"`
	Sub             string                  `json:"sub"`
	Aud             string                  `json:"aud,omitempty"`
	Iat             int64                   `json:"iat"`
	Exp             int64                   `json:"exp"`
	Nbf             *int64                  `json:"nbf,omitempty"`
	Jti             string                  `json:"jti"`
	AgentpinVersion string                  `json:"agentpin_version"`
	Capabilities    []Capability            `json:"capabilities"`
	Constraints     *Constraints            `json:"constraints,omitempty"`
	DelegationChain []DelegationAttestation `json:"delegation_chain,omitempty"`
	Nonce           string                  `json:"nonce,omitempty"`
}
