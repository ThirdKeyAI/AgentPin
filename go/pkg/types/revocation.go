package types

// RevocationReason enumerates why a credential, agent, or key was revoked.
type RevocationReason string

const (
	ReasonKeyCompromise        RevocationReason = "key_compromise"
	ReasonAffiliationChanged   RevocationReason = "affiliation_changed"
	ReasonSuperseded           RevocationReason = "superseded"
	ReasonCessationOfOperation RevocationReason = "cessation_of_operation"
	ReasonPrivilegeWithdrawn   RevocationReason = "privilege_withdrawn"
	ReasonPolicyViolation      RevocationReason = "policy_violation"
)

// RevokedCredential identifies a single revoked credential by its JTI.
type RevokedCredential struct {
	Jti       string           `json:"jti"`
	RevokedAt string           `json:"revoked_at"`
	Reason    RevocationReason `json:"reason"`
}

// RevokedAgent identifies a single revoked agent by URN.
type RevokedAgent struct {
	AgentID   string           `json:"agent_id"`
	RevokedAt string           `json:"revoked_at"`
	Reason    RevocationReason `json:"reason"`
}

// RevokedKey identifies a single revoked key by KID.
type RevokedKey struct {
	Kid       string           `json:"kid"`
	RevokedAt string           `json:"revoked_at"`
	Reason    RevocationReason `json:"reason"`
}

// RevocationDocument is the top-level
// `.well-known/agent-identity-revocations.json` payload.
type RevocationDocument struct {
	AgentpinVersion    string              `json:"agentpin_version"`
	Entity             string              `json:"entity"`
	UpdatedAt          string              `json:"updated_at"`
	RevokedCredentials []RevokedCredential `json:"revoked_credentials"`
	RevokedAgents      []RevokedAgent      `json:"revoked_agents"`
	RevokedKeys        []RevokedKey        `json:"revoked_keys"`
}
