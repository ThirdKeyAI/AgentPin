package types

// EntityType identifies whether a domain acts as a maker, deployer, or both.
type EntityType string

const (
	EntityMaker    EntityType = "maker"
	EntityDeployer EntityType = "deployer"
	EntityBoth     EntityType = "both"
)

// AgentStatus describes the operational state of an agent declaration.
type AgentStatus string

const (
	AgentActive     AgentStatus = "active"
	AgentSuspended  AgentStatus = "suspended"
	AgentDeprecated AgentStatus = "deprecated"
)

// AgentDeclaration is one agent entry inside a discovery document.
type AgentDeclaration struct {
	AgentID          string       `json:"agent_id"`
	AgentType        string       `json:"agent_type,omitempty"`
	Name             string       `json:"name"`
	Description      string       `json:"description,omitempty"`
	Version          string       `json:"version,omitempty"`
	Capabilities     []Capability `json:"capabilities"`
	Constraints      *Constraints `json:"constraints,omitempty"`
	MakerAttestation string       `json:"maker_attestation,omitempty"`
	CredentialTTLMax *uint64      `json:"credential_ttl_max,omitempty"`
	Status           AgentStatus  `json:"status"`
	// DirectoryListing, when set to false, signals that this agent SHOULD NOT
	// be included in public agent directories. Defaults to true if omitted.
	DirectoryListing *bool `json:"directory_listing,omitempty"`
}

// DiscoveryDocument is the top-level `.well-known/agent-identity.json`
// document published by a domain.
type DiscoveryDocument struct {
	AgentpinVersion    string             `json:"agentpin_version"`
	Entity             string             `json:"entity"`
	EntityType         EntityType         `json:"entity_type"`
	PublicKeys         []JWK              `json:"public_keys"`
	Agents             []AgentDeclaration `json:"agents"`
	RevocationEndpoint string             `json:"revocation_endpoint,omitempty"`
	PolicyURL          string             `json:"policy_url,omitempty"`
	SchemapinEndpoint  string             `json:"schemapin_endpoint,omitempty"`
	MaxDelegationDepth uint8              `json:"max_delegation_depth"`
	UpdatedAt          string             `json:"updated_at"`
}
