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
	// A2aEndpoint (v0.3.0) optionally identifies the URL of the entity's A2A
	// AgentCard endpoint, enabling cross-protocol discovery.
	A2aEndpoint string `json:"a2a_endpoint,omitempty"`
	// WebBotAuth (optional, v0.4.0) lists the Web Bot Auth key directories
	// this entity vouches for (spec §18).
	WebBotAuth         *WebBotAuth `json:"web_bot_auth,omitempty"`
	MaxDelegationDepth uint8       `json:"max_delegation_depth"`
	UpdatedAt          string      `json:"updated_at"`
}

// WebBotAuth is the Web Bot Auth binding of a discovery document (spec
// §18). SignatureAgents are the HTTPS URLs of the key directories
// (Signature-Agent values) whose keys may sign requests for this entity's
// agents. When the field is absent, only
// https://{entity}/.well-known/http-message-signatures-directory is accepted.
type WebBotAuth struct {
	SignatureAgents []string `json:"signature_agents"`
}
