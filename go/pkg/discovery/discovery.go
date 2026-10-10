// Package discovery builds and validates AgentPin discovery documents and
// (optionally) fetches them over HTTPS from the standard `.well-known`
// endpoint.
package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
	"github.com/ThirdKeyAi/agentpin/go/pkg/fetch"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// BuildDiscoveryDocument creates a new discovery document populated with the
// given keys/agents and the standard revocation endpoint URL.
func BuildDiscoveryDocument(
	entity string,
	entityType types.EntityType,
	publicKeys []types.JWK,
	agents []types.AgentDeclaration,
	maxDelegationDepth uint8,
	updatedAt string,
) types.DiscoveryDocument {
	return types.DiscoveryDocument{
		AgentpinVersion:    version.ProtocolVersion,
		Entity:             entity,
		EntityType:         entityType,
		PublicKeys:         publicKeys,
		Agents:             agents,
		RevocationEndpoint: fmt.Sprintf("https://%s/.well-known/agent-identity-revocations.json", entity),
		MaxDelegationDepth: maxDelegationDepth,
		UpdatedAt:          updatedAt,
	}
}

// ValidateDiscoveryDocument checks the basic structural requirements of a
// discovery document and that its entity matches the expected domain.
func ValidateDiscoveryDocument(doc *types.DiscoveryDocument, expectedEntity string) error {
	if doc.AgentpinVersion != version.ProtocolVersion {
		return fmt.Errorf("unsupported version: %s", doc.AgentpinVersion)
	}
	// Compare entity and the expected domain in normalized form (AP-3).
	expected, err := domain.Normalize(expectedEntity)
	if err != nil {
		return err
	}
	entity, err := domain.Normalize(doc.Entity)
	if err != nil {
		return fmt.Errorf("invalid entity: %w", err)
	}
	if entity != expected {
		return types.NewVerificationError(
			types.ErrDomainMismatch,
			fmt.Sprintf("Discovery entity '%s' does not match expected '%s'", doc.Entity, expectedEntity),
		)
	}
	// Endpoints the verifier may fetch must be https on the entity's own
	// host (AP-12; spec §17 for a2a_endpoint).
	if doc.RevocationEndpoint != "" {
		if err := domain.ValidateHTTPSURLForDomain(doc.RevocationEndpoint, entity); err != nil {
			return fmt.Errorf("invalid revocation_endpoint: %w", err)
		}
	}
	if doc.A2aEndpoint != "" {
		if err := domain.ValidateHTTPSURLForDomain(doc.A2aEndpoint, entity); err != nil {
			return fmt.Errorf("invalid a2a_endpoint: %w", err)
		}
	}
	if len(doc.PublicKeys) == 0 {
		return errors.New("discovery document must have at least one public key")
	}
	if doc.MaxDelegationDepth > 3 {
		return errors.New("max_delegation_depth must be 0-3")
	}
	return nil
}

// FindKeyByKid returns a pointer to the JWK in doc whose kid matches, or nil.
func FindKeyByKid(doc *types.DiscoveryDocument, kid string) *types.JWK {
	for i := range doc.PublicKeys {
		if doc.PublicKeys[i].Kid == kid {
			return &doc.PublicKeys[i]
		}
	}
	return nil
}

// FindAgentByID returns a pointer to the agent in doc whose AgentID matches,
// or nil.
func FindAgentByID(doc *types.DiscoveryDocument, agentID string) *types.AgentDeclaration {
	for i := range doc.Agents {
		if doc.Agents[i].AgentID == agentID {
			return &doc.Agents[i]
		}
	}
	return nil
}

// FetchDiscoveryDocument fetches `https://{domain}/.well-known/agent-identity.json`
// and validates it. Redirects are rejected, the request is bounded by a
// timeout and a 1 MiB body cap, and a JSON content type is required (see
// package fetch). A nil client uses fetch.DefaultClient.
func FetchDiscoveryDocument(client *http.Client, rawDomain string) (*types.DiscoveryDocument, error) {
	domainName, err := domain.Normalize(rawDomain)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s/.well-known/agent-identity.json", domainName)
	body, found, err := fetch.JSONBounded(client, url, 0)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("HTTP 404 fetching %s", url)
	}
	var doc types.DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s", url)
	}
	if err := ValidateDiscoveryDocument(&doc, domainName); err != nil {
		return nil, err
	}
	return &doc, nil
}
