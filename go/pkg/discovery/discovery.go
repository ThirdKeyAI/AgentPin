// Package discovery builds and validates AgentPin discovery documents and
// (optionally) fetches them over HTTPS from the standard `.well-known`
// endpoint.
package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
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
	if doc.Entity != expectedEntity {
		return types.NewVerificationError(
			types.ErrDomainMismatch,
			fmt.Sprintf("Discovery entity '%s' does not match expected '%s'", doc.Entity, expectedEntity),
		)
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
// and validates it. Redirects are rejected: the discovery endpoint MUST be
// served directly from the canonical hostname.
func FetchDiscoveryDocument(client *http.Client, domain string) (*types.DiscoveryDocument, error) {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	url := fmt.Sprintf("https://%s/.well-known/agent-identity.json", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("redirect detected fetching %s (status %d). Redirects are not allowed", url, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var doc types.DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s: %w", url, err)
	}
	if err := ValidateDiscoveryDocument(&doc, domain); err != nil {
		return nil, err
	}
	return &doc, nil
}
