// Package revocation builds revocation documents and provides revocation
// checks against credential / agent / key identifiers.
package revocation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// BuildRevocationDocument creates an empty revocation document for entity.
func BuildRevocationDocument(entity string) types.RevocationDocument {
	return types.RevocationDocument{
		AgentpinVersion:    version.ProtocolVersion,
		Entity:             entity,
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
		RevokedCredentials: []types.RevokedCredential{},
		RevokedAgents:      []types.RevokedAgent{},
		RevokedKeys:        []types.RevokedKey{},
	}
}

// AddRevokedCredential records jti as revoked with the given reason.
func AddRevokedCredential(doc *types.RevocationDocument, jti string, reason types.RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedCredentials = append(doc.RevokedCredentials, types.RevokedCredential{
		Jti:       jti,
		RevokedAt: now,
		Reason:    reason,
	})
	doc.UpdatedAt = now
}

// AddRevokedAgent records agentID as revoked with the given reason.
func AddRevokedAgent(doc *types.RevocationDocument, agentID string, reason types.RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedAgents = append(doc.RevokedAgents, types.RevokedAgent{
		AgentID:   agentID,
		RevokedAt: now,
		Reason:    reason,
	})
	doc.UpdatedAt = now
}

// AddRevokedKey records kid as revoked with the given reason.
func AddRevokedKey(doc *types.RevocationDocument, kid string, reason types.RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedKeys = append(doc.RevokedKeys, types.RevokedKey{
		Kid:       kid,
		RevokedAt: now,
		Reason:    reason,
	})
	doc.UpdatedAt = now
}

// CheckRevocation returns a typed VerificationError if the credential, agent,
// or key is on the revocation list.
func CheckRevocation(doc *types.RevocationDocument, jti, agentID, kid string) error {
	for _, rc := range doc.RevokedCredentials {
		if rc.Jti == jti {
			return types.NewVerificationError(
				types.ErrCredentialRevoked,
				fmt.Sprintf("Credential %s revoked: %s", jti, rc.Reason),
			)
		}
	}
	for _, ra := range doc.RevokedAgents {
		if ra.AgentID == agentID {
			return types.NewVerificationError(
				types.ErrAgentInactive,
				fmt.Sprintf("Agent %s revoked: %s", agentID, ra.Reason),
			)
		}
	}
	for _, rk := range doc.RevokedKeys {
		if rk.Kid == kid {
			return types.NewVerificationError(
				types.ErrKeyRevoked,
				fmt.Sprintf("Key %s revoked: %s", kid, rk.Reason),
			)
		}
	}
	return nil
}

// FetchRevocationDocument fetches a revocation document from url.
func FetchRevocationDocument(client *http.Client, url string) (*types.RevocationDocument, error) {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var doc types.RevocationDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s: %w", url, err)
	}
	return &doc, nil
}
