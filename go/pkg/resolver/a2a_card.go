package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// A2aAgentCardPath is the standard well-known URL suffix for an A2A
// AgentCard.
const A2aAgentCardPath = "/.well-known/agent-card.json"

// A2aAgentCardResolver fetches A2A AgentCards over HTTPS and exposes both the
// original card and the derived DiscoveryDocument.
//
//	GET https://{domain}/.well-known/agent-card.json
//	-> verify AgentPin extension signature
//	-> cross-check that the embedded agentpin_endpoint host == fetched domain
//	-> derive a DiscoveryDocument
type A2aAgentCardResolver struct {
	// Client is the HTTP client used for fetches. When nil, a client with a
	// 10s timeout and no redirects is constructed on first use.
	Client *http.Client

	mu       sync.RWMutex
	lastCard *types.A2aAgentCard
	lastFor  string
}

// NewA2aAgentCardResolver returns a resolver using the default HTTP client.
func NewA2aAgentCardResolver() *A2aAgentCardResolver {
	return &A2aAgentCardResolver{}
}

// LastCard returns the most recently resolved AgentCard for domain, or nil.
func (r *A2aAgentCardResolver) LastCard(domain string) *types.A2aAgentCard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastFor != domain || r.lastCard == nil {
		return nil
	}
	cp := *r.lastCard
	return &cp
}

// ResolveDiscovery fetches and verifies the AgentCard at the standard
// .well-known endpoint for domain, then returns the derived
// DiscoveryDocument.
func (r *A2aAgentCardResolver) ResolveDiscovery(domain string) (*types.DiscoveryDocument, error) {
	client := r.Client
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	url := fmt.Sprintf("https://%s%s", domain, A2aAgentCardPath)
	resp, err := client.Get(url)
	if err != nil {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryFetchFailed,
			fmt.Sprintf("Failed to fetch %s: %s", url, err),
		)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryFetchFailed,
			fmt.Sprintf("Redirect detected fetching %s (status %d). Redirects are not allowed.", url, resp.StatusCode),
		)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryFetchFailed,
			fmt.Sprintf("Failed to fetch %s: HTTP %d", url, resp.StatusCode),
		)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Failed to read AgentCard at %s: %s", url, err),
		)
	}
	var card types.A2aAgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Failed to parse AgentCard at %s: %s", url, err),
		)
	}
	if err := a2a.VerifyAgentpinExtension(&card); err != nil {
		return nil, err
	}
	endpointHost, err := CardEndpointHost(&card)
	if err != nil {
		return nil, err
	}
	if endpointHost != domain {
		return nil, types.NewVerificationError(
			types.ErrDomainMismatch,
			fmt.Sprintf("AgentCard at %s declares agentpin endpoint host %s (mismatch)", domain, endpointHost),
		)
	}
	doc, err := DeriveDiscoveryFromCard(&card)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.lastCard = &card
	r.lastFor = domain
	r.mu.Unlock()
	return &doc, nil
}

// ResolveRevocation always returns (nil, nil) — A2A AgentCards do not carry
// revocation data. Pair with a separate revocation resolver via
// ChainResolver if revocation is required.
func (r *A2aAgentCardResolver) ResolveRevocation(_ string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	return nil, nil
}
