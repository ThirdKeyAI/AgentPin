package resolver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
	"github.com/ThirdKeyAi/agentpin/go/pkg/fetch"
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
	// Client is the HTTP client used for fetches. When nil, fetch.DefaultClient
	// (10 s timeout, no redirects) is used; a supplied client's redirect
	// policy is always overridden so redirects are rejected.
	Client *http.Client
	// SkipDiscoveryBinding disables spec §4.10.4 step 5. By default, after
	// the card signature verifies, the domain's
	// .well-known/agent-identity.json is fetched and the card key must be
	// published there by thumbprint (AP-4). Skip only when another channel
	// establishes the card's provenance.
	SkipDiscoveryBinding bool

	mu       sync.RWMutex
	lastCard *types.A2aAgentCard
	lastFor  string
}

// NewA2aAgentCardResolver returns a resolver using the default HTTP client
// with discovery binding required.
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
func (r *A2aAgentCardResolver) ResolveDiscovery(rawDomain string) (*types.DiscoveryDocument, error) {
	domainName, err := domain.Normalize(rawDomain)
	if err != nil {
		return nil, types.NewVerificationError(types.ErrDiscoveryInvalid, err.Error())
	}
	url := fmt.Sprintf("https://%s%s", domainName, A2aAgentCardPath)
	// No redirects (spec §4.8.5), bounded timeout and body size (AP-7, AP-13).
	body, found, err := fetch.JSONBounded(r.Client, url, 0)
	if err != nil {
		return nil, types.NewVerificationError(types.ErrDiscoveryFetchFailed, err.Error())
	}
	if !found {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryFetchFailed,
			fmt.Sprintf("Failed to fetch %s: HTTP 404", url),
		)
	}
	var card types.A2aAgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Failed to parse AgentCard at %s", url),
		)
	}
	if err := a2a.VerifyAgentpinExtension(&card); err != nil {
		return nil, err
	}
	endpointHost, err := CardEndpointHost(&card)
	if err != nil {
		return nil, err
	}
	if endpointHost != domainName {
		return nil, types.NewVerificationError(
			types.ErrDomainMismatch,
			fmt.Sprintf("AgentCard at %s declares agentpin endpoint host %s (mismatch)", domainName, endpointHost),
		)
	}
	// Spec §4.10.4 step 5 (AP-4): bind the card to the AgentPin identity by
	// requiring its key in the authoritative discovery document.
	if !r.SkipDiscoveryBinding {
		authoritative, err := discovery.FetchDiscoveryDocument(r.Client, domainName)
		if err != nil {
			return nil, types.NewVerificationError(types.ErrDiscoveryFetchFailed, err.Error())
		}
		if !CardKeyPublishedIn(authoritative, &card) {
			return nil, types.NewVerificationError(types.ErrDiscoveryInvalid,
				fmt.Sprintf("AgentCard key for %s is not published in the domain's discovery document", domainName))
		}
	}
	doc, err := DeriveDiscoveryFromCard(&card)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.lastCard = &card
	r.lastFor = domainName
	r.mu.Unlock()
	return &doc, nil
}

// ResolveRevocation always returns (nil, nil) — A2A AgentCards do not carry
// revocation data. Pair with a separate revocation resolver via
// ChainResolver if revocation is required.
func (r *A2aAgentCardResolver) ResolveRevocation(_ string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	return nil, nil
}
