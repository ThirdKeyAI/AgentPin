package resolver

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// LocalAgentCardStore is an in-memory store of pre-registered A2A AgentCards
// keyed by their AgentPin discovery domain (v0.3.0).
//
// Mirrors the Rust agentpin::resolver_local::LocalAgentCardStore. Cards are
// added via Register (after the extension signature is verified) and looked
// up via ResolveDiscovery. Backs Symbiont's push-based external-agent
// registration flow.
type LocalAgentCardStore struct {
	mu    sync.RWMutex
	cards map[string]types.A2aAgentCard
	docs  map[string]types.DiscoveryDocument
}

// NewLocalAgentCardStore constructs an empty store.
func NewLocalAgentCardStore() *LocalAgentCardStore {
	return &LocalAgentCardStore{
		cards: make(map[string]types.A2aAgentCard),
		docs:  make(map[string]types.DiscoveryDocument),
	}
}

// Register verifies the extension signature on card and stores it keyed by
// the host of its agentpin_endpoint. Re-registering an existing domain
// replaces the prior entry — useful for handling key rotation.
func (s *LocalAgentCardStore) Register(card types.A2aAgentCard) error {
	if err := a2a.VerifyAgentpinExtension(&card); err != nil {
		return err
	}
	domain, err := CardEndpointHost(&card)
	if err != nil {
		return err
	}
	doc, err := DeriveDiscoveryFromCard(&card)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cards[domain] = card
	s.docs[domain] = doc
	return nil
}

// Len returns the number of registered AgentCards.
func (s *LocalAgentCardStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cards)
}

// IsEmpty reports whether no AgentCards are registered.
func (s *LocalAgentCardStore) IsEmpty() bool {
	return s.Len() == 0
}

// ResolveCard returns the original AgentCard for domain, or (zero, false).
func (s *LocalAgentCardStore) ResolveCard(domain string) (types.A2aAgentCard, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cards[domain]
	return c, ok
}

// ResolveDiscovery returns the derived DiscoveryDocument for domain. Returns
// a typed VerificationError(ErrDiscoveryInvalid) when the domain isn't
// registered.
func (s *LocalAgentCardStore) ResolveDiscovery(domain string) (*types.DiscoveryDocument, error) {
	s.mu.RLock()
	doc, ok := s.docs[domain]
	s.mu.RUnlock()
	if !ok {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Domain '%s' not in LocalAgentCardStore", domain),
		)
	}
	cp := doc
	return &cp, nil
}

// ResolveRevocation always returns (nil, nil) — the store carries no
// revocation data. Pair with another resolver via ChainResolver if revocation
// is required.
func (s *LocalAgentCardStore) ResolveRevocation(_ string, _ *types.DiscoveryDocument) (*types.RevocationDocument, error) {
	return nil, nil
}

// Remove drops a registered AgentCard. Returns true when one was removed.
func (s *LocalAgentCardStore) Remove(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cards[domain]
	delete(s.cards, domain)
	delete(s.docs, domain)
	return ok
}

// CardEndpointHost extracts the host portion of an AgentCard's
// agentpin_endpoint URL.
func CardEndpointHost(card *types.A2aAgentCard) (string, error) {
	if card == nil || card.Agentpin == nil {
		return "", types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"AgentCard has no agentpin extension",
		)
	}
	u, err := url.Parse(card.Agentpin.AgentpinEndpoint)
	if err != nil {
		return "", types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Invalid agentpin_endpoint URL: %s", err),
		)
	}
	if u.Hostname() == "" {
		return "", types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"agentpin_endpoint URL has no host",
		)
	}
	return u.Hostname(), nil
}

// DeriveDiscoveryFromCard turns a signed A2A AgentCard into a minimal
// DiscoveryDocument so the rest of the AgentPin verification stack runs
// against AgentCards unchanged.
func DeriveDiscoveryFromCard(card *types.A2aAgentCard) (types.DiscoveryDocument, error) {
	if card == nil || card.Agentpin == nil {
		return types.DiscoveryDocument{}, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"AgentCard has no agentpin extension",
		)
	}
	domain, err := CardEndpointHost(card)
	if err != nil {
		return types.DiscoveryDocument{}, err
	}

	caps := make([]types.Capability, 0, len(card.Skills))
	for _, s := range card.Skills {
		caps = append(caps, types.Capability(s.ID))
	}

	var constraints *types.Constraints
	if !types.AllowedDomainsHelper.IsUnrestricted(card.Capabilities.AllowedDomains) {
		constraints = &types.Constraints{
			AllowedDomains: append([]string{}, card.Capabilities.AllowedDomains...),
		}
	}

	agentID := fmt.Sprintf("urn:agentpin:%s:%s", domain, slug(card.Name))
	agent := types.AgentDeclaration{
		AgentID:      agentID,
		Name:         card.Name,
		Description:  card.Description,
		Version:      card.Version,
		Capabilities: caps,
		Constraints:  constraints,
		Status:       types.AgentActive,
	}

	return types.DiscoveryDocument{
		AgentpinVersion:    "0.3",
		Entity:             domain,
		EntityType:         types.EntityBoth,
		PublicKeys:         []types.JWK{card.Agentpin.PublicKeyJWK},
		Agents:             []types.AgentDeclaration{agent},
		A2aEndpoint:        card.Agentpin.AgentpinEndpoint,
		MaxDelegationDepth: 0,
		UpdatedAt:          time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

// slug lower-cases and replaces non-alphanumeric ASCII chars with '-', then
// strips leading/trailing '-'. Mirrors the Rust helper.
func slug(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
