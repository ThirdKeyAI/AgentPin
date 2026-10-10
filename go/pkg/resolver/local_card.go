package resolver

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// storeKey is the normalized domain when valid, the raw string otherwise
// (which can never match a registered card).
func storeKey(d string) string {
	if n, err := domain.Normalize(d); err == nil {
		return n
	}
	return d
}

// LocalAgentCardStore is an in-memory store of pre-registered A2A AgentCards
// keyed by their AgentPin discovery domain (v0.3.0).
//
// Mirrors the Rust agentpin::resolver_local::LocalAgentCardStore. Cards are
// added via Register (after the extension signature is verified and the
// trust anchor accepts the key) and looked up via ResolveDiscovery. Backs
// Symbiont's push-based external-agent registration flow.
//
// Trust anchor (spec §4.10.4 step 5, AP-4, design issue 9): an AgentCard
// is self-certifying, so verifying its signature proves nothing about which
// domain it speaks for. The store therefore requires an anchor:
//
//   - NewLocalAgentCardStoreWithThumbprints: allowlist of JWK thumbprints
//     the operator verified out of band;
//   - NewLocalAgentCardStoreWithResolver: the card key must be published,
//     by thumbprint, in the endpoint domain's discovery document;
//   - NewUnanchoredLocalAgentCardStore: explicit opt-out for callers whose
//     registration channel already establishes provenance.
//
// NewLocalAgentCardStore creates a store with an empty allowlist, which
// refuses every registration until TrustThumbprint is called.
type LocalAgentCardStore struct {
	mu    sync.RWMutex
	cards map[string]types.A2aAgentCard
	docs  map[string]types.DiscoveryDocument

	unanchored bool
	trusted    map[string]bool
	resolver   DiscoveryResolver
}

// NewLocalAgentCardStore constructs an empty store with an empty thumbprint
// allowlist (every registration refused until TrustThumbprint is called).
func NewLocalAgentCardStore() *LocalAgentCardStore {
	return &LocalAgentCardStore{
		cards:   make(map[string]types.A2aAgentCard),
		docs:    make(map[string]types.DiscoveryDocument),
		trusted: make(map[string]bool),
	}
}

// NewLocalAgentCardStoreWithThumbprints constructs a store that accepts only
// cards whose extension key has one of the given RFC 7638 thumbprints (hex).
func NewLocalAgentCardStoreWithThumbprints(thumbprints []string) *LocalAgentCardStore {
	s := NewLocalAgentCardStore()
	for _, tp := range thumbprints {
		s.trusted[tp] = true
	}
	return s
}

// NewLocalAgentCardStoreWithResolver constructs a store that accepts only
// cards whose extension key is published in the authoritative discovery
// document for the card's endpoint domain, as resolved by r.
func NewLocalAgentCardStoreWithResolver(r DiscoveryResolver) *LocalAgentCardStore {
	s := NewLocalAgentCardStore()
	s.trusted = nil
	s.resolver = r
	return s
}

// NewUnanchoredLocalAgentCardStore constructs a store with no trust anchor.
//
// Use only when the channel that delivers cards to Register already
// authenticates the registrant for the domain it claims (an authenticated
// coordinator API, an operator-controlled config file). This is the
// "documented substitute provenance check" spec §4.10.4 allows; without
// such a channel, anyone who can call Register can assert any domain.
func NewUnanchoredLocalAgentCardStore() *LocalAgentCardStore {
	s := NewLocalAgentCardStore()
	s.trusted = nil
	s.unanchored = true
	return s
}

// TrustThumbprint adds a trusted key thumbprint. Only meaningful for
// allowlist-anchored stores.
func (s *LocalAgentCardStore) TrustThumbprint(thumbprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trusted == nil {
		return errors.New("LocalAgentCardStore is not anchored on a thumbprint allowlist")
	}
	s.trusted[thumbprint] = true
	return nil
}

func (s *LocalAgentCardStore) checkAnchor(card *types.A2aAgentCard, domainName string) error {
	tp := a2a.ExtensionKeyThumbprint(card.Agentpin)
	s.mu.RLock()
	unanchored, trusted, resolver := s.unanchored, s.trusted, s.resolver
	s.mu.RUnlock()
	switch {
	case unanchored:
		return nil
	case resolver != nil:
		doc, err := resolver.ResolveDiscovery(domainName)
		if err != nil {
			return err
		}
		if !CardKeyPublishedIn(doc, card) {
			return types.NewVerificationError(types.ErrDiscoveryInvalid,
				fmt.Sprintf("AgentCard key %s is not published in the discovery document for '%s'", tp, domainName))
		}
		return nil
	default:
		if trusted[tp] {
			return nil
		}
		return types.NewVerificationError(types.ErrDiscoveryInvalid,
			fmt.Sprintf("AgentCard key %s is not a trusted thumbprint for domain '%s'", tp, domainName))
	}
}

// CardKeyPublishedIn reports whether the card's extension key appears, by
// RFC 7638 thumbprint, in doc.PublicKeys (spec §4.10.4 step 5).
func CardKeyPublishedIn(doc *types.DiscoveryDocument, card *types.A2aAgentCard) bool {
	if doc == nil || card == nil || card.Agentpin == nil {
		return false
	}
	tp := a2a.ExtensionKeyThumbprint(card.Agentpin)
	for i := range doc.PublicKeys {
		if jwk.JWKThumbprint(&doc.PublicKeys[i]) == tp {
			return true
		}
	}
	return false
}

// Register verifies the extension signature on card, requires the trust
// anchor to accept the card key for the endpoint's domain, and stores it
// keyed by the (normalized) host of its agentpin_endpoint. Re-registering
// an existing domain replaces the prior entry — useful for handling key
// rotation.
func (s *LocalAgentCardStore) Register(card types.A2aAgentCard) error {
	if err := a2a.VerifyAgentpinExtension(&card); err != nil {
		return err
	}
	domainName, err := CardEndpointHost(&card)
	if err != nil {
		return err
	}
	if err := s.checkAnchor(&card, domainName); err != nil {
		return err
	}
	doc, err := DeriveDiscoveryFromCard(&card)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cards[domainName] = card
	s.docs[domainName] = doc
	return nil
}

// RegisterForDomain is Register with the additional requirement that the
// card's endpoint host equals expectedDomain (normalized). Use it when the
// registration channel tells you which domain the registrant may speak for.
func (s *LocalAgentCardStore) RegisterForDomain(card types.A2aAgentCard, expectedDomain string) error {
	expected, err := domain.Normalize(expectedDomain)
	if err != nil {
		return err
	}
	host, err := CardEndpointHost(&card)
	if err != nil {
		return err
	}
	if host != expected {
		return types.NewVerificationError(types.ErrDomainMismatch,
			fmt.Sprintf("AgentCard agentpin_endpoint host '%s' does not match expected domain '%s'", host, expected))
	}
	return s.Register(card)
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
func (s *LocalAgentCardStore) ResolveCard(domainName string) (types.A2aAgentCard, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cards[storeKey(domainName)]
	return c, ok
}

// ResolveDiscovery returns the derived DiscoveryDocument for domain. Returns
// a typed VerificationError(ErrDiscoveryInvalid) when the domain isn't
// registered.
func (s *LocalAgentCardStore) ResolveDiscovery(domainName string) (*types.DiscoveryDocument, error) {
	s.mu.RLock()
	doc, ok := s.docs[storeKey(domainName)]
	s.mu.RUnlock()
	if !ok {
		return nil, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Domain '%s' not in LocalAgentCardStore", domainName),
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
func (s *LocalAgentCardStore) Remove(domainName string) bool {
	key := storeKey(domainName)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cards[key]
	delete(s.cards, key)
	delete(s.docs, key)
	return ok
}

// CardEndpointHost extracts the normalized host of an AgentCard's
// agentpin_endpoint URL. The endpoint must be https with a domain host and
// no userinfo, port or fragment (AP-3, AP-12).
func CardEndpointHost(card *types.A2aAgentCard) (string, error) {
	if card == nil || card.Agentpin == nil {
		return "", types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"AgentCard has no agentpin extension",
		)
	}
	host, err := domain.HTTPSURLHost(card.Agentpin.AgentpinEndpoint)
	if err != nil {
		return "", types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			fmt.Sprintf("Invalid agentpin_endpoint URL: %s", err),
		)
	}
	return host, nil
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
			AllowedDomains: types.AllowedDomainsHelper.FromDomains(card.Capabilities.AllowedDomains),
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
		AgentpinVersion:    "0.1",
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
