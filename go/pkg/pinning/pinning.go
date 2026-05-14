// Package pinning provides a TOFU (trust-on-first-use) key pin store keyed
// by domain. The store persists by JSON serialization and is used by the
// AgentPin verifier to detect key changes.
package pinning

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// Result is the outcome of a CheckAndPin call.
type Result int

const (
	// ResultFirstUse indicates the domain was unknown and the key is now pinned.
	ResultFirstUse Result = iota
	// ResultMatched indicates the key matches a previously pinned key.
	ResultMatched
	// ResultChanged indicates the domain was known but the key does not match
	// any pinned key — likely key rotation or attack.
	ResultChanged
)

// String returns a stable label for r.
func (r Result) String() string {
	switch r {
	case ResultFirstUse:
		return "first_use"
	case ResultMatched:
		return "pinned"
	case ResultChanged:
		return "changed"
	}
	return "unknown"
}

// KeyPinStore is a concurrent-safe in-memory TOFU pin store.
type KeyPinStore struct {
	mu      sync.Mutex
	domains map[string]*types.PinnedDomain
}

// NewKeyPinStore creates a new empty store.
func NewKeyPinStore() *KeyPinStore {
	return &KeyPinStore{domains: make(map[string]*types.PinnedDomain)}
}

// CheckAndPin checks j against the pinned keys for domain. On first use it
// pins j and returns ResultFirstUse.
func (s *KeyPinStore) CheckAndPin(domain string, j *types.JWK) Result {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := jwk.JWKThumbprint(j)
	now := time.Now().UTC().Format(time.RFC3339)

	if pd, ok := s.domains[domain]; ok {
		for i := range pd.PinnedKeys {
			if pd.PinnedKeys[i].PublicKeyHash == hash {
				pd.PinnedKeys[i].LastSeen = now
				return ResultMatched
			}
		}
		return ResultChanged
	}

	s.domains[domain] = &types.PinnedDomain{
		Domain: domain,
		PinnedKeys: []types.PinnedKey{
			{
				Kid:           j.Kid,
				PublicKeyHash: hash,
				FirstSeen:     now,
				LastSeen:      now,
				TrustLevel:    types.TrustTOFU,
			},
		},
	}
	return ResultFirstUse
}

// AddKey adds an additional pinned key to a domain (e.g., during key rotation).
func (s *KeyPinStore) AddKey(domain string, j *types.JWK) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := jwk.JWKThumbprint(j)
	now := time.Now().UTC().Format(time.RFC3339)

	pd, ok := s.domains[domain]
	if !ok {
		pd = &types.PinnedDomain{Domain: domain}
		s.domains[domain] = pd
	}
	for _, k := range pd.PinnedKeys {
		if k.PublicKeyHash == hash {
			return
		}
	}
	pd.PinnedKeys = append(pd.PinnedKeys, types.PinnedKey{
		Kid:           j.Kid,
		PublicKeyHash: hash,
		FirstSeen:     now,
		LastSeen:      now,
		TrustLevel:    types.TrustTOFU,
	})
}

// GetDomain returns the pinned-domain entry for domain, or nil.
func (s *KeyPinStore) GetDomain(domain string) *types.PinnedDomain {
	s.mu.Lock()
	defer s.mu.Unlock()
	pd, ok := s.domains[domain]
	if !ok {
		return nil
	}
	cp := *pd
	cp.PinnedKeys = append([]types.PinnedKey(nil), pd.PinnedKeys...)
	return &cp
}

// MarshalJSON serializes the store as a JSON array of PinnedDomain (matching
// the Rust port's `to_json` shape).
func (s *KeyPinStore) MarshalJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domains := make([]*types.PinnedDomain, 0, len(s.domains))
	for _, d := range s.domains {
		domains = append(domains, d)
	}
	return json.MarshalIndent(domains, "", "  ")
}

// LoadFromJSON populates s from the JSON array produced by MarshalJSON.
func (s *KeyPinStore) LoadFromJSON(data []byte) error {
	var domains []types.PinnedDomain
	if err := json.Unmarshal(data, &domains); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = make(map[string]*types.PinnedDomain, len(domains))
	for i := range domains {
		d := domains[i]
		s.domains[d.Domain] = &d
	}
	return nil
}

// CheckPinning runs CheckAndPin and returns ResultChanged as a typed
// VerificationError so verifiers can fail closed cleanly.
func CheckPinning(store *KeyPinStore, domain string, j *types.JWK) (Result, error) {
	r := store.CheckAndPin(domain, j)
	if r == ResultChanged {
		return r, types.NewVerificationError(
			types.ErrKeyPinMismatch,
			fmt.Sprintf("Key for domain '%s' has changed since last pinned (kid: '%s')", domain, j.Kid),
		)
	}
	return r, nil
}
