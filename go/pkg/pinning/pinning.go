// Package pinning provides a TOFU (trust-on-first-use) key pin store keyed
// by domain. The store persists by JSON serialization and is used by the
// AgentPin verifier to detect key changes.
package pinning

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// pinKey is the normalized hostname when valid, the raw string otherwise
// (AP-3).
func pinKey(d string) string {
	if n, err := domain.Normalize(d); err == nil {
		return n
	}
	return d
}

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
	// ResultRotated indicates the key was not pinned but appeared in a
	// discovery document alongside an already-pinned key, so it has been
	// pinned as a rotation (spec §7.2 continuity).
	ResultRotated
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
	case ResultRotated:
		return "rotated"
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
// pins j and returns ResultFirstUse. Prefer CheckAndPinSet when the full
// validated discovery document is available.
func (s *KeyPinStore) CheckAndPin(domain string, j *types.JWK) Result {
	return s.CheckAndPinSet(domain, j, []types.JWK{*j})
}

// CheckAndPinSet checks j against the pin store using the key set of a
// validated discovery document (spec §7.3 "pins the public key(s)").
//
//   - First use: every key in docKeys (plus j) is pinned.
//   - Known domain, j pinned: ResultMatched.
//   - Known domain, j not pinned, but at least one other key in docKeys is
//     already pinned: j is pinned and ResultRotated is returned.
//   - Otherwise ResultChanged; nothing is modified.
func (s *KeyPinStore) CheckAndPinSet(domain string, j *types.JWK, docKeys []types.JWK) Result {
	domain = pinKey(domain)
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := jwk.JWKThumbprint(j)
	now := time.Now().UTC().Format(time.RFC3339)

	pd, ok := s.domains[domain]
	if !ok {
		pd = &types.PinnedDomain{Domain: domain}
		s.domains[domain] = pd
		addKeyLocked(pd, j, now)
		for i := range docKeys {
			addKeyLocked(pd, &docKeys[i], now)
		}
		return ResultFirstUse
	}

	for i := range pd.PinnedKeys {
		if pd.PinnedKeys[i].PublicKeyHash == hash {
			pd.PinnedKeys[i].LastSeen = now
			return ResultMatched
		}
	}

	for i := range docKeys {
		h := jwk.JWKThumbprint(&docKeys[i])
		if h == hash {
			continue
		}
		for _, pk := range pd.PinnedKeys {
			if pk.PublicKeyHash == h {
				addKeyLocked(pd, j, now)
				return ResultRotated
			}
		}
	}
	return ResultChanged
}

func addKeyLocked(pd *types.PinnedDomain, j *types.JWK, now string) {
	hash := jwk.JWKThumbprint(j)
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

// AddKey adds an additional pinned key to a domain (e.g., during key rotation).
func (s *KeyPinStore) AddKey(domain string, j *types.JWK) {
	domain = pinKey(domain)
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
	domain = pinKey(domain)
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
		key := pinKey(d.Domain)
		d.Domain = key
		if existing, ok := s.domains[key]; ok {
			// Merge entries that differ only by case into one pin set.
			for _, pk := range d.PinnedKeys {
				dup := false
				for _, e := range existing.PinnedKeys {
					if e.PublicKeyHash == pk.PublicKeyHash {
						dup = true
						break
					}
				}
				if !dup {
					existing.PinnedKeys = append(existing.PinnedKeys, pk)
				}
			}
			continue
		}
		s.domains[key] = &d
	}
	return nil
}

// CheckPinning runs CheckAndPin and returns ResultChanged as a typed
// VerificationError so verifiers can fail closed cleanly.
func CheckPinning(store *KeyPinStore, domain string, j *types.JWK) (Result, error) {
	return CheckPinningSet(store, domain, j, []types.JWK{*j})
}

// CheckPinningSet is CheckPinning over a validated document's key set; see
// KeyPinStore.CheckAndPinSet.
func CheckPinningSet(store *KeyPinStore, domain string, j *types.JWK, docKeys []types.JWK) (Result, error) {
	r := store.CheckAndPinSet(domain, j, docKeys)
	if r == ResultChanged {
		return r, types.NewVerificationError(
			types.ErrKeyPinMismatch,
			fmt.Sprintf("Key for domain '%s' has changed since last pinned (kid: '%s')", domain, j.Kid),
		)
	}
	return r, nil
}
