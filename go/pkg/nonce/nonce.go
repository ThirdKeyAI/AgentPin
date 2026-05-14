// Package nonce provides a nonce deduplication store interface and an
// in-memory implementation used to defend against challenge-response replay.
package nonce

import (
	"sync"
	"time"
)

// Store is the dedup interface implemented by nonce stores.
//
// CheckAndRecord returns true if nonce has not been seen before (and records
// it with ttl). Returns false if it has been seen — i.e. this is a replay.
type Store interface {
	CheckAndRecord(nonce string, ttl time.Duration) (bool, error)
}

// InMemoryStore is a goroutine-safe in-memory nonce store with lazy expiry.
type InMemoryStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewInMemoryStore creates a new in-memory nonce store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{entries: make(map[string]time.Time)}
}

// CheckAndRecord implements Store.
func (s *InMemoryStore) CheckAndRecord(nonce string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Lazy cleanup: drop expired entries.
	for k, exp := range s.entries {
		if !exp.After(now) {
			delete(s.entries, k)
		}
	}

	if _, ok := s.entries[nonce]; ok {
		return false, nil
	}
	s.entries[nonce] = now.Add(ttl)
	return true, nil
}
