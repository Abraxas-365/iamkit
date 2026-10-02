// Package cachememory is a cache.Store in this process: each replica keeps
// its own entries. It backs the rate-limit fallback when Redis is
// unavailable, and tests.
package cachememory

import (
	"context"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
)

type entry struct {
	value   []byte
	expires time.Time
}

// Store is a TTL map; expired entries are swept as it is written.
type Store struct {
	mu      sync.Mutex
	entries map[string]entry
	now     func() time.Time
	swept   time.Time
}

var _ cache.Store = (*Store)(nil)

func New() *Store { return &Store{entries: map[string]entry{}, now: time.Now} }

func (s *Store) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if ok && !s.now().Before(e.expires) {
		delete(s.entries, key)
		return nil, false, nil
	}
	return e.value, ok, nil
}

func (s *Store) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.swept) > time.Minute {
		for k, e := range s.entries {
			if !now.Before(e.expires) {
				delete(s.entries, k)
			}
		}
		s.swept = now
	}
	s.entries[key] = entry{value: append([]byte(nil), value...), expires: now.Add(ttl)}
	return nil
}

func (s *Store) Delete(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.entries, k)
	}
	return nil
}

// Reset removes every entry.
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = map[string]entry{}
}
