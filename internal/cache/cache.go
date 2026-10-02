// Package cache is the port for short-lived copies of hot reads (a
// foundation package like query: domain services may import it). Postgres
// stays the source of truth: a miss or a failing store reads the
// database, and writers delete the keys they make stale. Adapters:
// cachememory (this process) and cacheredis (REDIS_URL, shared by the
// replicas); only the composition root picks one, and services given a nil
// Store read the database every time.
package cache

import (
	"context"
	"encoding/json"
	"time"
)

// Store keeps values for a while. Implementations are safe for concurrent
// use; errors mean "unavailable", never "missing". Keys are
// "<family>:<…>" (the family labels metrics).
type Store interface {
	// Get returns the value of key, found=false when absent or expired.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
	// Set keeps value under key for ttl.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete removes keys; absent keys are not an error.
	Delete(ctx context.Context, keys ...string) error
}

// Read returns the cached value of key, else load's, which it caches for
// ttl as JSON. A nil store, a failing store or an undecodable entry fall
// back to load; load's errors are returned and never cached.
func Read[T any](ctx context.Context, store Store, key string, ttl time.Duration, load func() (T, error)) (T, error) {
	if store == nil {
		return load()
	}
	if raw, found, err := store.Get(ctx, key); err == nil && found {
		var out T
		if json.Unmarshal(raw, &out) == nil {
			return out, nil
		}
	}
	out, err := load()
	if err != nil {
		return out, err
	}
	if raw, err := json.Marshal(out); err == nil {
		_ = store.Set(ctx, key, raw, ttl)
	}
	return out, nil
}

// Forget deletes keys; a nil store or a failure is ignored (entries then
// expire with their TTL).
func Forget(ctx context.Context, store Store, keys ...string) {
	if store != nil && len(keys) > 0 {
		_ = store.Delete(ctx, keys...)
	}
}
