// Package cacheredis is the shared cache of the replicas (REDIS_URL): a
// cache.Store, the usage per-minute window and the rate limiters' storage.
// Redis only holds copies and counters; when it is unavailable the cache
// reads the database and the counters fall back to this process.
package cacheredis

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

// Prefix namespaces every key IAMKit writes.
const Prefix = "iamkit:"

// timeout bounds one Redis call; past it the caller takes its fallback.
const timeout = 250 * time.Millisecond

// Client is a connection pool to one Redis.
type Client struct {
	rdb *redis.Client
	// warned rate-limits "unavailable" log lines.
	mu     sync.Mutex
	warned time.Time
}

// Open parses a redis:// or rediss:// URL and checks the server answers.
// An unreachable server is not an error (it may come up later; calls fail
// over meanwhile); an invalid URL is.
func Open(ctx context.Context, url string) (*Client, error) {
	options, err := redis.ParseURL(url)
	if err != nil {
		return nil, errx.Validation("REDIS_URL is not a valid redis:// or rediss:// URL")
	}
	options.DialTimeout, options.ReadTimeout, options.WriteTimeout = time.Second, timeout, timeout
	c := &Client{rdb: redis.NewClient(options)}
	ping, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.rdb.Ping(ping).Err(); err != nil {
		slog.WarnContext(ctx, "redis unavailable at start-up; reading the database and counting in memory until it answers", "err", err)
	}
	return c, nil
}

func (c *Client) Close() error { return c.rdb.Close() }

// Ping reports whether Redis answers.
func (c *Client) Ping(ctx context.Context) error { return c.rdb.Ping(ctx).Err() }

// failed logs an unavailable Redis at most once a minute.
func (c *Client) failed(ctx context.Context, op string, err error) {
	c.mu.Lock()
	now := time.Now()
	log := now.Sub(c.warned) > time.Minute
	if log {
		c.warned = now
	}
	c.mu.Unlock()
	if log {
		slog.WarnContext(ctx, "redis unavailable, falling back", "op", op, "err", err)
	}
}

func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// Store is the shared cache.Store.
type Store struct{ c *Client }

var _ cache.Store = Store{}

func (c *Client) Store() Store { return Store{c} }

func (s Store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	family, _, _ := strings.Cut(key, ":")
	raw, err := s.c.rdb.Get(ctx, Prefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		telemetry.CacheLookup(ctx, family, telemetry.CacheMiss)
		return nil, false, nil
	}
	if err != nil {
		telemetry.CacheLookup(ctx, family, telemetry.CacheError)
		s.c.failed(ctx, "get", err)
		return nil, false, err
	}
	telemetry.CacheLookup(ctx, family, telemetry.CacheHit)
	return raw, true, nil
}

func (s Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	if err := s.c.rdb.Set(ctx, Prefix+key, value, ttl).Err(); err != nil {
		s.c.failed(ctx, "set", err)
		return err
	}
	return nil
}

func (s Store) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = Prefix + k
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	if err := s.c.rdb.Del(ctx, full...).Err(); err != nil {
		s.c.failed(ctx, "delete", err)
		return err
	}
	return nil
}

// fallbackWindow is the in-process counter used while Redis is down
// (usagememory.Window satisfies it).
type fallbackWindow interface {
	Take(ctx context.Context, key string, max int64, window time.Duration) (bool, error)
}

// Window is a fixed-window counter shared by the replicas (INCR + EXPIRE
// of the window's key); while Redis is unavailable it counts in fallback.
type Window struct {
	c        *Client
	fallback fallbackWindow
	now      func() time.Time
}

func (c *Client) Window(fallback fallbackWindow) *Window {
	return &Window{c: c, fallback: fallback, now: time.Now}
}

// incr adds one to the current window of key and returns the new count.
var incr = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n`)

func (w *Window) Take(ctx context.Context, key string, max int64, length time.Duration) (bool, error) {
	start := w.now().Truncate(length)
	full := Prefix + "window:" + key + ":" + start.UTC().Format("20060102T150405")
	call, cancel := bounded(ctx)
	defer cancel()
	n, err := incr.Run(call, w.c.rdb, []string{full}, (length + time.Second).Milliseconds()).Int64()
	if err != nil {
		w.c.failed(ctx, "window", err)
		return w.fallback.Take(ctx, key, max, length)
	}
	return n <= max, nil
}

// Storage is fiber's limiter storage on Redis; while Redis is unavailable
// it keeps entries in this process. Limiter entries are read and written
// separately, so concurrent requests on several replicas may slightly
// exceed a limit.
type Storage struct {
	c        *Client
	fallback *cachememory.Store
}

var _ fiber.Storage = (*Storage)(nil)

func (c *Client) Storage() *Storage { return &Storage{c: c, fallback: cachememory.New()} }

func (s *Storage) Get(key string) ([]byte, error) {
	ctx := context.Background()
	call, cancel := bounded(ctx)
	defer cancel()
	raw, err := s.c.rdb.Get(call, Prefix+"limit:"+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		s.c.failed(ctx, "limit", err)
		raw, _, _ = s.fallback.Get(ctx, key)
	}
	return raw, nil
}

func (s *Storage) Set(key string, value []byte, ttl time.Duration) error {
	if key == "" || len(value) == 0 {
		return nil
	}
	ctx := context.Background()
	if err := (Store{s.c}).Set(ctx, "limit:"+key, value, ttl); err != nil {
		return s.fallback.Set(ctx, key, value, ttl)
	}
	return nil
}

func (s *Storage) Delete(key string) error {
	ctx := context.Background()
	_ = s.fallback.Delete(ctx, key)
	return Store{s.c}.Delete(ctx, "limit:"+key)
}

// Reset clears the fallback only: limiter keys in Redis expire on their own.
func (s *Storage) Reset() error {
	s.fallback.Reset()
	return nil
}

// Close leaves the shared client open (the server closes it).
func (s *Storage) Close() error { return nil }
