package resourceserver

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

// Introspection makes Verify also ask IAMKit (RFC 7662) whether a token
// that passed the signature checks is still live: a revoked consent, a
// disconnected application, a blocked client or an ended session stop it
// at once instead of when the access token expires. Each request costs a
// call to IAMKit unless CacheTTL is set.
//
// It fails closed: when IAMKit cannot be asked (network, 5xx, refused
// client credentials) the request is answered 503 without a challenge, so
// the client keeps its token and retries; the token is never admitted
// unchecked.
type Introspection struct {
	// ClientID and ClientSecret are a confidential OAuth client of the
	// resource's environment (introspection is refused to public and
	// external clients).
	ClientID     string
	ClientSecret string
	// CacheTTL keeps an active answer for at most this long (never past the
	// token's exp). Zero, the default, asks on every request; a cached
	// answer admits a revoked token for up to CacheTTL.
	CacheTTL time.Duration
	// MaxCacheEntries bounds the cache (default 10000).
	MaxCacheEntries int
}

// introspector asks IAMKit and caches active answers.
type introspector struct {
	client *authclient.OAuthClient
	ttl    time.Duration
	max    int
	now    func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]time.Time
}

func newIntrospector(issuer string, cfg *Introspection, hc *http.Client) (*introspector, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("resourceserver: Introspection needs ClientID and ClientSecret")
	}
	if cfg.CacheTTL < 0 {
		return nil, errors.New("resourceserver: Introspection.CacheTTL cannot be negative")
	}
	var opts []authclient.OAuthOption
	if hc != nil {
		opts = append(opts, authclient.WithOAuthHTTPClient(hc))
	}
	limit := cfg.MaxCacheEntries
	if limit <= 0 {
		limit = 10000
	}
	return &introspector{client: authclient.NewOAuth(issuer, cfg.ClientID, cfg.ClientSecret, opts...), ttl: cfg.CacheTTL, max: limit,
		now: time.Now, cache: map[[sha256.Size]byte]time.Time{}}, nil
}

// check reports ErrInvalidToken for an inactive token (or one IAMKit
// describes differently from its claims, see describes) and ErrUnavailable when IAMKit
// could not answer.
func (in *introspector) check(ctx context.Context, raw, resource string, c *Claims) error {
	key := sha256.Sum256([]byte(raw))
	now := in.now()
	if in.ttl > 0 {
		in.mu.Lock()
		until, ok := in.cache[key]
		if ok && !now.Before(until) {
			delete(in.cache, key)
			ok = false
		}
		in.mu.Unlock()
		if ok {
			return nil
		}
	}
	answer, err := in.client.Introspect(ctx, raw)
	if err != nil {
		return ErrUnavailable
	}
	if !describes(answer, resource, c) {
		return ErrInvalidToken
	}
	if in.ttl > 0 {
		until := now.Add(in.ttl)
		if !c.ExpiresAt.IsZero() && c.ExpiresAt.Before(until) {
			until = c.ExpiresAt
		}
		in.store(key, until, now)
	}
	return nil
}

// describes reports whether IAMKit's answer is about this token: active,
// an access token of the same subject, session and client, with the same
// granted scopes and the resource in its audience. An answer that differs
// in any of them describes another token (or a grant that changed), so the
// token is refused.
func describes(answer authclient.Introspection, resource string, c *Claims) bool {
	return answer.Active && answer.TokenUse == "access_token" && answer.Subject == c.Subject && answer.SessionID == c.SessionID &&
		c.ClientID != "" && answer.ClientID == c.ClientID && sameScopes(strings.Fields(answer.Scope), c.Scopes) &&
		slices.ContainsFunc(answer.Audience, func(aud string) bool { got, err := CanonicalResource(aud); return err == nil && got == resource })
}

// sameScopes compares two scope lists as sets.
func sameScopes(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// store keeps an answer, first dropping expired entries and, when still
// full, an arbitrary one: the cache is an optimization, never a list of
// what is allowed.
func (in *introspector) store(key [sha256.Size]byte, until, now time.Time) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.cache) >= in.max {
		for k, v := range in.cache {
			if !now.Before(v) {
				delete(in.cache, k)
			}
		}
		for k := range in.cache {
			if len(in.cache) < in.max {
				break
			}
			delete(in.cache, k)
		}
	}
	in.cache[key] = until
}
