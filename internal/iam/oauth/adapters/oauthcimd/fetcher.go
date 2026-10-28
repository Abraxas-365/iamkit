// Package oauthcimd reads OAuth Client ID Metadata Documents and the key
// sets their private_key_jwt clients publish (MCP authorization 2025-11-25,
// draft-ietf-oauth-client-id-metadata-document). Both are fetched over the
// guarded transport (public addresses only), without redirects, within
// config.ClientMetadataTimeout and a size cap, and kept in a cache.Store
// for their Cache-Control max-age held to [config.ClientMetadataMinTTL,
// config.ClientMetadataMaxTTL]; a failed fetch is remembered for
// config.ClientMetadataFailureTTL so a broken host is not hammered.
package oauthcimd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/go-jose/go-jose/v3"
	"golang.org/x/sync/singleflight"
)

// Fetcher implements oauth.MetadataDocuments.
type Fetcher struct {
	client *http.Client
	store  cache.Store
	now    func() time.Time
	group  singleflight.Group
	// refreshed throttles key set refetches forced by an unknown kid
	// (per replica, like oauthfosite.KeyFetcher).
	mu        sync.Mutex
	refreshed map[string]time.Time
}

// New fetches over transport (nil: the guarded one) and caches in store
// (bootstrap passes the shared store, or a process one without Redis; nil:
// no cache, tests only).
func New(transport http.RoundTripper, store cache.Store) *Fetcher {
	if transport == nil {
		transport = netx.Guarded()
	}
	if store == nil {
		store = noCache{}
	}
	return &Fetcher{
		client: &http.Client{Transport: telemetry.Transport(transport), Timeout: config.ClientMetadataTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		store: store, now: time.Now, refreshed: map[string]time.Time{},
	}
}

var _ oauth.MetadataDocuments = (*Fetcher)(nil)

// noCache keeps nothing.
type noCache struct{}

func (noCache) Get(context.Context, string) ([]byte, bool, error)        { return nil, false, nil }
func (noCache) Set(context.Context, string, []byte, time.Duration) error { return nil }
func (noCache) Delete(context.Context, ...string) error                  { return nil }

// cached is a cache entry: a document or key set body, or the reason the
// last fetch failed.
type cached struct {
	Body    json.RawMessage `json:"body,omitempty"`
	Failure string          `json:"failure,omitempty"`
	Fetched time.Time       `json:"fetched"`
}

func key(prefix, location string) string {
	sum := sha256.Sum256([]byte(location))
	return prefix + hex.EncodeToString(sum[:])
}

// Document returns the validated document at clientID (oauth.ParseClientIDURL
// already checked) and when it was fetched. A document that does not
// validate is never cached; the failure is, briefly.
func (f *Fetcher) Document(ctx context.Context, clientID *url.URL) (oauth.ExternalClient, time.Time, error) {
	entry, err := f.read(ctx, key("cimd:", clientID.String()), clientID.String(), config.ClientMetadataMaxBytes, false, func(body []byte) error {
		m, err := oauth.ParseClientMetadata(body)
		if err != nil {
			return err
		}
		_, err = m.Validate(clientID)
		return err
	})
	if err != nil {
		return oauth.ExternalClient{}, time.Time{}, err
	}
	m, err := oauth.ParseClientMetadata(entry.Body)
	if err != nil {
		return oauth.ExternalClient{}, time.Time{}, err
	}
	out, err := m.Validate(clientID)
	return out, entry.Fetched, err
}

// Resolve implements fosite.JWKSFetcherStrategy for external clients: the
// key set at location (a jwks_uri the client's document named, on its
// origin). ignoreCache (fosite found no key for the assertion's kid)
// refetches at most once per config.ClientJWKSRefreshInterval.
func (f *Fetcher) Resolve(ctx context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	refresh := false
	if ignoreCache {
		f.mu.Lock()
		if last, ok := f.refreshed[location]; !ok || f.now().Sub(last) >= config.ClientJWKSRefreshInterval {
			if len(f.refreshed) > config.ClientJWKSCacheEntries {
				f.refreshed = map[string]time.Time{}
			}
			f.refreshed[location] = f.now()
			refresh = true
		}
		f.mu.Unlock()
	}
	entry, err := f.read(ctx, key("cimdjwks:", location), location, config.ClientJWKSMaxBytes, refresh, func(body []byte) error {
		_, err := parseKeys(body)
		return err
	})
	if err != nil {
		return nil, err
	}
	return parseKeys(entry.Body)
}

// parseKeys reads a key set, keeping the public signing keys (keys without
// "use" are signing keys).
func parseKeys(body []byte) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, errx.Validation("the client's jwks_uri is not a JSON Web Key Set")
	}
	out := &jose.JSONWebKeySet{}
	for _, k := range set.Keys {
		if k.Use == "" {
			k.Use = "sig"
		}
		if k.Use == "sig" && k.IsPublic() {
			out.Keys = append(out.Keys, k)
		}
	}
	return out, nil
}

// read serves key from the cache or fetches location once for every
// concurrent caller (singleflight), caching a body check accepts for its
// max-age and a failure for config.ClientMetadataFailureTTL. fresh skips a
// cached body (never a cached failure).
func (f *Fetcher) read(ctx context.Context, key, location string, limit int64, fresh bool, check func([]byte) error) (cached, error) {
	var prior cached
	if raw, found, err := f.store.Get(ctx, key); err == nil && found {
		if json.Unmarshal(raw, &prior) == nil && (prior.Failure != "" || !fresh) {
			return prior, prior.err()
		}
	}
	v, err, _ := f.group.Do(key, func() (any, error) {
		// The fetch outlives a caller that gives up: the others wait on it.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), config.ClientMetadataTimeout)
		defer cancel()
		body, ttl, err := f.fetch(fetchCtx, location, limit)
		if err == nil {
			err = check(body)
		}
		if err != nil && prior.Body != nil {
			// A forced refresh that fails keeps the copy still in the cache.
			return prior, nil
		}
		entry := cached{Body: body, Fetched: f.now()}
		if err != nil {
			entry, ttl = cached{Failure: failureText(err), Fetched: f.now()}, config.ClientMetadataFailureTTL
		}
		if raw, merr := json.Marshal(entry); merr == nil {
			_ = f.store.Set(context.WithoutCancel(ctx), key, raw, ttl)
		}
		return entry, entry.err()
	})
	entry, _ := v.(cached)
	return entry, err
}

func (c cached) err() error {
	if c.Failure != "" {
		return errx.Validation(c.Failure)
	}
	return nil
}

// failureText keeps a validation message and names a transport cause only
// (never an address, a header or the body).
func failureText(err error) string {
	var e *errx.Error
	if errors.As(err, &e) && e.Type == errx.TypeValidation {
		return e.Message
	}
	return "the client metadata document could not be read: " + netx.Reason(err)
}

// fetch GETs location: 200, a JSON media type, at most limit bytes. It
// returns the body and how long it may be cached.
func (f *Fetcher) fetch(ctx context.Context, location string, limit int64) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, 0, errx.Validation("the client metadata document could not be read: the host answered " + strconv.Itoa(res.StatusCode))
	}
	if media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || !(media == "application/json" || strings.HasSuffix(media, "+json")) {
		return nil, 0, errx.Validation("the client metadata document is not served as application/json")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(body)) > limit {
		return nil, 0, errx.Validation("the client metadata document is larger than " + strconv.FormatInt(limit/1024, 10) + " KB")
	}
	return body, CacheTTL(res.Header), nil
}

// CacheTTL is how long an answer may be kept: its Cache-Control max-age
// held to [config.ClientMetadataMinTTL, config.ClientMetadataMaxTTL];
// no-store, no-cache, private or no max-age keep it the minimum.
func CacheTTL(h http.Header) time.Duration {
	ttl := time.Duration(0)
	for _, directive := range strings.Split(h.Get("Cache-Control"), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		switch name {
		case "no-store", "no-cache":
			return config.ClientMetadataMinTTL
		case "max-age":
			if seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64); err == nil && seconds > 0 {
				ttl = time.Duration(min(seconds, int64(config.ClientMetadataMaxTTL/time.Second))) * time.Second
			}
		}
	}
	return min(max(ttl, config.ClientMetadataMinTTL), config.ClientMetadataMaxTTL)
}
