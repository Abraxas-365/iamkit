package oauthfosite

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/go-jose/go-jose/v3"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

// clientKeys is an inline JSON Web Key Set as fosite reads it. Keys that
// do not name a use are signing keys (fosite only picks use=sig).
func clientKeys(raw json.RawMessage) *jose.JSONWebKeySet {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal(raw, &set) != nil {
		return &jose.JSONWebKeySet{}
	}
	return signingKeys(&set)
}

func signingKeys(set *jose.JSONWebKeySet) *jose.JSONWebKeySet {
	out := &jose.JSONWebKeySet{}
	for _, key := range set.Keys {
		if key.Use == "" {
			key.Use = "sig"
		}
		if key.Use == "sig" && key.IsPublic() {
			out.Keys = append(out.Keys, key)
		}
	}
	return out
}

// authClient is the fosite view of a client's token endpoint
// authentication.
func authClient(base *fosite.DefaultClient, auth identity.ClientAuth) *fosite.DefaultOpenIDConnectClient {
	method := auth.Method
	if base.Public {
		method = identity.AuthNone
	}
	if method == "" {
		method = identity.AuthSecretBasic
	}
	out := &fosite.DefaultOpenIDConnectClient{DefaultClient: base, TokenEndpointAuthMethod: method, TokenEndpointAuthSigningAlgorithm: auth.SigningAlg}
	if method == identity.AuthPrivateKeyJWT {
		out.JSONWebKeys, out.JSONWebKeysURI = clientKeys(auth.JWKS), auth.JWKSURI
	}
	return out
}

// Assertions remembers used client assertion jti values until the
// assertion expires (RFC 7523 §3 replay protection), per client.
type Assertions struct{ DB *sqlx.DB }

func assertionKey(ctx context.Context, jti string) []byte {
	client, _ := ctx.Value(ClientContextKey{}).(string)
	sum := sha256.Sum256([]byte(client + "\x00" + jti))
	return sum[:]
}

// Valid is fosite's ClientAssertionJWTValid: an error when the jti was used.
func (a Assertions) Valid(ctx context.Context, jti string) error {
	var used bool
	err := a.DB.GetContext(ctx, &used, `SELECT EXISTS(SELECT 1 FROM client_assertion_jtis WHERE hash=$1 AND expires_at>now())`, assertionKey(ctx, jti))
	if err != nil {
		return fosite.ErrServerError
	}
	if used {
		return fosite.ErrJTIKnown
	}
	return nil
}

// Use is fosite's SetClientAssertionJWT: it records the jti atomically, so
// two concurrent requests with one assertion cannot both pass.
func (a Assertions) Use(ctx context.Context, jti string, expires time.Time) error {
	if time.Until(expires) > config.ClientAssertionMaxAge {
		return fosite.ErrInvalidClient.WithHint("The client_assertion expires too far in the future.")
	}
	if _, err := a.DB.ExecContext(ctx, `DELETE FROM client_assertion_jtis WHERE expires_at<now()`); err != nil {
		return fosite.ErrServerError
	}
	res, err := a.DB.ExecContext(ctx, `INSERT INTO client_assertion_jtis(hash,expires_at) VALUES($1,$2) ON CONFLICT (hash) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE client_assertion_jtis.expires_at<=now()`, assertionKey(ctx, jti), expires)
	if err != nil {
		return fosite.ErrServerError
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return fosite.ErrJTIKnown
	}
	return nil
}

// KeyFetcher reads clients' jwks_uri over the given transport (public
// addresses only by default), caching each set for config.ClientJWKSCacheTTL
// and refetching on an unknown key at most once per
// config.ClientJWKSRefreshInterval, so unknown kids cannot make IAMKit
// hammer a URL.
type KeyFetcher struct {
	client *http.Client
	mu     sync.Mutex
	sets   map[string]fetchedKeys
}
type fetchedKeys struct {
	set     *jose.JSONWebKeySet
	fetched time.Time
}

// NewKeyFetcher uses transport (nil: GuardedTransport).
func NewKeyFetcher(transport http.RoundTripper) *KeyFetcher {
	if transport == nil {
		transport = GuardedTransport()
	}
	return &KeyFetcher{client: &http.Client{Transport: telemetry.Transport(transport), Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, sets: map[string]fetchedKeys{}}
}

// GuardedTransport dials only public addresses, ignoring proxies.
func GuardedTransport() http.RoundTripper {
	return &http.Transport{DialContext: netx.GuardedDialer().DialContext, TLSHandshakeTimeout: config.ExternalHTTPTimeout, ResponseHeaderTimeout: config.ExternalHTTPTimeout, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true}
}

// Resolve implements fosite.JWKSFetcherStrategy.
func (f *KeyFetcher) Resolve(ctx context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	f.mu.Lock()
	cached, ok := f.sets[location]
	f.mu.Unlock()
	age := time.Since(cached.fetched)
	if ok && (age < config.ClientJWKSRefreshInterval || (!ignoreCache && age < config.ClientJWKSCacheTTL)) {
		return cached.set, nil
	}
	set, err := f.fetch(ctx, location)
	if err != nil {
		if ok && age < config.ClientJWKSCacheTTL {
			return cached.set, nil
		}
		return nil, fosite.ErrInvalidClient.WithHint("The client's jwks_uri could not be read.")
	}
	f.mu.Lock()
	if len(f.sets) > config.ClientJWKSCacheEntries {
		f.sets = map[string]fetchedKeys{}
	}
	f.sets[location] = fetchedKeys{set: set, fetched: time.Now()}
	f.mu.Unlock()
	return set, nil
}

func (f *KeyFetcher) fetch(ctx context.Context, location string) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fosite.ErrServerError
	}
	var set jose.JSONWebKeySet
	if err = json.NewDecoder(io.LimitReader(res.Body, config.ClientJWKSMaxBytes)).Decode(&set); err != nil {
		return nil, err
	}
	return signingKeys(&set), nil
}

// tokenURLs accepts the issuer as well as the token endpoint as a client
// assertion audience.
type tokenURLs struct {
	*fosite.Config
	issuer string
}

func (c tokenURLs) GetTokenURLs(context.Context) []string {
	return []string{c.issuer + "/oauth/token", c.issuer}
}

// digest compares service account secrets, stored as SHA-256.
type digest struct{}

func (digest) Compare(_ context.Context, hash, data []byte) error {
	sum := sha256.Sum256(data)
	if len(hash) != len(sum) || subtle.ConstantTimeCompare(hash, sum[:]) != 1 {
		return fosite.ErrInvalidClient
	}
	return nil
}
func (digest) Hash(_ context.Context, data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	return sum[:], nil
}
