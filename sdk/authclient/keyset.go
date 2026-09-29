package authclient

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/golang-jwt/jwt/v5"
)

// KeySet caches IAMKit's published signing keys (/.well-known/jwks.json)
// by kid. Environments can rotate their keys: a new key is published
// before it signs, so a cached set refreshed on an unknown kid (at most
// once per MinRefresh) and every MaxAge always holds it.
type KeySet struct {
	url        string
	client     *http.Client
	MaxAge     time.Duration // refresh every MaxAge (default 10 minutes)
	MinRefresh time.Duration // at most one refresh per MinRefresh on an unknown kid (default 30 seconds)

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetched   time.Time // last successful fetch
	attempted time.Time // last fetch, successful or not
	now       func() time.Time
}

// NewKeySet fetches keys from jwksURL (for example
// "https://iam.example.com/.well-known/jwks.json") on first use.
// client may be nil (http.DefaultClient with a 10 second timeout).
func NewKeySet(jwksURL string, client *http.Client) *KeySet {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &KeySet{url: jwksURL, client: client, MaxAge: 10 * time.Minute, MinRefresh: 30 * time.Second, now: time.Now}
}

// Key returns the published key named kid, refreshing the set when kid is
// unknown or the set is older than MaxAge.
func (k *KeySet) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	stale := k.keys == nil || now.Sub(k.fetched) >= k.MaxAge
	if key, ok := k.keys[kid]; ok && !stale {
		return key, nil
	}
	// Fetch attempts (also failed ones, during an outage) are spaced by
	// MinRefresh; a failed refresh keeps serving the last set.
	if k.attempted.IsZero() || now.Sub(k.attempted) >= k.MinRefresh {
		k.attempted = now
		if err := k.refresh(ctx); err != nil && k.keys == nil {
			return nil, err
		}
	}
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "unknown signing key", HTTPStatus: 401}
}

func (k *KeySet) refresh(ctx context.Context) error {
	failed := &apierror.Error{Code: "JWKS_UNAVAILABLE", Message: "signing keys could not be fetched", HTTPStatus: 503}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return failed
	}
	res, err := k.client.Do(req)
	if err != nil {
		return failed
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return failed
	}
	var body struct {
		Keys []struct {
			Kty, Use, Alg, Kid, N, E string
		} `json:"keys"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return failed
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range body.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(jwk.N)
		e, errE := base64.RawURLEncoding.DecodeString(jwk.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	k.keys, k.fetched = keys, k.now()
	return nil
}

// ValidateWithKeySet is Validate with the key picked by the token's kid
// from keys: tokens keep validating across signing-key rotations.
func ValidateWithKeySet(ctx context.Context, raw string, keys *KeySet, issuer, audience, environment, application, resource string) (*Claims, error) {
	if keys == nil {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "key and expected token boundaries required", HTTPStatus: 400}
	}
	return validate(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return keys.Key(ctx, kid)
	}, issuer, audience, environment, application, resource)
}
