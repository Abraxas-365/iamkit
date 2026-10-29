package resourceserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/golang-jwt/jwt/v5"
)

// introspectionFixture is a fixture whose server introspects at a fake
// IAMKit answering with answer (nil: 503).
type introspectionFixture struct {
	*fixture
	calls  atomic.Int32
	answer atomic.Pointer[map[string]any]
}

func newIntrospectionFixture(t *testing.T, ttl time.Duration) *introspectionFixture {
	f := &introspectionFixture{fixture: newFixture(t, Config{})}
	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		id, secret, ok := r.BasicAuth()
		if r.URL.Path != "/oauth/introspect" || !ok || id != "rs-client" || secret != "rs-secret" || r.FormValue("token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		answer := f.answer.Load()
		if answer == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(*answer)
	}))
	t.Cleanup(iam.Close)
	in, err := newIntrospector(issuer, &Introspection{ClientID: "rs-client", ClientSecret: "rs-secret", CacheTTL: ttl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's issuer is not served: route its URLs to the fake.
	target, _ := url.Parse(iam.URL)
	in.client = authclient.NewOAuth(issuer, "rs-client", "rs-secret", authclient.WithOAuthHTTPClient(&http.Client{Transport: rewrite{target}}))
	f.server.introspect = in
	f.active()
	return f
}

type rewrite struct{ target *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host, req.Host = r.target.Scheme, r.target.Host, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func (f *introspectionFixture) active() {
	f.set(map[string]any{"active": true, "token_use": "access_token", "sub": "user-1", "sid": "s-1", "aud": []string{"https://mcp.example.com/mcp"}})
}

func (f *introspectionFixture) set(answer map[string]any) { f.answer.Store(&answer) }

func TestIntrospectionConfig(t *testing.T) {
	for name, cfg := range map[string]*Introspection{
		"no client":    {ClientSecret: "s"},
		"no secret":    {ClientID: "c"},
		"negative ttl": {ClientID: "c", ClientSecret: "s", CacheTTL: -time.Second},
	} {
		if _, err := New(Config{Issuer: issuer, Resource: resource, EnvironmentID: "env-1", Introspection: cfg}); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

func TestIntrospection(t *testing.T) {
	f := newIntrospectionFixture(t, 0)
	ctx := context.Background()
	raw := f.token(nil)
	if _, err := f.server.Verify(ctx, raw); err != nil {
		t.Fatalf("active token: %v", err)
	}
	// No cache by default: every request asks.
	f.server.Verify(ctx, raw)
	if n := f.calls.Load(); n != 2 {
		t.Fatalf("calls without cache = %d, want 2", n)
	}
	// A revoked token stops at once.
	f.set(map[string]any{"active": false})
	if _, err := f.server.Verify(ctx, raw); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("inactive token: %v", err)
	}
	// An answer about another token, session or audience is not this one's.
	for name, answer := range map[string]map[string]any{
		"other subject":  {"active": true, "token_use": "access_token", "sub": "user-2", "sid": "s-1", "aud": []string{resource}},
		"other session":  {"active": true, "token_use": "access_token", "sub": "user-1", "sid": "s-2", "aud": []string{resource}},
		"other audience": {"active": true, "token_use": "access_token", "sub": "user-1", "sid": "s-1", "aud": []string{"https://other.example"}},
		"refresh token":  {"active": true, "token_use": "refresh_token", "sub": "user-1", "sid": "s-1", "aud": []string{resource}},
	} {
		f.set(answer)
		if _, err := f.server.Verify(ctx, raw); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Fails closed: IAMKit down → 503, no challenge, the token is not admitted.
	f.answer.Store(nil)
	if _, err := f.server.Verify(ctx, raw); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("introspection down: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	f.server.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler reached") })).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("down: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	// A token that fails the local checks never reaches IAMKit.
	f.active()
	before := f.calls.Load()
	if _, err := f.server.Verify(ctx, f.token(func(c jwt.MapClaims) { c["aud"] = "https://other.example" })); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("foreign token: %v", err)
	}
	if f.calls.Load() != before {
		t.Fatal("a locally invalid token was introspected")
	}
}

func TestIntrospectionCache(t *testing.T) {
	f := newIntrospectionFixture(t, time.Minute)
	now := time.Now()
	f.server.introspect.now = func() time.Time { return now }
	ctx := context.Background()
	raw := f.token(func(c jwt.MapClaims) { c["exp"] = now.Add(30 * time.Second).Unix() })
	for range 3 {
		if _, err := f.server.Verify(ctx, raw); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("cached calls = %d, want 1", n)
	}
	// An inactive answer is never cached.
	other := f.token(func(c jwt.MapClaims) { c["jti"] = "j2" })
	f.set(map[string]any{"active": false})
	f.server.Verify(ctx, other)
	f.active()
	if _, err := f.server.Verify(ctx, other); err != nil {
		t.Fatalf("after an inactive answer: %v", err)
	}
	// The cache holds no answer past the token's exp (30s < CacheTTL).
	calls := f.calls.Load()
	now = now.Add(31 * time.Second)
	f.server.introspect.check(ctx, raw, resource, &Claims{Subject: "user-1", SessionID: "s-1"})
	if f.calls.Load() != calls+1 {
		t.Fatal("cache answered past the token's exp")
	}
}

func TestIntrospectionCacheBound(t *testing.T) {
	in := &introspector{max: 2, ttl: time.Minute, cache: map[[32]byte]time.Time{}}
	now := time.Now()
	for i := range 5 {
		in.store([32]byte{byte(i)}, now.Add(time.Minute), now)
	}
	if len(in.cache) > 2 {
		t.Fatalf("cache grew to %d", len(in.cache))
	}
}
