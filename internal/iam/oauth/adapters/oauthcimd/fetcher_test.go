package oauthcimd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/cache/cachememory"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/netx"
)

// host answers every request with status, headers and body, counting them.
type host struct {
	mu      sync.Mutex
	status  int
	header  http.Header
	body    string
	calls   atomic.Int32
	release chan struct{}
}

func (h *host) RoundTrip(r *http.Request) (*http.Response, error) {
	h.calls.Add(1)
	if h.release != nil {
		<-h.release
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	header := h.header.Clone()
	if header == nil {
		header = http.Header{"Content-Type": {"application/json"}}
	}
	return &http.Response{StatusCode: h.status, Header: header, Body: io.NopCloser(strings.NewReader(h.body)), Request: r}, nil
}

const claudeCode = "https://claude.ai/oauth/claude-code-client-metadata"

func doc(clientID string) string {
	return `{"client_id":"` + clientID + `","client_name":"Claude Code","redirect_uris":["http://localhost/callback"],"token_endpoint_auth_method":"none"}`
}

func clientURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestDocumentCachedAndValidated(t *testing.T) {
	h := &host{status: 200, body: doc(claudeCode)}
	f := New(h, cachememory.New())
	out, fetched, err := f.Document(context.Background(), clientURL(t, claudeCode), nil)
	if err != nil || out.ExternalID != claudeCode || out.Name != "Claude Code" || !out.Public() || fetched.IsZero() {
		t.Fatalf("document = %+v %v %v", out, fetched, err)
	}
	again, fetchedAgain, err := f.Document(context.Background(), clientURL(t, claudeCode), nil)
	if err != nil || again.ExternalID != claudeCode || !fetchedAgain.Equal(fetched) || h.calls.Load() != 1 {
		t.Fatalf("cached read: %v, %d calls", err, h.calls.Load())
	}
}

func TestDocumentRefusals(t *testing.T) {
	big := `{"client_id":"` + claudeCode + `","client_name":"` + strings.Repeat("x", int(config.ClientMetadataMaxBytes)) + `"}`
	for name, h := range map[string]*host{
		"not found":      {status: 404},
		"redirect":       {status: 302, header: http.Header{"Location": {"https://evil.example/doc"}}},
		"not json":       {status: 200, header: http.Header{"Content-Type": {"text/html"}}, body: doc(claudeCode)},
		"too large":      {status: 200, body: big},
		"other id":       {status: 200, body: doc("https://claude.ai/oauth/other")},
		"secret":         {status: 200, body: `{"client_id":"` + claudeCode + `","redirect_uris":["http://localhost/cb"],"client_secret":"s"}`},
		"embedded jwks":  {status: 200, body: `{"client_id":"` + claudeCode + `","redirect_uris":["http://localhost/cb"],"jwks":{"keys":[]}}`},
		"foreign jwks":   {status: 200, body: `{"client_id":"` + claudeCode + `","redirect_uris":["https://claude.ai/cb"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://keys.example/jwks"}`},
		"secret method":  {status: 200, body: `{"client_id":"` + claudeCode + `","redirect_uris":["https://claude.ai/cb"],"token_endpoint_auth_method":"client_secret_basic"}`},
		"http redirect":  {status: 200, body: `{"client_id":"` + claudeCode + `","redirect_uris":["http://claude.ai/cb"]}`},
		"malformed json": {status: 200, body: `{`},
	} {
		f := New(h, cachememory.New())
		if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A failure is remembered briefly: a broken host is read once per
// config.ClientMetadataFailureTTL, not on every authorization.
func TestFailureCached(t *testing.T) {
	h := &host{status: 500}
	f := New(h, cachememory.New())
	for range 3 {
		if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode), nil); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("err = %v", err)
		}
	}
	if h.calls.Load() != 1 {
		t.Fatalf("calls = %d", h.calls.Load())
	}
}

// M-4: only a failure that says nothing about the document (an error
// status, a transport error), cached or not, is "unavailable"; a document
// that does not validate is not.
func TestUnavailableOnlyForHostFailures(t *testing.T) {
	code := func(err error) string {
		var e *errx.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	h := &host{status: 503}
	f := New(h, cachememory.New())
	for range 2 { // the second answer is the cached failure
		if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode), nil); code(err) != oauth.CodeDocumentUnavailable {
			t.Fatalf("503: %v", err)
		}
	}
	down := New(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") }), cachememory.New())
	for range 2 {
		if _, _, err := down.Document(context.Background(), clientURL(t, claudeCode), nil); code(err) != oauth.CodeDocumentUnavailable {
			t.Fatalf("transport error: %v", err)
		}
	}
	for name, h := range map[string]*host{
		"invalid":  {status: 200, body: `{"client_id":"` + claudeCode + `"}`},
		"not json": {status: 200, header: http.Header{"Content-Type": {"text/html"}}, body: doc(claudeCode)},
		"other id": {status: 200, body: doc("https://claude.ai/oauth/other")},
	} {
		f := New(h, cachememory.New())
		for range 2 {
			if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode), nil); err == nil || code(err) == oauth.CodeDocumentUnavailable {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	// A refusal by the budget is returned as it is (and cached nowhere).
	budget := New(&host{status: 200, body: doc(claudeCode)}, cachememory.New())
	if _, _, err := budget.Document(context.Background(), clientURL(t, claudeCode), func(context.Context) error { return oauth.ErrFetchBudget() }); code(err) != oauth.CodeFetchBudget {
		t.Fatalf("budget: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Concurrent first reads of one URL fetch it once.
func TestSingleFetch(t *testing.T) {
	h := &host{status: 200, body: doc(claudeCode), release: make(chan struct{})}
	f := New(h, cachememory.New())
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := f.Document(context.Background(), clientURL(t, claudeCode), nil)
			errs <- err
		}()
	}
	for h.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(h.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if h.calls.Load() != 1 {
		t.Fatalf("calls = %d", h.calls.Load())
	}
}

func TestCacheTTL(t *testing.T) {
	for header, want := range map[string]time.Duration{
		"":                       config.ClientMetadataMinTTL,
		"no-store":               config.ClientMetadataMinTTL,
		"max-age=60":             config.ClientMetadataMinTTL,
		"public, max-age=3600":   time.Hour,
		"max-age=31536000":       config.ClientMetadataMaxTTL,
		"max-age=3600, no-cache": config.ClientMetadataMinTTL,
		"max-age=abc":            config.ClientMetadataMinTTL,
	} {
		if got := CacheTTL(http.Header{"Cache-Control": {header}}); got != want {
			t.Errorf("%q = %v, want %v", header, got, want)
		}
	}
}

func TestResolveKeys(t *testing.T) {
	h := &host{status: 200, body: `{"keys":[{"kty":"RSA","kid":"k1","use":"sig","n":"` + strings.Repeat("A", 342) + `Q","e":"AQAB"},{"kty":"RSA","kid":"enc","use":"enc","n":"` + strings.Repeat("A", 342) + `Q","e":"AQAB"}]}`}
	f := New(h, cachememory.New())
	set, err := f.Resolve(context.Background(), "https://chatgpt.com/oauth/jwks.json", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "k1" {
		t.Fatalf("keys = %+v", set.Keys)
	}
	// An unknown kid refetches at most once per refresh interval.
	f.Resolve(context.Background(), "https://chatgpt.com/oauth/jwks.json", true)
	f.Resolve(context.Background(), "https://chatgpt.com/oauth/jwks.json", true)
	if h.calls.Load() != 2 {
		t.Fatalf("calls = %d", h.calls.Load())
	}
}

// The fetch budget is asked for network reads only: cached answers are
// free, and a refusal reads nothing and caches nothing.
func TestDocumentAdmitOnlyForNetworkReads(t *testing.T) {
	h := &host{status: 200, body: doc(claudeCode)}
	f := New(h, cachememory.New())
	asked := 0
	deny := false
	admit := func(context.Context) error {
		asked++
		if deny {
			return context.DeadlineExceeded
		}
		return nil
	}
	deny = true
	if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode), admit); err == nil || h.calls.Load() != 0 {
		t.Fatalf("refused read: %v, %d calls", err, h.calls.Load())
	}
	deny = false
	for range 3 {
		if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode), admit); err != nil {
			t.Fatal(err)
		}
	}
	if asked != 2 || h.calls.Load() != 1 {
		t.Fatalf("asked %d (want 2: the refusal and the one fetch), %d calls", asked, h.calls.Load())
	}
}

// The unknown-kid refetch is throttled in the shared store: two replicas
// (two fetchers on one store) refetch at most once between them per
// interval, and again after it.
func TestResolveRefreshThrottleIsShared(t *testing.T) {
	const location = "https://chatgpt.com/oauth/jwks.json"
	body := `{"keys":[{"kty":"RSA","kid":"k1","use":"sig","n":"` + strings.Repeat("A", 342) + `Q","e":"AQAB"}]}`
	h := &host{status: 200, body: body}
	store := cachememory.New()
	a, b := New(h, store), New(h, store)
	ctx := context.Background()
	if _, err := a.Resolve(ctx, location, false); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*Fetcher{a, b, a, b} {
		if _, err := f.Resolve(ctx, location, true); err != nil {
			t.Fatal(err)
		}
	}
	if h.calls.Load() != 2 {
		t.Fatalf("calls = %d, want the first read and one forced refetch for both replicas", h.calls.Load())
	}
	// Another location is throttled on its own.
	if _, err := b.Resolve(ctx, "https://chatgpt.com/other/jwks.json", true); err != nil {
		t.Fatal(err)
	}
	if h.calls.Load() != 3 {
		t.Fatalf("calls = %d", h.calls.Load())
	}
}

// TestRefreshClaimWithoutStore is N-7: with no cache store the claim to
// refetch a key set is still one per interval (per process), not every call.
func TestRefreshClaimWithoutStore(t *testing.T) {
	f := New(&host{status: 200}, nil)
	ctx := context.Background()
	const location = "https://chatgpt.com/oauth/jwks.json"
	if !f.mayRefresh(ctx, location) {
		t.Fatal("first claim refused")
	}
	if f.mayRefresh(ctx, location) {
		t.Fatal("second claim within the interval granted")
	}
	f.now = func() time.Time { return time.Now().Add(config.ClientJWKSRefreshInterval + time.Second) }
	if !f.mayRefresh(ctx, location) {
		t.Fatal("claim after the interval refused")
	}
}

// downStore is a cache that is unavailable.
type downStore struct{ noCache }

func (downStore) Get(context.Context, string) ([]byte, bool, error) {
	return nil, false, context.DeadlineExceeded
}
func (downStore) Set(context.Context, string, []byte, time.Duration) error {
	return context.DeadlineExceeded
}
func (downStore) SetNX(context.Context, string, []byte, time.Duration) (bool, error) {
	return false, context.DeadlineExceeded
}

// With the shared store down the throttle falls back to the process: it
// still limits refetches.
func TestResolveRefreshThrottleStoreDown(t *testing.T) {
	const location = "https://chatgpt.com/oauth/jwks.json"
	h := &host{status: 200, body: `{"keys":[{"kty":"RSA","kid":"k1","use":"sig","n":"` + strings.Repeat("A", 342) + `Q","e":"AQAB"}]}`}
	f := New(h, downStore{})
	for range 5 {
		if _, err := f.Resolve(context.Background(), location, true); err != nil {
			t.Fatal(err)
		}
	}
	// Nothing is cached, so each Resolve reads; the throttle only decides
	// whether the read is forced past a cached body, which cannot matter
	// here: the claim must be granted once per interval.
	f.mu.Lock()
	n := len(f.refreshed)
	f.mu.Unlock()
	if n != 1 || !f.mayRefresh(context.Background(), "https://other.example/jwks") || f.mayRefresh(context.Background(), "https://other.example/jwks") {
		t.Fatalf("fallback throttle: %d tracked", n)
	}
}

// Whatever the environment says, the default transport of the fetcher is
// the shared guarded one, which has no proxy.
func TestDefaultTransportIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:3128")
	tr, ok := netx.Guarded().(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("guarded transport %T has a proxy", netx.Guarded())
	}
	// And the fetcher built without a transport takes exactly that one.
	f := New(nil, nil)
	if f.client.Transport == nil {
		t.Fatal("no transport")
	}
}
