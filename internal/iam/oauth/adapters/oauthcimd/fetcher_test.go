package oauthcimd

import (
	"context"
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
	out, fetched, err := f.Document(context.Background(), clientURL(t, claudeCode))
	if err != nil || out.ExternalID != claudeCode || out.Name != "Claude Code" || !out.Public() || fetched.IsZero() {
		t.Fatalf("document = %+v %v %v", out, fetched, err)
	}
	again, fetchedAgain, err := f.Document(context.Background(), clientURL(t, claudeCode))
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
		if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode)); err == nil {
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
		if _, _, err := f.Document(context.Background(), clientURL(t, claudeCode)); err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("err = %v", err)
		}
	}
	if h.calls.Load() != 1 {
		t.Fatalf("calls = %d", h.calls.Load())
	}
}

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
			_, _, err := f.Document(context.Background(), clientURL(t, claudeCode))
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
