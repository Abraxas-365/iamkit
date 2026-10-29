package netx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type fixed struct{ status int }

func (f fixed) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 2*MaxErrorBody)))}, nil
}

func TestCapErrors(t *testing.T) {
	for status, want := range map[int]int{500: MaxErrorBody, 403: MaxErrorBody, 200: 2 * MaxErrorBody} {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
		res, err := CapErrors(fixed{status}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if len(body) != want {
			t.Errorf("%d: read %d bytes, want %d", status, len(body), want)
		}
	}
}

// The outbound transport for operator- and client-supplied URLs dials the
// target itself: a proxy from the environment would be reached instead of
// the guarded dial (and could be pointed at private addresses), so
// HTTP(S)_PROXY must never apply.
func TestGuardedIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:3128")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:3128")
	t.Setenv("NO_PROXY", "")
	tr, ok := Guarded().(*http.Transport)
	if !ok {
		t.Fatalf("Guarded is %T", Guarded())
	}
	if tr.Proxy != nil || tr.DialContext == nil {
		t.Fatalf("Proxy set = %v, dial guarded = %v", tr.Proxy != nil, tr.DialContext != nil)
	}
}

// Behaviour, not just configuration: with a proxy in the environment a
// request to a loopback target is refused by the guarded dial and nothing
// reaches the proxy.
func TestGuardedRequestsNeverReachTheProxy(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	for _, target := range []string{"http://127.0.0.1:1/doc", "http://localhost:1/doc", "https://127.0.0.1:1/doc"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		res, err := Guarded().RoundTrip(req)
		if err == nil {
			_ = res.Body.Close()
			t.Fatalf("%s: dialed", target)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("the proxy saw %d requests", hits.Load())
	}
}
