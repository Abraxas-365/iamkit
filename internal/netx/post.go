package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// Guarded is the shared outbound transport that dials public addresses
// only. Tests and IAMKIT_ALLOW_PRIVATE_DELIVERY replace it per feature.
var Guarded = sync.OnceValue(func() http.RoundTripper {
	return &http.Transport{
		DialContext:           GuardedDialer().DialContext,
		TLSHandshakeTimeout:   config.ExternalHTTPTimeout,
		ResponseHeaderTimeout: config.LogStreamTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
	}
})

// MaxResponseRead caps how much of an answer is read (and discarded).
const MaxResponseRead = 4096

// MaxErrorBody caps the body of a non-2xx answer read through CapErrors.
const MaxErrorBody = 64 << 10

// CapErrors wraps transport so the body of a non-2xx answer ends after
// MaxErrorBody bytes: SDKs that parse error documents (S3) cannot be made
// to read an endless one. Successful bodies pass unchanged.
func CapErrors(transport http.RoundTripper) http.RoundTripper {
	return capErrors{transport}
}

type capErrors struct{ next http.RoundTripper }

func (c capErrors) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(req)
	if err == nil && (res.StatusCode < 200 || res.StatusCode > 299) && res.Body != nil {
		res.Body = cappedBody{io.LimitReader(res.Body, MaxErrorBody), res.Body}
	}
	return res, err
}

type cappedBody struct {
	io.Reader
	io.Closer
}

// Do sends req through transport (nil: Guarded) without following
// redirects, within timeout, reading at most MaxResponseRead bytes of the
// answer. It returns the HTTP status (0 when no response arrived) and an
// operator-facing error text, empty for a 2xx answer. The text names a
// cause only (never the URL, a header or the body), so it can be stored
// and shown.
func Do(ctx context.Context, transport http.RoundTripper, req *http.Request, timeout time.Duration) (int, string) {
	if transport == nil {
		transport = Guarded()
	}
	client := http.Client{Transport: telemetry.Transport(transport), Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, Reason(err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, MaxResponseRead))
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return res.StatusCode, ""
	}
	return res.StatusCode, "endpoint answered " + strconv.Itoa(res.StatusCode)
}

// Reason is a short, operator-facing cause of a failed request (no
// internal addresses).
func Reason(err error) string {
	var timeout interface{ Timeout() bool }
	switch {
	case errors.Is(err, ErrNotPublic):
		return "the URL does not resolve to a public address"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timed out"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "host not found"
	}
	return "endpoint unreachable"
}
