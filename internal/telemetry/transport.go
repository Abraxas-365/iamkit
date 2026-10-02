package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
)

// Transport instruments outbound requests (identity providers, email/SMS
// providers, webhooks, JWKS, back-channel logout): a client span named after
// the method and a duration metric by server address. It propagates only
// the W3C trace context — never incoming baggage — to third parties. nil
// means http.DefaultTransport.
func Transport(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	if _, ok := next.(*otelhttp.Transport); ok {
		return next
	}
	return otelhttp.NewTransport(next, otelhttp.WithPropagators(propagation.TraceContext{}),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return "HTTP " + Method(r.Method) }))
}
