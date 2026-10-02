package telemetry

import (
	"context"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Instruments are created from the global meter provider and rebuilt if
// it is replaced (tests); before Setup the global delegates, so instruments
// made then still export.
type instrumentSet struct {
	provider    metric.MeterProvider
	httpServer  metric.Float64Histogram
	signIns     metric.Int64Counter
	mfaFailures metric.Int64Counter
	deliveries  metric.Int64Counter
	deliveryDur metric.Float64Histogram
	tokens      metric.Int64Counter
	logouts     metric.Int64Counter
	webhooks    metric.Int64Counter
	workerRuns  metric.Float64Histogram
	workerLag   metric.Float64Gauge
	cache       metric.Int64Counter
}

var current atomic.Pointer[instrumentSet]

// Duration buckets in seconds (OpenTelemetry HTTP semantic conventions).
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}

func instruments() *instrumentSet {
	provider := otel.GetMeterProvider()
	if s := current.Load(); s != nil && s.provider == provider {
		return s
	}
	m := provider.Meter(ScopeName)
	s := &instrumentSet{provider: provider}
	s.httpServer, _ = m.Float64Histogram("http.server.request.duration", metric.WithUnit("s"),
		metric.WithDescription("Duration of HTTP server requests."), metric.WithExplicitBucketBoundaries(durationBuckets...))
	s.signIns, _ = m.Int64Counter("iamkit.sign_ins", metric.WithUnit("{sign_in}"),
		metric.WithDescription("End-user sign-in outcomes by first-factor method."))
	s.mfaFailures, _ = m.Int64Counter("iamkit.mfa.failures", metric.WithUnit("{failure}"),
		metric.WithDescription("Wrong second-factor answers."))
	s.deliveries, _ = m.Int64Counter("iamkit.delivery.attempts", metric.WithUnit("{attempt}"),
		metric.WithDescription("Email and SMS delivery attempts."))
	s.deliveryDur, _ = m.Float64Histogram("iamkit.delivery.duration", metric.WithUnit("s"),
		metric.WithDescription("Email and SMS delivery latency."), metric.WithExplicitBucketBoundaries(durationBuckets...))
	s.tokens, _ = m.Int64Counter("iamkit.oauth.token_requests", metric.WithUnit("{request}"),
		metric.WithDescription("OAuth token endpoint requests by grant type and outcome."))
	s.logouts, _ = m.Int64Counter("iamkit.logout.deliveries", metric.WithUnit("{delivery}"),
		metric.WithDescription("Back-channel logout delivery outcomes."))
	s.webhooks, _ = m.Int64Counter("iamkit.webhook.deliveries", metric.WithUnit("{delivery}"),
		metric.WithDescription("Event webhook delivery attempts by outcome."))
	s.workerRuns, _ = m.Float64Histogram("iamkit.worker.round.duration", metric.WithUnit("s"),
		metric.WithDescription("Background job rounds by job and outcome."), metric.WithExplicitBucketBoundaries(durationBuckets...))
	s.workerLag, _ = m.Float64Gauge("iamkit.worker.lag", metric.WithUnit("s"),
		metric.WithDescription("How long the oldest due item of a background job has waited."))
	s.cache, _ = m.Int64Counter("iamkit.cache.lookups", metric.WithUnit("{lookup}"),
		metric.WithDescription("Shared cache (REDIS_URL) lookups by key family and result."))
	current.Store(s)
	return s
}

// HTTPRequest records one served request. route must be a route template.
func HTTPRequest(ctx context.Context, method, route string, status int, elapsed time.Duration) {
	instruments().httpServer.Record(ctx, elapsed.Seconds(), metric.WithAttributes(
		attribute.String("http.request.method", Method(method)),
		attribute.String("http.route", route),
		attribute.Int("http.response.status_code", status)))
}

// Method maps a request method to itself when standard, else "_OTHER".
func Method(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return method
	}
	return "_OTHER"
}

// Sign-in outcomes.
const (
	Success = "success"
	Failure = "failure"
)

// SignIn records an end-user sign-in outcome; amr are the session's
// authentication methods (the first names the first factor).
func SignIn(ctx context.Context, amr []string, result string) {
	method, mfa := "other", false
	if len(amr) > 0 {
		switch amr[0] {
		case "pwd", "email", "fed", "hwk":
			method = amr[0]
		}
	}
	for _, m := range amr {
		mfa = mfa || m == "mfa"
	}
	instruments().signIns.Add(ctx, 1, metric.WithAttributes(attribute.String("method", method),
		attribute.String("result", result), attribute.Bool("mfa", mfa)))
}

// MFAFailure records one wrong second-factor answer.
func MFAFailure(ctx context.Context) {
	instruments().mfaFailures.Add(ctx, 1)
}

// Delivery records one email or SMS delivery attempt. channel, source and
// purpose are the bounded values of authentication.Attempt.
func Delivery(ctx context.Context, channel, source, purpose string, delivered bool, elapsed time.Duration) {
	result := Success
	if !delivered {
		result = Failure
	}
	attrs := metric.WithAttributes(attribute.String("channel", channel), attribute.String("source", source),
		attribute.String("purpose", purpose), attribute.String("result", result))
	s := instruments()
	s.deliveries.Add(ctx, 1, attrs)
	s.deliveryDur.Record(ctx, elapsed.Seconds(), attrs)
}

// grants are the token endpoint grant types reported by name.
var grants = map[string]bool{
	"authorization_code": true, "refresh_token": true, "client_credentials": true,
	"urn:ietf:params:oauth:grant-type:device_code":    true,
	"urn:ietf:params:oauth:grant-type:token-exchange": true,
	"urn:ietf:params:oauth:grant-type:jwt-bearer":     true,
}

// TokenRequest records a token endpoint response by grant type; unknown
// grant types are reported as "other".
func TokenRequest(ctx context.Context, grant string, status int) {
	if !grants[grant] {
		grant = "other"
	}
	result := Success
	if status >= 400 {
		result = Failure
	}
	instruments().tokens.Add(ctx, 1, metric.WithAttributes(attribute.String("grant_type", grant), attribute.String("result", result)))
}

// Logout delivery outcomes.
const (
	LogoutDelivered = "delivered"
	LogoutRetried   = "retried"
	LogoutFailed    = "failed"
)

// Logout records one back-channel logout delivery outcome.
func Logout(ctx context.Context, result string) {
	instruments().logouts.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// Event webhook delivery outcomes.
const (
	WebhookDelivered = "delivered"
	WebhookRetried   = "retried"
	WebhookFailed    = "failed"
)

// Webhook records one event webhook delivery attempt.
func Webhook(ctx context.Context, result string) {
	instruments().webhooks.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// WorkerRun records one background job round.
func WorkerRun(ctx context.Context, job, result string, elapsed time.Duration) {
	instruments().workerRuns.Record(ctx, elapsed.Seconds(), metric.WithAttributes(
		attribute.String("job", job), attribute.String("result", result)))
}

// WorkerLag records how long the oldest due item of job has waited (zero
// when nothing is due).
func WorkerLag(ctx context.Context, job string, lag time.Duration) {
	instruments().workerLag.Record(ctx, max(lag, 0).Seconds(), metric.WithAttributes(attribute.String("job", job)))
}

// Cache lookup results.
const (
	CacheHit   = "hit"
	CacheMiss  = "miss"
	CacheError = "error"
)

// CacheLookup records one cache lookup of a key family (feature, action,
// oidc).
func CacheLookup(ctx context.Context, family, result string) {
	instruments().cache.Add(ctx, 1, metric.WithAttributes(attribute.String("family", family), attribute.String("result", result)))
}
