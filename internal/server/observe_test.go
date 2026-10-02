package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestObserve checks the request id, the server span (continuing the
// caller's trace), the route-template metric and the log line.
func TestObserve(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(telemetry.LogHandler(slog.NewTextHandler(&logs, nil))))
	t.Cleanup(func() { slog.SetDefault(previous) })

	app := fiber.New(fiber.Config{ErrorHandler: errorHandler})
	app.Use(observe)
	var seen string
	app.Get("/users/:id", func(c *fiber.Ctx) error {
		seen = telemetry.RequestID(c.UserContext())
		slog.InfoContext(c.UserContext(), "inside")
		return errx.NotFound("user not found")
	})

	req := httptest.NewRequest("GET", "/users/0f9a", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set(RequestIDHeader, "caller-id.1")
	res, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 404 || res.Header.Get(RequestIDHeader) != "caller-id.1" || seen != "caller-id.1" {
		t.Fatalf("status %d, echoed %q, seen %q", res.StatusCode, res.Header.Get(RequestIDHeader), seen)
	}

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("%d spans", len(ended))
	}
	span := ended[0]
	if span.Name() != "GET /users/:id" || span.SpanContext().TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("span %q in trace %s", span.Name(), span.SpanContext().TraceID())
	}
	if !hasAttr(span.Attributes(), attribute.Int("http.response.status_code", 404)) {
		t.Fatalf("span attributes %v", span.Attributes())
	}

	var rm metricdata.ResourceMetrics
	if err = reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var route string
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				v, _ := dp.Attributes.Value("http.route")
				route = v.AsString()
			}
		}
	}
	if route != "/users/:id" {
		t.Fatalf("metric route %q, want the template", route)
	}

	out := logs.String()
	for _, want := range []string{"request_id=caller-id.1", "trace_id=4bf92f3577b34da6a3ce929d0e0e4736", "msg=inside", "route=/users/:id", "status=404"} {
		if !strings.Contains(out, want) {
			t.Fatalf("logs lack %q:\n%s", want, out)
		}
	}

	// An unusable incoming id is replaced, and unmatched paths share a label.
	req = httptest.NewRequest("GET", "/nothing/here", nil)
	req.Header.Set(RequestIDHeader, "bad id\n")
	if res, err = app.Test(req); err != nil {
		t.Fatal(err)
	}
	if id := res.Header.Get(RequestIDHeader); len(id) != 32 || !telemetry.ValidRequestID(id) {
		t.Fatalf("generated id %q", id)
	}
	if last := spans.Ended()[len(spans.Ended())-1]; last.Name() != "GET unmatched" {
		t.Fatalf("unmatched span %q", last.Name())
	}
}

func hasAttr(attrs []attribute.KeyValue, want attribute.KeyValue) bool {
	for _, a := range attrs {
		if a == want {
			return true
		}
	}
	return false
}
