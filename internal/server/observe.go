package server

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// RequestIDHeader carries the request id: a valid incoming value is kept,
// otherwise one is generated; it is echoed on every response.
const RequestIDHeader = "X-Request-Id"

// headerCarrier reads propagation headers (traceparent, baggage) from the
// request.
type headerCarrier struct{ c *fiber.Ctx }

func (h headerCarrier) Get(key string) string { return h.c.Get(key) }
func (h headerCarrier) Set(string, string)    {}
func (h headerCarrier) Keys() []string        { return nil }

var _ propagation.TextMapCarrier = headerCarrier{}

// observe is the outermost middleware: it assigns the request id, starts
// the server span (continuing an incoming W3C trace context), and after the
// handlers — and the error handler, which it runs itself so the status is
// final — records the request duration by route template and logs one line.
// Handlers pass c.UserContext() on, so database and outbound spans and log
// lines join the request.
func observe(c *fiber.Ctx) error {
	start := time.Now()
	id := c.Get(RequestIDHeader)
	if !telemetry.ValidRequestID(id) {
		id = telemetry.NewRequestID()
	}
	c.Set(RequestIDHeader, id)
	ctx := otel.GetTextMapPropagator().Extract(telemetry.WithRequestID(c.UserContext(), id), headerCarrier{c})
	method := telemetry.Method(c.Method())
	var span trace.Span
	traced := c.Path() != "/health"
	if traced {
		ctx, span = otel.Tracer(telemetry.ScopeName).Start(ctx, method, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", method), attribute.String("url.scheme", c.Protocol())))
	}
	c.SetUserContext(ctx)

	err := c.Next()
	route := c.Route().Path
	var routerErr *fiber.Error
	if errors.As(err, &routerErr) && routerErr.Code == fiber.StatusNotFound && strings.HasPrefix(routerErr.Message, "Cannot ") {
		// The router's own answer: no route matched (only prefix
		// middleware ran), so no template names the request.
		route = ""
	}
	if err != nil {
		if err = c.App().ErrorHandler(c, err); err != nil {
			_ = c.SendStatus(fiber.StatusInternalServerError)
		}
	}
	status := c.Response().StatusCode()
	if route == "" {
		route = "unmatched"
	}
	elapsed := time.Since(start)
	telemetry.HTTPRequest(ctx, method, route, status, elapsed)
	if traced {
		span.SetName(method + " " + route)
		span.SetAttributes(attribute.String("http.route", route), attribute.Int("http.response.status_code", status))
		if status >= 500 {
			span.SetStatus(codes.Error, "")
		}
		span.End()
	}
	slog.InfoContext(ctx, "request",
		"method", c.Method(),
		"path", c.Path(),
		"route", route,
		"status", status,
		"latency", elapsed.String(),
		"ip", c.IP(),
	)
	return nil
}
