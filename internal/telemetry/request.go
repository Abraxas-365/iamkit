package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

type requestIDKey struct{}

// WithRequestID returns ctx carrying the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID is the id of the request ctx serves, "" outside requests.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewRequestID returns a random 32-hex-digit id.
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidRequestID accepts a caller-supplied id of 1–128 characters from
// [A-Za-z0-9._:-], so it is safe to echo and to log.
func ValidRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == ':' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

// LogHandler adds request_id, trace_id and span_id from the record's
// context to every log line.
func LogHandler(next slog.Handler) slog.Handler { return logHandler{next} }

type logHandler struct{ next slog.Handler }

func (h logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h logHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		if id := RequestID(ctx); id != "" {
			r.AddAttrs(slog.String("request_id", id))
		}
		if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
			r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
		}
	}
	return h.next.Handle(ctx, r)
}

func (h logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return logHandler{h.next.WithAttrs(attrs)}
}

func (h logHandler) WithGroup(name string) slog.Handler { return logHandler{h.next.WithGroup(name)} }
