// Package telemetry sets up OpenTelemetry tracing and metrics for IAMKit and
// holds the instruments the rest of the code records into.
//
// Everything is off by default: without OTEL_* exporter settings the global
// providers stay OpenTelemetry's no-ops and recording costs nothing. Traces
// and metrics are exported over OTLP/HTTP when the standard variables ask for
// it (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_TRACES_EXPORTER, …); metrics can also
// be scraped in the Prometheus format from a separate listener
// (IAMKIT_METRICS_ADDR), never the public one.
//
// Attributes are low-cardinality only: route templates, methods, outcomes —
// never emails, user ids or raw paths.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ScopeName is the instrumentation scope of IAMKit's own spans and metrics.
const ScopeName = "github.com/Abraxas-365/iamkit"

// Config selects the exporters. The zero value turns everything off.
type Config struct {
	// Traces exports spans over OTLP/HTTP.
	Traces bool
	// Metrics exports metrics over OTLP/HTTP.
	Metrics bool
	// MetricsAddr serves Prometheus metrics at /metrics on this address.
	MetricsAddr string
	// Version is reported as service.version.
	Version string
}

// Enabled reports whether any exporter is on.
func (c Config) Enabled() bool { return c.Traces || c.Metrics || c.MetricsAddr != "" }

// FromEnvironment reads the configuration: OTLP traces when
// OTEL_TRACES_EXPORTER is "otlp" or an OTLP endpoint is set (and the
// exporter is not "none"), metrics the same way with OTEL_METRICS_EXPORTER,
// and IAMKIT_METRICS_ADDR for the Prometheus listener. OTEL_SDK_DISABLED
// turns everything off.
func FromEnvironment() Config {
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return Config{}
	}
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
	wants := func(exporter, signalEndpoint string) bool {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(exporter))) {
		case "otlp":
			return true
		case "":
			return endpoint || os.Getenv(signalEndpoint) != ""
		}
		return false
	}
	return Config{
		Traces:      wants("OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
		Metrics:     wants("OTEL_METRICS_EXPORTER", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"),
		MetricsAddr: strings.TrimSpace(os.Getenv("IAMKIT_METRICS_ADDR")),
	}
}

// Setup installs the global tracer and meter providers and the W3C trace
// context propagator, and starts the Prometheus listener. The returned
// shutdown flushes exporters and stops the listener. With nothing enabled
// it only installs the propagator (incoming trace ids still reach logs).
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if !cfg.Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("iamkit"), semconv.ServiceVersion(version(cfg.Version))),
		resource.WithFromEnv(), resource.WithHost(), resource.WithProcessRuntimeName(), resource.WithProcessRuntimeVersion())
	if err != nil && !errors.Is(err, resource.ErrPartialResource) {
		return nil, err
	}
	var shutdowns []func(context.Context) error
	shutdown := func(ctx context.Context) error {
		var errs error
		for i := len(shutdowns) - 1; i >= 0; i-- {
			errs = errors.Join(errs, shutdowns[i](ctx))
		}
		return errs
	}
	if cfg.Traces {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, err
		}
		provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
		otel.SetTracerProvider(provider)
		shutdowns = append(shutdowns, provider.Shutdown)
	}
	var readers []sdkmetric.Option
	if cfg.Metrics {
		exporter, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, errors.Join(err, shutdown(ctx))
		}
		readers = append(readers, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)))
	}
	if cfg.MetricsAddr != "" {
		registry := prometheus.NewRegistry()
		registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
		if err != nil {
			return nil, errors.Join(err, shutdown(ctx))
		}
		readers = append(readers, sdkmetric.WithReader(exporter))
		stop, err := serveMetrics(cfg.MetricsAddr, registry)
		if err != nil {
			return nil, errors.Join(err, shutdown(ctx))
		}
		shutdowns = append(shutdowns, stop)
	}
	if len(readers) > 0 {
		provider := sdkmetric.NewMeterProvider(append(readers, sdkmetric.WithResource(res))...)
		otel.SetMeterProvider(provider)
		shutdowns = append(shutdowns, provider.Shutdown)
	}
	return shutdown, nil
}

// serveMetrics listens on addr and serves registry at /metrics.
func serveMetrics(addr string, registry *prometheus.Registry) (func(context.Context) error, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics listener stopped", "err", err)
		}
	}()
	slog.Info("metrics listening", "addr", listener.Addr().String())
	return server.Shutdown, nil
}

func version(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}
