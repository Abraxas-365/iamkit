package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestFromEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want Config
	}{
		{"nothing set", nil, Config{}},
		{"endpoint enables both", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318"}, Config{Traces: true, Metrics: true}},
		{"exporter none wins", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://c:4318", "OTEL_METRICS_EXPORTER": "none"}, Config{Traces: true}},
		{"signal endpoint", map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://c:4318/v1/traces"}, Config{Traces: true}},
		{"explicit otlp", map[string]string{"OTEL_METRICS_EXPORTER": "otlp"}, Config{Metrics: true}},
		{"prometheus only", map[string]string{"IAMKIT_METRICS_ADDR": "127.0.0.1:9464"}, Config{MetricsAddr: "127.0.0.1:9464"}},
		{"sdk disabled", map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://c:4318", "IAMKIT_METRICS_ADDR": ":9464"}, Config{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"OTEL_SDK_DISABLED", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER", "IAMKIT_METRICS_ADDR"} {
				t.Setenv(k, tc.env[k])
			}
			if got := FromEnvironment(); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestValidRequestID(t *testing.T) {
	for id, want := range map[string]bool{
		"":                        false,
		"abc-123_X.y:z":           true,
		"has space":               false,
		"new\nline":               false,
		strings.Repeat("a", 128):  true,
		strings.Repeat("a", 129):  false,
		"<script>":                false,
		NewRequestID():            true,
		"0af7651916cd43dd8448eb2": true,
	} {
		if ValidRequestID(id) != want {
			t.Errorf("ValidRequestID(%q) = %v", id, !want)
		}
	}
}

// TestLabelsBounded checks free-form inputs collapse to fixed values.
func TestLabelsBounded(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	ctx := context.Background()
	TokenRequest(ctx, "urn:attacker:anything", 400)
	TokenRequest(ctx, "client_credentials", 200)
	SignIn(ctx, []string{"custom", "mfa"}, Success)
	SignIn(ctx, []string{"pwd"}, Failure)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string][]attribute.Set{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				got[m.Name] = append(got[m.Name], dp.Attributes)
			}
		}
	}
	grants := map[string]bool{}
	for _, s := range got["iamkit.oauth.token_requests"] {
		v, _ := s.Value("grant_type")
		grants[v.AsString()] = true
	}
	if !grants["other"] || !grants["client_credentials"] || len(grants) != 2 {
		t.Fatalf("grant labels %v", grants)
	}
	methods := map[string]bool{}
	for _, s := range got["iamkit.sign_ins"] {
		v, _ := s.Value("method")
		methods[v.AsString()] = true
	}
	if !methods["other"] || !methods["pwd"] || len(methods) != 2 {
		t.Fatalf("method labels %v", methods)
	}
}

// TestPrometheusListener serves /metrics on its own address.
func TestPrometheusListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	shutdown, err := Setup(context.Background(), Config{MetricsAddr: addr, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = shutdown(context.Background())
		otel.SetMeterProvider(sdkmetric.NewMeterProvider())
	})
	HTTPRequest(context.Background(), "GET", "/health", 200, 3*time.Millisecond)

	res, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	for _, want := range []string{"http_server_request_duration_seconds_bucket", `http_route="/health"`, "go_goroutines", `service_name="iamkit"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("/metrics lacks %q", want)
		}
	}
}
