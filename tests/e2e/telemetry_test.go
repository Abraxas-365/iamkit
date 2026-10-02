package e2e_test

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestTelemetry drives real requests through a database opened like
// production and checks spans and metrics: the server span is the parent
// of the query spans, and sign-in outcomes are counted after commit.
func TestTelemetry(t *testing.T) {
	requireE2E(t)
	spans := tracetest.NewSpanRecorder()
	reader := sdkmetric.NewManualReader()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetMeterProvider(sdkmetric.NewMeterProvider())
	})

	e := newEnv(t)
	// A second pool on the same database, opened the production way.
	var name string
	if err := e.DB.Get(&name, `SELECT current_database()`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", withDB(adminDSN, name))
	db, err := bootstrap.OpenDatabase()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key, err := bootstrap.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	app := bootstrap.New(db, key, "https://iam.example", e.Mail).App()
	t.Cleanup(func() { app.Shutdown() })
	h := &Harness{t: t, DB: db, App: contracted(t, app), Owner: e.Owner}

	h.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 200)
	h.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, "wrong password!!"), 401)
	h.Must("GET", "/identity/v1/login/nope", "", nil, 404)

	var server trace.SpanContext
	queries := 0
	for _, s := range spans.Ended() {
		if s.Name() == "POST /identity/v1/login" && !server.IsValid() {
			server = s.SpanContext()
		}
	}
	if !server.IsValid() {
		t.Fatal("no server span for the login route")
	}
	for _, s := range spans.Ended() {
		if s.SpanKind() == trace.SpanKindClient && s.Parent().SpanID() == server.SpanID() {
			queries++
		}
	}
	if queries == 0 {
		t.Fatal("no database spans under the login request")
	}

	var rm metricdata.ResourceMetrics
	if err = reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	signIns := map[string]int64{}
	names := map[string]bool{}
	routes := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if m.Name == "iamkit.sign_ins" {
					for _, dp := range data.DataPoints {
						method, _ := dp.Attributes.Value("method")
						result, _ := dp.Attributes.Value("result")
						signIns[method.AsString()+" "+result.AsString()] += dp.Value
					}
				}
			case metricdata.Histogram[float64]:
				if m.Name == "http.server.request.duration" {
					for _, dp := range data.DataPoints {
						route, _ := dp.Attributes.Value(attribute.Key("http.route"))
						routes[route.AsString()] = true
					}
				}
			}
		}
	}
	if signIns["pwd success"] != 1 || signIns["pwd failure"] != 1 {
		t.Fatalf("sign-ins %v", signIns)
	}
	if !routes["/identity/v1/login"] || !routes["unmatched"] {
		t.Fatalf("routes %v", routes)
	}
	for _, want := range []string{"db.client.operation.duration", "db.sql.connection.open"} {
		if !names[want] {
			t.Fatalf("metric %s missing from %v", want, names)
		}
	}
}
