package e2e_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestWorkers: the background jobs are registered on the runner, report
// their state on /health, drain the logout outbox and record the lag of
// its oldest due row; IAMKIT_WORKERS=false keeps them off.
func TestWorkers(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(sdkmetric.NewMeterProvider()) })
	e := newEnv(t)

	w := e.Server.Workers
	want := []string{"logout_delivery", "logout_prune", "client_admission_expire", "client_documents_reconcile", "client_pending_prune", "client_registration_prune", "event_prune", "event_webhook", "event_webhook_maintenance",
		"log_stream_delivery", "log_stream_maintenance", "action_call_prune", "usage_rollup", "usage_prune", "audit_log_prune", "waitlist_prune", "sign_in_attempt_prune", "captcha_pass_prune", "saml_logout_delivery", "saml_logout_prune", "federation_logout_prune", "federation_draft_prune"}
	if got := w.Jobs(); !slices.Equal(got, want) {
		t.Fatalf("jobs = %v", got)
	}
	if health := e.Must("GET", "/health", "", nil, 200).JSON; health["workers"] != "idle" {
		t.Fatalf("health = %v", health)
	}

	// A notification due for a minute (no client URI: it is given up).
	e.DB.MustExec(`INSERT INTO logout_notifications (environment_id, client_id, session_id, subject, attempts, next_attempt_at)
		VALUES ($1, gen_random_uuid(), gen_random_uuid(), $2, 7, now() - interval '1 minute')`, e.EnvID, e.Alice)
	if found, err := w.RunOnce(context.Background(), "logout_delivery"); !found || err != nil {
		t.Fatalf("run once: %v %v", found, err)
	}
	var open int
	e.DB.Get(&open, `SELECT count(*) FROM logout_notifications WHERE delivered_at IS NULL AND failed_at IS NULL`)
	if open != 0 {
		t.Fatalf("undrained notifications = %d", open)
	}
	if found, _ := w.RunOnce(context.Background(), "nope"); found {
		t.Fatal("unknown job ran")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var lag float64
	var rounds uint64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Gauge[float64]:
				if m.Name == "iamkit.worker.lag" {
					lag = data.DataPoints[0].Value
				}
			case metricdata.Histogram[float64]:
				if m.Name == "iamkit.worker.round.duration" {
					rounds += data.DataPoints[0].Count
				}
			}
		}
	}
	if lag < 55 || lag > 600 || rounds != 1 {
		t.Fatalf("lag = %v s, rounds = %d", lag, rounds)
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.Server.Start(ctx)
	if health := e.Must("GET", "/health", "", nil, 200).JSON; health["workers"] != "running" {
		t.Fatalf("health = %v", health)
	}
	cancel()
	if !w.Wait(5 * time.Second) {
		t.Fatal("workers did not stop")
	}

	// Turned off by IAMKIT_WORKERS=false.
	w.Disabled = true
	if health := e.Must("GET", "/health", "", nil, 200).JSON; health["workers"] != "disabled" {
		t.Fatalf("health = %v", health)
	}
}
