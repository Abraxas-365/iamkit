package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditLogsManagement(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("X-API-Key") != "ik_mgmt_test" {
			t.Errorf("key = %q", r.Header.Get("X-API-Key"))
		}
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/audit-logs/events"):
			if r.Header.Get("Idempotency-Key") != "k1" {
				t.Errorf("idempotency key = %q", r.Header.Get("Idempotency-Key"))
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"a1","created_at":"2026-01-02T03:04:05Z"}`))
		case strings.HasSuffix(r.URL.Path, "/export"):
			io.WriteString(w, `{"seq":4,"action":"invoice.paid"}`+"\n")
		case strings.HasSuffix(r.URL.Path, "/log-streams"):
			w.Write([]byte(`{"items":[{"id":"s1","organization_id":"o1","sources":["audit_logs"],"secret_set":true}]}`))
		default:
			w.Write([]byte(`{"items":[{"seq":2,"action":"invoice.paid"}],"next":2}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	env := New(srv.URL, "ik_mgmt_test").Environment("env")

	if r, err := env.CreateAuditLogEvent(ctx, AuditLogInput{OrganizationID: "o1", Action: "invoice.paid", OccurredAt: time.Now()}, "k1"); err != nil || r.ID != "a1" {
		t.Fatalf("receipt = %+v, %v", r, err)
	}
	if p, err := env.AuditLogEvents(ctx, AuditLogFilter{OrganizationID: "o1", Limit: 3}); err != nil || p.Next != 2 {
		t.Fatalf("page = %+v, %v", p, err)
	}
	body, err := env.ExportAuditLogEvents(ctx, AuditLogFilter{}, AuditLogFormatNDJSON)
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int64
	err = DecodeAuditLogEvents(body, func(e AuditLogEvent) error { seqs = append(seqs, e.Seq); return nil })
	body.Close()
	if err != nil || len(seqs) != 1 || seqs[0] != 4 {
		t.Fatalf("export = %v, %v", seqs, err)
	}
	if ss, err := env.LogStreams(ctx); err != nil || len(ss) != 1 || ss[0].OrganizationID != "o1" {
		t.Fatalf("streams = %+v, %v", ss, err)
	}
	if calls[1] != "GET /management/v1/environments/env/audit-logs/events?limit=3&organization_id=o1" ||
		calls[2] != "GET /management/v1/environments/env/audit-logs/events/export?format=ndjson" {
		t.Fatalf("calls = %v", calls)
	}
	if _, err := New(srv.URL, "nope").Environment("env").ExportAuditLogEvents(ctx, AuditLogFilter{}, ""); err == nil {
		t.Fatal("export without a management key")
	}
}
