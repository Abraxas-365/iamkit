package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditLogEmitListExport(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/environments/e1/audit-logs/events":
			if r.Header.Get("Idempotency-Key") != "key-1" || r.Header.Get("Authorization") != "Bearer jwt" {
				t.Errorf("headers = %v", r.Header)
			}
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			if in["action"] != "invoice.paid" || in["targets"] == nil {
				t.Errorf("body = %v", in)
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"a1","created_at":"2026-01-02T03:04:05Z"}`))
		case strings.HasSuffix(r.URL.Path, "/export"):
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Write([]byte(`{"seq":1,"action":"invoice.paid","actor":{"type":"user","id":"u"}}` + "\n" + `{"seq":2,"action":"invoice.paid"}` + "\n"))
		default:
			w.Write([]byte(`{"items":[{"seq":9,"id":"a1","action":"invoice.paid"}],"next":9}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	env := New(srv.URL, "jwt").Environment("e1")

	receipt, err := env.CreateAuditLogEvent(ctx, AuditLogInput{OrganizationID: "o1", Action: "invoice.paid", OccurredAt: time.Now(),
		Actor: AuditLogParty{Type: "user", ID: "u"}}, "key-1")
	if err != nil || receipt.ID != "a1" {
		t.Fatalf("receipt = %+v, err = %v", receipt, err)
	}
	after := int64(3)
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	page, err := env.AuditLogEvents(ctx, AuditLogFilter{Actions: []string{"invoice.paid", "invoice.void"}, ActorID: "u", After: &after, OccurredAfter: &since, Limit: 5})
	if err != nil || page.Next != 9 || len(page.Items) != 1 || page.Items[0].Seq != 9 {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
	body, err := env.ExportAuditLogEvents(ctx, AuditLogFilter{ActorID: "u", Limit: 5}, "ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	var seqs []int64
	if err := DecodeAuditLogEvents(body, func(e AuditLogEvent) error { seqs = append(seqs, e.Seq); return nil }); err != nil || len(seqs) != 2 {
		t.Fatalf("seqs = %v, err = %v", seqs, err)
	}
	list := calls[1]
	for _, want := range []string{"action=invoice.paid", "action=invoice.void", "actor_id=u", "after=3", "limit=5", "occurred_after=2026-01-01T00%3A00%3A00Z"} {
		if !strings.Contains(list, want) {
			t.Errorf("%s lacks %s", list, want)
		}
	}
	if export := calls[2]; strings.Contains(export, "limit") || !strings.Contains(export, "format=ndjson") {
		t.Errorf("export = %s", export)
	}
}

func TestAuditLogActionsAndStreams(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.Method == "POST" && r.URL.Path == "/api/v1/environments/e1/log-streams":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"s1","secret":"signing-material"}`))
		case strings.HasSuffix(r.URL.Path, "/test"):
			w.Write([]byte(`{"delivered":false,"status":500,"error":"boom"}`))
		case strings.HasSuffix(r.URL.Path, "/retry"):
			w.WriteHeader(202)
		case strings.HasSuffix(r.URL.Path, "/deliveries"):
			w.Write([]byte(`{"items":[{"id":4,"stream_id":"s1","status":"failed","source":"audit_logs"}],"page":{"total":1,"limit":20,"offset":0}}`))
		case r.URL.Path == "/api/v1/environments/e1/log-streams":
			w.Write([]byte(`{"items":[{"id":"s1","name":"siem","secret_set":true,"sources":["audit_logs"]}]}`))
		case strings.Contains(r.URL.Path, "/audit-logs/actions") && r.Method == "GET" && !strings.HasSuffix(r.URL.Path, "/actions"):
			w.Write([]byte(`{"id":"a1","name":"invoice.paid","version":2}`))
		case strings.HasSuffix(r.URL.Path, "/actions"):
			if r.Method == "POST" {
				w.WriteHeader(201)
				w.Write([]byte(`{"id":"a1","name":"invoice.paid","version":1}`))
				return
			}
			w.Write([]byte(`{"items":[{"id":"a1","name":"invoice.paid"}]}`))
		default:
			w.Write([]byte(`{"id":"s1","name":"siem","active":true,"secret_set":true}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	env := New(srv.URL, "jwt").Environment("e1")

	if a, err := env.CreateAuditLogAction(ctx, AuditLogActionInput{Name: "invoice.paid"}); err != nil || a.Version != 1 {
		t.Fatalf("create action = %+v, %v", a, err)
	}
	if as, err := env.AuditLogActions(ctx); err != nil || len(as) != 1 {
		t.Fatalf("actions = %+v, %v", as, err)
	}
	if a, err := env.AuditLogAction(ctx, "a1"); err != nil || a.Version != 2 {
		t.Fatalf("action = %+v, %v", a, err)
	}
	desc := "paid"
	if _, err := env.UpdateAuditLogAction(ctx, "a1", AuditLogActionPatch{Description: &desc}); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteAuditLogAction(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	made, err := env.CreateLogStream(ctx, LogStreamInput{Name: "siem", Destination: "https", Config: LogStreamConfig{URL: "https://siem.example.com/in"}})
	if err != nil || made.ID != "s1" || made.Secret == "" {
		t.Fatalf("create = %+v, %v", made, err)
	}
	if ss, err := env.LogStreams(ctx); err != nil || len(ss) != 1 || !ss[0].SecretSet {
		t.Fatalf("streams = %+v, %v", ss, err)
	}
	active := false
	if s, err := env.UpdateLogStream(ctx, "s1", LogStreamPatch{Active: &active}); err != nil || s.ID != "" && s.Name != "siem" {
		t.Fatalf("update = %+v, %v", s, err)
	}
	if _, err := env.EnableLogStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.RotateLogStreamSecret(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if res, err := env.TestLogStream(ctx, "s1"); err != nil || res.Delivered || res.Status != 500 {
		t.Fatalf("test = %+v, %v", res, err)
	}
	if ds, err := env.LogStreamDeliveries(ctx, "s1", "failed"); err != nil || len(ds) != 1 || ds[0].ID != 4 {
		t.Fatalf("deliveries = %+v, %v", ds, err)
	}
	if err := env.RetryLogStreamDelivery(ctx, "s1", 4); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteLogStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.LogStream(ctx, "../x"); err == nil {
		t.Fatal("path traversal accepted")
	}
	want := []string{
		"POST /api/v1/environments/e1/audit-logs/actions",
		"GET /api/v1/environments/e1/audit-logs/actions",
		"GET /api/v1/environments/e1/audit-logs/actions/a1",
		"PATCH /api/v1/environments/e1/audit-logs/actions/a1",
		"DELETE /api/v1/environments/e1/audit-logs/actions/a1",
		"POST /api/v1/environments/e1/log-streams",
		"GET /api/v1/environments/e1/log-streams",
		"PATCH /api/v1/environments/e1/log-streams/s1",
		"POST /api/v1/environments/e1/log-streams/s1/enable",
		"POST /api/v1/environments/e1/log-streams/s1/rotate-secret",
		"POST /api/v1/environments/e1/log-streams/s1/test",
		"GET /api/v1/environments/e1/log-streams/s1/deliveries?status=failed",
		"POST /api/v1/environments/e1/log-streams/s1/deliveries/4/retry",
		"DELETE /api/v1/environments/e1/log-streams/s1",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}

func TestOrgAdminAuditLogsAndStreams(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/audit-logs/export"):
			io.WriteString(w, `{"seq":1}`+"\n")
		case strings.HasSuffix(r.URL.Path, "/audit-logs"):
			w.Write([]byte(`{"items":[{"seq":3}],"next":3}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/log-streams"):
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"s1"}`))
		case strings.HasSuffix(r.URL.Path, "/log-streams"):
			w.Write([]byte(`{"items":[{"id":"s1"}]}`))
		case strings.HasSuffix(r.URL.Path, "/deliveries"):
			w.Write([]byte(`{"items":[],"page":{"total":0,"limit":20,"offset":0}}`))
		case strings.HasSuffix(r.URL.Path, "/retry"):
			w.WriteHeader(202)
		case strings.HasSuffix(r.URL.Path, "/test"):
			w.Write([]byte(`{"delivered":true,"status":204}`))
		default:
			w.Write([]byte(`{"id":"s1","active":true}`))
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	admin := New(srv.URL, "jwt").Environment("e1").OrgAdmin("o1")

	// The organization is the caller's: the filter's is not sent.
	page, err := admin.AuditLogEvents(ctx, AuditLogFilter{OrganizationID: "other", TargetType: "invoice", Before: 8})
	if err != nil || page.Next != 3 {
		t.Fatalf("page = %+v, %v", page, err)
	}
	body, err := admin.ExportAuditLogEvents(ctx, AuditLogFilter{}, "csv")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(body)
	body.Close()
	if !strings.Contains(string(raw), `"seq":1`) {
		t.Fatalf("export = %s", raw)
	}
	if _, err := admin.CreateLogStream(ctx, LogStreamInput{Name: "siem", Destination: "https", Config: LogStreamConfig{URL: "https://siem.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if ss, err := admin.LogStreams(ctx); err != nil || len(ss) != 1 {
		t.Fatalf("streams = %+v, %v", ss, err)
	}
	if _, err := admin.LogStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	if _, err := admin.UpdateLogStream(ctx, "s1", LogStreamPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if res, err := admin.TestLogStream(ctx, "s1"); err != nil || !res.Delivered {
		t.Fatalf("test = %+v, %v", res, err)
	}
	if _, err := admin.EnableLogStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.RotateLogStreamSecret(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.LogStreamDeliveries(ctx, "s1", ""); err != nil {
		t.Fatal(err)
	}
	if err := admin.RetryLogStreamDelivery(ctx, "s1", 7); err != nil {
		t.Fatal(err)
	}
	if err := admin.DeleteLogStream(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.LogStream(ctx, "a/b"); err == nil {
		t.Fatal("unsafe id accepted")
	}
	base := "/api/v1/environments/e1/organizations/o1/admin"
	if !strings.HasPrefix(calls[0], "GET "+base+"/audit-logs?") || !strings.Contains(calls[0], "before=8") {
		t.Errorf("list = %s", calls[0])
	}
	if strings.Contains(calls[0], "organization_id") {
		t.Errorf("organization_id sent: %s", calls[0])
	}
	if calls[1] != "GET "+base+"/audit-logs/export?format=csv" {
		t.Errorf("export = %s", calls[1])
	}
	for _, want := range []string{
		"POST " + base + "/log-streams", "GET " + base + "/log-streams", "GET " + base + "/log-streams/s1",
		"PATCH " + base + "/log-streams/s1", "POST " + base + "/log-streams/s1/test", "POST " + base + "/log-streams/s1/enable",
		"POST " + base + "/log-streams/s1/rotate-secret", "GET " + base + "/log-streams/s1/deliveries",
		"POST " + base + "/log-streams/s1/deliveries/7/retry", "DELETE " + base + "/log-streams/s1",
	} {
		found := false
		for _, c := range calls {
			found = found || c == want
		}
		if !found {
			t.Errorf("missing call %s in %v", want, calls)
		}
	}
}
