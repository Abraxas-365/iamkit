package e2e_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lshttps"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// streamReceiver is a loopback https log stream endpoint that verifies
// Standard Webhooks signatures and records each batch.
type streamReceiver struct {
	mu      sync.Mutex
	secrets []string
	status  int
	batches [][]map[string]any
	ids     []string
	bad     int
}

func (r *streamReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status >= 300 {
		w.WriteHeader(r.status)
		return
	}
	verified := false
	for _, secret := range r.secrets {
		want, _ := lshttps.Sign([]string{secret}, req.Header.Get("webhook-id"), req.Header.Get("webhook-timestamp"), body)
		for _, sig := range strings.Split(req.Header.Get("webhook-signature"), " ") {
			verified = verified || sig == want
		}
	}
	if !verified {
		r.bad++
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var batch []map[string]any
	_ = json.Unmarshal(body, &batch)
	r.batches = append(r.batches, batch)
	r.ids = append(r.ids, req.Header.Get("webhook-id"))
	w.WriteHeader(http.StatusNoContent)
}

func (r *streamReceiver) set(status int, secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
	if secrets != nil {
		r.secrets = secrets
	}
}

func (r *streamReceiver) records() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []map[string]any
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

func (r *streamReceiver) batchCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.batches)
}

// drainStreams runs delivery rounds until no active stream has a due batch.
func (e *Env) drainStreams() {
	e.t.Helper()
	for i := 0; i < 50; i++ {
		more, err := e.Server.LogStreamDispatcher.DispatchRound(context.Background())
		if err != nil {
			e.t.Fatal(err)
		}
		var due int
		if err := e.DB.Get(&due, `SELECT count(*) FROM (SELECT DISTINCT ON (d.stream_id) d.next_attempt_at FROM log_stream_deliveries d
			JOIN log_streams s ON s.id=d.stream_id AND s.active WHERE d.status='pending' ORDER BY d.stream_id, d.id) h
			WHERE h.next_attempt_at <= now()`); err != nil {
			e.t.Fatal(err)
		}
		if !more && due == 0 {
			return
		}
	}
	e.t.Fatal("log stream deliveries never drained")
}

// auditRow inserts what W1's ingest would: one audit log event.
func (e *Env) auditRow(org, action string) {
	e.t.Helper()
	e.DB.MustExec(`INSERT INTO audit_log_events (id, environment_id, organization_id, action, version, occurred_at, actor)
		VALUES (gen_random_uuid(), $1, $2, $3, 1, now(), '{"type":"user","id":"u-1"}')`, e.EnvID, org, action)
}

func (e *Env) deliveries(stream, status string) []any {
	e.t.Helper()
	return e.Must("GET", e.Base+"/log-streams/"+stream+"/deliveries?status="+status, e.Owner, nil, 200).JSON["items"].([]any)
}

// TestLogStreamsHTTPS: an https stream receives signed batches of events
// and audit logs; failures retry with backoff, then fail and can be
// retried (same batch id); rotation signs with both secrets; a failing
// stream is disabled by maintenance and resumes when enabled; secrets are
// never returned; /api/v1 enforces iam:audit-logs:*.
func TestLogStreamsHTTPS(t *testing.T) {
	receiver := &streamReceiver{}
	srv := httptest.NewServer(receiver)
	defer srv.Close()
	e := newEnv(t, bootstrap.WithLogStreamTransport(http.DefaultTransport))
	ls := e.Base + "/log-streams"

	e.Must("POST", ls, e.Owner, fiber.Map{"name": "bad", "destination": "https", "config": fiber.Map{"url": "ftp://x"}}, 400)
	e.Must("POST", ls, e.Owner, fiber.Map{"name": "bad", "destination": "https", "config": fiber.Map{"url": srv.URL}, "sources": []string{"nope"}}, 400)
	created := e.Must("POST", ls, e.Owner, fiber.Map{"name": "SIEM", "destination": "https", "config": fiber.Map{"url": srv.URL}, "sources": []string{"events", "audit_logs"}}, 201).JSON
	stream, secret := created["id"].(string), created["secret"].(string)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret = %q", secret)
	}
	receiver.set(0, secret)
	got := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200)
	if strings.Contains(got.Body, "whsec_") || got.JSON["secret_set"] != true || got.JSON["active"] != true {
		t.Fatalf("stream = %s", got.Body)
	}
	if list := e.Must("GET", ls, e.Owner, nil, 200); strings.Contains(list.Body, "whsec_") {
		t.Fatalf("list leaks a secret: %s", list.Body)
	}
	// https streams sign with a generated secret.
	e.Must("PATCH", ls+"/"+stream, e.Owner, fiber.Map{"secret": "mine"}, 400)

	// Everything queued before a round goes out as one ordered batch.
	bob := e.User("Bob", "bob@example.com")
	e.User("Carol", "carol@example.com")
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})
	e.auditRow(e.Org, "doc.view")
	e.auditRow(other, "doc.edit")
	e.drainStreams()
	if n := receiver.batchCount(); n != 1 {
		t.Fatalf("batches = %d, want 1", n)
	}
	records := receiver.records()
	var sawBob, audits int
	for _, r := range records {
		if r["environment_id"] != e.EnvID {
			t.Fatalf("record without environment: %v", r)
		}
		if r["source"] == "audit_logs" {
			audits++
		}
		if r["source"] == "events" && r["type"] == "user.created" && r["subject"].(map[string]any)["id"] == bob {
			sawBob++
		}
	}
	if audits != 2 || sawBob != 1 || receiver.bad != 0 {
		t.Fatalf("records = %v bad = %d", records, receiver.bad)
	}
	if d := e.deliveries(stream, "delivered"); len(d) != len(records) {
		t.Fatalf("delivered rows = %d, records = %d", len(d), len(records))
	}
	first := e.deliveries(stream, "delivered")[0].(map[string]any)
	if first["batch"] == nil {
		t.Fatalf("delivery without a batch: %v", first)
	}

	// Test delivery: sent now, never queued.
	test := e.Must("POST", ls+"/"+stream+"/test", e.Owner, nil, 200).JSON
	if test["delivered"] != true || receiver.batchCount() != 2 {
		t.Fatalf("test = %v", test)
	}

	// A failing endpoint: the batch retries later, keeping its rows, then
	// is given up past the window; an operator retries it.
	receiver.set(http.StatusServiceUnavailable)
	e.auditRow(e.Org, "doc.a")
	e.auditRow(e.Org, "doc.b")
	e.drainStreams()
	pending := e.deliveries(stream, "pending")
	if len(pending) != 2 {
		t.Fatalf("pending = %v", pending)
	}
	for _, p := range pending {
		row := p.(map[string]any)
		if row["attempts"].(float64) != 1 || row["response_status"].(float64) != 503 || row["batch"] == nil {
			t.Fatalf("pending row = %v", row)
		}
	}
	if s := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200).JSON; s["failing_since"] == nil || s["pending"].(float64) != 2 {
		t.Fatalf("failing stream = %v", s)
	}
	e.DB.MustExec(`UPDATE log_stream_deliveries SET first_attempt_at = now() - interval '25 hours', next_attempt_at = now() WHERE stream_id=$1 AND status='pending'`, stream)
	e.drainStreams()
	failed := e.deliveries(stream, "failed")
	if len(failed) != 2 {
		t.Fatalf("failed = %v", failed)
	}
	receiver.set(0)
	failedID := int64(failed[0].(map[string]any)["id"].(float64))
	retry := fmt.Sprintf("%s/%s/deliveries/%d/retry", ls, stream, failedID)
	e.Must("POST", retry, e.Owner, nil, 202)
	e.Must("POST", retry, e.Owner, nil, 404)
	before := receiver.batchCount()
	e.drainStreams()
	// The retry's own audit event (log_stream.delivery_retried) is a second batch.
	if receiver.batchCount() < before+1 || len(e.deliveries(stream, "failed")) != 0 {
		t.Fatalf("retry: batches %d→%d failed %v", before, receiver.batchCount(), e.deliveries(stream, "failed"))
	}
	if s := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200).JSON; s["failing_since"] != nil {
		t.Fatalf("recovered stream = %v", s)
	}

	// Rotation: both secrets sign during the overlap.
	rotated := e.Must("POST", ls+"/"+stream+"/rotate-secret", e.Owner, nil, 200).JSON["secret"].(string)
	receiver.set(0, secret)
	e.auditRow(e.Org, "doc.c")
	e.drainStreams()
	receiver.set(0, rotated)
	e.auditRow(e.Org, "doc.d")
	e.drainStreams()
	if receiver.bad != 0 {
		t.Fatalf("bad signatures after rotation = %d", receiver.bad)
	}

	// Failing for three days disables the stream; events keep queuing and
	// enabling resumes delivery.
	receiver.set(http.StatusInternalServerError)
	e.auditRow(e.Org, "doc.e")
	e.drainStreams()
	e.DB.MustExec(`UPDATE log_streams SET failing_since = now() - interval '4 days' WHERE id=$1`, stream)
	if found, err := e.Server.Workers.RunOnce(context.Background(), "log_stream_maintenance"); !found || err != nil {
		t.Fatalf("maintenance: %v %v", found, err)
	}
	s := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200).JSON
	if s["active"] != false || s["disabled_reason"] != "failing" {
		t.Fatalf("disabled = %v", s)
	}
	queued := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200).JSON["pending"].(float64)
	e.auditRow(e.Org, "doc.f")
	if s := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200).JSON; s["pending"].(float64) != queued+1 {
		t.Fatalf("pending while disabled = %v, want %v", s["pending"], queued+1)
	}
	receiver.set(0)
	n := len(receiver.records())
	// What queued during the outage is older than the retry window by now;
	// enabling restarts its clock so it is sent, not given up.
	e.DB.MustExec(`UPDATE log_stream_deliveries SET first_attempt_at = now() - interval '4 days', next_attempt_at = now() + interval '1 hour'
		WHERE stream_id=$1 AND status='pending' AND attempts > 0`, stream)
	enabled := e.Must("POST", ls+"/"+stream+"/enable", e.Owner, nil, 200).JSON
	if enabled["active"] != true || enabled["failing_since"] != nil || enabled["disabled_reason"] != nil {
		t.Fatalf("enabled = %v", enabled)
	}
	e.drainStreams()
	if got := len(receiver.records()); got < n+int(queued)+1 {
		t.Fatalf("resumed records %d → %d", n, got)
	}
	if failed := e.deliveries(stream, "failed"); len(failed) != 0 {
		t.Fatalf("backlog given up after enabling: %v", failed)
	}

	// A stream disabled for failing keeps queuing, but not forever: what
	// waited past the delivery retention fails at maintenance.
	e.DB.MustExec(`UPDATE log_streams SET active = false, disabled_reason = 'failing' WHERE id=$1`, stream)
	e.auditRow(e.Org, "doc.g")
	e.DB.MustExec(`UPDATE log_stream_deliveries SET queued_at = now() - interval '8 days' WHERE stream_id=$1 AND status='pending'`, stream)
	if _, err := e.Server.Workers.RunOnce(context.Background(), "log_stream_maintenance"); err != nil {
		t.Fatal(err)
	}
	if failed := e.deliveries(stream, "failed"); len(failed) != 1 || failed[0].(map[string]any)["last_error"] != "the stream was disabled for too long" {
		t.Fatalf("expired backlog = %v", failed)
	}
	e.Must("POST", ls+"/"+stream+"/enable", e.Owner, nil, 200)
	types := eventTypes(e.Must("GET", e.Base+"/events?type=log_stream.*", e.Owner, nil, 200))
	for _, want := range []string{"log_stream.created", "log_stream.secret_rotated", "log_stream.disabled", "log_stream.delivery_retried", "log_stream.updated"} {
		if !contains(types, want) {
			t.Fatalf("event %s missing in %v", want, types)
		}
	}

	// /api/v1: iam:audit-logs:read lists, iam:audit-logs:manage changes.
	api := "/api/v1/environments/" + e.EnvID + "/log-streams"
	e.Must("GET", api, e.scopedToken("iam:events:read"), nil, 403)
	reader := e.scopedToken("iam:audit-logs:read")
	if items := e.Must("GET", api, reader, nil, 200).JSON["items"].([]any); len(items) != 1 {
		t.Fatalf("api list = %v", items)
	}
	e.Must("DELETE", api+"/"+stream, reader, nil, 403)
	e.Must("DELETE", api+"/"+stream, e.scopedToken("iam:audit-logs:manage"), nil, 204)
	e.Must("GET", ls+"/"+stream, e.Owner, nil, 404)
}

// TestLogStreamsOrganizationScope: an organization's stream sees only its
// organization's audit logs; environment streams see all; organization
// streams take audit_logs only; destinations validate; the limit holds.
func TestLogStreamsOrganizationScope(t *testing.T) {
	acme, globex := &streamReceiver{}, &streamReceiver{}
	all := &streamReceiver{}
	srvA, srvG, srvAll := httptest.NewServer(acme), httptest.NewServer(globex), httptest.NewServer(all)
	defer srvA.Close()
	defer srvG.Close()
	defer srvAll.Close()
	e := newEnv(t, bootstrap.WithLogStreamTransport(http.DefaultTransport))
	ls := e.Base + "/log-streams"
	other := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Globex"})

	body := func(name, url, org string, sources ...string) fiber.Map {
		m := fiber.Map{"name": name, "destination": "https", "config": fiber.Map{"url": url}}
		if org != "" {
			m["organization_id"] = org
		}
		if sources != nil {
			m["sources"] = sources
		}
		return m
	}
	e.Must("POST", ls, e.Owner, body("a", srvA.URL, e.Org, "events"), 400)
	e.Must("POST", ls, e.Owner, body("a", srvA.URL, e.Org, "events", "audit_logs"), 400)
	e.Must("POST", ls, e.Owner, body("a", srvA.URL, "00000000-0000-0000-0000-000000000001"), 404)
	sa := e.Must("POST", ls, e.Owner, body("acme", srvA.URL, e.Org), 201).JSON
	sg := e.Must("POST", ls, e.Owner, body("globex", srvG.URL, other), 201).JSON
	sAll := e.Must("POST", ls, e.Owner, body("all", srvAll.URL, "", "audit_logs"), 201).JSON
	acme.set(0, sa["secret"].(string))
	globex.set(0, sg["secret"].(string))
	all.set(0, sAll["secret"].(string))
	if got := e.Must("GET", ls+"/"+sa["id"].(string), e.Owner, nil, 200).JSON; fmt.Sprint(got["sources"]) != "[audit_logs]" || got["organization_id"] != e.Org {
		t.Fatalf("org stream = %v", got)
	}

	e.auditRow(e.Org, "acme.1")
	e.auditRow(other, "globex.1")
	e.auditRow(e.Org, "acme.2")
	e.User("Bob", "bob@example.com") // an event: only environment streams with events see it
	e.drainStreams()
	actions := func(r *streamReceiver) string {
		var out []string
		for _, rec := range r.records() {
			if rec["source"] != "audit_logs" {
				t.Fatalf("unexpected source %v", rec)
			}
			out = append(out, rec["action"].(string))
		}
		return strings.Join(out, ",")
	}
	if got := actions(acme); got != "acme.1,acme.2" {
		t.Fatalf("acme saw %q", got)
	}
	if got := actions(globex); got != "globex.1" {
		t.Fatalf("globex saw %q", got)
	}
	if got := actions(all); got != "acme.1,globex.1,acme.2" {
		t.Fatalf("env stream saw %q", got)
	}

	// The unconfigured private destination is refused by the guard, and
	// datadog/splunk/s3 configurations validate per destination.
	e.Must("POST", ls, e.Owner, fiber.Map{"name": "dd", "destination": "datadog", "config": fiber.Map{"site": "evil.example"}, "secret": "k"}, 400)
	e.Must("POST", ls, e.Owner, fiber.Map{"name": "dd", "destination": "datadog", "config": fiber.Map{"site": "datadoghq.eu"}}, 400)
	e.Must("POST", ls, e.Owner, fiber.Map{"name": "sp", "destination": "splunk", "config": fiber.Map{"url": "http://splunk.example"}, "secret": "t"}, 400)
	e.Must("POST", ls, e.Owner, fiber.Map{"name": "s3", "destination": "s3", "config": fiber.Map{"bucket": "Bad_Bucket", "region": "us-east-1", "access_key_id": "a"}, "secret": "s"}, 400)
	dd := e.Must("POST", ls, e.Owner, fiber.Map{"name": "dd", "destination": "datadog", "config": fiber.Map{"site": "datadoghq.eu"}, "secret": "dd-api-key-123"}, 201)
	if strings.Contains(dd.Body, "dd-api-key-123") || dd.JSON["secret"] != nil {
		t.Fatalf("datadog create leaks: %s", dd.Body)
	}
	if got := e.Must("GET", ls, e.Owner, nil, 200); strings.Contains(got.Body, "dd-api-key-123") {
		t.Fatalf("list leaks: %s", got.Body)
	}
	e.Must("POST", ls+"/"+dd.JSON["id"].(string)+"/rotate-secret", e.Owner, nil, 400)
	// Datadog is guarded: its test delivery cannot reach a private address,
	// and the outcome never carries the key.
	test := e.Must("POST", ls+"/"+dd.JSON["id"].(string)+"/test", e.Owner, nil, 200)
	if strings.Contains(test.Body, "dd-api-key-123") {
		t.Fatalf("test leaks: %s", test.Body)
	}
}

// Without an encryption key secrets cannot be stored.
func TestLogStreamsNeedEncryptionKey(t *testing.T) {
	e := newEnv(t, bootstrap.WithSealer(nil))
	res := e.Do("POST", e.Base+"/log-streams", e.Owner, fiber.Map{"name": "s", "destination": "https", "config": fiber.Map{"url": "https://example.com/hook"}})
	if res.Status != 422 || errorOf(res)["code"] != "ENCRYPTION_KEY_REQUIRED" {
		t.Fatalf("create: %d %s", res.Status, res.Body)
	}
}

// rustFS is a running S3-compatible server and a client for it.
func startRustFS(t *testing.T, bucket string) (endpoint string, client *s3.Client) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, "rustfs/rustfs:1.0.0",
		testcontainers.WithExposedPorts("9000/tcp"),
		testcontainers.WithEnv(map[string]string{"RUSTFS_ACCESS_KEY": "testaccess", "RUSTFS_SECRET_KEY": "testsecret123"}),
		testcontainers.WithWaitStrategyAndDeadline(2*time.Minute, wait.ForHTTP("/health").WithPort("9000/tcp")))
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err = c.PortEndpoint(ctx, "9000/tcp", "http")
	if err != nil {
		t.Fatal(err)
	}
	client = s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("testaccess", "testsecret123", "")})
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	return endpoint, client
}

// TestLogStreamsS3: batches land in an S3-compatible bucket (RustFS) as
// gzip NDJSON under <prefix>/<yyyy>/<mm>/<dd>/<HH>/<stream>-<batch>.ndjson.gz;
// bad credentials fail the delivery without leaking the key.
func TestLogStreamsS3(t *testing.T) {
	requireE2E(t)
	endpoint, client := startRustFS(t, "iam-logs")
	e := newEnv(t, bootstrap.WithLogStreamTransport(http.DefaultTransport))
	ls := e.Base + "/log-streams"
	cfg := fiber.Map{"bucket": "iam-logs", "region": "us-east-1", "prefix": "iam/prod", "endpoint": endpoint, "path_style": true, "access_key_id": "testaccess"}
	created := e.Must("POST", ls, e.Owner, fiber.Map{"name": "archive", "destination": "s3", "config": cfg, "secret": "testsecret123", "sources": []string{"audit_logs"}}, 201)
	if strings.Contains(created.Body, "testsecret123") {
		t.Fatalf("create leaks the secret: %s", created.Body)
	}
	stream := created.JSON["id"].(string)
	if got := e.Must("GET", ls+"/"+stream, e.Owner, nil, 200); strings.Contains(got.Body, "testsecret123") || got.JSON["config"].(map[string]any)["access_key_id"] != "testaccess" {
		t.Fatalf("stream = %s", got.Body)
	}

	e.auditRow(e.Org, "doc.view")
	e.auditRow(e.Org, "doc.edit")
	e.drainStreams()
	delivered := e.deliveries(stream, "delivered")
	if len(delivered) != 2 {
		t.Fatalf("delivered = %v", delivered)
	}
	batch := int64(delivered[0].(map[string]any)["batch"].(float64))
	prefix := fmt.Sprintf("iam/prod/%s/", time.Now().UTC().Format("2006/01/02/15"))
	key := fmt.Sprintf("%s%s-%d.ndjson.gz", prefix, stream, batch)
	list, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String("iam-logs")})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, o := range list.Contents {
		keys = append(keys, aws.ToString(o.Key))
	}
	if len(keys) != 1 || (keys[0] != key && !strings.HasPrefix(keys[0], "iam/prod/")) || !strings.HasSuffix(keys[0], fmt.Sprintf("%s-%d.ndjson.gz", stream, batch)) {
		t.Fatalf("keys = %v, want %s", keys, key)
	}
	obj, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("iam-logs"), Key: aws.String(keys[0])})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("object is not gzip: %v", err)
	}
	text, _ := io.ReadAll(zr)
	lines := strings.Split(strings.TrimSpace(string(text)), "\n")
	if len(lines) != 2 {
		t.Fatalf("ndjson = %q", text)
	}
	for i, action := range []string{"doc.view", "doc.edit"} {
		var rec map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &rec); err != nil || rec["action"] != action || rec["source"] != "audit_logs" || rec["environment_id"] != e.EnvID {
			t.Fatalf("line %d = %s (%v)", i, lines[i], err)
		}
	}

	// A test delivery writes its own object.
	if test := e.Must("POST", ls+"/"+stream+"/test", e.Owner, nil, 200).JSON; test["delivered"] != true {
		t.Fatalf("test = %v", test)
	}

	// Moving the stored secret to another host needs the secret again.
	moved := fiber.Map{}
	for k, v := range cfg {
		moved[k] = v
	}
	moved["endpoint"] = "https://storage.example.com"
	e.Must("PATCH", ls+"/"+stream, e.Owner, fiber.Map{"config": moved}, 400)
	renamed := fiber.Map{}
	for k, v := range cfg {
		renamed[k] = v
	}
	renamed["prefix"] = "iam/prod"
	e.Must("PATCH", ls+"/"+stream, e.Owner, fiber.Map{"config": renamed}, 200)

	// Wrong credentials: the delivery retries, records a readable error
	// and never echoes the secret.
	e.Must("PATCH", ls+"/"+stream, e.Owner, fiber.Map{"secret": "wrong-secret-00"}, 200)
	e.auditRow(e.Org, "doc.delete")
	e.drainStreams()
	pending := e.deliveries(stream, "pending")
	if len(pending) != 1 {
		t.Fatalf("pending = %v", pending)
	}
	row := pending[0].(map[string]any)
	if row["attempts"].(float64) != 1 || row["last_error"] == nil || strings.Contains(fmt.Sprint(row["last_error"]), "wrong-secret-00") {
		t.Fatalf("pending row = %v", row)
	}
}
