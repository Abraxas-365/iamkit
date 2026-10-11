package lssplunk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lssplunk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestSend(t *testing.T) {
	var path, auth string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	at := time.Date(2026, 3, 4, 9, 0, 1, 500_000_000, time.UTC)
	out := lssplunk.Sender{Transport: http.DefaultTransport}.Send(context.Background(), logstream.Outbound{
		Environment: identity.NewEnvironmentID(), Destination: "splunk",
		Config:  logstream.Config{URL: srv.URL + "/", Index: "main", SourceType: "_json"},
		Secrets: []string{"hec-token"},
		Records: []logstream.Record{{Source: "events", At: at, Fields: json.RawMessage(`{"type":"a.b"}`)}, {Source: "events", At: at, Fields: json.RawMessage(`{"type":"c.d"}`)}}})
	if !out.OK() {
		t.Fatalf("outcome %+v", out)
	}
	if path != "/services/collector/event" || auth != "Splunk hec-token" {
		t.Fatalf("request %s %s", path, auth)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var n int
	for dec.More() {
		var e map[string]any
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		n++
		inner, _ := e["event"].(map[string]any)
		if e["index"] != "main" || e["source"] != "iamkit" || e["sourcetype"] != "_json" || e["time"] != 1772614801.5 || inner["source"] != "events" {
			t.Fatalf("event %v", e)
		}
	}
	if n != 2 {
		t.Fatalf("want 2 concatenated events, got %d in %s", n, body)
	}
}

func TestFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	out := lssplunk.Sender{Transport: http.DefaultTransport}.Send(context.Background(), logstream.Outbound{
		Config: logstream.Config{URL: srv.URL}, Secrets: []string{"hec-token"}})
	if out.OK() || out.Status != 403 {
		t.Fatalf("outcome %+v", out)
	}
}
