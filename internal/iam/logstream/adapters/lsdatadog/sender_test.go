package lsdatadog_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lsdatadog"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func batch() logstream.Outbound {
	at := time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	return logstream.Outbound{Stream: identity.NewLogStreamID(), Environment: identity.NewEnvironmentID(), Destination: "datadog",
		Config:  logstream.Config{Site: "datadoghq.com", Service: "iam", Tags: []string{"env:prod", "team:id"}},
		Secrets: []string{"dd-key"}, Batch: 3, At: at,
		Records: []logstream.Record{{Source: "events", At: at, Fields: json.RawMessage(`{"id":1,"type":"user.created"}`)},
			{Source: "audit_logs", At: at, Fields: json.RawMessage(`{"action":"doc.view"}`)}}}
}

func TestSend(t *testing.T) {
	var header http.Header
	var body []byte
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header, method = r.Header.Clone(), r.Method
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	out := lsdatadog.Sender{Transport: http.DefaultTransport, URL: srv.URL}.Send(context.Background(), batch())
	if !out.OK() || out.Status != 202 {
		t.Fatalf("outcome %+v", out)
	}
	if method != http.MethodPost || header.Get("DD-API-KEY") != "dd-key" || header.Get("Content-Type") != "application/json" {
		t.Fatalf("request %s %v", method, header)
	}
	var got []map[string]any
	if err := json.Unmarshal(body, &got); err != nil || len(got) != 2 {
		t.Fatalf("body %s: %v", body, err)
	}
	if got[0]["ddsource"] != "iamkit" || got[0]["service"] != "iam" || got[0]["ddtags"] != "env:prod,team:id" ||
		got[0]["message"] != "user.created" || got[0]["source"] != "events" || got[1]["message"] != "doc.view" {
		t.Fatalf("entries %v", got)
	}
}

func TestFailureNeverLeaksSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("bad key dd-key"))
	}))
	defer srv.Close()
	out := lsdatadog.Sender{Transport: http.DefaultTransport, URL: srv.URL}.Send(context.Background(), batch())
	if out.OK() || out.Status != 403 || out.Error == "" {
		t.Fatalf("outcome %+v", out)
	}
	if contains(out.Error, "dd-key") {
		t.Fatalf("error leaks the key: %s", out.Error)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	out := lsdatadog.Sender{Transport: http.DefaultTransport, URL: srv.URL}.Send(context.Background(), batch())
	if out.OK() || out.Status != 307 || hits != 0 {
		t.Fatalf("outcome %+v hits %d", out, hits)
	}
}

func TestGuardedByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	out := lsdatadog.Sender{URL: srv.URL}.Send(context.Background(), batch())
	if out.OK() || out.Status != 0 || out.Error == "" {
		t.Fatalf("a loopback destination must be refused: %+v", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
