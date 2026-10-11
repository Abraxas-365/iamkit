package lshttps_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lshttps"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestSendSigned(t *testing.T) {
	old, _ := lshttps.Secrets{}.Generate()
	current, _ := lshttps.Secrets{}.Generate()
	if !strings.HasPrefix(current, "whsec_") {
		t.Fatal(current)
	}
	var header http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	at := time.Now()
	b := logstream.Outbound{Environment: identity.NewEnvironmentID(), Destination: "https", Batch: 9, At: at,
		Config: logstream.Config{URL: srv.URL}, Secrets: []string{current, old},
		Records: []logstream.Record{{Source: "events", At: at, Fields: json.RawMessage(`{"type":"a.b"}`)}}}
	out := lshttps.Sender{Transport: http.DefaultTransport}.Send(context.Background(), b)
	if !out.OK() {
		t.Fatalf("outcome %+v", out)
	}
	if header.Get("webhook-id") != "msg_ls_9" {
		t.Fatalf("id %s", header.Get("webhook-id"))
	}
	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err != nil || len(arr) != 1 || arr[0]["type"] != "a.b" || arr[0]["source"] != "events" {
		t.Fatalf("body %s %v", body, err)
	}
	// One signature per live secret, each verifying over id.timestamp.body.
	sigs := strings.Fields(header.Get("webhook-signature"))
	if len(sigs) != 2 {
		t.Fatalf("signatures %v", sigs)
	}
	for i, secret := range []string{current, old} {
		want, err := lshttps.Sign([]string{secret}, header.Get("webhook-id"), header.Get("webhook-timestamp"), body)
		if err != nil || want != sigs[i] {
			t.Fatalf("signature %d mismatch: %s vs %s (%v)", i, want, sigs[i], err)
		}
	}
}

func TestMalformedSecret(t *testing.T) {
	out := lshttps.Sender{Transport: http.DefaultTransport}.Send(context.Background(), logstream.Outbound{
		Config: logstream.Config{URL: "https://example.com"}, Secrets: []string{"whsec_!!!"}})
	if out.OK() || strings.Contains(out.Error, "whsec_") {
		t.Fatalf("outcome %+v", out)
	}
}
