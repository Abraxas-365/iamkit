package eventhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
)

// The Standard Webhooks reference test vector.
func TestSignStandardWebhooksVector(t *testing.T) {
	got, err := Sign([]string{"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", []byte(`{"test": 2432232314}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="; got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestSignSeveralSecrets(t *testing.T) {
	a, _ := Secrets{}.Generate()
	b, _ := Secrets{}.Generate()
	got, err := Sign([]string{a, b}, "msg_1", "1", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(got, " "); len(parts) != 2 || !strings.HasPrefix(parts[1], "v1,") {
		t.Fatalf("signature = %q", got)
	}
	if !strings.HasPrefix(a, event.SecretPrefix) || a == b {
		t.Fatalf("secrets %q %q", a, b)
	}
}

func TestBodyTruncatesLargeData(t *testing.T) {
	big, _ := json.Marshal(map[string]string{"x": strings.Repeat("a", config.EventWebhookMaxPayload)})
	body, err := Body(event.Event{ID: 7, Type: "user.updated", Data: big})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 1024 || !strings.Contains(string(body), `"truncated":true`) {
		t.Fatalf("body = %s", body)
	}
}

func TestSendSignsAndReportsStatus(t *testing.T) {
	secret, _ := Secrets{}.Generate()
	var got http.Header
	var body []byte
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, body = r.Header.Clone(), must(io.ReadAll(r.Body))
		w.WriteHeader(status)
	}))
	defer srv.Close()
	s := Sender{Transport: http.DefaultTransport, now: func() time.Time { return time.Unix(1700000000, 0) }}
	out := s.Send(context.Background(), event.Outbound{ID: "msg_5", URL: srv.URL, Secrets: []string{secret}, Event: event.Event{ID: 5, Type: "user.created", Data: []byte(`{}`)}})
	if !out.OK() || out.Status != http.StatusNoContent {
		t.Fatalf("outcome = %+v", out)
	}
	want, _ := Sign([]string{secret}, "msg_5", "1700000000", body)
	if got.Get("webhook-id") != "msg_5" || got.Get("webhook-timestamp") != "1700000000" || got.Get("webhook-signature") != want {
		t.Fatalf("headers = %v", got)
	}
	status = http.StatusInternalServerError
	if out = s.Send(context.Background(), event.Outbound{ID: "msg_6", URL: srv.URL, Secrets: []string{secret}, Event: event.Event{ID: 6}}); out.OK() || out.Status != 500 {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestSendRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	secret, _ := Secrets{}.Generate()
	out := Sender{}.Send(context.Background(), event.Outbound{ID: "msg_1", URL: srv.URL, Secrets: []string{secret}, Event: event.Event{ID: 1}})
	if out.OK() || out.Error != "the URL does not resolve to a public address" {
		t.Fatalf("outcome = %+v", out)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
