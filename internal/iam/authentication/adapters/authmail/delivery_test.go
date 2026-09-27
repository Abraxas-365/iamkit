package authmail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// Delivery errors classify into a status and a reason that never carries
// the URL or response body.
func TestWebhookDeliveryOutcomes(t *testing.T) {
	var got string
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(202)
		case "/slow":
			<-release
		default:
			http.Error(w, "secret-body", 503)
		}
	}))
	defer srv.Close()
	defer close(release)
	send := func(ctx context.Context, path string) error {
		return WebhookDelivery{URL: srv.URL + path, Token: "tok"}.Send(ctx, authentication.Message{Email: "a@b.example", Purpose: authentication.PurposeTest})
	}
	if err := send(context.Background(), "/ok"); err != nil || got != "Bearer tok" {
		t.Fatalf("ok: %v %q", err, got)
	}
	status, reason := authentication.Describe(send(context.Background(), "/fail"))
	if status == nil || *status != 503 || reason != "webhook rejected the request" {
		t.Fatalf("rejected: %v %q", status, reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if status, reason = authentication.Describe(send(ctx, "/slow")); status != nil || reason != "webhook did not respond in time" {
		t.Fatalf("timeout: %v %q", status, reason)
	}
	err := WebhookDelivery{URL: "http://127.0.0.1:1/hook"}.Send(context.Background(), authentication.Message{})
	if status, reason = authentication.Describe(err); status != nil || reason != "webhook could not be reached" || strings.Contains(reason, "127.0.0.1") {
		t.Fatalf("unreachable: %v %q", status, reason)
	}
}

func TestWebhookDeliveryValidate(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://mail.example.com/send": true,
		"http://localhost:9099/mail":    true,
		"http://127.0.0.1:9099/mail":    true,
		"http://mail.example.com/send":  false,
		"https://user:pw@mail.example":  false,
		"https://mail.example.com/#x":   false,
		"":                              false,
	} {
		if err := (WebhookDelivery{URL: url}).Validate(); (err == nil) != ok {
			t.Errorf("%q: got err=%v, want ok=%v", url, err, ok)
		}
	}
}
