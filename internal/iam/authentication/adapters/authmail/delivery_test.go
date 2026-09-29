package authmail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// Delivery errors classify into a status and a reason that never carries
// the URL or response body.
func TestWebhookDeliveryOutcomes(t *testing.T) {
	var got string
	var headers http.Header
	var body []byte
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		headers = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
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
		return WebhookDelivery{URL: srv.URL + path, Token: "tok", Transport: http.DefaultTransport}.Send(ctx, authentication.Message{Email: "a@b.example", Purpose: authentication.PurposeTest})
	}
	if err := send(context.Background(), "/ok"); err != nil || got != "Bearer tok" {
		t.Fatalf("ok: %v %q", err, got)
	}
	// Standard Webhooks signature over id.timestamp.body.
	id, ts, sig := headers.Get("webhook-id"), headers.Get("webhook-timestamp"), headers.Get("webhook-signature")
	unix, err := strconv.ParseInt(ts, 10, 64)
	if !strings.HasPrefix(id, "msg_") || err != nil || time.Since(time.Unix(unix, 0)).Abs() > time.Minute {
		t.Fatalf("webhook headers: id=%q ts=%q", id, ts)
	}
	mac := hmac.New(sha256.New, []byte("tok"))
	mac.Write([]byte(id + "." + ts + "." + string(body)))
	if want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)); sig != want || sig != SignWebhook("tok", id, ts, body) {
		t.Fatalf("signature = %q, want %q", sig, want)
	}
	firstID := id
	if err := send(context.Background(), "/ok"); err != nil || headers.Get("webhook-id") == firstID {
		t.Fatalf("webhook-id must be unique per send: %v", err)
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
	err = WebhookDelivery{URL: "http://127.0.0.1:1/hook", Transport: http.DefaultTransport}.Send(context.Background(), authentication.Message{})
	if status, reason = authentication.Describe(err); status != nil || reason != "webhook could not be reached" || strings.Contains(reason, "127.0.0.1") {
		t.Fatalf("unreachable: %v %q", status, reason)
	}
}

// Without a token nothing is signed.
func TestWebhookDeliveryUnsigned(t *testing.T) {
	var headers http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { headers = r.Header.Clone() }))
	defer srv.Close()
	if err := (WebhookDelivery{URL: srv.URL, Transport: http.DefaultTransport}).Send(context.Background(), authentication.Message{}); err != nil {
		t.Fatal(err)
	}
	if headers.Get("webhook-signature") != "" || headers.Get("webhook-id") != "" || headers.Get("webhook-timestamp") != "" {
		t.Fatalf("headers = %v", headers)
	}
}

// By default (environment webhooks) private and loopback addresses are
// refused before any request is sent.
func TestWebhookDeliveryGuarded(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	for _, url := range []string{srv.URL + "/hook", strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/hook"} {
		err := WebhookDelivery{URL: url, Token: "tok"}.Send(context.Background(), authentication.Message{Email: "a@b.example"})
		if status, reason := authentication.Describe(err); status != nil || reason != "webhook address is not allowed" {
			t.Fatalf("%s: %v %q", url, status, reason)
		}
	}
	if hit {
		t.Fatal("guarded webhook reached a loopback server")
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
