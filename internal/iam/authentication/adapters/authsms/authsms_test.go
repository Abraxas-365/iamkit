package authsms

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// sid is a syntactically valid Twilio account SID, built at run time so the
// fake never looks like a leaked credential to secret scanners.
var sid = "AC" + strings.Repeat("0123456789abcdef", 2)

func TestTwilio(t *testing.T) {
	var got url.Values
	var path, user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		user, pass, _ = r.BasicAuth()
		body, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(body))
		w.WriteHeader(201)
	}))
	defer srv.Close()
	tw := Twilio{AccountSID: sid, AuthToken: "secret", From: "+15550001111", Endpoint: srv.URL, Transport: http.DefaultTransport}
	if err := tw.SendSMS(context.Background(), authentication.SMS{Phone: "+15551234567", Body: "123456 is your code"}); err != nil {
		t.Fatal(err)
	}
	if path != "/2010-04-01/Accounts/"+sid+"/Messages.json" || user != sid || pass != "secret" {
		t.Fatalf("request %s %s:%s", path, user, pass)
	}
	if got.Get("To") != "+15551234567" || got.Get("From") != "+15550001111" || got.Get("Body") != "123456 is your code" {
		t.Fatalf("form %v", got)
	}
	tw.MessagingServiceSID = "MG0123456789abcdef0123456789abcdef"
	if err := tw.SendSMS(context.Background(), authentication.SMS{Phone: "+15551234567"}); err != nil {
		t.Fatal(err)
	}
	if got.Get("MessagingServiceSid") == "" || got.Has("From") {
		t.Fatalf("messaging service form %v", got)
	}
}

func TestTwilioFailures(t *testing.T) {
	status := 401
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	tw := Twilio{AccountSID: sid, AuthToken: "x", From: "+15550001111", Endpoint: srv.URL, Transport: http.DefaultTransport}
	for _, c := range []struct {
		status int
		code   string
	}{{401, authentication.CodeSMSProviderAuth}, {400, authentication.CodeSMSProviderRejected}} {
		status = c.status
		var e *errx.Error
		if err := tw.SendSMS(context.Background(), authentication.SMS{Phone: "+15551234567"}); !errx.As(err, &e) || e.Code != c.code {
			t.Fatalf("%d: %v", c.status, err)
		}
	}
	// The guarded transport refuses loopback.
	tw.Transport = nil
	var e *errx.Error
	if err := tw.SendSMS(context.Background(), authentication.SMS{Phone: "+15551234567"}); !errx.As(err, &e) || e.Code != authentication.CodeWebhookAddress {
		t.Fatalf("guarded: %v", err)
	}
}

func TestWebhook(t *testing.T) {
	var got authentication.SMS
	var header http.Header
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header
		raw, _ = io.ReadAll(r.Body)
		json.Unmarshal(raw, &got)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	w := Webhook{URL: "http://localhost:" + u.Port(), Token: "tok", Transport: http.DefaultTransport}
	if err := w.SendSMS(context.Background(), authentication.SMS{Phone: "+15551234567", Purpose: "mfa", Code: "123456", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if got.Phone != "+15551234567" || got.Purpose != "mfa" || got.Code != "123456" || got.Body != "b" {
		t.Fatalf("payload %+v", got)
	}
	if header.Get("Authorization") != "Bearer tok" || header.Get("webhook-signature") != Sign("tok", header.Get("webhook-id"), header.Get("webhook-timestamp"), raw) {
		t.Fatalf("headers %v", header)
	}
	if err := (Webhook{URL: "http://example.com/sms"}).SendSMS(context.Background(), authentication.SMS{}); err == nil {
		t.Fatal("plain HTTP accepted")
	}
}

func TestFactory(t *testing.T) {
	f := Factory(nil, "")
	if d, err := f(authentication.SMSConfig{Provider: "twilio", AccountSID: sid}, "tok"); err != nil || d.(Twilio).AuthToken != "tok" {
		t.Fatalf("twilio %v %v", d, err)
	}
	if d, err := f(authentication.SMSConfig{Provider: "webhook", WebhookURL: "https://x"}, "tok"); err != nil || d.(Webhook).Token != "tok" {
		t.Fatalf("webhook %v %v", d, err)
	}
	if _, err := f(authentication.SMSConfig{Provider: "fax"}, ""); err == nil {
		t.Fatal("unknown provider")
	}
}
