package authmail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

func testEmail() authentication.Email {
	return authentication.Email{From: "no-reply@acme.io", FromName: "Acme, Inc.", ReplyTo: "help@acme.io", To: "ana@example.com",
		Subject: "Tu código", HTML: "<p>hi</p>", Text: "hi"}
}

func code(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestResendRequest(t *testing.T) {
	var got resendRequest
	var auth, contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, contentType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Write([]byte(`{"id":"49a3999c"}`))
	}))
	defer srv.Close()
	r := Resend{APIKey: "re_123", Endpoint: srv.URL, Transport: http.DefaultTransport}
	if err := r.Deliver(context.Background(), testEmail()); err != nil {
		t.Fatal(err)
	}
	want := resendRequest{From: `"Acme, Inc." <no-reply@acme.io>`, To: []string{"ana@example.com"}, Subject: "Tu código", HTML: "<p>hi</p>", Text: "hi", ReplyTo: "help@acme.io"}
	if auth != "Bearer re_123" || contentType != "application/json" || got.From != want.From || got.To[0] != want.To[0] ||
		got.Subject != want.Subject || got.HTML != want.HTML || got.Text != want.Text || got.ReplyTo != want.ReplyTo {
		t.Fatalf("auth %q type %q body %+v", auth, contentType, got)
	}
}

func TestResendOutcomes(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/401":
			http.Error(w, `{"name":"missing_api_key","message":"secret detail"}`, 401)
		case "/403-key":
			http.Error(w, `{"name":"restricted_api_key"}`, 403)
		case "/403-domain":
			http.Error(w, `{"name":"validation_error","message":"The acme.io domain is not verified"}`, 403)
		case "/422":
			http.Error(w, `{"name":"missing_required_field"}`, 422)
		case "/500":
			http.Error(w, `not json`, 500)
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/slow":
			<-release
		}
	}))
	defer srv.Close()
	defer close(release)
	for _, tc := range []struct {
		path, code, reason string
		status             int
	}{
		{"/401", authentication.CodeProviderAuth, "email provider rejected the credentials", 0},
		{"/403-key", authentication.CodeProviderAuth, "email provider rejected the credentials", 0},
		{"/403-domain", authentication.CodeProviderRejected, "email provider rejected the request", 403},
		{"/422", authentication.CodeProviderRejected, "email provider rejected the request", 422},
		{"/500", authentication.CodeProviderRejected, "email provider rejected the request", 500},
		{"/redirect", authentication.CodeProviderRejected, "email provider rejected the request", 302},
	} {
		err := Resend{APIKey: "k", Endpoint: srv.URL + tc.path, Transport: http.DefaultTransport}.Deliver(context.Background(), testEmail())
		status, reason := authentication.Describe(err)
		if code(err) != tc.code || reason != tc.reason || (tc.status == 0) != (status == nil) || (status != nil && *status != tc.status) {
			t.Errorf("%s: code %q status %v reason %q", tc.path, code(err), status, reason)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := Resend{APIKey: "k", Endpoint: srv.URL + "/slow", Transport: http.DefaultTransport}.Deliver(ctx, testEmail())
	if code(err) != authentication.CodeProviderTimeout {
		t.Errorf("slow: %v", err)
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	err = Resend{APIKey: "k", Endpoint: closed.URL, Transport: http.DefaultTransport}.Deliver(context.Background(), testEmail())
	if code(err) != authentication.CodeProviderUnreachable {
		t.Errorf("closed: %v", err)
	}
}

// The default transport refuses non-public addresses such as a loopback
// test server: an environment can't point IAMKit at internal services.
func TestResendGuardedByDefault(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	err := Resend{APIKey: "k", Endpoint: srv.URL}.Deliver(context.Background(), testEmail())
	if _, reason := authentication.Describe(err); reason != "email provider address is not allowed" || hit {
		t.Fatalf("reason %q hit %v", reason, hit)
	}
}
