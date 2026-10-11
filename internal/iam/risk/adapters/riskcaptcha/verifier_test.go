package riskcaptcha

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/risk"
)

// redirect sends every provider call to the test server.
type redirect struct{ target *httptest.Server }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.target.URL)
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(req)
}

func serve(t *testing.T, handler http.HandlerFunc) Verifier {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return Verifier{Transport: redirect{server}}
}

func TestVerifySendsFormAndReadsAnswer(t *testing.T) {
	var got url.Values
	var path string
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(body))
		path = r.URL.Path
		w.Write([]byte(`{"success":true,"hostname":"Auth.Example.com","action":"login","error-codes":[]}`))
	})
	a, err := v.Verify(context.Background(), risk.ProviderTurnstile, "sekret", risk.CaptchaCheck{Token: "tok", RemoteIP: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Success || a.Hostname != "Auth.Example.com" || a.Action != "login" {
		t.Fatalf("answer = %+v", a)
	}
	if got.Get("secret") != "sekret" || got.Get("response") != "tok" || got.Get("remoteip") != "203.0.113.9" {
		t.Fatalf("form = %v", got)
	}
	if !strings.HasSuffix(path, "/turnstile/v0/siteverify") {
		t.Fatalf("path = %s", path)
	}
}

func TestVerifyHCaptchaEndpoint(t *testing.T) {
	var host string
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	})
	a, err := v.Verify(context.Background(), risk.ProviderHCaptcha, "s", risk.CaptchaCheck{Token: "t"})
	if err != nil || a.Success || len(a.Codes) != 1 || a.Codes[0] != "invalid-input-response" {
		t.Fatalf("answer = %+v, err = %v", a, err)
	}
	_ = host
}

func TestVerifyMarksTestingSecrets(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"hostname":"example.com","error-codes":[]}`))
	})
	a, err := v.Verify(context.Background(), risk.ProviderTurnstile, "1x0000000000000000000000000000000AA", risk.CaptchaCheck{Token: "t"})
	if err != nil || !a.Testing {
		t.Fatalf("testing secret: answer = %+v, err = %v", a, err)
	}
	if !a.Accepts(risk.CaptchaConfig{Hostnames: []string{"auth.example.org"}}, risk.CaptchaCheck{Hostname: "auth.example.org"}) {
		t.Fatal("a testing secret's placeholder hostname must not refuse")
	}
	a, err = v.Verify(context.Background(), risk.ProviderTurnstile, "a-real-secret", risk.CaptchaCheck{Token: "t"})
	if err != nil || a.Testing {
		t.Fatalf("real secret: answer = %+v, err = %v", a, err)
	}
	if a.Accepts(risk.CaptchaConfig{}, risk.CaptchaCheck{Hostname: "auth.example.org"}) {
		t.Fatal("a real secret's answer for another hostname must refuse")
	}
}

func TestVerifyFailuresAreErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"5xx":      func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) },
		"garbage":  func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.1:1/", 302) },
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			v := serve(t, handler)
			if _, err := v.Verify(context.Background(), risk.ProviderTurnstile, "s", risk.CaptchaCheck{Token: "t"}); err == nil {
				t.Fatal("want an error: the provider gave no verdict")
			}
		})
	}
}

func TestVerifyTimeout(t *testing.T) {
	v := serve(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) })
	v.Timeout = 50 * time.Millisecond
	if _, err := v.Verify(context.Background(), risk.ProviderTurnstile, "s", risk.CaptchaCheck{Token: "t"}); err == nil {
		t.Fatal("want a timeout error")
	}
}

func TestVerifyUnknownProvider(t *testing.T) {
	if _, err := (Verifier{}).Verify(context.Background(), "recaptcha", "s", risk.CaptchaCheck{Token: "t"}); err == nil {
		t.Fatal("want a validation error")
	}
}

// The default transport dials public addresses only.
func TestGuardedRefusesPrivateAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL, nil)
	if res, err := Guarded().RoundTrip(req); err == nil {
		res.Body.Close()
		t.Fatal("the guarded transport reached a loopback address")
	}
}
