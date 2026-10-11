package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestCaptchaAndSignals(t *testing.T) {
	var path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		body = nil
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/identity/v1/captcha/env-1":
			w.Write([]byte(`{"enabled":true,"provider":"turnstile","site_key":"1x00000000000000000000AA","headless":true}`))
		case "/identity/v1/login":
			w.Write([]byte(`{"mfa_required":true,"mfa_token":"ik_mfa_x","factors":["email"],"reason":"risk_challenge"}`))
		default:
			w.Write([]byte(`{"challenge_id":"c1"}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()

	got, err := c.Captcha(ctx, "env-1")
	if err != nil || !got.Enabled || got.Provider != "turnstile" || got.SiteKey == "" || path != "GET /identity/v1/captcha/env-1" {
		t.Fatalf("captcha = %+v %v (%s)", got, err, path)
	}
	if _, err := c.Captcha(ctx, "../x"); err == nil {
		t.Fatal("unsafe environment accepted")
	}

	pair, err := c.Login(ctx, PasswordLogin{Email: "a@b.com", Password: "pw", CaptchaToken: "tok", DeviceID: "0123456789abcdef"})
	if err != nil || !pair.MFARequired || pair.MFAReason != MFAReasonRiskChallenge {
		t.Fatalf("login = %+v %v", pair, err)
	}
	if body["captcha_token"] != "tok" || body["device_id"] != "0123456789abcdef" {
		t.Fatalf("login body %v", body)
	}
	if _, err := c.InitiateChallengeWith(ctx, ChallengeRequest{Environment: "e", Email: "a@b.com", Purpose: "login", CaptchaToken: "tok2", DeviceID: "d"}); err != nil || body["captcha_token"] != "tok2" || body["device_id"] != "d" {
		t.Fatalf("challenge body %v %v", body, err)
	}
	if _, err := c.Signup(ctx, SignupRequest{Environment: "e", Email: "a@b.com", Name: "A", CaptchaToken: "tok3"}); err != nil || body["captcha_token"] != "tok3" {
		t.Fatalf("signup body %v %v", body, err)
	}
	if _, err := c.DirectoryLoginWith(ctx, DirectoryLogin{ConnectionID: "conn", Email: "a@b.com", Password: "pw", CaptchaToken: "tok4", DeviceID: "d"}); err != nil || body["captcha_token"] != "tok4" || body["connection_id"] != "conn" {
		t.Fatalf("ldap body %v %v", body, err)
	}
	// Existing shapes stay unchanged when the new fields are unset.
	if _, err := c.Login(ctx, PasswordLogin{Email: "a@b.com", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["captcha_token"]; ok {
		t.Fatalf("empty captcha_token sent: %v", body)
	}
	if _, ok := body["device_id"]; ok {
		t.Fatalf("empty device_id sent: %v", body)
	}
}

func TestCaptchaRequiredError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		w.Write([]byte(`{"error":{"code":"CAPTCHA_REQUIRED","message":"complete the CAPTCHA","type":"forbidden","http_status":403,"details":{"provider":"hcaptcha"}}}`))
	}))
	defer srv.Close()
	_, err := New(srv.URL).Login(context.Background(), PasswordLogin{})
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || !apiErr.IsCaptchaRequired() || apiErr.Provider() != "hcaptcha" || apiErr.IsSignInBlocked() {
		t.Fatalf("err = %#v", err)
	}
}
