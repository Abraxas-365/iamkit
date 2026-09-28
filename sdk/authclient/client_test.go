package authclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestNew(t *testing.T) {
	c := New("http://localhost:8080/")
	if c.baseURL != "http://localhost:8080" {
		t.Fatalf("trailing slash not trimmed: %s", c.baseURL)
	}
	custom := &http.Client{}
	c2 := New("http://localhost", WithHTTPClient(custom))
	if c2.http != custom {
		t.Fatal("WithHTTPClient not applied")
	}
}

func TestClientCustomError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/v1/login" {
			t.Error("wrong path")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"error":{"code":"AUTHORIZATION","message":"invalid credential","type":"AUTHORIZATION","http_status":401}}`))
	}))
	defer server.Close()
	_, err := New(server.URL).Login(context.Background(), PasswordLogin{})
	var custom *apierror.Error
	if !errors.As(err, &custom) || custom.Code != "AUTHORIZATION" || custom.HTTPStatus != 401 {
		t.Fatalf("expected typed error: %v", err)
	}
}

func TestIdentityClientRefusesRedirects(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	_, err := New(source.URL).MachineToken(context.Background(), "ik_svc_secret")
	if err == nil || leaked {
		t.Fatal("followed credential redirect")
	}
}

func TestFederationStart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/v1/federation/start" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_url":"https://idp.example/authorize?state=xyz"}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	result, err := c.StartFederation(context.Background(), FederationStart{
		LoginContext: LoginContext{EnvironmentID: "env-1"},
		ConnectionID: "conn-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AuthorizationURL != "https://idp.example/authorize?state=xyz" {
		t.Fatalf("unexpected URL: %s", result.AuthorizationURL)
	}
}

func TestAddMember(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identity/v1/memberships" || r.Method != "POST" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing token")
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	c := New(srv.URL)
	err := c.AddMember(context.Background(), "test-token", AddMemberRequest{
		EnvironmentID: "env-1",
		Audience:      "aud",
		UserID:        "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllIdentityPaths(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	c.Login(ctx, PasswordLogin{})
	c.Refresh(ctx, LoginContext{}, "refresh")
	c.InitiateChallenge(ctx, "env", "a@b.com", "login")
	c.VerifyChallenge(ctx, ChallengeVerification{})
	c.StartFederation(ctx, FederationStart{})
	c.Logout(ctx, "tok", "env", "aud")
	c.Profile(ctx, "tok", "env", "aud")
	c.UpdateProfile(ctx, "tok", "env", "aud", "name")
	c.Organizations(ctx, "tok", "env", "aud")
	c.AddMember(ctx, "tok", AddMemberRequest{})
	c.Introspect(ctx, "tok", "iss", "aud", "env", "app", "res")

	expected := []string{
		"POST /identity/v1/login",
		"POST /identity/v1/refresh",
		"POST /identity/v1/challenges",
		"POST /identity/v1/challenges/verify",
		"POST /identity/v1/federation/start",
		"POST /identity/v1/logout",
		"GET /identity/v1/me",
		"PATCH /identity/v1/me",
		"GET /identity/v1/organizations",
		"POST /identity/v1/memberships",
		"POST /identity/v1/introspect",
	}
	if len(paths) != len(expected) {
		t.Fatalf("paths count %d != %d: %v", len(paths), len(expected), paths)
	}
	for i, p := range expected {
		if paths[i] != p {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], p)
		}
	}
}

func TestMFAEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/identity/v1/login" {
			w.Write([]byte(`{"mfa_required":true,"mfa_token":"ik_mfa_x","factors":["totp","recovery"],"enrollment_required":false,"expires_in":300}`))
			return
		}
		w.Write([]byte(`{"access_token":"a","recovery_codes":["c1"],"secret":"S","otpauth_uri":"otpauth://totp/x","factors":[],"recovery_codes_remaining":3}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	pair, err := c.Login(ctx, PasswordLogin{})
	if err != nil || !pair.MFARequired || pair.MFAToken != "ik_mfa_x" || pair.AccessToken != "" || len(pair.Factors) != 2 {
		t.Fatalf("login = %+v %v", pair, err)
	}
	if pair, err = c.VerifyMFA(ctx, pair.MFAToken, "123456"); err != nil || pair.AccessToken != "a" || len(pair.RecoveryCodes) != 1 {
		t.Fatalf("verify = %+v %v", pair, err)
	}
	if e, err := c.EnrollMFA(ctx, "ik_mfa_x"); err != nil || e.Secret != "S" || e.URI == "" {
		t.Fatalf("enroll = %+v %v", e, err)
	}
	if f, err := c.ListFactors(ctx, "tok", "env", "https://a.example"); err != nil || f.RecoveryCodesRemaining != 3 {
		t.Fatalf("factors = %+v %v", f, err)
	}
	c.StartTOTP(ctx, "tok", "env", "aud")
	c.ConfirmTOTP(ctx, "tok", "env", "aud", "123456")
	c.RemoveTOTP(ctx, "tok", "env", "aud", "123456")
	c.RegenerateRecoveryCodes(ctx, "tok", "env", "aud", "123456")
	want := []string{
		"POST /identity/v1/login",
		"POST /identity/v1/mfa/verify",
		"POST /identity/v1/mfa/enroll",
		"GET /identity/v1/me/factors?environment_id=env&audience=https%3A%2F%2Fa.example",
		"POST /identity/v1/me/factors/totp",
		"POST /identity/v1/me/factors/totp/confirm",
		"DELETE /identity/v1/me/factors/totp",
		"POST /identity/v1/me/factors/recovery-codes",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
}

func TestClaimsHasMFA(t *testing.T) {
	if (Claims{AMR: []string{"pwd"}}).HasMFA() || !(Claims{AMR: []string{"pwd", "otp", "mfa"}}).HasMFA() {
		t.Fatal("HasMFA")
	}
}

func TestInvitationEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user_id":"u-1","sso_required":true,"organization_name":"Acme"}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	p, err := c.PreviewInvitation(context.Background(), "ik_inv_x")
	if err != nil || p.OrganizationName != "Acme" || !p.SSORequired {
		t.Fatalf("preview = %+v %v", p, err)
	}
	a, err := c.AcceptInvitation(context.Background(), InvitationAcceptance{Token: "ik_inv_x"})
	if err != nil || a.UserID != "u-1" {
		t.Fatalf("accept = %+v %v", a, err)
	}
	// Tokens travel in the body, never in the URL.
	if len(calls) != 2 || calls[0] != "POST /identity/v1/invitations/preview" || calls[1] != "POST /identity/v1/invitations/accept" {
		t.Fatalf("calls = %v", calls)
	}
}

func TestInitiateChallengeLocale(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"challenge_id":"ch-1"}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	if _, err := c.InitiateChallenge(context.Background(), "env", "a@b.com", "login"); err != nil {
		t.Fatal(err)
	}
	out, err := c.InitiateChallengeWith(context.Background(), ChallengeRequest{Environment: "env", Email: "a@b.com", Purpose: "login", Locale: "es"})
	if err != nil || out.ID != "ch-1" {
		t.Fatalf("challenge = %+v %v", out, err)
	}
	want := []string{
		`{"environment_id":"env","email":"a@b.com","purpose":"login"}`,
		`{"environment_id":"env","email":"a@b.com","purpose":"login","locale":"es"}`,
	}
	for i, b := range bodies {
		if strings.TrimSpace(b) != want[i] {
			t.Errorf("body[%d] = %s, want %s", i, b, want[i])
		}
	}
}
