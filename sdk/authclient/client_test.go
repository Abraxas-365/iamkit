package authclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
