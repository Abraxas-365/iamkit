package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

const keyAnswer = `{"active":true,"claims":{"purpose":"api_key","sub":"","environment_id":"env-1","organization_id":"o1","resource_id":"r1","permissions":["orders:read"],"aud":["https://orders"],"exp":0,"api_key":{"id":"k1","name":"erp","owner":{"type":"organization","organization_id":"o1"},"resource_id":"r1","permissions":["orders:read","orders:write"],"expires_at":%d}}}`

func introspectServer(t *testing.T, answer string, seen *map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/identity/v1/introspect" || r.Header.Get("Authorization") != "Bearer ik_key_secret" {
			t.Errorf("unexpected: %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		if seen != nil {
			_ = json.NewDecoder(r.Body).Decode(seen)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(answer))
	}))
}

func unauthorized(err error) bool {
	var apiErr *apierror.Error
	return errors.As(err, &apiErr) && apiErr.Code == "UNAUTHORIZED" && apiErr.HTTPStatus == 401
}

func TestValidateAPIKey(t *testing.T) {
	var sent map[string]string
	srv := introspectServer(t, strings.Replace(keyAnswer, "%d", "0", 1), &sent)
	defer srv.Close()
	c := New(srv.URL, WithAudience("env-1", "https://orders"))
	key, err := c.ValidateAPIKey(context.Background(), "ik_key_secret")
	if err != nil {
		t.Fatal(err)
	}
	if sent["environment_id"] != "env-1" || sent["audience"] != "https://orders" {
		t.Fatalf("boundary sent = %v", sent)
	}
	if key.ID != "k1" || key.Name != "erp" || key.Owner.Type != "organization" || key.OrganizationID != "o1" || key.ResourceID != "r1" || !key.ExpiresAt.IsZero() {
		t.Fatalf("key = %+v", key)
	}
	if !key.HasPermission("orders:write") || key.HasPermission("orders:delete") {
		t.Fatalf("permissions = %v", key.Permissions)
	}
}

func TestValidateAPIKeyExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	srv := introspectServer(t, strings.Replace(keyAnswer, "%d", json.Number(itoa(future)).String(), 1), nil)
	defer srv.Close()
	key, err := New(srv.URL, WithAudience("env-1", "https://orders")).ValidateAPIKey(context.Background(), "ik_key_secret")
	if err != nil || key.ExpiresAt.Unix() != future {
		t.Fatalf("key = %+v %v", key, err)
	}
	past := introspectServer(t, strings.Replace(keyAnswer, "%d", itoa(time.Now().Add(-time.Hour).Unix()), 1), nil)
	defer past.Close()
	if _, err := New(past.URL, WithAudience("env-1", "https://orders")).ValidateAPIKey(context.Background(), "ik_key_secret"); !unauthorized(err) {
		t.Fatalf("expired key accepted: %v", err)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestValidateAPIKeyRefusals(t *testing.T) {
	good := strings.Replace(keyAnswer, "%d", "0", 1)
	for name, answer := range map[string]string{
		"inactive":          `{"active":false}`,
		"token purpose":     strings.Replace(good, `"purpose":"api_key"`, `"purpose":"application"`, 1),
		"other environment": strings.Replace(good, `"environment_id":"env-1"`, `"environment_id":"env-2"`, 1),
		"other audience":    strings.Replace(good, `"https://orders"]`, `"https://other"]`, 1),
		"no key":            `{"active":true,"claims":{"purpose":"api_key","environment_id":"env-1","aud":["https://orders"]}}`,
		"no permissions":    strings.Replace(good, `"permissions":["orders:read","orders:write"]`, `"permissions":[]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			srv := introspectServer(t, answer, nil)
			defer srv.Close()
			if _, err := New(srv.URL, WithAudience("env-1", "https://orders")).ValidateAPIKey(context.Background(), "ik_key_secret"); !unauthorized(err) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	c := New(srv.URL, WithAudience("env-1", "https://orders"))
	for _, value := range []string{"", "ik_pat_x", "ik_svc_x", "eyJhbGciOi.x.y"} {
		if _, err := c.ValidateAPIKey(context.Background(), value); !unauthorized(err) {
			t.Fatalf("%q: err = %v", value, err)
		}
	}
	if _, err := New(srv.URL).ValidateAPIKey(context.Background(), "ik_key_secret"); err == nil {
		t.Fatal("validated without an environment and audience")
	}
	if called {
		t.Fatal("a refused value reached the server")
	}
}

func TestValidateAPIKeyServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"error":{"code":"UNAVAILABLE","message":"later"}}`))
	}))
	defer srv.Close()
	_, err := New(srv.URL, WithAudience("env-1", "https://orders")).ValidateAPIKey(context.Background(), "ik_key_secret")
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != 503 {
		t.Fatalf("err = %v", err)
	}
}

func TestPrincipal(t *testing.T) {
	key := Principal{APIKey: &APIKey{OrganizationID: "o1", Permissions: []string{"a"}, Owner: APIKeyOwner{Type: "user", ID: "u1"}}}
	token := Principal{Claims: &Claims{Purpose: "application", OrganizationID: "o1", Permissions: []string{"a"}}}
	machine := Principal{Claims: &Claims{Purpose: "machine", Permissions: []string{"a"}}}
	for name, p := range map[string]Principal{"key": key, "token": token} {
		if p.OrganizationID() != "o1" || !p.HasPermission("a") || p.HasPermission("b") || !p.OrganizationBound("o1") || p.OrganizationBound("o2") || p.OrganizationBound("") {
			t.Errorf("%s = %+v", name, p)
		}
	}
	if key.Owner() == nil || key.Owner().ID != "u1" || token.Owner() != nil {
		t.Fatal("owner")
	}
	if machine.OrganizationBound("") || machine.OrganizationID() != "" || (Principal{}).HasPermission("a") {
		t.Fatal("machine or empty principal")
	}
}

func TestMeAPIKeys(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer user-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		call := r.Method + " " + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			call += "?" + r.URL.RawQuery
		}
		calls = append(calls, call)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case r.Method == "POST":
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"k1","name":"cli","state":"active","expires":false,"obfuscated_value":"ik_key_…wxyz","value":"ik_key_secret"}`))
		case strings.HasSuffix(r.URL.Path, "/options"):
			w.Write([]byte(`{"enabled":true,"max_ttl_days":null,"resources":[{"id":"r1","name":"Orders","audience":"https://orders","permissions":["orders:read"]}]}`))
		default:
			w.Write([]byte(`{"items":[{"id":"k1","name":"cli","state":"active","last_used_at":"2026-10-01T00:00:00Z"}],"page":{"total":1,"limit":20,"offset":0}}`))
		}
	}))
	defer srv.Close()
	me := New(srv.URL).Me("user-token", "env 1", "https://app")
	ctx := context.Background()

	list, err := me.APIKeys(ctx, 5, 10)
	if err != nil || len(list.Items) != 1 || list.Items[0].LastUsedAt == nil || list.Page.Total != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	options, err := me.APIKeyOptions(ctx)
	if err != nil || !options.Enabled || options.MaxTTLDays != nil || len(options.Resources) != 1 {
		t.Fatalf("options = %+v %v", options, err)
	}
	issued, err := me.CreateAPIKey(ctx, NewUserAPIKey{ResourceID: "r1", Name: "cli", Permissions: []string{"orders:read"}, ExpiresIn: "720h"})
	if err != nil || issued.Value != "ik_key_secret" || issued.ObfuscatedValue != "ik_key_…wxyz" {
		t.Fatalf("issued = %+v %v", issued, err)
	}
	if bodies[2]["environment_id"] != nil || bodies[2]["resource_id"] != "r1" || bodies[2]["expires_in"] != "720h" {
		t.Fatalf("create body = %v", bodies[2])
	}
	if err := me.RevokeAPIKey(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := me.RevokeAPIKey(ctx, "a/b"); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"GET /identity/v1/me/api-keys?environment_id=env+1&audience=https%3A%2F%2Fapp&limit=5&offset=10",
		"GET /identity/v1/me/api-keys/options?environment_id=env+1&audience=https%3A%2F%2Fapp",
		"POST /identity/v1/me/api-keys?environment_id=env+1&audience=https%3A%2F%2Fapp",
		"DELETE /identity/v1/me/api-keys/k1?environment_id=env+1&audience=https%3A%2F%2Fapp",
		"DELETE /identity/v1/me/api-keys/a%2Fb?environment_id=env+1&audience=https%3A%2F%2Fapp",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
}
