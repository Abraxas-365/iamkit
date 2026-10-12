package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

func TestChangePasswordAndSwitchOrganization(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
		bodies = append(bodies, body)
		switch {
		case r.URL.Path == "/identity/v1/me/password" && body["current_password"] == "stale":
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":"REAUTHENTICATION_REQUIRED","message":"sign in again","http_status":403}}`))
		case r.URL.Path == "/identity/v1/me/password":
			w.Write([]byte(`{"sessions_revoked":2}`))
		case body["switch_organization_id"] == "sso-org":
			w.WriteHeader(403)
			w.Write([]byte(`{"error":{"code":"REAUTHENTICATION_REQUIRED","message":"sign in to this organization again","http_status":403,"details":{"organization_id":"sso-org","reason":"sso"}}}`))
		default:
			w.Write([]byte(`{"access_token":"a2","refresh_token":"r2","token_type":"Bearer","expires_in":900}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()

	out, err := c.ChangePassword(ctx, "tok", "env", "https://a.example", "old", "new")
	if err != nil || out.SessionsRevoked != 2 {
		t.Fatalf("change = %+v %v", out, err)
	}
	if bodies[0]["current_password"] != "old" || bodies[0]["new_password"] != "new" {
		t.Fatalf("body = %v", bodies[0])
	}
	_, err = c.ChangePassword(ctx, "tok", "env", "https://a.example", "stale", "new")
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "REAUTHENTICATION_REQUIRED" || apiErr.HTTPStatus != 403 {
		t.Fatalf("stale error = %v", err)
	}

	boundary := LoginContext{EnvironmentID: "env", OrganizationID: "org", ApplicationID: "app", ResourceID: "res"}
	pair, err := c.SwitchOrganization(ctx, boundary, "r1", "other")
	if err != nil || pair.AccessToken != "a2" || pair.RefreshToken != "r2" {
		t.Fatalf("switch = %+v %v", pair, err)
	}
	if b := bodies[2]; b["refresh_token"] != "r1" || b["switch_organization_id"] != "other" || b["organization_id"] != "org" || b["environment_id"] != "env" {
		t.Fatalf("switch body = %v", b)
	}
	_, err = c.SwitchOrganization(ctx, boundary, "r1", "sso-org")
	if !errors.As(err, &apiErr) || apiErr.Code != "REAUTHENTICATION_REQUIRED" || apiErr.Details["reason"] != "sso" {
		t.Fatalf("sso error = %v", err)
	}
	if calls[0] != "POST /identity/v1/me/password?environment_id=env&audience=https%3A%2F%2Fa.example Bearer tok" || calls[2] != "POST /identity/v1/refresh " {
		t.Fatalf("calls = %q", calls)
	}
}
