package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

type seenRequest struct {
	Method, Path, Query string
	Body                map[string]any
}

// runCLI runs the real command tree against a fake management API and
// returns what the command wrote to stdout and stderr.
func runCLI(t *testing.T, handler func(r seenRequest) (int, string), args ...string) (stdout, stderr string, seen []seenRequest, err error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			t.Errorf("missing management key on %s %s", r.Method, r.URL.Path)
		}
		req := seenRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery}
		_ = json.NewDecoder(r.Body).Decode(&req.Body)
		seen = append(seen, req)
		status, body := handler(req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("IAMKIT_URL", srv.URL)
	t.Setenv("IAMKIT_KEY", "k")
	t.Setenv("IAMKIT_ENVIRONMENT", "env")
	t.Setenv("IAMKIT_PROFILE", "")

	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	cmd := Root()
	cmd.SetArgs(append([]string{"-o", "json"}, args...))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err = cmd.Execute()
	os.Stdout, os.Stderr = oldOut, oldErr
	outW.Close()
	errW.Close()
	o, _ := io.ReadAll(outR)
	e, _ := io.ReadAll(errR)
	return string(o), string(e), seen, err
}

func ok(status int, body string) func(seenRequest) (int, string) {
	return func(seenRequest) (int, string) { return status, body }
}

const base = "/management/v1/environments/env"

func TestAPIKeysList(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"items":[],"page":{"total":0,"limit":20,"offset":0}}`),
		"api-keys", "list", "--owner-type", "user", "--organization", "o1", "--user", "u1", "--resource", "r1", "--state", "revoked", "--limit", "5")
	if err != nil {
		t.Fatal(err)
	}
	want := "limit=5&organization_id=o1&owner_type=user&resource_id=r1&state=revoked&user_id=u1"
	if len(seen) != 1 || seen[0].Method != "GET" || seen[0].Path != base+"/api-keys" || seen[0].Query != want {
		t.Fatalf("seen = %+v", seen)
	}
	for _, bad := range [][]string{{"--owner-type", "robot"}, {"--state", "gone"}} {
		_, _, seen, err := runCLI(t, ok(200, `{}`), append([]string{"api-keys", "list"}, bad...)...)
		if err == nil || len(seen) != 0 {
			t.Fatalf("%v: err = %v, requests = %d", bad, err, len(seen))
		}
	}
}

func TestAPIKeysGetAndRevoke(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"id":"k1","state":"active"}`), "api-keys", "get", "k1")
	if err != nil || !strings.Contains(out, `"k1"`) || seen[0].Path != base+"/api-keys/k1" {
		t.Fatalf("get: %v %q %+v", err, out, seen)
	}
	_, errOut, seen, err := runCLI(t, ok(204, ``), "api-keys", "revoke", "k1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/api-keys/k1" || !strings.Contains(errOut, "revoked") {
		t.Fatalf("revoke: %v %q %+v", err, errOut, seen)
	}
}

func TestAPIKeysCreatePrintsValueOnceWithWarning(t *testing.T) {
	out, errOut, seen, err := runCLI(t, ok(201, `{"id":"k1","name":"erp","value":"ik_key_secret","obfuscated_value":"ik_key_…cret"}`),
		"api-keys", "create", "--organization", "o1", "--resource", "r1", "--name", "erp", "--permission", "orders:read", "--permission", "orders:write", "--expires-in", "720h")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "erp", "resource_id": "r1", "organization_id": "o1", "permissions": []any{"orders:read", "orders:write"}, "expires_in": "720h"}
	if seen[0].Method != "POST" || seen[0].Path != base+"/api-keys" || !reflect.DeepEqual(seen[0].Body, want) {
		t.Fatalf("seen = %+v", seen[0])
	}
	if !strings.Contains(out, "ik_key_secret") || strings.Contains(errOut, "ik_key_secret") {
		t.Fatalf("value must reach stdout only: out=%q err=%q", out, errOut)
	}
	if !strings.Contains(errOut, "only time") {
		t.Fatalf("missing warning: %q", errOut)
	}

	// expires-in omitted = never: the field is not sent.
	_, _, seen, err = runCLI(t, ok(201, `{"id":"k1","value":"ik_key_x"}`),
		"api-keys", "create", "--organization", "o1", "--resource", "r1", "--name", "erp", "--permission", "orders:read,orders:write")
	if err != nil {
		t.Fatal(err)
	}
	if _, has := seen[0].Body["expires_in"]; has || len(seen[0].Body["permissions"].([]any)) != 2 {
		t.Fatalf("body = %v", seen[0].Body)
	}

	// A failed create prints no warning.
	out, errOut, _, err = runCLI(t, ok(422, `{"error":{"message":"policy forbids","type":"VALIDATION"}}`),
		"api-keys", "create", "--organization", "o1", "--resource", "r1", "--name", "erp", "--permission", "a")
	if err == nil || out != "" || strings.Contains(errOut, "only time") {
		t.Fatalf("err=%v out=%q errOut=%q", err, out, errOut)
	}
	if _, _, seen, err := runCLI(t, ok(201, `{}`), "api-keys", "create", "--organization", "o1", "--resource", "r1", "--name", "x"); err == nil || len(seen) != 0 {
		t.Fatalf("permission-less create must fail locally: %v", err)
	}
}

func TestAPIKeyPolicy(t *testing.T) {
	current := `{"user_keys":true,"organization_keys":true,"max_ttl_days":90,"max_per_user":10,"max_per_organization":50,"updated_at":"2026-10-01T00:00:00Z"}`
	_, _, seen, err := runCLI(t, ok(200, current), "api-keys", "policy", "get")
	if err != nil || seen[0].Method != "GET" || seen[0].Path != base+"/api-key-policy" {
		t.Fatalf("get: %v %+v", err, seen)
	}

	handler := func(r seenRequest) (int, string) { return 200, current }
	_, _, seen, err = runCLI(t, handler, "api-keys", "policy", "set", "--user-keys=false", "--no-max-ttl", "--max-per-organization", "200")
	if err != nil || len(seen) != 2 || seen[1].Method != "PUT" || seen[1].Path != base+"/api-key-policy" {
		t.Fatalf("set: %v %+v", err, seen)
	}
	want := map[string]any{"user_keys": false, "organization_keys": true, "max_ttl_days": nil, "max_per_user": float64(10), "max_per_organization": float64(200)}
	if !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("body = %v", seen[1].Body)
	}

	_, _, seen, err = runCLI(t, handler, "api-keys", "policy", "set", "--max-ttl-days", "30")
	if err != nil || seen[1].Body["max_ttl_days"] != float64(30) || seen[1].Body["user_keys"] != true {
		t.Fatalf("ttl: %v %+v", err, seen)
	}

	for _, bad := range [][]string{
		{}, {"--max-ttl-days", "30", "--no-max-ttl"}, {"--max-ttl-days", "400"}, {"--max-per-user", "0"}, {"--max-per-user", "101"}, {"--max-per-organization", "501"},
	} {
		_, _, seen, err := runCLI(t, handler, append([]string{"api-keys", "policy", "set"}, bad...)...)
		if err == nil || len(seen) != 0 {
			t.Fatalf("%v: err = %v, requests = %d", bad, err, len(seen))
		}
	}
}

func TestResourceAPIKeyPermissions(t *testing.T) {
	resource := `{"id":"r1","name":"Orders","api_key_permissions":{"user":["a"],"organization":["a","b"]}}`
	out, _, seen, err := runCLI(t, ok(200, resource), "resources", "api-key-permissions", "get", "r1")
	if err != nil || seen[0].Path != base+"/resources/r1" || !strings.Contains(out, `"organization"`) {
		t.Fatalf("get: %v %q %+v", err, out, seen)
	}

	handler := func(r seenRequest) (int, string) {
		if r.Method == "PUT" {
			return 204, ""
		}
		return 200, resource
	}
	// Setting one list keeps the other.
	_, _, seen, err = runCLI(t, handler, "resources", "api-key-permissions", "set", "r1", "--user", "x,y")
	if err != nil || seen[1].Method != "PUT" || seen[1].Path != base+"/resources/r1/api-key-permissions" {
		t.Fatalf("set: %v %+v", err, seen)
	}
	if want := map[string]any{"user": []any{"x", "y"}, "organization": []any{"a", "b"}}; !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("body = %v", seen[1].Body)
	}
	// An empty value clears a list and sends [] not null.
	_, _, seen, err = runCLI(t, handler, "resources", "api-key-permissions", "set", "r1", "--organization=")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"user": []any{"a"}, "organization": []any{}}; !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("clear body = %v", seen[1].Body)
	}
	// A resource without allowlists sends empty lists.
	_, _, seen, err = runCLI(t, func(r seenRequest) (int, string) {
		if r.Method == "PUT" {
			return 204, ""
		}
		return 200, `{"id":"r1"}`
	}, "resources", "api-key-permissions", "set", "r1", "--user", "x")
	if err != nil || !reflect.DeepEqual(seen[1].Body, map[string]any{"user": []any{"x"}, "organization": []any{}}) {
		t.Fatalf("bare: %v %+v", err, seen)
	}
	if _, _, seen, err := runCLI(t, handler, "resources", "api-key-permissions", "set", "r1"); err == nil || len(seen) != 0 {
		t.Fatalf("no flags must fail locally: %v", err)
	}
}

func TestMachineUserAPIKeys(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"items":[],"page":{"total":0,"limit":20,"offset":0}}`), "machine-users", "api-keys", "list", "m1", "--limit", "3")
	if err != nil || seen[0].Method != "GET" || seen[0].Path != base+"/users/m1/api-keys" || seen[0].Query != "limit=3" {
		t.Fatalf("list: %v %+v", err, seen)
	}
	out, errOut, seen, err := runCLI(t, ok(201, `{"id":"k1","value":"ik_key_secret"}`),
		"machine-users", "api-keys", "create", "m1", "--name", "ci", "--org", "o1", "--app", "a1", "--resource", "r1")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "ci", "organization_id": "o1", "application_id": "a1", "resource_id": "r1"}
	if seen[0].Method != "POST" || seen[0].Path != base+"/users/m1/api-keys" || !reflect.DeepEqual(seen[0].Body, want) {
		t.Fatalf("create: %+v", seen[0])
	}
	if !strings.Contains(out, "ik_key_secret") || !strings.Contains(errOut, "only time") {
		t.Fatalf("out=%q err=%q", out, errOut)
	}
	_, _, seen, err = runCLI(t, ok(201, `{}`), "machine-users", "api-keys", "create", "m1", "--name", "ci", "--org", "o1", "--app", "a1", "--resource", "r1", "--permission", "orders:read", "--expires-in", "never")
	if err != nil || seen[0].Body["expires_in"] != "never" || len(seen[0].Body["permissions"].([]any)) != 1 {
		t.Fatalf("create with options: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "machine-users", "api-keys", "revoke", "m1", "k1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/users/m1/api-keys/k1" {
		t.Fatalf("revoke: %v %+v", err, seen)
	}
	// The personal access token commands are gone.
	if _, _, seen, err := runCLI(t, ok(200, `{}`), "machine-users", "tokens", "list", "m1"); len(seen) != 0 {
		t.Fatalf("tokens still routes: %v", err)
	}
}

func TestAPIKeyRowFormatting(t *testing.T) {
	row := apiKeyRow(map[string]any{
		"id": "k1", "name": "erp", "owner": map[string]any{"type": "user", "user_id": "123456789012345678"}, "organization_id": "o1", "resource_name": "Orders",
		"obfuscated_value": "ik_key_…abcd", "expires": false, "state": "active",
	})
	want := []string{"k1", "erp", "user:123456789012…", "o1", "Orders", "ik_key_…abcd", "never", "—", "active"}
	if !reflect.DeepEqual(row, want) {
		t.Fatalf("row = %q", row)
	}
	if got := apiKeyRow(map[string]any{"expires": true, "expires_at": "2027-01-01T00:00:00Z"}); got[6] != "2027-01-01T00:00:00Z" {
		t.Fatalf("expiry = %q", got[6])
	}
}
