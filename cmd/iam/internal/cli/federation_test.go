package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestFederationCreateSAMLDraft(t *testing.T) {
	handler := func(r seenRequest) (int, string) {
		if r.Method == "POST" {
			return 201, `{"id":"conn-1"}`
		}
		return 200, `{"id":"conn-1","draft":true,"saml":{"entity_id":"https://iam.example/saml/e/c/metadata","acs_url":"https://iam.example/identity/v1/federation/saml/acs","metadata_url":"https://iam.example/saml/e/c/metadata"}}`
	}
	out, _, seen, err := runCLI(t, handler, "federation", "create", "--provider", "saml", "--name", "Okta", "--organization", "org-1", "--draft", "--name-id-format", "email")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "Okta", "provider": "saml", "organization_id": "org-1", "draft": true, "options": map[string]any{"name_id_format": "email"}}
	if len(seen) != 2 || seen[0].Method != "POST" || seen[0].Path != base+"/federation-connections" || !reflect.DeepEqual(seen[0].Body, want) {
		t.Fatalf("seen = %+v", seen)
	}
	if seen[1].Method != "GET" || seen[1].Path != base+"/federation-connections/conn-1" || !strings.Contains(out, "acs_url") {
		t.Fatalf("detail: %+v %s", seen[1], out)
	}

	// The connections alias, and no metadata with a draft.
	_, _, seen, err = runCLI(t, handler, "connections", "create", "--provider", "saml", "--name", "Okta", "--organization", "org-1", "--draft", "--metadata-url", "https://idp.example.com/m")
	if err == nil || len(seen) != 0 {
		t.Fatalf("draft with metadata: err = %v, requests = %d", err, len(seen))
	}
}

func TestFederationTest(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"url":"https://iam.example/identity/v1/federation/test/env/conn-1?ticket=ik_fedtest_abc","expires_at":"2030-01-01T00:00:00Z"}`), "federation", "test", "conn-1")
	if err != nil || len(seen) != 1 || seen[0].Method != "POST" || seen[0].Path != base+"/federation-connections/conn-1/test" {
		t.Fatalf("test: %v %+v", err, seen)
	}
	if !strings.Contains(out, "federation/test/env/conn-1?ticket=ik_fedtest_") {
		t.Fatalf("out = %s", out)
	}
	if _, _, _, err = runCLI(t, ok(422, `{"error":{"code":"VALIDATION","message":"LDAP connections cannot be tested"}}`), "federation", "test", "ldap-1"); err == nil {
		t.Fatal("a refused test must fail")
	}
}
