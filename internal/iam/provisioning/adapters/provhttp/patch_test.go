package provhttp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
)

func ops(t *testing.T, raw string) []patchOp {
	t.Helper()
	var body struct {
		Operations []patchOp `json:"Operations"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	return body.Operations
}

func scimTypeOf(err error) string {
	var e *errx.Error
	if errx.As(err, &e) && e != nil {
		s, _ := e.Details["scimType"].(string)
		return s
	}
	return ""
}

func TestApplyPatch(t *testing.T) {
	old := provisioning.User{Email: "a@example.com", External: "ext-1", Name: "A"}
	const mgr = "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name     string
		body     string
		active   *bool
		display  string
		manager  *string
		scimType string
	}{
		{name: "entra string active", body: `{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, active: ptr(false)},
		{name: "bool active", body: `{"Operations":[{"op":"replace","path":"active","value":true}]}`, active: ptr(true)},
		{name: "bad active", body: `{"Operations":[{"op":"replace","path":"active","value":"nope"}]}`, scimType: scimInvalidValue},
		{name: "entra manager bare string", body: `{"Operations":[{"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"` + mgr + `"}]}`, manager: ptr(mgr)},
		{name: "manager object", body: `{"Operations":[{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":{"value":"` + mgr + `"}}]}`, manager: ptr(mgr)},
		{name: "manager.value", body: `{"Operations":[{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value","value":"` + mgr + `"}]}`, manager: ptr(mgr)},
		{name: "remove manager", body: `{"Operations":[{"op":"Remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager"}]}`, manager: ptr("")},
		{name: "path-less okta", body: `{"Operations":[{"op":"replace","value":{"active":false,"displayName":"New","name":{"givenName":"N","familyName":"W"}}}]}`, active: ptr(false), display: "New"},
		{name: "path-less enterprise", body: `{"Operations":[{"op":"add","value":{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":"` + mgr + `","department":"X"}}}]}`, manager: ptr(mgr)},
		{name: "entra unstored attrs ignored", body: `{"Operations":[{"op":"Add","path":"title","value":"Eng"},{"op":"Replace","path":"name.givenName","value":"A"},{"op":"Replace","path":"emails[type eq \"work\"].value","value":"a@example.com"},{"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"R&D"},{"op":"Remove","path":"phoneNumbers[type eq \"work\"].value"}]}`},
		{name: "name.formatted", body: `{"Operations":[{"op":"replace","path":"name.formatted","value":"Formatted"}]}`, display: "Formatted"},
		{name: "same userName ok", body: `{"Operations":[{"op":"replace","path":"userName","value":"A@Example.com"}]}`},
		{name: "remove userName", body: `{"Operations":[{"op":"remove","path":"userName"}]}`, scimType: scimMutability},
		{name: "remove externalId", body: `{"Operations":[{"op":"remove","path":"externalId"}]}`, scimType: scimMutability},
		{name: "unknown op", body: `{"Operations":[{"op":"move","path":"active","value":true}]}`, scimType: scimInvalidSyntax},
		{name: "remove without path", body: `{"Operations":[{"op":"remove"}]}`, scimType: scimInvalidPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyPatch(old, ops(t, tc.body))
			if tc.scimType != "" {
				if scimTypeOf(err) != tc.scimType {
					t.Fatalf("want scimType %s, got err %v", tc.scimType, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (tc.active == nil) != (got.Active == nil) || (tc.active != nil && *tc.active != *got.Active) {
				t.Errorf("active: want %v got %v", deref(tc.active), deref(got.Active))
			}
			if tc.display != "" && (got.Name == nil || *got.Name != tc.display) {
				t.Errorf("name: want %q got %v", tc.display, deref(got.Name))
			}
			if tc.display == "" && got.Name != nil {
				t.Errorf("name: unexpected %q", *got.Name)
			}
			if (tc.manager == nil) != (got.Manager == nil) || (tc.manager != nil && *tc.manager != *got.Manager) {
				t.Errorf("manager: want %v got %v", deref(tc.manager), deref(got.Manager))
			}
		})
	}
}

func TestApplyPatchIdentity(t *testing.T) {
	old := provisioning.User{Email: "a@example.com", External: "ext-1", Aliases: []provisioning.Email{{Value: "old@example.com", Type: "other"}, {Value: "home@example.com", Type: "home"}}}
	cases := []struct {
		name, body    string
		email, extern string
		aliases       []string // nil = aliases untouched
	}{
		{name: "rename keeps old primary out", body: `{"Operations":[{"op":"Replace","path":"userName","value":"B@example.com"}]}`, email: "B@example.com", aliases: []string{"old@example.com", "home@example.com"}},
		{name: "rename to alias", body: `{"Operations":[{"op":"replace","path":"userName","value":"old@example.com"}]}`, email: "old@example.com", aliases: []string{"home@example.com"}},
		{name: "path-less rename", body: `{"Operations":[{"op":"replace","value":{"userName":"c@example.com","externalId":"ext-2"}}]}`, email: "c@example.com", extern: "ext-2", aliases: []string{"old@example.com", "home@example.com"}},
		{name: "externalId same is no-op", body: `{"Operations":[{"op":"replace","path":"externalId","value":"ext-1"}]}`},
		{name: "replace emails", body: `{"Operations":[{"op":"replace","path":"emails","value":[{"value":"a@example.com","primary":true},{"value":"x@example.com","type":"work"}]}]}`, aliases: []string{"x@example.com"}},
		{name: "add emails merges", body: `{"Operations":[{"op":"add","path":"emails","value":[{"value":"x@example.com"}]}]}`, aliases: []string{"old@example.com", "home@example.com", "x@example.com"}},
		{name: "remove emails", body: `{"Operations":[{"op":"remove","path":"emails"}]}`, aliases: []string{}},
		{name: "remove by value filter", body: `{"Operations":[{"op":"remove","path":"emails[value eq \"old@example.com\"]"}]}`, aliases: []string{"home@example.com"}},
		{name: "replace by type filter", body: `{"Operations":[{"op":"replace","path":"emails[type eq \"home\"].value","value":"h2@example.com"}]}`, aliases: []string{"old@example.com", "h2@example.com"}},
		{name: "entra work email is primary noop", body: `{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"a@example.com"}]}`, aliases: []string{"old@example.com", "home@example.com"}},
		{name: "primary filter renames", body: `{"Operations":[{"op":"replace","path":"emails[primary eq true].value","value":"p@example.com"}]}`, email: "p@example.com", aliases: []string{"old@example.com", "home@example.com"}},
		{name: "unsupported email filter ignored", body: `{"Operations":[{"op":"replace","path":"emails[type eq \"work\" and primary eq true].value","value":"z@example.com"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyPatch(old, ops(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if tc.email != "" != (got.Email != nil) || (got.Email != nil && *got.Email != tc.email) {
				t.Errorf("email: want %q got %v", tc.email, deref(got.Email))
			}
			if tc.extern != "" != (got.External != nil) || (got.External != nil && *got.External != tc.extern) {
				t.Errorf("externalId: want %q got %v", tc.extern, deref(got.External))
			}
			if tc.aliases == nil {
				if got.Aliases != nil {
					t.Errorf("aliases: unexpected %v", *got.Aliases)
				}
				return
			}
			if got.Aliases == nil {
				t.Fatalf("aliases: want %v got nil", tc.aliases)
			}
			values := []string{}
			for _, a := range *got.Aliases {
				values = append(values, a.Value)
			}
			if strings.Join(values, ",") != strings.Join(tc.aliases, ",") {
				t.Errorf("aliases: want %v got %v", tc.aliases, values)
			}
		})
	}
}

func TestParseFilter(t *testing.T) {
	cases := []struct {
		raw, field, value string
		ok                bool
	}{
		{`userName eq "a@example.com"`, "userName", "a@example.com", true},
		{`username EQ "a@example.com"`, "userName", "a@example.com", true},
		{`externalId eq "ext \"quoted\""`, "externalId", `ext "quoted"`, true},
		{`emails.value eq "a@example.com"`, "emails.value", "a@example.com", true},
		{`emails eq "a@example.com"`, "emails.value", "a@example.com", true},
		{`id eq "x"`, "id", "x", true},
		{`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a@example.com"`, "userName", "a@example.com", true},
		{`displayName eq "A"`, "", "", false},
		{`userName sw "a"`, "", "", false},
		{`userName eq "a" and active eq true`, "", "", false},
		{`userName eq a`, "", "", false},
	}
	for _, tc := range cases {
		field, value, err := parseFilter(tc.raw)
		if !tc.ok {
			if scimTypeOf(err) != scimInvalidFilter {
				t.Errorf("%s: want invalidFilter, got %v", tc.raw, err)
			}
			continue
		}
		if err != nil || field != tc.field || value != tc.value {
			t.Errorf("%s: got (%q,%q,%v)", tc.raw, field, value, err)
		}
	}
}

func TestFilterClamped(t *testing.T) {
	got := provisioning.Filter{Start: 0, Count: 500}.Clamped()
	if got.Start != 1 || got.Count != provisioning.MaxResults {
		t.Fatalf("clamp high: %+v", got)
	}
	got = provisioning.Filter{Start: -3, Count: -1}.Clamped()
	if got.Start != 1 || got.Count != 0 {
		t.Fatalf("clamp low: %+v", got)
	}
}

func ptr[T any](v T) *T { return &v }
func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}
