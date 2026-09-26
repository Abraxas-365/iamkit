package provhttp

import (
	"sort"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func ids(list []identity.UserID) []string {
	out := make([]string, 0, len(list))
	for _, id := range list {
		out = append(out, id.String())
	}
	sort.Strings(out)
	return out
}

func sameIDs(got []identity.UserID, want ...string) bool {
	g := ids(got)
	sort.Strings(want)
	if len(g) != len(want) {
		return false
	}
	for i := range g {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

func TestApplyGroupPatch(t *testing.T) {
	const a = "11111111-1111-1111-1111-111111111111"
	const b = "22222222-2222-2222-2222-222222222222"
	const c = "33333333-3333-3333-3333-333333333333"
	cases := []struct {
		name    string
		body    string
		display string
		members *[]string // nil = no replace-set
		add     []string
		remove  []string
		err     string // expected scimType
	}{
		{name: "entra add members",
			body: `{"Operations":[{"op":"Add","path":"members","value":[{"value":"` + a + `"},{"value":"` + b + `"}]}]}`,
			add:  []string{a, b}},
		{name: "entra remove member by filter",
			body:   `{"Operations":[{"op":"Remove","path":"members[value eq \"` + a + `\"]"}]}`,
			remove: []string{a}},
		{name: "remove members with value list",
			body:   `{"Operations":[{"op":"remove","path":"members","value":[{"value":"` + a + `"}]}]}`,
			remove: []string{a}},
		{name: "entra replace displayName",
			body:    `{"Operations":[{"op":"Replace","path":"displayName","value":"Engineering"}]}`,
			display: "Engineering"},
		{name: "okta path-less replace",
			body:    `{"Operations":[{"op":"replace","value":{"id":"x","displayName":"Ops","members":[{"value":"` + c + `"}]}}]}`,
			display: "Ops", members: &[]string{c}},
		{name: "remove all members",
			body:    `{"Operations":[{"op":"remove","path":"members"}]}`,
			members: &[]string{}},
		{name: "replace then add folds into replace-set",
			body:    `{"Operations":[{"op":"replace","path":"members","value":[{"value":"` + a + `"}]},{"op":"add","path":"members","value":[{"value":"` + b + `"}]}]}`,
			members: &[]string{a, b}},
		{name: "add then remove cancels",
			body:   `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + a + `"}]},{"op":"remove","path":"members[value eq \"` + a + `\"]"}]}`,
			remove: []string{a}},
		{name: "schema-qualified path",
			body: `{"Operations":[{"op":"add","path":"urn:ietf:params:scim:schemas:core:2.0:Group:members","value":[{"value":"` + a + `"}]}]}`,
			add:  []string{a}},
		{name: "unknown attribute ignored",
			body: `{"Operations":[{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:custom:2.0:Group:foo","value":"x"}]}`},
		{name: "bad member id",
			body: `{"Operations":[{"op":"add","path":"members","value":[{"value":"nope"}]}]}`, err: "invalidValue"},
		{name: "unsupported member filter",
			body: `{"Operations":[{"op":"remove","path":"members[display eq \"x\"]"}]}`, err: "invalidPath"},
		{name: "displayName cannot be removed",
			body: `{"Operations":[{"op":"remove","path":"displayName"}]}`, err: "mutability"},
		{name: "bad op",
			body: `{"Operations":[{"op":"move","path":"members"}]}`, err: "invalidSyntax"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := applyGroupPatch(ops(t, tc.body))
			if tc.err != "" {
				if scimTypeOf(err) != tc.err {
					t.Fatalf("err = %v (%s), want %s", err, scimTypeOf(err), tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.display != "" && (u.Name == nil || *u.Name != tc.display) {
				t.Errorf("name = %v", u.Name)
			}
			if (tc.members == nil) != (u.Members == nil) {
				t.Fatalf("members = %v, want %v", u.Members, tc.members)
			}
			if tc.members != nil && !sameIDs(*u.Members, *tc.members...) {
				t.Errorf("members = %v, want %v", ids(*u.Members), *tc.members)
			}
			if !sameIDs(u.Add, tc.add...) {
				t.Errorf("add = %v, want %v", ids(u.Add), tc.add)
			}
			if !sameIDs(u.Remove, tc.remove...) {
				t.Errorf("remove = %v, want %v", ids(u.Remove), tc.remove)
			}
		})
	}
}

func TestParseGroupFilter(t *testing.T) {
	for raw, want := range map[string]string{
		`displayName eq "Eng"`: "displayName",
		`externalId eq "x"`:    "externalId",
		`id eq "x"`:            "id",
		`urn:ietf:params:scim:schemas:core:2.0:Group:displayName eq "Eng"`: "displayName",
	} {
		field, _, err := parseGroupFilter(raw)
		if err != nil || field != want {
			t.Errorf("%s: %q %v", raw, field, err)
		}
	}
	if _, _, err := parseGroupFilter(`members eq "x"`); scimTypeOf(err) != "invalidFilter" {
		t.Errorf("members filter: %v", err)
	}
}
