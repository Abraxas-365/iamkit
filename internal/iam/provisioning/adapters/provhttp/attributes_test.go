package provhttp

import (
	"encoding/json"
	"testing"
)

func TestProject(t *testing.T) {
	user := map[string]any{
		"schemas":            []string{scimUserSchema, scimEnterpriseSchema},
		"id":                 "u1",
		"userName":           "a@example.com",
		"displayName":        "A",
		"name":               map[string]any{"formatted": "A"},
		"emails":             []any{map[string]any{"value": "a@example.com", "type": "work", "primary": true}},
		scimEnterpriseSchema: map[string]any{"manager": map[string]any{"value": "m1"}},
	}
	cases := []struct{ include, exclude, want string }{
		{"", "", ""}, // unchanged
		{"", "displayName,Emails", `{"id":"u1","name":{"formatted":"A"},"schemas":["` + scimUserSchema + `","` + scimEnterpriseSchema + `"],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":"m1"}},"userName":"a@example.com"}`},
		{"", "id,schemas," + scimEnterpriseSchema + ",emails.type,name,userName,displayName", `{"emails":[{"primary":true,"value":"a@example.com"}],"id":"u1","schemas":["` + scimUserSchema + `"]}`},
		{"userName", "", `{"id":"u1","schemas":["` + scimUserSchema + `"],"userName":"a@example.com"}`},
		{scimUserSchema + ":DISPLAYNAME, emails.value", "", `{"displayName":"A","emails":[{"value":"a@example.com"}],"id":"u1","schemas":["` + scimUserSchema + `"]}`},
		{scimEnterpriseSchema + ":manager", "", `{"id":"u1","schemas":["` + scimUserSchema + `","` + scimEnterpriseSchema + `"],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":"m1"}}}`},
		{"userName", "userName", `{"id":"u1","schemas":["` + scimUserSchema + `"],"userName":"a@example.com"}`}, // attributes wins
		{"nickName", "", `{"id":"u1","schemas":["` + scimUserSchema + `"]}`},
	}
	for _, tc := range cases {
		got := project(tc.include, tc.exclude, scimUserSchema, user)
		raw, _ := json.Marshal(got)
		want := tc.want
		if want == "" {
			b, _ := json.Marshal(user)
			want = string(b)
		}
		if string(raw) != want {
			t.Errorf("attributes=%q excluded=%q:\n got %s\nwant %s", tc.include, tc.exclude, raw, want)
		}
	}
}
