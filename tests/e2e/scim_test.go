package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// scimClient talks to /scim/v2 exactly like a directory: raw headers, raw JSON.
type scimClient struct {
	e          *Env
	header     map[string]string
	connection string
}

type scimResponse struct {
	Status      int
	ContentType string
	Body        string
	JSON        map[string]any
}

func newSCIM(t *testing.T, e *Env) (*scimClient, string) {
	t.Helper()
	cred := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Directory", "organization_id": e.Org}, 201).JSON
	secret := cred["secret"].(string)
	return &scimClient{e: e, header: map[string]string{"Authorization": "Bearer " + secret}, connection: cred["connection_id"].(string)}, secret
}

func (s *scimClient) with(header map[string]string) *scimClient {
	return &scimClient{e: s.e, header: header, connection: s.connection}
}

func (s *scimClient) do(method, path, body string) scimResponse {
	s.e.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	r := httptest.NewRequest(method, "/scim/v2"+path, reader)
	r.Header.Set("Content-Type", "application/scim+json")
	for k, v := range s.header {
		r.Header.Set(k, v)
	}
	res, err := s.e.App.Test(r, 10000)
	if err != nil {
		s.e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := scimResponse{Status: res.StatusCode, ContentType: res.Header.Get("Content-Type"), Body: string(raw)}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

func (s *scimClient) must(method, path, body string, want int) scimResponse {
	s.e.t.Helper()
	res := s.do(method, path, body)
	if res.Status != want {
		s.e.t.Fatalf("%s %s: got %d want %d: %s", method, path, res.Status, want, res.Body)
	}
	return res
}

func (s *scimClient) total(filter string) int {
	s.e.t.Helper()
	path := "/Users"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	n, _ := s.must("GET", path, "", 200).JSON["totalResults"].(float64)
	return int(n)
}

func scimType(r scimResponse) string {
	v, _ := r.JSON["scimType"].(string)
	return v
}

// Authentication: Bearer (RFC 7644 §2) and X-API-Key; conflicting headers and
// non-provisioning credentials are rejected.
func TestSCIMAuthentication(t *testing.T) {
	e := newEnv(t)
	bearer, secret := newSCIM(t, e)

	bearer.must("GET", "/ServiceProviderConfig", "", 200)
	bearer.with(map[string]string{"Authorization": "bearer " + secret}).must("GET", "/Users", "", 200)
	bearer.with(map[string]string{"X-API-Key": secret}).must("GET", "/Users", "", 200)
	bearer.with(map[string]string{"Authorization": "Bearer " + secret, "X-API-Key": secret}).must("GET", "/Users", "", 200)

	_, other := newSCIM(t, e)
	for name, header := range map[string]map[string]string{
		"none":              {},
		"conflicting":       {"Authorization": "Bearer " + secret, "X-API-Key": other},
		"management key":    {"Authorization": "Bearer " + e.Owner},
		"basic":             {"Authorization": "Basic " + secret},
		"garbage bearer":    {"Authorization": "Bearer ik_scim_nope"},
		"empty bearer":      {"Authorization": "Bearer "},
		"management header": {"X-API-Key": e.Owner},
	} {
		if res := bearer.with(header).do("GET", "/Users", ""); res.Status != 401 {
			t.Errorf("%s: got %d want 401", name, res.Status)
		}
	}
}

// Discovery endpoints advertise what the server actually does.
func TestSCIMDiscovery(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	cfg := s.must("GET", "/ServiceProviderConfig", "", 200)
	if !strings.HasPrefix(cfg.ContentType, "application/scim+json") {
		t.Errorf("content type: %s", cfg.ContentType)
	}
	schemes := cfg.JSON["authenticationSchemes"].([]any)
	if schemes[0].(map[string]any)["type"] != "oauthbearertoken" {
		t.Errorf("auth scheme: %v", schemes)
	}
	schemas := s.must("GET", "/Schemas", "", 200).JSON
	if schemas["totalResults"].(float64) != 3 {
		t.Errorf("schemas: %v", schemas)
	}
	user := s.must("GET", "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", 200).JSON
	names := map[string]string{}
	for _, a := range user["attributes"].([]any) {
		attr := a.(map[string]any)
		names[attr["name"].(string)] = attr["mutability"].(string)
	}
	if names["userName"] != "readWrite" || names["externalId"] != "immutable" || names["emails"] == "" || names["active"] != "readWrite" {
		t.Errorf("user schema attributes: %v", names)
	}
	s.must("GET", "/ResourceTypes/User", "", 200)
	s.must("GET", "/ResourceTypes/Group", "", 200)
	s.must("GET", "/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", "", 200)
	if types := s.must("GET", "/ResourceTypes", "", 200).JSON; types["totalResults"].(float64) != 2 {
		t.Errorf("resource types: %v", types)
	}
	if res := s.do("GET", "/Roles", ""); res.Status != 404 || res.JSON["schemas"] == nil {
		t.Errorf("unsupported resource: %d %s", res.Status, res.Body)
	}
}

// Microsoft Entra ID provisioning cycle, replaying its actual payload shapes.
func TestSCIMEntraCycle(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)

	// Entra probes by a random userName filter on "Test Connection".
	if n := s.total(`userName eq "4b5a8c2f-probe@example.com"`); n != 0 {
		t.Fatalf("probe: %d", n)
	}
	// Match-before-create by externalId (objectId).
	if n := s.total(`externalId eq "00aa00aa-bb11-cc22-dd33-44ee44ee44ee"`); n != 0 {
		t.Fatalf("pre-create lookup: %d", n)
	}
	boss := s.must("POST", "/Users", `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
		"externalId":"boss-object-id","userName":"Boss@Contoso.com","active":true,"displayName":"The Boss",
		"emails":[{"primary":true,"type":"work","value":"Boss@Contoso.com"}],
		"meta":{"resourceType":"User"},"name":{"formatted":"The Boss","familyName":"Boss","givenName":"The"},
		"title":"CEO","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Exec","employeeNumber":"1"}
	}`, 201)
	bossID := boss.JSON["id"].(string)
	if loc := boss.JSON["meta"].(map[string]any)["location"].(string); !strings.HasSuffix(loc, "/scim/v2/Users/"+bossID) {
		t.Errorf("meta.location: %s", loc)
	}
	if boss.JSON["userName"] != "boss@contoso.com" {
		t.Errorf("userName normalized: %v", boss.JSON["userName"])
	}

	created := s.must("POST", "/Users", `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
		"externalId":"00aa00aa-bb11-cc22-dd33-44ee44ee44ee","userName":"jdoe@contoso.com","active":"True","displayName":"Jane Doe",
		"emails":[{"primary":true,"type":"work","value":"jdoe@contoso.com"}],
		"name":{"formatted":"Jane Doe","familyName":"Doe","givenName":"Jane"},
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":{"value":"`+bossID+`"}}
	}`, 201)
	id := created.JSON["id"].(string)
	got := s.must("GET", "/Users/"+id, "", 200).JSON
	if created.JSON["displayName"] != got["displayName"] || got["active"] != true || got["externalId"] != "00aa00aa-bb11-cc22-dd33-44ee44ee44ee" {
		t.Errorf("POST/GET mismatch:\n%v\n%v", created.JSON, got)
	}
	if mgr := got["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)["manager"].(map[string]any)["value"]; mgr != bossID {
		t.Errorf("manager: %v", mgr)
	}
	emails := got["emails"].([]any)
	if len(emails) != 1 || emails[0].(map[string]any)["primary"] != true {
		t.Errorf("emails: %v", emails)
	}

	// Duplicate create → 409 uniqueness.
	dup := s.do("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"00aa00aa-bb11-cc22-dd33-44ee44ee44ee","userName":"jdoe@contoso.com"}`)
	if dup.Status != 409 || scimType(dup) != "uniqueness" {
		t.Errorf("duplicate: %d %s", dup.Status, dup.Body)
	}

	// Attribute update PATCH exactly as Entra sends it (capitalised ops,
	// string booleans, value-filter paths, unstored attributes).
	s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"Replace","path":"displayName","value":"Jane Q. Doe"},
		{"op":"Replace","path":"name.givenName","value":"Jane Q."},
		{"op":"Add","path":"title","value":"Engineer"},
		{"op":"Replace","path":"emails[type eq \"work\"].value","value":"jdoe@contoso.com"},
		{"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"R&D"},
		{"op":"Replace","path":"active","value":"True"}
	]}`, 200)
	if got := s.must("GET", "/Users/"+id, "", 200).JSON; got["displayName"] != "Jane Q. Doe" {
		t.Errorf("displayName: %v", got["displayName"])
	}

	// Manager as a bare string (Entra), then removed.
	s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"`+bossID+`"}]}`, 200)
	s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager"}]}`, 200)
	if got := s.must("GET", "/Users/"+id, "", 200).JSON; got["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] != nil {
		t.Errorf("manager not cleared: %v", got)
	}

	// Manager that is not a UUID → 400 invalidValue, not 500.
	bad := s.do("PATCH", "/Users/"+id, `{"Operations":[{"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"not-a-uuid"}]}`)
	if bad.Status != 400 || scimType(bad) != "invalidValue" {
		t.Errorf("bad manager: %d %s", bad.Status, bad.Body)
	}

	// Soft-deprovision (user unassigned) then hard delete.
	s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`, 200)
	if got := s.must("GET", "/Users/"+id, "", 200).JSON; got["active"] != false {
		t.Errorf("deactivate: %v", got["active"])
	}
	s.must("DELETE", "/Users/"+id, "", 204)
}

// Okta-style: path-less replace, PUT full replace, no externalId on create.
func TestSCIMOktaCycle(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	if n := s.total(`userName eq "okta.user@example.com"`); n != 0 {
		t.Fatalf("pre-create: %d", n)
	}
	created := s.must("POST", "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"okta.user@example.com",
		"name":{"givenName":"Okta","familyName":"User"},"emails":[{"primary":true,"value":"okta.user@example.com","type":"work"}],"displayName":"Okta User","locale":"en-US","active":true,"password":"ignored"}`, 201)
	id := created.JSON["id"].(string)
	// No externalId sent: the derived anchor is internal and not echoed back.
	if created.JSON["externalId"] != nil {
		t.Errorf("derived anchor leaked: %v", created.JSON)
	}
	s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`, 200)
	s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":true,"name":{"givenName":"Okta2","familyName":"User"}}}]}`, 200)

	put := s.must("PUT", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"`+id+`","userName":"okta.user@example.com",
		"name":{"givenName":"Renamed","familyName":"Person"},"emails":[{"primary":true,"value":"okta.user@example.com","type":"work"}],"active":true,"groups":[]}`, 200)
	if put.JSON["displayName"] != "Renamed Person" {
		t.Errorf("PUT displayName from name: %v", put.JSON["displayName"])
	}
	// Rename via PUT: the derived anchor survives, the old address is released.
	put = s.must("PUT", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"new@example.com","active":true}`, 200)
	if put.JSON["userName"] != "new@example.com" || put.JSON["id"] != id {
		t.Errorf("PUT rename: %v", put.JSON)
	}
	if n := s.total(`userName eq "okta.user@example.com"`); n != 0 {
		t.Errorf("old address still matches: %d", n)
	}
	// Okta later pushes its own externalId: the derived anchor upgrades once.
	s.must("PATCH", "/Users/"+id, `{"Operations":[{"op":"replace","path":"externalId","value":"00u1okta"}]}`, 200)
	if n := s.total(`externalId eq "00u1okta"`); n != 1 {
		t.Errorf("upgraded anchor: %d", n)
	}
	res := s.do("PATCH", "/Users/"+id, `{"Operations":[{"op":"replace","path":"externalId","value":"00u2other"}]}`)
	if res.Status != 400 || scimType(res) != "mutability" {
		t.Errorf("client anchor change: %d %s", res.Status, res.Body)
	}
}

// Generic RFC 7644 behaviours: filters, pagination, errors, content type.
func TestSCIMProtocol(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	var ids []string
	for _, u := range []string{"a", "b", "c"} {
		ids = append(ids, s.must("POST", "/Users", `{"userName":"`+u+`@example.com","externalId":"ext-`+u+`"}`, 201).JSON["id"].(string))
	}

	for filter, want := range map[string]int{
		`userName eq "A@example.com"`:     1,
		`USERNAME EQ "a@example.com"`:     1,
		`emails.value eq "b@example.com"`: 1,
		`externalId eq "ext-c"`:           1,
		`externalId eq "EXT-C"`:           0, // caseExact
		`id eq "` + ids[0] + `"`:          1,
		`id eq "not-a-uuid"`:              0,
	} {
		if got := s.total(filter); got != want {
			t.Errorf("filter %s: got %d want %d", filter, got, want)
		}
	}
	for _, filter := range []string{`displayName eq "x"`, `userName co "a"`, `userName eq "a" or userName eq "b"`} {
		res := s.do("GET", "/Users?filter="+url.QueryEscape(filter), "")
		if res.Status != 400 || scimType(res) != "invalidFilter" {
			t.Errorf("filter %s: %d %s", filter, res.Status, res.Body)
		}
	}

	// Pagination: out-of-range values are clamped, not rejected.
	page := s.must("GET", "/Users?startIndex=0&count=2", "", 200).JSON
	if page["startIndex"].(float64) != 1 || page["itemsPerPage"].(float64) != 2 || page["totalResults"].(float64) != 3 {
		t.Errorf("page: %v", page)
	}
	page = s.must("GET", "/Users?startIndex=3&count=1000", "", 200).JSON
	if page["itemsPerPage"].(float64) != 1 || page["totalResults"].(float64) != 3 {
		t.Errorf("page 2: %v", page)
	}
	page = s.must("GET", "/Users?count=0", "", 200).JSON
	if page["itemsPerPage"].(float64) != 0 || page["totalResults"].(float64) != 3 {
		t.Errorf("count=0: %v", page)
	}

	// totalResults agrees with rows when an operator removes the membership.
	e.Must("DELETE", e.Base+"/organizations/"+e.Org+"/members/"+ids[2], e.Owner, nil, 204)
	if page = s.must("GET", "/Users", "", 200).JSON; page["totalResults"].(float64) != float64(len(page["Resources"].([]any))) {
		t.Errorf("total/rows mismatch: %v", page)
	}

	// Errors: SCIM error schema, content type, scimType.
	res := s.do("PATCH", "/Users/"+ids[0], `{"Operations":[{"op":"move","path":"active","value":true}]}`)
	if res.Status != 400 || scimType(res) != "invalidSyntax" || !strings.HasPrefix(res.ContentType, "application/scim+json") {
		t.Errorf("bad op: %d %s %s", res.Status, res.ContentType, res.Body)
	}
	if res = s.do("POST", "/Users", `{not json`); res.Status != 400 || scimType(res) != "invalidSyntax" {
		t.Errorf("bad json: %d %s", res.Status, res.Body)
	}
	if res = s.do("GET", "/Users/"+ids[0][:8], ""); res.Status != 404 || res.JSON["status"] != "404" {
		t.Errorf("not found: %d %s", res.Status, res.Body)
	}
	if res = s.do("POST", "/Users", `{"userName":"bad-manager@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":"nope"}}`); res.Status != 400 || scimType(res) != "invalidValue" {
		t.Errorf("create bad manager: %d %s", res.Status, res.Body)
	}
}

// Entra renames a user's UPN/mail: the identity (id, externalId) survives, the
// user logs in with the new address and the old one is kept as an alias only
// if the directory lists it.
func TestSCIMRenameAndAliases(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	id := s.must("POST", "/Users", `{"userName":"jane@contoso.com","externalId":"obj-jane","displayName":"Jane",
		"emails":[{"value":"jane@contoso.com","primary":true,"type":"work"},{"value":"j.doe@contoso.com","type":"other"}]}`, 201).JSON["id"].(string)
	got := s.must("GET", "/Users/"+id, "", 200).JSON
	if emails := got["emails"].([]any); len(emails) != 2 {
		t.Fatalf("aliases on create: %v", emails)
	}
	if n := s.total(`emails.value eq "J.Doe@contoso.com"`); n != 1 {
		t.Errorf("alias filter: %d", n)
	}
	if n := s.total(`userName eq "j.doe@contoso.com"`); n != 0 {
		t.Errorf("alias must not match userName: %d", n)
	}

	// Entra rename: userName + work email in one PATCH.
	renamed := s.must("PATCH", "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
		{"op":"Replace","path":"userName","value":"jane.smith@contoso.com"},
		{"op":"Replace","path":"emails[type eq \"work\"].value","value":"jane.smith@contoso.com"}]}`, 200).JSON
	if renamed["userName"] != "jane.smith@contoso.com" || renamed["externalId"] != "obj-jane" || renamed["id"] != id {
		t.Fatalf("rename: %v", renamed)
	}
	if n := s.total(`externalId eq "obj-jane"`); n != 1 {
		t.Errorf("anchor lookup after rename: %d", n)
	}
	// The management API sees the new primary address.
	user := e.Must("GET", e.Base+"/users/"+id, e.Owner, nil, 200).JSON
	if user["email"] != "jane.smith@contoso.com" {
		t.Errorf("users.email: %v", user["email"])
	}

	// PUT replaces the alias set.
	put := s.must("PUT", "/Users/"+id, `{"userName":"jane.smith@contoso.com","externalId":"obj-jane","displayName":"Jane Smith",
		"emails":[{"value":"jane.smith@contoso.com","primary":true},{"value":"jane@contoso.com","type":"other"}]}`, 200).JSON
	values := []string{}
	for _, raw := range put["emails"].([]any) {
		values = append(values, raw.(map[string]any)["value"].(string))
	}
	if strings.Join(values, ",") != "jane.smith@contoso.com,jane@contoso.com" {
		t.Errorf("PUT aliases: %v", values)
	}

	// Rename to another user's userName → 409 uniqueness.
	other := s.must("POST", "/Users", `{"userName":"bob@contoso.com","externalId":"obj-bob"}`, 201).JSON["id"].(string)
	res := s.do("PATCH", "/Users/"+other, `{"Operations":[{"op":"replace","path":"userName","value":"jane.smith@contoso.com"}]}`)
	if res.Status != 409 || scimType(res) != "uniqueness" {
		t.Errorf("rename onto another user: %d %s", res.Status, res.Body)
	}
	// Aliases are informational and never reserve an address.
	s.must("PATCH", "/Users/"+other, `{"Operations":[{"op":"add","path":"emails","value":[{"value":"shared-mailbox@contoso.com"}]}]}`, 200)
	s.must("PATCH", "/Users/"+id, `{"Operations":[{"op":"add","path":"emails","value":[{"value":"shared-mailbox@contoso.com"}]}]}`, 200)
	if n := s.total(`emails.value eq "shared-mailbox@contoso.com"`); n != 2 {
		t.Errorf("shared alias: %d", n)
	}
	res = s.do("PATCH", "/Users/"+other, `{"Operations":[{"op":"replace","path":"userName","value":"not an email"}]}`)
	if res.Status != 400 || scimType(res) != "invalidValue" {
		t.Errorf("invalid userName: %d %s", res.Status, res.Body)
	}

	// A user shared with another organization cannot be renamed by this directory.
	org2 := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Other"})
	e.Join(org2, other)
	res = s.do("PATCH", "/Users/"+other, `{"Operations":[{"op":"replace","path":"userName","value":"robert@contoso.com"}]}`)
	if res.Status != 400 || scimType(res) != "mutability" {
		t.Errorf("rename shared user: %d %s", res.Status, res.Body)
	}
}

// SCIM DELETE deprovisions: 404 afterwards, hidden from lists, no longer a
// member; re-creating the same externalId reactivates the same user.
func TestSCIMDeleteAndReactivate(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	boss := s.must("POST", "/Users", `{"userName":"boss@contoso.com","externalId":"obj-boss"}`, 201).JSON["id"].(string)
	id := s.must("POST", "/Users", `{"userName":"leaver@contoso.com","externalId":"obj-leaver","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":"`+boss+`"}}`, 201).JSON["id"].(string)

	s.must("DELETE", "/Users/"+boss, "", 204)
	s.must("GET", "/Users/"+boss, "", 404)
	s.must("PATCH", "/Users/"+boss, `{"Operations":[{"op":"replace","path":"active","value":true}]}`, 404)
	s.must("DELETE", "/Users/"+boss, "", 404)
	if n := s.total(`externalId eq "obj-boss"`); n != 0 {
		t.Errorf("deleted user listed: %d", n)
	}
	if got := s.must("GET", "/Users/"+id, "", 200).JSON; got["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] != nil {
		t.Errorf("reports still point to deleted manager: %v", got)
	}
	// A deprovisioned user cannot be referenced as manager.
	res := s.do("PATCH", "/Users/"+id, `{"Operations":[{"op":"add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"`+boss+`"}]}`)
	if res.Status != 400 {
		t.Errorf("deleted manager: %d %s", res.Status, res.Body)
	}

	// Re-assignment in the directory: same externalId → same user, active again.
	back := s.must("POST", "/Users", `{"userName":"boss@contoso.com","externalId":"obj-boss","displayName":"Boss Again","active":true}`, 201).JSON
	if back["id"] != boss || back["active"] != true || back["displayName"] != "Boss Again" {
		t.Errorf("reactivate: %v", back)
	}

	// A different directory object at a reused address is a different person:
	// it must not inherit the deprovisioned user (409, explicit linking).
	s.must("DELETE", "/Users/"+boss, "", 204)
	if res := s.do("POST", "/Users", `{"userName":"boss@contoso.com","externalId":"obj-boss-2"}`); res.Status != 409 {
		t.Errorf("reused address with new anchor: %d %s", res.Status, res.Body)
	}
	// An operator can re-link it explicitly under the new anchor.
	e.Must("POST", e.Base+"/provisioned-identities", e.Owner, fiber.Map{"connection_id": s.connection, "user_id": boss, "external_id": "obj-boss-2"}, 204)
	if got := s.must("GET", "/Users/"+boss, "", 200).JSON; got["externalId"] != "obj-boss-2" {
		t.Errorf("re-link: %v", got)
	}

	// Derived anchors reactivate by userName.
	derived := s.must("POST", "/Users", `{"userName":"noanchor@contoso.com"}`, 201).JSON["id"].(string)
	s.must("DELETE", "/Users/"+derived, "", 204)
	if again := s.must("POST", "/Users", `{"userName":"noanchor@contoso.com"}`, 201).JSON; again["id"] != derived {
		t.Errorf("derived reactivation: %v", again["id"])
	}
}

// Existing organization members: 409 by default (explicit link required),
// adopted automatically when the connection opts in.
func TestSCIMAdoptExistingMembers(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	res := s.do("POST", "/Users", `{"userName":"`+e.AliceEmail+`","externalId":"obj-alice"}`)
	if res.Status != 409 || scimType(res) != "uniqueness" {
		t.Fatalf("default adoption: %d %s", res.Status, res.Body)
	}

	cred := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Adopting", "organization_id": e.Org, "adopt_existing_members": true}, 201).JSON
	adopting := s.with(map[string]string{"Authorization": "Bearer " + cred["secret"].(string)})
	got := adopting.must("POST", "/Users", `{"userName":"`+strings.ToUpper(e.AliceEmail)+`","externalId":"obj-alice","displayName":"Alice (directory)"}`, 201).JSON
	if got["id"] != e.Alice || got["externalId"] != "obj-alice" {
		t.Fatalf("adopted: %v", got)
	}
	// Alice keeps her password and application access.
	e.Login(e.AliceEmail)
	// Her login email is not the directory's to change: it did not create her.
	if res := adopting.do("PATCH", "/Users/"+e.Alice, `{"Operations":[{"op":"replace","path":"userName","value":"alice.renamed@example.com"}]}`); res.Status != 400 || scimType(res) != "mutability" {
		t.Errorf("rename adopted user: %d %s", res.Status, res.Body)
	}
	e.Login(e.AliceEmail)
	// Adoption never crosses the organization boundary.
	outsider := e.User("Outsider", "outsider@example.com")
	res = adopting.do("POST", "/Users", `{"userName":"outsider@example.com"}`)
	if res.Status != 409 {
		t.Errorf("non-member adopted: %d %s (%s)", res.Status, res.Body, outsider)
	}
	list := e.Must("GET", e.Base+"/provisioning-credentials", e.Owner, nil, 200)
	var views []map[string]any
	if err := json.Unmarshal([]byte(list.Body), &views); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range views {
		if v["connection_id"] == cred["connection_id"] && v["adopt_existing_members"] == true {
			found = true
		}
	}
	if !found {
		t.Errorf("adopt flag not listed: %s", list.Body)
	}
}

// meta carries timestamps; lastModified moves on update.
func TestSCIMMetaTimestamps(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	created := s.must("POST", "/Users", `{"userName":"meta@example.com","externalId":"meta"}`, 201).JSON
	meta := created["meta"].(map[string]any)
	if meta["created"] == nil || meta["lastModified"] == nil {
		t.Fatalf("meta: %v", meta)
	}
	if _, err := time.Parse(time.RFC3339, meta["created"].(string)); err != nil {
		t.Errorf("created format: %v", meta["created"])
	}
}

// Review regressions: tenant boundaries of aliases, access removal on DELETE.
func TestSCIMBoundaries(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	// Another organization's directory.
	org2 := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Org B"})
	cred := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "B", "organization_id": org2}, 201).JSON
	b := s.with(map[string]string{"Authorization": "Bearer " + cred["secret"].(string)})

	// Directory A cannot squat an address: aliases do not block B or the
	// management API, and A cannot probe B's users through alias conflicts.
	a1 := s.must("POST", "/Users", `{"userName":"a1@a.com","externalId":"a1","emails":[{"value":"ceo@b.com"}]}`, 201).JSON["id"].(string)
	b.must("POST", "/Users", `{"userName":"ceo@b.com","externalId":"b-ceo"}`, 201)
	e.User("Squat", "squat@b.com")
	s.must("PATCH", "/Users/"+a1, `{"Operations":[{"op":"add","path":"emails","value":[{"value":"squat@b.com"}]}]}`, 200)
	// B does not see A's aliases for a shared user.
	shared := e.User("Shared", "shared@x.com")
	e.Join(e.Org, shared)
	e.Join(org2, shared)
	e.Must("POST", e.Base+"/provisioned-identities", e.Owner, fiber.Map{"connection_id": s.connection, "user_id": shared, "external_id": "a-shared"}, 204)
	e.Must("POST", e.Base+"/provisioned-identities", e.Owner, fiber.Map{"connection_id": cred["connection_id"], "user_id": shared, "external_id": "b-shared"}, 204)
	s.must("PUT", "/Users/"+shared, `{"userName":"shared@x.com","externalId":"a-shared","emails":[{"value":"shared@x.com","primary":true},{"value":"a-alias@x.com"}]}`, 200)
	b.must("PUT", "/Users/"+shared, `{"userName":"shared@x.com","externalId":"b-shared","emails":[{"value":"shared@x.com","primary":true},{"value":"b-alias@x.com"}]}`, 200)
	for client, want := range map[*scimClient]string{s: "a-alias@x.com", b: "b-alias@x.com"} {
		emails := client.must("GET", "/Users/"+shared, "", 200).JSON["emails"].([]any)
		if len(emails) != 2 || emails[1].(map[string]any)["value"] != want {
			t.Errorf("alias isolation: %v", emails)
		}
	}

	// DELETE removes the user's access in the organization.
	e.Grant(e.Org, a1, e.Res, "invoices:read")
	s.must("DELETE", "/Users/"+a1, "", 204)
	var grants int
	if err := e.DB.Get(&grants, `SELECT count(*) FROM grants WHERE organization_id=$1 AND user_id=$2`, e.Org, a1); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Errorf("grants survive DELETE: %d", grants)
	}
}

// Concurrent PATCH adds to emails[] must not lose updates.
func TestSCIMConcurrentPatch(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	id := s.must("POST", "/Users", `{"userName":"race@example.com","externalId":"race"}`, 201).JSON["id"].(string)
	const n = 6
	done := make(chan scimResponse, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			done <- s.do("PATCH", "/Users/"+id, fmt.Sprintf(`{"Operations":[{"op":"add","path":"emails","value":[{"value":"alias%d@example.com"}]}]}`, i))
		}(i)
	}
	ok := 0
	for i := 0; i < n; i++ {
		if res := <-done; res.Status == 200 {
			ok++
		} else if res.Status != 409 {
			t.Errorf("patch: %d %s", res.Status, res.Body)
		}
	}
	emails := s.must("GET", "/Users/"+id, "", 200).JSON["emails"].([]any)
	if len(emails)-1 != ok {
		t.Errorf("lost update: %d successful PATCHes, %d aliases", ok, len(emails)-1)
	}
}

// Identities anchored internally (externalId never sent, or an email-valued
// externalId re-keyed by migration 002) are claimed when the directory later
// creates them with an externalId, and operators can re-anchor them.
func TestSCIMClaimDerivedAnchor(t *testing.T) {
	e := newEnv(t)
	s, _ := newSCIM(t, e)
	id := s.must("POST", "/Users", `{"userName":"legacy@example.com"}`, 201).JSON["id"].(string)
	if n := s.total(`externalId eq "legacy@example.com"`); n != 0 {
		t.Fatalf("derived anchor visible: %d", n)
	}
	got := s.must("POST", "/Users", `{"userName":"legacy@example.com","externalId":"legacy@example.com"}`, 201).JSON
	if got["id"] != id || got["externalId"] != "legacy@example.com" {
		t.Fatalf("claim: %v", got)
	}
	// Now a client anchor: a second claim with another value conflicts.
	if res := s.do("POST", "/Users", `{"userName":"legacy@example.com","externalId":"other"}`); res.Status != 409 {
		t.Errorf("claim of client anchor: %d %s", res.Status, res.Body)
	}

	// Operator re-anchors an internally anchored identity.
	other := s.must("POST", "/Users", `{"userName":"legacy2@example.com"}`, 201).JSON["id"].(string)
	e.Must("POST", e.Base+"/provisioned-identities", e.Owner, fiber.Map{"connection_id": s.connection, "user_id": other, "external_id": "obj-legacy2"}, 204)
	if n := s.total(`externalId eq "obj-legacy2"`); n != 1 {
		t.Errorf("operator re-anchor: %d", n)
	}
	// A live directory anchor is not overwritten.
	e.Must("POST", e.Base+"/provisioned-identities", e.Owner, fiber.Map{"connection_id": s.connection, "user_id": other, "external_id": "obj-hijack"}, 409)
}

// The adoption policy can be switched off again when rotating a credential.
func TestSCIMAdoptToggle(t *testing.T) {
	e := newEnv(t)
	cred := e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "On", "organization_id": e.Org, "adopt_existing_members": true}, 201).JSON
	conn := cred["connection_id"].(string)
	adopt := func() bool {
		var on bool
		if err := e.DB.Get(&on, `SELECT adopt_existing_members FROM provisioning_connections WHERE id=$1`, conn); err != nil {
			t.Fatal(err)
		}
		return on
	}
	e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Keep", "organization_id": e.Org, "connection_id": conn}, 201)
	if !adopt() {
		t.Fatal("omitted flag must keep the setting")
	}
	e.Must("POST", e.Base+"/provisioning-credentials", e.Owner, fiber.Map{"name": "Off", "organization_id": e.Org, "connection_id": conn, "adopt_existing_members": false}, 201)
	if adopt() {
		t.Error("explicit false must disable adoption")
	}
	var audited int
	if err := e.DB.Get(&audited, `SELECT count(*) FROM audit_events WHERE target_id LIKE '%adopt_existing_members=false'`); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Errorf("adoption change audit events: %d", audited)
	}
}
