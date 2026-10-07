package scimclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestGroups(t *testing.T) {
	var calls []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		bodies = append(bodies, body)
		switch {
		case r.Method == "PATCH" || r.Method == "DELETE":
			w.WriteHeader(204)
		case r.URL.Path == "/scim/v2/Groups" && r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"totalResults": 1, "startIndex": 1, "itemsPerPage": 1, "Resources": []Group{{ID: "g1", DisplayName: "Eng"}}})
		default:
			json.NewEncoder(w).Encode(Group{ID: "g1", DisplayName: "Eng", Members: []Member{{Value: "u1"}}})
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "ik_scim_test")
	ctx := context.Background()
	g, err := c.CreateGroup(ctx, Group{DisplayName: "Eng", Members: []Member{{Value: "u1"}}})
	if err != nil || g.ID != "g1" || len(g.Members) != 1 {
		t.Fatalf("create %+v %v", g, err)
	}
	if _, err = c.Group(ctx, "g1", true); err != nil {
		t.Fatal(err)
	}
	list, err := c.Groups(ctx, `displayName eq "Eng"`, 1, 10, false)
	if err != nil || list.TotalResults != 1 || list.Resources[0].ID != "g1" {
		t.Fatalf("list %+v %v", list, err)
	}
	if _, err = c.ReplaceGroup(ctx, "g1", Group{DisplayName: "Eng"}); err != nil {
		t.Fatal(err)
	}
	if err = c.PatchGroup(ctx, "g1", []Operation{{Op: "add", Path: "members", Value: []Member{{Value: "u2"}}}}); err != nil {
		t.Fatal(err)
	}
	if err = c.DeleteGroup(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Group(ctx, "../x", false); err == nil {
		t.Fatal("unsafe path")
	}
	want := []string{
		"POST /scim/v2/Groups",
		"GET /scim/v2/Groups/g1?excludedAttributes=members",
		"GET /scim/v2/Groups?count=10&filter=displayName+eq+%22Eng%22&startIndex=1",
		"PUT /scim/v2/Groups/g1",
		"PATCH /scim/v2/Groups/g1",
		"DELETE /scim/v2/Groups/g1",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls %v", calls)
	}
	if bodies[0]["schemas"].([]any)[0] != groupSchema {
		t.Fatalf("create body %v", bodies[0])
	}
	if bodies[4]["schemas"].([]any)[0] != patchSchema {
		t.Fatalf("patch body %v", bodies[4])
	}
}
