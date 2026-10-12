package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWaitlist(t *testing.T) {
	var seen []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /management/v1/environments/env/waitlist":
			w.Write([]byte(`{"items":[{"id":"w1","email":"a@example.com","status":"pending"}],"page":{"total":1,"limit":20,"offset":0}}`))
		case "POST /management/v1/environments/env/waitlist/approve":
			if body["all_pending"] != true {
				t.Errorf("approve body = %v", body)
			}
			w.Write([]byte(`{"approved":3,"skipped":1,"more":true}`))
		case "POST /management/v1/environments/env/waitlist/w1/reject":
			if body["notify"] != true {
				t.Errorf("reject body = %v", body)
			}
			w.Write([]byte(`{"id":"w1","status":"rejected"}`))
		case "DELETE /management/v1/environments/env/waitlist/w1":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Write([]byte(`{"id":"w1","status":"approved"}`))
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "ik_mgmt_test").Environment("env")
	ctx := context.Background()
	list, err := env.WaitlistEntries(ctx, WaitlistFilter{Status: WaitlistStatusPending, Email: "a@"}, Page{Limit: 5})
	if err != nil || len(list.Items) != 1 || list.Items[0].Email != "a@example.com" || list.Page.Total != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if got, err := env.ApproveWaitlistEntry(ctx, "w1"); err != nil || got.Status != WaitlistStatusApproved {
		t.Fatalf("approve = %+v %v", got, err)
	}
	if out, err := env.ApproveWaitlist(ctx, WaitlistApproval{AllPending: true}); err != nil || out.Approved != 3 || !out.More {
		t.Fatalf("bulk = %+v %v", out, err)
	}
	if got, err := env.RejectWaitlistEntry(ctx, "w1", true); err != nil || got.Status != WaitlistStatusRejected {
		t.Fatalf("reject = %+v %v", got, err)
	}
	if err := env.DeleteWaitlistEntry(ctx, "w1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.WaitlistEntry(ctx, "../x"); err == nil {
		t.Fatal("unsafe id accepted")
	}
	if seen[0] != "GET /management/v1/environments/env/waitlist?email=a%40&limit=5&status=pending" {
		t.Fatalf("seen = %v", seen)
	}
}
