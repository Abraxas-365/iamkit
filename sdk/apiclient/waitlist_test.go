package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWaitlist(t *testing.T) {
	var calls []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/environments/env/waitlist":
			w.Write([]byte(`{"items":[{"id":"w1","status":"pending"}],"page":{"total":1}}`))
		case "POST /api/v1/environments/env/waitlist/approve":
			w.Write([]byte(`{"approved":1,"skipped":0,"more":false}`))
		case "DELETE /api/v1/environments/env/waitlist/w1":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Write([]byte(`{"id":"w1","status":"rejected"}`))
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "tok").Environment("env")
	ctx := context.Background()
	list, err := env.WaitlistEntries(ctx, WaitlistFilter{Status: "pending"}, Page{})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if out, err := env.ApproveWaitlist(ctx, WaitlistApproval{IDs: []string{"w1"}}); err != nil || out.Approved != 1 {
		t.Fatalf("bulk = %+v %v", out, err)
	}
	if got, err := env.RejectWaitlistEntry(ctx, "w1", false); err != nil || got.Status != "rejected" {
		t.Fatalf("reject = %+v %v", got, err)
	}
	if err := env.DeleteWaitlistEntry(ctx, "w1"); err != nil {
		t.Fatal(err)
	}
	if calls[0] != "GET /api/v1/environments/env/waitlist?status=pending" {
		t.Fatalf("calls = %v", calls)
	}
}
