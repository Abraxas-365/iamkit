package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestWaitlistList(t *testing.T) {
	out, _, seen, err := runCLI(t, ok(200, `{"items":[{"id":"w1","email":"a@x.com","status":"pending"}],"page":{"total":1,"limit":20,"offset":0}}`),
		"waitlist", "list", "--status", "pending", "--email", "a@")
	if err != nil || !strings.Contains(out, "a@x.com") {
		t.Fatalf("%v %s", err, out)
	}
	if seen[0].Method != "GET" || seen[0].Path != base+"/waitlist" || seen[0].Query != "email=a%40&status=pending" {
		t.Fatalf("seen = %+v", seen)
	}
}

func TestWaitlistDecisions(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"id":"w1","status":"approved"}`), "waitlist", "approve", "w1")
	if err != nil || seen[0].Method != "POST" || seen[0].Path != base+"/waitlist/w1/approve" {
		t.Fatalf("approve: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"id":"w1","status":"rejected"}`), "waitlist", "reject", "w1", "--notify")
	if err != nil || seen[0].Path != base+"/waitlist/w1/reject" || !reflect.DeepEqual(seen[0].Body, map[string]any{"notify": true}) {
		t.Fatalf("reject: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(204, ``), "waitlist", "delete", "w1")
	if err != nil || seen[0].Method != "DELETE" || seen[0].Path != base+"/waitlist/w1" {
		t.Fatalf("delete: %v %+v", err, seen)
	}
	_, _, seen, err = runCLI(t, ok(200, `{"id":"w1"}`), "waitlist", "get", "w1")
	if err != nil || seen[0].Method != "GET" || seen[0].Path != base+"/waitlist/w1" {
		t.Fatalf("get: %v %+v", err, seen)
	}
}

func TestWaitlistApproveMany(t *testing.T) {
	_, _, seen, err := runCLI(t, ok(200, `{"approved":2,"skipped":0,"more":false}`), "waitlist", "approve", "a", "b")
	if err != nil || seen[0].Path != base+"/waitlist/approve" || !reflect.DeepEqual(seen[0].Body, map[string]any{"ids": []any{"a", "b"}}) {
		t.Fatalf("ids: %v %+v", err, seen)
	}
	// --all-pending repeats while more remain.
	calls := 0
	handler := func(r seenRequest) (int, string) {
		calls++
		if calls < 3 {
			return 200, `{"approved":500,"skipped":0,"more":true}`
		}
		return 200, `{"approved":7,"skipped":1,"more":false}`
	}
	_, _, seen, err = runCLI(t, handler, "waitlist", "approve", "--all-pending")
	if err != nil || len(seen) != 3 || !reflect.DeepEqual(seen[0].Body, map[string]any{"all_pending": true}) {
		t.Fatalf("all: %v %+v", err, seen)
	}
	for _, args := range [][]string{{"waitlist", "approve"}, {"waitlist", "approve", "a", "--all-pending"}} {
		_, _, seen, err = runCLI(t, ok(200, `{}`), args...)
		if err == nil || len(seen) != 0 {
			t.Fatalf("%v: err = %v, requests = %d", args, err, len(seen))
		}
	}
}

func TestSignInPolicyWaitlistFlags(t *testing.T) {
	handler := func(r seenRequest) (int, string) {
		return 200, `{"allow_signup":true,"signup_organization_id":"o","custom":true,"updated_at":"x"}`
	}
	_, _, seen, err := runCLI(t, handler, "sign-in-policy", "set", "--waitlist", "--waitlist-auto-approve-domains", "a.com,b.com", "--waitlist-signup-url", "https://app.example.com/signup")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"allow_signup": true, "signup_organization_id": "o", "waitlist": true, "waitlist_auto_approve_domains": []any{"a.com", "b.com"}, "waitlist_signup_url": "https://app.example.com/signup"}
	if len(seen) != 2 || seen[1].Method != "PUT" || !reflect.DeepEqual(seen[1].Body, want) {
		t.Fatalf("seen = %+v", seen)
	}
}
