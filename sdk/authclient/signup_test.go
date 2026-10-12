package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignupWaitlist(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body = nil
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if body["waitlist_token"] == nil {
			w.Write([]byte(`{"challenge_id":"c0","status":"waitlisted","message":"listed","expires_in":600}`))
			return
		}
		w.Write([]byte(`{"challenge_id":"c1","status":"code_sent","message":"sent","expires_in":600}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	got, err := c.Signup(ctx, SignupRequest{Environment: "e", Email: "a@b.com", Name: "A"})
	if err != nil || got.Status != SignupWaitlisted {
		t.Fatalf("waitlisted = %+v %v", got, err)
	}
	if _, ok := body["waitlist_token"]; ok {
		t.Fatalf("empty waitlist_token sent: %v", body)
	}
	got, err = c.Signup(ctx, SignupRequest{Environment: "e", Email: "a@b.com", Name: "A", WaitlistToken: "tok"})
	if err != nil || got.Status != SignupCodeSent || body["waitlist_token"] != "tok" {
		t.Fatalf("approved = %+v %v %v", got, err, body)
	}
}
