package oauth

import (
	"testing"
	"time"
)

func TestRetryAfter(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute}
	for i, w := range want {
		got, ok := RetryAfter(i + 1)
		if !ok || got != w {
			t.Fatalf("attempt %d = %v %v, want %v", i+1, got, ok, w)
		}
	}
	if _, ok := RetryAfter(LogoutMaxAttempts); ok {
		t.Fatal("the last attempt must give up")
	}
}

func TestBackchannelValidation(t *testing.T) {
	for _, ok := range []string{"", "https://app.example/logout", "https://app.example:8443/bc?x=1"} {
		if err := ValidateBackchannelURI(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://app.example/logout", "/logout", "https://u:p@app.example/", "https://app.example/#f"} {
		if ValidateBackchannelURI(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	uri := "ftp://x"
	if (ClientUpdate{BackchannelLogoutURI: &uri}).Validate() == nil {
		t.Error("update accepted a bad URI")
	}
	off, on := "", true
	if err := (ClientUpdate{BackchannelLogoutURI: &off}).Validate(); err != nil {
		t.Errorf("clearing the URI: %v", err)
	}
	if err := (ClientUpdate{BackchannelLogoutSessionRequired: &on}).Validate(); err != nil {
		t.Errorf("session_required alone: %v", err)
	}
	if (LogoutFilter{Status: "sent"}).Validate() == nil {
		t.Error("unknown status accepted")
	}
}
