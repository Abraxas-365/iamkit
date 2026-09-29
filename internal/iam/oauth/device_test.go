package oauth

import (
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestGrantTypes(t *testing.T) {
	cases := []struct {
		grants []string
		hosted bool
		ok     bool
	}{
		{[]string{GrantAuthorizationCode}, false, true},
		{[]string{GrantAuthorizationCode, GrantRefreshToken}, false, true},
		{[]string{GrantDeviceCode}, true, true},
		{[]string{GrantDeviceCode, GrantRefreshToken, GrantAuthorizationCode}, true, true},
		{[]string{GrantDeviceCode}, false, false},
		{[]string{GrantRefreshToken}, false, false},
		{[]string{}, false, false},
		{[]string{"client_credentials"}, false, false},
		{[]string{GrantAuthorizationCode, GrantAuthorizationCode}, false, false},
	}
	for _, c := range cases {
		if err := ValidateGrantTypes(c.grants, c.hosted); (err == nil) != c.ok {
			t.Errorf("%v hosted=%v: %v", c.grants, c.hosted, err)
		}
	}
	// A device-only client needs no redirect URIs; a code client does.
	base := Registration{Application: identity.NewApplicationID(), Resource: identity.NewResourceID(), Public: true, HostedLogin: true}
	device := base
	device.GrantTypes = []string{GrantDeviceCode, GrantRefreshToken}
	if err := device.Validate(); err != nil {
		t.Fatalf("device-only client: %v", err)
	}
	if err := base.Validate(); err == nil {
		t.Fatal("default grants accepted without redirect URIs")
	}
	empty := base
	empty.GrantTypes = []string{}
	empty.Redirects = []string{"https://app.example/cb"}
	if err := empty.Validate(); err == nil {
		t.Fatal("empty grant_types accepted")
	}
	grants := []string{GrantDeviceCode}
	if err := (ClientUpdate{GrantTypes: &grants}).Validate(); err != nil {
		t.Fatalf("grant update: %v", err)
	}
	if !(&Client{GrantTypes: DefaultGrantTypes}).Allows(GrantRefreshToken) || (&Client{GrantTypes: DefaultGrantTypes}).Allows(GrantDeviceCode) {
		t.Fatal("Allows")
	}
}

func TestUserCode(t *testing.T) {
	for raw, want := range map[string]string{"bcdf-ghjk": "BCDFGHJK", " BCDF GHJK ": "BCDFGHJK", "BCDFGHJK": "BCDFGHJK", "BCDF-GHJ": "", "ABCD-EFGH": "", "BCDF-GHJK-L": "", "": ""} {
		if got := NormalizeUserCode(raw); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", raw, got, want)
		}
	}
	if FormatUserCode("BCDFGHJK") != "BCDF-GHJK" {
		t.Fatal("FormatUserCode")
	}
	if ValidateDeviceScope("openid offline_access") != nil || ValidateDeviceScope("openid admin") == nil {
		t.Fatal("ValidateDeviceScope")
	}
}

func code(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestDevicePoll(t *testing.T) {
	now := time.Now()
	pending := Device{Status: DevicePending, Interval: 5, Expires: now.Add(time.Minute)}

	next, err := pending.Poll(now)
	if code(err) != DeviceAuthorizationPending || next.LastPoll == nil || next.Interval != 5 {
		t.Fatalf("first poll: %v %+v", err, next)
	}
	// Polling again before the interval slows the device down.
	next, err = next.Poll(now.Add(2 * time.Second))
	if code(err) != DeviceSlowDownError || next.Interval != 10 {
		t.Fatalf("fast poll: %v %+v", err, next)
	}
	next, err = next.Poll(now.Add(13 * time.Second))
	if code(err) != DeviceAuthorizationPending || next.Interval != 10 {
		t.Fatalf("patient poll: %v %+v", err, next)
	}

	approved := pending
	approved.Status = DeviceApproved
	next, err = approved.Poll(now)
	if err != nil || next.Status != DeviceConsumed {
		t.Fatalf("approved: %v %+v", err, next)
	}
	if _, err = next.Poll(now); code(err) != DeviceInvalidGrant {
		t.Fatalf("consumed: %v", err)
	}
	denied := pending
	denied.Status = DeviceDenied
	if _, err = denied.Poll(now); code(err) != DeviceAccessDenied {
		t.Fatalf("denied: %v", err)
	}
	if _, err = approved.Poll(now.Add(2 * time.Minute)); code(err) != DeviceExpiredToken {
		t.Fatalf("expired: %v", err)
	}
}
