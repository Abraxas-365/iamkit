package event

import (
	"testing"
	"time"
)

func TestDeliveryRetryAfter(t *testing.T) {
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base, ceiling, window := 15*time.Second, time.Hour, 24*time.Hour
	for _, c := range []struct {
		attempts int
		want     time.Duration
	}{{1, 15 * time.Second}, {2, 30 * time.Second}, {3, time.Minute}, {9, time.Hour}, {40, time.Hour}} {
		if got, ok := DeliveryRetryAfter(c.attempts, first, first, base, ceiling, window); !ok || got != c.want {
			t.Errorf("attempt %d: %v %v, want %v", c.attempts, got, ok, c.want)
		}
	}
	if _, ok := DeliveryRetryAfter(20, first, first.Add(23*time.Hour+30*time.Minute), base, ceiling, window); ok {
		t.Error("a retry past the window must be given up")
	}
}

func TestValidEndpoint(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://hooks.example.com/iam": true,
		"http://localhost:8080/hook":    true,
		"http://127.0.0.1/hook":         true,
		"http://hooks.example.com":      false,
		"https://user:pw@example.com":   false,
		"https://example.com/#frag":     false,
		"ftp://example.com":             false,
		"not a url":                     false,
	} {
		if err := ValidEndpoint(raw); (err == nil) != ok {
			t.Errorf("%q: err = %v", raw, err)
		}
	}
}

func TestSubscriptionValidate(t *testing.T) {
	ok := SubscriptionCreate{Name: "CRM", URL: "https://x.example", Types: []string{"user.created", "membership.*"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.Types = []string{"User Created"}
	if bad.Validate() == nil {
		t.Fatal("bad type accepted")
	}
	bad = ok
	bad.Name = " "
	if bad.Validate() == nil {
		t.Fatal("empty name accepted")
	}
}

func TestClassifyWebhookActions(t *testing.T) {
	c, ok := Classify(ActionWebhookRotate, "0b3c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11")
	if !ok || c.Type != WebhookSecretRotated || c.Subject.Kind != "webhook" || c.Subject.ID != "0b3c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11" {
		t.Fatalf("classified %+v %v", c, ok)
	}
}

func TestClassifySignInTexts(t *testing.T) {
	const env = "/management/v1/environments/0b3c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11"
	for _, tc := range []struct {
		method, path, typ, kind, id string
	}{
		{"PUT", env + "/login-settings/texts/es", SignInTextsUpdated, "environment", ""},
		{"DELETE", env + "/login-settings/clients/7f0c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11/texts/en", SignInTextsDeleted, "oauth_client", "7f0c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11"},
		{"PUT", env + "/login-settings/organizations/9a0c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11/texts/en", SignInTextsUpdated, "organization", "9a0c8a6e-6a0e-4c43-9d55-0d2d9b2b8a11"},
	} {
		c, ok := Classify(tc.method, tc.path)
		if !ok || c.Type != tc.typ || c.Subject.Kind != tc.kind || c.Subject.ID != tc.id || c.Data["locale_id"] == nil {
			t.Errorf("%s %s: %+v %v", tc.method, tc.path, c, ok)
		}
	}
}
