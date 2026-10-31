package event

import (
	"testing"
	"time"
)

func seconds(d time.Duration) *int64 { v := int64(d.Seconds()); return &v }

var ceilings = Ceilings{Security: 365 * 24 * time.Hour, Default: 90 * 24 * time.Hour}

func TestRetentionClassOf(t *testing.T) {
	for typ, want := range map[string]string{
		"session.created":               ClassSecurity,
		"session.revoked":               ClassSecurity,
		"sign_in.blocked":               ClassSecurity,
		"login.failed":                  ClassSecurity,
		"risk.detected":                 ClassSecurity,
		"api_key.revoked":               ClassSecurity,
		"oauth_consent.granted":         ClassSecurity,
		"oauth_client.approved":         ClassSecurity,
		"mfa.enrolled":                  ClassSecurity,
		"saml.assertion_issued":         ClassSecurity,
		"signing_key.created":           ClassSecurity,
		"user.locked":                   ClassSecurity,
		"user.password_changed":         ClassSecurity,
		"user.sessions_revoked":         ClassSecurity,
		"user.password_change_required": ClassSecurity,
		"user.created":                  ClassDefault,
		"user.updated":                  ClassDefault,
		"organization.created":          ClassDefault,
		"webhook.created":               ClassDefault,
		"event_retention.updated":       ClassDefault,
		"saml_service_provider.created": ClassDefault,
		"api_key_policy.updated":        ClassDefault,
	} {
		if got := RetentionClassOf(typ); got != want {
			t.Errorf("RetentionClassOf(%s) = %s, want %s", typ, got, want)
		}
	}
}

func TestEffectiveClampsToTheCeiling(t *testing.T) {
	cases := []struct {
		name   string
		policy RetentionPolicy
		class  string
		want   time.Duration
	}{
		{"no override keeps the ceiling", RetentionPolicy{}, ClassSecurity, ceilings.Security},
		{"override shortens", RetentionPolicy{SecuritySeconds: seconds(30 * 24 * time.Hour)}, ClassSecurity, 30 * 24 * time.Hour},
		{"classes are independent", RetentionPolicy{SecuritySeconds: seconds(24 * time.Hour)}, ClassDefault, ceilings.Default},
		{"an override above a lowered ceiling is clamped", RetentionPolicy{DefaultSeconds: seconds(200 * 24 * time.Hour)}, ClassDefault, ceilings.Default},
	}
	for _, c := range cases {
		if got := c.policy.Effective(ceilings, c.class); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRetentionPolicyValidate(t *testing.T) {
	ok := []RetentionPolicy{
		{},
		{SecuritySeconds: seconds(24 * time.Hour)},
		{SecuritySeconds: seconds(ceilings.Security), DefaultSeconds: seconds(ceilings.Default)},
	}
	for _, p := range ok {
		if err := p.Validate(ceilings); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []RetentionPolicy{
		{SecuritySeconds: seconds(time.Hour)},
		{DefaultSeconds: seconds(0)},
		{DefaultSeconds: seconds(ceilings.Default + time.Second)},
		{SecuritySeconds: seconds(ceilings.Security + 24*time.Hour)},
		{SecuritySeconds: seconds(-time.Hour)},
	}
	for _, p := range bad {
		err := p.Validate(ceilings)
		if err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestDescribe(t *testing.T) {
	r := RetentionPolicy{DefaultSeconds: seconds(48 * time.Hour)}.Describe(ceilings)
	if r.SecuritySeconds != nil || *r.DefaultSeconds != 48*3600 {
		t.Fatalf("overrides = %+v", r)
	}
	if r.Effective.Default != 48*3600 || r.Effective.Security != int64(ceilings.Security.Seconds()) {
		t.Fatalf("effective = %+v", r)
	}
	if r.Ceilings.Default != int64(ceilings.Default.Seconds()) || r.Ceilings.Security != int64(ceilings.Security.Seconds()) {
		t.Fatalf("ceilings = %+v", r)
	}
}
