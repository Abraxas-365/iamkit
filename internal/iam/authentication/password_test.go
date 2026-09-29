package authentication

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

func rule(err error) string {
	var e *errx.Error
	if !errors.As(err, &e) || e.Code != CodePasswordPolicy {
		return ""
	}
	r, _ := e.Details["rule"].(string)
	return r
}

func TestPasswordPolicyCheck(t *testing.T) {
	strict := PasswordPolicy{MinLength: 10, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true, LockoutMinutes: 15}
	for password, want := range map[string]string{
		"Short1!":                 RuleLength,
		strings.Repeat("A", 73):   RuleLength,
		"lowercase1!":             RuleUpper,
		"UPPERCASE1!":             RuleLower,
		"NoDigitsHere!":           RuleDigit,
		"NoSymbols123":            RuleSymbol,
		"Spaces Are Not 1 Symbol": RuleSymbol,
		"Val1d-Password":          "",
		"Ünïcode-Pässw0rd":        "",
	} {
		err := strict.Check(password)
		if got := rule(err); got != want || (want == "") != (err == nil) {
			t.Errorf("%q: rule %q (%v), want %q", password, got, err, want)
		}
	}
	if err := DefaultPasswordPolicy().Check("twelve chars"); err != nil {
		t.Errorf("default policy: %v", err)
	}
	var e *errx.Error
	if errors.As(strict.Check("short"), &e); e.Details["min_length"] != 10 || e.HTTPStatus != 400 {
		t.Errorf("details %+v status %d", e.Details, e.HTTPStatus)
	}
}

func TestPasswordPolicyValidate(t *testing.T) {
	ok := DefaultPasswordPolicy()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PasswordPolicy){
		"min_length low":  func(p *PasswordPolicy) { p.MinLength = 7 },
		"min_length high": func(p *PasswordPolicy) { p.MinLength = 73 },
		"max_age":         func(p *PasswordPolicy) { p.MaxAgeDays = -1 },
		"threshold":       func(p *PasswordPolicy) { p.LockoutThreshold = 101 },
		"minutes":         func(p *PasswordPolicy) { p.LockoutMinutes = 0 },
	} {
		p := ok
		mutate(&p)
		if p.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// An organization only tightens: longer minimum, extra classes, the
// shorter non-zero expiry, breach check; zero values change nothing.
func TestPasswordPolicyTighten(t *testing.T) {
	env := PasswordPolicy{MinLength: 12, RequireDigit: true, MaxAgeDays: 90, LockoutThreshold: 5, LockoutMinutes: 15}
	if got := env.Tighten(PasswordRequirements{}); got != env {
		t.Fatalf("empty requirements changed the policy: %+v", got)
	}
	got := env.Tighten(PasswordRequirements{MinLength: 16, RequireSymbol: true, MaxAgeDays: 30, BreachCheck: true})
	want := env
	want.MinLength, want.RequireSymbol, want.MaxAgeDays, want.BreachCheck = 16, true, 30, true
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got = env.Tighten(PasswordRequirements{MinLength: 8, MaxAgeDays: 365}); got.MinLength != 12 || got.MaxAgeDays != 90 {
		t.Fatalf("requirements loosened the policy: %+v", got)
	}
	noExpiry := PasswordPolicy{MinLength: 12}
	if got = noExpiry.Tighten(PasswordRequirements{MaxAgeDays: 60}); got.MaxAgeDays != 60 {
		t.Fatalf("organization expiry ignored: %+v", got)
	}
	for _, bad := range []PasswordRequirements{{MinLength: 7}, {MinLength: 73}, {MaxAgeDays: -1}, {MaxAgeDays: 3651}} {
		if bad.Validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestPasswordExpiry(t *testing.T) {
	now := time.Now()
	p := PasswordPolicy{MaxAgeDays: 90}
	if p.Expired(now.Add(-89*24*time.Hour), now) || !p.Expired(now.Add(-90*24*time.Hour), now) {
		t.Fatal("90-day boundary wrong")
	}
	if (PasswordPolicy{}).Expired(now.Add(-10000*24*time.Hour), now) {
		t.Fatal("max_age_days 0 must never expire")
	}
}

func TestPasswordLockout(t *testing.T) {
	now := time.Now()
	p := PasswordPolicy{LockoutThreshold: 3, LockoutMinutes: 10}
	for failures, want := range map[int]time.Duration{1: 0, 2: 0, 3: 10 * time.Minute, 4: 0, 6: 20 * time.Minute, 9: 40 * time.Minute, 300: 24 * time.Hour} {
		until := p.LockedUntil(failures, now)
		var got time.Duration
		if until != nil {
			got = until.Sub(now)
		}
		if got != want {
			t.Errorf("%d failures: %v, want %v", failures, got, want)
		}
	}
	if (PasswordPolicy{LockoutMinutes: 10}).LockedUntil(1000, now) != nil {
		t.Error("threshold 0 must never lock")
	}
	a := PasswordAccount{LockedUntil: p.LockedUntil(3, now)}
	if !a.Locked(now) || a.Locked(now.Add(11*time.Minute)) {
		t.Error("Locked window wrong")
	}
}
