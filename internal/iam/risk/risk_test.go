package risk

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestValidDevice(t *testing.T) {
	for id, want := range map[string]bool{
		"":                                 false,
		"short":                            false,
		strings.Repeat("a", 16):            true,
		strings.Repeat("a", MaxDeviceID):   true,
		strings.Repeat("a", MaxDeviceID+1): false,
		"has space in the device id":       false,
		"tab\tinside-the-device-id-123":    false,
		"unicode-é-in-the-device-id-1234":  false,
		"0123456789abcdef0123456789abcdef": true,
	} {
		if got := ValidDevice(id); got != want {
			t.Errorf("ValidDevice(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestResolve(t *testing.T) {
	ask := Decision{Action: ActionChallenge}
	for _, c := range []struct {
		name                       string
		d                          Decision
		mfa, proof, verified       bool
		wantAction, wantSatisfied  string
		wantChallenge, wantBlocked bool
	}{
		{"asks", ask, false, false, true, ActionChallenge, "", true, false},
		{"mfa satisfies", ask, true, false, true, ActionChallenge, "mfa", false, false},
		{"email proof satisfies", ask, false, true, true, ActionChallenge, "email_proof", false, false},
		{"unverifiable goes on", ask, false, false, false, ActionChallenge, "unverifiable", false, false},
		{"unverifiable blocks", Decision{Action: ActionChallenge, BlockIfUnverifiable: true}, false, false, false, ActionBlock, "", false, true},
		{"mfa beats block_if_unverifiable", Decision{Action: ActionChallenge, BlockIfUnverifiable: true}, true, false, false, ActionChallenge, "mfa", false, false},
		{"log untouched", Decision{Action: ActionLog}, false, false, false, ActionLog, "", false, false},
		{"block untouched", Decision{Action: ActionBlock}, true, true, true, ActionBlock, "", false, true},
	} {
		got := c.d.Resolve(c.mfa, c.proof, c.verified)
		if got.Action != c.wantAction || got.SatisfiedBy != c.wantSatisfied || got.Challenge() != c.wantChallenge || got.Block() != c.wantBlocked {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

func TestStrongerOrdersActions(t *testing.T) {
	order := []string{ActionNone, ActionLog, ActionNotify, ActionChallenge, ActionBlock}
	for i, a := range order {
		for j, b := range order {
			want := order[max(i, j)]
			if got := Stronger(a, b); got != want {
				t.Errorf("Stronger(%s, %s) = %s, want %s", a, b, got, want)
			}
		}
	}
}

func TestDefaultPolicyIsInactive(t *testing.T) {
	p := DefaultPolicy(identity.EnvironmentID{})
	if p.Active() {
		t.Fatal("the default policy must do nothing")
	}
	for _, d := range Detections {
		if p.Action(d) != ActionOff {
			t.Errorf("%s defaults to %s", d, p.Action(d))
		}
	}
	saved := PolicyInput{Actions: map[string]string{NewDevice: ActionNotify}}.Policy(identity.EnvironmentID{})
	if !saved.Active() || saved.Action(NewDevice) != ActionNotify || saved.Action(IPVelocity) != ActionOff || saved.Thresholds != DefaultThresholds() {
		t.Fatalf("saved = %+v", saved)
	}
}

func TestPolicyInputValidate(t *testing.T) {
	ok := []PolicyInput{{}, {Actions: map[string]string{IPVelocity: ActionBlock, NewDevice: ActionChallenge, StaleAccount: ActionNotify}}, {Thresholds: &Thresholds{StaleAfterDays: 7}}}
	for _, in := range ok {
		if err := in.Validate(); err != nil {
			t.Errorf("%+v: %v", in, err)
		}
	}
	bad := []PolicyInput{
		{Actions: map[string]string{"nope": ActionLog}},
		{Actions: map[string]string{NewDevice: ActionBlock}},
		{Actions: map[string]string{IPVelocity: ActionNotify}},
		{Thresholds: &Thresholds{IPFailuresPerHour: -1}},
		{Thresholds: &Thresholds{UserFailuresPerHour: 1001}},
		{Thresholds: &Thresholds{StaleAfterDays: 6}},
		{Thresholds: &Thresholds{TravelSpeedKmh: 99}},
	}
	for _, in := range bad {
		if err := in.Validate(); err == nil {
			t.Errorf("%+v validated", in)
		}
	}
}

func TestRestrictions(t *testing.T) {
	norm := func(kind, value string) NewRestriction {
		return NewRestriction{Kind: kind, Value: value, Action: Deny}.Normalize()
	}
	if got := norm(RestrictIP, "203.0.113.9").Value; got != "203.0.113.9/32" {
		t.Errorf("bare address = %s", got)
	}
	if got := norm(RestrictIP, "203.0.113.9/24").Value; got != "203.0.113.0/24" {
		t.Errorf("masked = %s", got)
	}
	if got := norm(RestrictCountry, "pe").Value; got != "PE" {
		t.Errorf("country = %s", got)
	}
	if got := norm(RestrictEmailDomain, "@Example.COM").Value; got != "example.com" {
		t.Errorf("domain = %s", got)
	}
	// An IPv4-mapped prefix is stored as its IPv4 prefix (clients are unmapped).
	if got := norm(RestrictIP, "::ffff:203.0.113.0/120").Value; got != "203.0.113.0/24" {
		t.Errorf("mapped prefix = %s", got)
	}
	for _, in := range []NewRestriction{norm(RestrictIP, "nope"), norm(RestrictCountry, "PER"), norm(RestrictEmailDomain, "a b"), norm("bogus", "x"), {Kind: RestrictIP, Value: "10.0.0.0/8", Action: "maybe"}} {
		if in.Validate() == nil {
			t.Errorf("%+v validated", in)
		}
	}
	rules := []Restriction{
		{Kind: RestrictIP, Value: "203.0.113.0/24", Action: Allow},
		{Kind: RestrictCountry, Value: "RU", Action: Deny},
		{Kind: RestrictEmailDomain, Value: "evil.example", Action: Deny},
	}
	for _, c := range []struct {
		s               Subject
		denied, allowed bool
	}{
		{Subject{IP: "203.0.113.5"}, false, true},
		{Subject{IP: "198.51.100.1", Country: "ru"}, true, false},
		{Subject{IP: "203.0.113.5", Country: "RU"}, true, false}, // a deny wins over an allow
		{Subject{IP: "198.51.100.1", Email: "Eve@Sub.Evil.Example"}, true, false},
		{Subject{IP: "198.51.100.1", Email: "eve@notevil.example"}, false, false},
		{Subject{IP: "198.51.100.1", Email: `"a@good.example"@evil.example`}, true, false}, // the domain follows the last @
		{Subject{IP: "198.51.100.1", Email: "eve@evil.example."}, true, false},
		{Subject{IP: "::ffff:203.0.113.5"}, false, true},
		{Subject{}, false, false},
	} {
		denied, allowed, _ := Decide(rules, c.s)
		if denied != c.denied || allowed != c.allowed {
			t.Errorf("%+v: denied=%v allowed=%v", c.s, denied, allowed)
		}
	}
}

func TestTraveled(t *testing.T) {
	lat := func(v float64) *float64 { return &v }
	now := time.Now()
	lima := Last{At: now.Add(-time.Hour), Latitude: -12.04, Longitude: -77.03}
	madrid := Location{Latitude: lat(40.42), Longitude: lat(-3.70)}
	if !Traveled(lima, madrid, now, 1000, 100) {
		t.Error("Lima to Madrid in an hour is impossible")
	}
	if Traveled(Last{At: now.Add(-24 * time.Hour), Latitude: -12.04, Longitude: -77.03}, madrid, now, 1000, 100) {
		t.Error("Lima to Madrid in a day is possible")
	}
	if Traveled(lima, Location{Latitude: lat(-12.1), Longitude: lat(-77.0)}, now, 1000, 100) {
		t.Error("a few kilometres is never impossible")
	}
	if Traveled(lima, Location{Country: "ES"}, now, 1000, 100) {
		t.Error("an unlocated address cannot travel")
	}
}

func TestRequestContext(t *testing.T) {
	ctx := WithRequest(context.Background(), Request{Surface: SurfaceHeadless, Device: "short"})
	if got := RequestFrom(ctx); got.Device != "" || got.Surface != SurfaceHeadless {
		t.Errorf("invalid device kept: %+v", got)
	}
	id := strings.Repeat("d", 32)
	if got := RequestFrom(WithRequest(context.Background(), Request{Surface: SurfaceHosted, Device: id})); got.Device != id {
		t.Errorf("valid device dropped: %+v", got)
	}
	if got := RequestFrom(context.Background()); got != (Request{Surface: SurfaceHeadless}) {
		t.Errorf("empty context = %+v", got)
	}
}
