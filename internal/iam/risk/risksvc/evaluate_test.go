package risksvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakePolicies struct {
	policy       *risk.Policy
	restrictions []risk.Restriction
	err          error
}

func (f *fakePolicies) Policy(_ context.Context, e identity.EnvironmentID) (risk.Policy, error) {
	if f.err != nil {
		return risk.Policy{}, f.err
	}
	if f.policy == nil {
		return risk.Policy{}, errx.NotFound("no policy")
	}
	return *f.policy, nil
}
func (f *fakePolicies) SavePolicy(context.Context, risk.Mutation, risk.Policy) error { return nil }
func (f *fakePolicies) DeletePolicy(context.Context, risk.Mutation) error            { return nil }
func (f *fakePolicies) Restrictions(_ context.Context, _ identity.EnvironmentID, filter risk.RestrictionFilter) ([]risk.Restriction, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []risk.Restriction
	for _, r := range f.restrictions {
		if filter.Action == "" || r.Action == filter.Action {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakePolicies) CreateRestriction(context.Context, risk.Mutation, risk.Restriction) error {
	return nil
}
func (f *fakePolicies) DeleteRestriction(context.Context, risk.Mutation, identity.RestrictionID) error {
	return nil
}

type fakeAttempts struct {
	recorded []risk.Attempt
	loginH   [][]byte
	counts   risk.Counts
	known    bool
	last     *risk.Last
	signedIn *time.Time
	alerts   []risk.Attempt
	err      error
}

func (f *fakeAttempts) Record(_ context.Context, a risk.Attempt, l, _ []byte) error {
	if f.err != nil {
		return f.err
	}
	f.recorded = append(f.recorded, a)
	f.loginH = append(f.loginH, l)
	return nil
}
func (f *fakeAttempts) Attempts(_ context.Context, _ identity.EnvironmentID, _ risk.AttemptFilter) ([]risk.Attempt, error) {
	return f.alerts, f.err
}
func (f *fakeAttempts) Attempt(context.Context, identity.EnvironmentID, identity.SignInAttemptID) (risk.Attempt, error) {
	return risk.Attempt{}, nil
}
func (f *fakeAttempts) Devices(context.Context, identity.EnvironmentID, identity.UserID) ([]risk.Device, error) {
	return nil, nil
}
func (f *fakeAttempts) Counts(context.Context, identity.EnvironmentID, []byte, string, time.Time) (risk.Counts, error) {
	return f.counts, f.err
}
func (f *fakeAttempts) KnownDevice(context.Context, identity.EnvironmentID, identity.UserID, []byte) (bool, error) {
	return f.known, f.err
}
func (f *fakeAttempts) LastLocated(context.Context, identity.EnvironmentID, identity.UserID) (risk.Last, bool, error) {
	if f.last == nil {
		return risk.Last{}, false, f.err
	}
	return *f.last, true, f.err
}
func (f *fakeAttempts) LastSignedIn(context.Context, identity.EnvironmentID, identity.UserID) (*time.Time, error) {
	return f.signedIn, f.err
}
func (f *fakeAttempts) Prune(context.Context, time.Time) (int, error) { return 0, nil }

type fakeGeo struct{ loc risk.Location }

func (g fakeGeo) Locate(string, string) (risk.Location, bool) { return g.loc, g.loc.Country != "" }
func (g fakeGeo) Status() risk.GeoStatus                      { return risk.GeoStatus{} }

type fakeNotifier struct{ alerts []risk.Alert }

func (n *fakeNotifier) Alert(_ context.Context, a risk.Alert) error {
	n.alerts = append(n.alerts, a)
	return nil
}

type fakeFeatures struct{ on bool }

func (f fakeFeatures) Enabled(context.Context, identity.EnvironmentID, string) (bool, error) {
	return f.on, nil
}

type rig struct {
	policies *fakePolicies
	attempts *fakeAttempts
	notifier *fakeNotifier
	svc      *Service
	env      identity.EnvironmentID
	user     identity.UserID
	now      time.Time
}

func newRig(geo risk.Geo) *rig {
	r := &rig{policies: &fakePolicies{}, attempts: &fakeAttempts{}, notifier: &fakeNotifier{}, env: identity.NewEnvironmentID(), user: identity.NewUserID(),
		now: time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)}
	r.svc = New(Deps{Policies: r.policies, Attempts: r.attempts, Notifier: r.notifier, Geo: geo, Keys: HashKeys{}})
	r.svc.SetClock(func() time.Time { return r.now })
	return r
}

func (r *rig) policy(actions map[string]string) {
	p := risk.DefaultPolicy(r.env)
	for k, v := range actions {
		p.Actions[k] = v
	}
	r.policies.policy = &p
}

func (r *rig) signal() risk.Signal {
	return risk.Signal{Environment: r.env, User: r.user, Login: "Ana@Example.com", Method: "password"}
}

func ctxWith(ip, device string) context.Context {
	ctx := identity.WithClientInfo(context.Background(), identity.ClientInfo{IP: ip, UserAgent: "ua"})
	return risk.WithRequest(ctx, risk.Request{Device: device})
}

const device = "0123456789abcdef0123456789abcdef"

func TestNoPolicyDoesNothing(t *testing.T) {
	r := newRig(nil)
	d := r.svc.Assess(ctxWith("1.2.3.4", device), r.signal())
	if d.Action != risk.ActionNone || len(d.Detections) != 0 {
		t.Fatalf("default policy must detect nothing: %+v", d)
	}
	if err := r.svc.Screen(ctxWith("1.2.3.4", device), r.signal()); err != nil {
		t.Fatal(err)
	}
}

func TestFlagOffSkipsEverything(t *testing.T) {
	r := newRig(nil)
	r.svc = New(Deps{Policies: r.policies, Attempts: r.attempts, Features: fakeFeatures{on: false}, Keys: HashKeys{}})
	r.policies.restrictions = []risk.Restriction{{Kind: "ip", Value: "1.2.3.0/24", Action: risk.Deny}}
	ctx := ctxWith("1.2.3.4", device)
	if err := r.svc.Screen(ctx, r.signal()); err != nil {
		t.Fatalf("flag off must not screen: %v", err)
	}
	d := r.svc.Assess(ctx, r.signal())
	if !d.Off {
		t.Fatalf("flag off: decision must be Off: %+v", d)
	}
	r.svc.Record(ctx, r.signal(), risk.OutcomeSuccess, d)
	if len(r.attempts.recorded) != 0 {
		t.Fatal("flag off must write no attempt rows")
	}
}

func TestDenyRestrictionBlocksAndRecords(t *testing.T) {
	r := newRig(nil)
	r.policies.restrictions = []risk.Restriction{{Kind: "ip", Value: "1.2.3.0/24", Action: risk.Deny}}
	err := r.svc.Screen(ctxWith("1.2.3.4", ""), r.signal())
	var e *errx.Error
	if !errors.As(err, &e) || e.Code != "SIGN_IN_BLOCKED" {
		t.Fatalf("want SIGN_IN_BLOCKED, got %v", err)
	}
	if len(r.attempts.recorded) != 1 || r.attempts.recorded[0].Outcome != risk.OutcomeBlocked || r.attempts.recorded[0].Reason != risk.ReasonRestriction {
		t.Fatalf("blocked attempt not recorded: %+v", r.attempts.recorded)
	}
	// Another address passes.
	if err := r.svc.Screen(ctxWith("9.9.9.9", ""), r.signal()); err != nil {
		t.Fatal(err)
	}
}

func TestDenyEmailDomainAndCountry(t *testing.T) {
	r := newRig(fakeGeo{loc: risk.Location{Country: "KP"}})
	r.policies.restrictions = []risk.Restriction{{Kind: "email_domain", Value: "bad.test", Action: risk.Deny}, {Kind: "country", Value: "KP", Action: risk.Deny}}
	if err := r.svc.Screen(ctxWith("5.5.5.5", ""), r.signal()); err == nil {
		t.Fatal("country deny must block")
	}
	r2 := newRig(nil)
	r2.policies.restrictions = r.policies.restrictions
	s := r2.signal()
	s.Login = "x@bad.test"
	s.Method = risk.MethodSignup
	if err := r2.svc.Screen(ctxWith("5.5.5.5", ""), s); err == nil {
		t.Fatal("email domain deny must block a signup")
	}
}

// An email domain deny also holds for the account behind a username,
// passkey or code sign-in: Assess checks the account's own address.
func TestAssessDeniesAccountEmailDomain(t *testing.T) {
	r := newRig(nil)
	r.policies.restrictions = []risk.Restriction{{Kind: "email_domain", Value: "bad.test", Action: risk.Deny}}
	s := r.signal()
	s.Login, s.Email = "ana", "ana@bad.test"
	d := r.svc.Assess(ctxWith("5.5.5.5", ""), s)
	if !d.Block() || !d.Restricted {
		t.Fatalf("account email deny must block: %+v", d)
	}
	r.svc.Record(ctxWith("5.5.5.5", ""), s, risk.OutcomeBlocked, d)
	if n := len(r.attempts.recorded); n != 1 || r.attempts.recorded[0].Reason != risk.ReasonRestriction {
		t.Fatalf("blocked attempt must have reason restriction: %+v", r.attempts.recorded)
	}
	s.Email = "ana@good.test"
	if d := r.svc.Assess(ctxWith("5.5.5.5", ""), s); d.Block() {
		t.Fatalf("other domain blocked: %+v", d)
	}
}

func TestAllowSkipsDetections(t *testing.T) {
	r := newRig(nil)
	r.policy(map[string]string{risk.NewDevice: risk.ActionBlock})
	r.policies.policy.Actions[risk.NewDevice] = risk.ActionLog
	r.policies.restrictions = []risk.Restriction{{Kind: "ip", Value: "1.2.3.4/32", Action: risk.Allow}}
	d := r.svc.Assess(ctxWith("1.2.3.4", device), r.signal())
	if !d.Allowed || len(d.Detections) != 0 {
		t.Fatalf("allow must skip detections: %+v", d)
	}
}

func TestIPVelocityBlockAtScreen(t *testing.T) {
	r := newRig(nil)
	r.policy(map[string]string{risk.IPVelocity: risk.ActionBlock})
	r.attempts.counts = risk.Counts{IPFailures1h: 25}
	if err := r.svc.Screen(ctxWith("7.7.7.7", ""), r.signal()); err == nil {
		t.Fatal("ip_velocity block must refuse at Screen")
	}
	r.attempts.counts = risk.Counts{IPFailures1h: 3}
	if err := r.svc.Screen(ctxWith("7.7.7.7", ""), r.signal()); err != nil {
		t.Fatal(err)
	}
}

func TestBruteForceChallenge(t *testing.T) {
	r := newRig(nil)
	r.policy(map[string]string{risk.UserBruteForce: risk.ActionChallenge})
	r.attempts.counts = risk.Counts{UserFailures1h: 10}
	d := r.svc.Assess(ctxWith("7.7.7.7", ""), r.signal())
	if d.Action != risk.ActionChallenge || len(d.Detections) != 1 || d.Detections[0] != risk.UserBruteForce || !d.Challenge() {
		t.Fatalf("want challenge: %+v", d)
	}
	if d.Resolve(true, false, true).Challenge() {
		t.Fatal("MFA satisfies the challenge")
	}
}

func TestNewDeviceOnlyWithDeviceID(t *testing.T) {
	r := newRig(nil)
	r.policy(map[string]string{risk.NewDevice: risk.ActionNotify})
	if d := r.svc.Assess(ctxWith("1.1.1.1", ""), r.signal()); len(d.Detections) != 0 {
		t.Fatalf("no device id: nothing to compare: %+v", d)
	}
	d := r.svc.Assess(ctxWith("1.1.1.1", device), r.signal())
	if len(d.Detections) != 1 || d.Detections[0] != risk.NewDevice || len(d.Notify) != 1 {
		t.Fatalf("new device should notify: %+v", d)
	}
	r.attempts.known = true
	d = r.svc.Assess(ctxWith("1.1.1.1", device), r.signal())
	if len(d.Detections) != 0 || !d.DeviceKnown {
		t.Fatalf("known device: %+v", d)
	}
}

func TestImpossibleTravel(t *testing.T) {
	lat, lon := 51.5, -0.12 // London
	r := newRig(fakeGeo{loc: risk.Location{Country: "GB", Latitude: &lat, Longitude: &lon}})
	r.policy(map[string]string{risk.ImpossibleTravel: risk.ActionLog})
	// Last sign-in in Sydney ten minutes ago.
	r.attempts.last = &risk.Last{At: r.now.Add(-10 * time.Minute), Latitude: -33.87, Longitude: 151.2, Country: "AU"}
	d := r.svc.Assess(ctxWith("8.8.8.8", ""), r.signal())
	if len(d.Detections) != 1 || d.Detections[0] != risk.ImpossibleTravel || d.Country != "GB" {
		t.Fatalf("want impossible_travel: %+v", d)
	}
	// A day earlier is plausible.
	r.attempts.last.At = r.now.Add(-24 * time.Hour)
	if d := r.svc.Assess(ctxWith("8.8.8.8", ""), r.signal()); len(d.Detections) != 0 {
		t.Fatalf("a day apart is fine: %+v", d)
	}
}

func TestStaleAccount(t *testing.T) {
	r := newRig(nil)
	r.policy(map[string]string{risk.StaleAccount: risk.ActionLog})
	old := r.now.Add(-90 * 24 * time.Hour)
	r.attempts.signedIn = &old
	if d := r.svc.Assess(ctxWith("1.1.1.1", ""), r.signal()); len(d.Detections) != 1 {
		t.Fatalf("want stale_account: %+v", d)
	}
	recent := r.now.Add(-time.Hour)
	r.attempts.signedIn = &recent
	if d := r.svc.Assess(ctxWith("1.1.1.1", ""), r.signal()); len(d.Detections) != 0 {
		t.Fatalf("recent: %+v", d)
	}
}

func TestFailOpenOnRepositoryErrors(t *testing.T) {
	r := newRig(nil)
	r.policy(map[string]string{risk.UserBruteForce: risk.ActionBlock})
	r.attempts.err = errors.New("db down")
	d := r.svc.Assess(ctxWith("1.1.1.1", device), r.signal())
	if d.Block() {
		t.Fatal("repository errors must not block")
	}
	r.policies.err = errors.New("db down")
	if err := r.svc.Screen(ctxWith("1.1.1.1", device), r.signal()); err != nil {
		t.Fatalf("screen must fail open: %v", err)
	}
	if d := r.svc.Assess(ctxWith("1.1.1.1", device), r.signal()); d.Block() {
		t.Fatal("policy errors must not block")
	}
	r.svc.Record(ctxWith("1.1.1.1", device), r.signal(), risk.OutcomeSuccess, d) // must not panic
}

func TestRecordHashesLoginAndAlertsOncePerInterval(t *testing.T) {
	r := newRig(nil)
	d := risk.Decision{Action: risk.ActionNotify, Detections: []string{risk.NewDevice}, Notify: []string{risk.NewDevice}}
	r.svc.Record(ctxWith("1.1.1.1", device), r.signal(), risk.OutcomeSuccess, d)
	if len(r.attempts.recorded) != 1 {
		t.Fatalf("recorded %d", len(r.attempts.recorded))
	}
	if h := r.attempts.loginH[0]; len(h) != 32 {
		t.Fatalf("login must be stored hashed: %x", h)
	}
	if len(r.notifier.alerts) != 1 {
		t.Fatalf("alert not sent: %d", len(r.notifier.alerts))
	}
	// Same detection alerted a minute ago: suppressed.
	r.attempts.alerts = []risk.Attempt{{CreatedAt: r.now.Add(-time.Minute)}}
	r.svc.Record(ctxWith("1.1.1.1", device), r.signal(), risk.OutcomeSuccess, d)
	if len(r.notifier.alerts) != 1 {
		t.Fatalf("alert repeated within the interval: %d", len(r.notifier.alerts))
	}
	// Failures never alert.
	r.attempts.alerts = nil
	r.svc.Record(ctxWith("1.1.1.1", device), r.signal(), risk.OutcomeFailure, d)
	if len(r.notifier.alerts) != 1 {
		t.Fatal("failed sign-ins must not alert")
	}
}

func TestHashKeys(t *testing.T) {
	a, b := identity.NewEnvironmentID(), identity.NewEnvironmentID()
	k := HashKeys{Secret: func() string { return "s3" }}
	if string(k.Hash(a, "login", "x")) == string(k.Hash(b, "login", "x")) {
		t.Fatal("environments must not share hashes")
	}
	if string(k.Hash(a, "login", "x")) == string(k.Hash(a, "device", "x")) {
		t.Fatal("purposes must not share hashes")
	}
	if string(k.Hash(a, "login", "x")) != string(k.Hash(a, "login", "x")) {
		t.Fatal("hash must be stable")
	}
	plain := HashKeys{}
	if len(plain.Hash(a, "login", "x")) != 32 || string(plain.Hash(a, "login", "x")) == string(k.Hash(a, "login", "x")) {
		t.Fatal("fallback must be a distinct 32 byte hash")
	}
}
