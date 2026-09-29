package mfasvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfatotp"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// memory is an in-memory mfa.Repository for one user. Begin snapshots the
// state; Rollback without Commit restores it.
type memory struct {
	factor   *mfa.Factor
	recovery map[string]bool // hash -> used
	pending  map[string]*mfa.Pending
	audits   []string
	saved    *memory
	clock    *time.Time
}

func newMemory() *memory {
	now := time.Now()
	return &memory{recovery: map[string]bool{}, pending: map[string]*mfa.Pending{}, clock: &now}
}

func (m *memory) snapshot() *memory {
	c := &memory{recovery: map[string]bool{}, pending: map[string]*mfa.Pending{}, audits: append([]string{}, m.audits...), clock: m.clock}
	if m.factor != nil {
		f := *m.factor
		c.factor = &f
	}
	for k, v := range m.recovery {
		c.recovery[k] = v
	}
	for k, v := range m.pending {
		p := *v
		c.pending[k] = &p
	}
	return c
}

func (m *memory) Begin(context.Context) (mfa.Transaction, error) {
	m.saved = m.snapshot()
	return m, nil
}
func (m *memory) Summary(context.Context, identity.EnvironmentID, identity.UserID) (mfa.Summary, error) {
	out := mfa.Summary{Factors: []mfa.Factor{}}
	if m.factor != nil {
		out.Factors = append(out.Factors, *m.factor)
	}
	for _, used := range m.recovery {
		if !used {
			out.RecoveryCodes++
		}
	}
	return out, nil
}
func (m *memory) Policy(context.Context, authentication.Context, identity.UserID) (mfa.Policy, error) {
	return mfa.Policy{}, nil
}
func (m *memory) Account(context.Context, identity.EnvironmentID, identity.UserID) (mfa.Account, error) {
	return mfa.Account{Email: "alice@example.com", Issuer: "Acme"}, nil
}
func (m *memory) SaveUnconfirmed(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, factor identity.FactorID, sealed string) error {
	if m.factor != nil && m.factor.Active() {
		return errx.Conflict("an authenticator is already enrolled")
	}
	// Its own transaction: survives a rollback of an enclosing one.
	for _, s := range []*memory{m, m.saved} {
		if s != nil {
			s.factor = &mfa.Factor{ID: factor, Kind: mfa.KindTOTP, Secret: sealed, Created: *m.clock}
		}
	}
	return nil
}
func (m *memory) SavePending(_ context.Context, hash []byte, p mfa.Pending) error {
	for _, s := range []*memory{m, m.saved} {
		if s != nil {
			q := p
			s.pending[string(hash)] = &q
		}
	}
	return nil
}
func (m *memory) Factor(context.Context, identity.EnvironmentID, identity.UserID) (mfa.Factor, bool, error) {
	if m.factor == nil {
		return mfa.Factor{}, false, nil
	}
	return *m.factor, true, nil
}
func (m *memory) UseStep(_ context.Context, _ identity.FactorID, step int64) error {
	m.factor.LastStep = step
	return nil
}
func (m *memory) Confirm(_ context.Context, _ identity.FactorID, step int64) error {
	now := time.Now()
	m.factor.Confirmed, m.factor.LastStep = &now, step
	return nil
}
func (m *memory) SetFailures(_ context.Context, _ identity.FactorID, failures int, until *time.Time) error {
	m.factor.Failures, m.factor.LockedUntil = failures, until
	return nil
}
func (m *memory) UseRecovery(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, hash []byte) (bool, error) {
	used, ok := m.recovery[string(hash)]
	if !ok || used {
		return false, nil
	}
	m.recovery[string(hash)] = true
	return true, nil
}
func (m *memory) ReplaceRecovery(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, hashes [][]byte) error {
	m.recovery = map[string]bool{}
	for _, h := range hashes {
		m.recovery[string(h)] = false
	}
	return nil
}
func (m *memory) DeleteFactors(context.Context, identity.EnvironmentID, identity.UserID) (bool, error) {
	removed := m.factor != nil || len(m.recovery) > 0
	m.factor, m.recovery = nil, map[string]bool{}
	return removed, nil
}
func (m *memory) Pending(_ context.Context, hash []byte) (mfa.Pending, error) {
	p, ok := m.pending[string(hash)]
	if !ok {
		return mfa.Pending{}, errx.Unauthorized("sign in again")
	}
	return *p, nil
}
func (m *memory) FailPending(_ context.Context, hash []byte) error {
	m.pending[string(hash)].Attempts++
	return nil
}
func (m *memory) DeletePending(_ context.Context, hash []byte) error {
	delete(m.pending, string(hash))
	return nil
}
func (m *memory) Audit(_ context.Context, mu mfa.Mutation) error {
	m.audits = append(m.audits, mu.Action)
	return nil
}
func (m *memory) Commit() error { m.saved = nil; return nil }
func (m *memory) Rollback() error {
	if m.saved != nil {
		s := m.saved
		m.factor, m.recovery, m.pending, m.audits, m.saved = s.factor, s.recovery, s.pending, s.audits, nil
	}
	return nil
}

// plain is a reversible stand-in for the sealer.
type plain struct{ off bool }

func (p plain) Enabled() bool               { return !p.off }
func (plain) Seal(b []byte) (string, error) { return "sealed:" + string(b), nil }
func (plain) Open(s string) ([]byte, error) { return []byte(s[len("sealed:"):]), nil }

type secrets struct{}

func (s *secrets) Generate(prefix string) (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, s.Hash(raw), nil
}
func (*secrets) Hash(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

var (
	env  = identity.MustParseEnvironmentID("11111111-1111-4111-8111-111111111111")
	user = identity.MustParseUserID("22222222-2222-4222-8222-222222222222")
)

func setup(t *testing.T) (*Service, *memory, *time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	repo := newMemory()
	repo.clock = &now
	return New(repo, mfatotp.TOTP{}, plain{}, &secrets{}, func() time.Time { return now }), repo, &now
}

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return mfatotp.Code(key, at.Unix()/config.TOTPPeriod)
}

func status(err error) int {
	var e *errx.Error
	if errors.As(err, &e) {
		return e.HTTPStatus
	}
	return 0
}

// enroll starts and confirms a factor, returning its secret and recovery codes.
func enroll(t *testing.T, s *Service, now *time.Time) (string, []string) {
	t.Helper()
	ctx := context.Background()
	e, err := s.Start(ctx, env, user)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, code(t, e.Secret, *now))
	if err != nil || len(codes) != config.RecoveryCodes {
		t.Fatalf("confirm = %v %v", codes, err)
	}
	*now = now.Add(config.TOTPPeriod * time.Second)
	return e.Secret, codes
}

func TestEnrollConfirmAndReplay(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	e, err := s.Start(ctx, env, user)
	if err != nil || e.Secret == "" || e.URI == "" || repo.factor.Secret == e.Secret {
		t.Fatalf("start = %+v %v (stored %q)", e, err, repo.factor.Secret)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "000000"); status(err) != 422 {
		t.Fatalf("wrong confirm = %v", err)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "abcd-efgh-2345"); status(err) != 422 {
		t.Fatalf("recovery code cannot confirm: %v", err)
	}
	c := code(t, e.Secret, *now)
	codes, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, c)
	if err != nil || len(codes) != config.RecoveryCodes || !repo.factor.Active() {
		t.Fatalf("confirm = %v %v", codes, err)
	}
	if last := repo.audits[len(repo.audits)-1]; last != mfa.ActionEnrolled {
		t.Fatalf("audit = %v", repo.audits)
	}
	// The confirming code cannot be replayed, and a second enrollment conflicts.
	if _, err := s.Verify(ctx, env, user, c, false); status(err) != 401 {
		t.Fatalf("replayed code = %v", err)
	}
	if _, err := s.Start(ctx, env, user); status(err) != 409 {
		t.Fatalf("second start = %v", err)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, c); status(err) != 422 {
		t.Fatalf("confirm when active = %v", err)
	}
}

func TestStartNeedsCipher(t *testing.T) {
	s := New(newMemory(), mfatotp.TOTP{}, plain{off: true}, &secrets{}, nil)
	if _, err := s.Start(context.Background(), env, user); status(err) != 422 {
		t.Fatalf("start without key = %v", err)
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	s, repo, now := setup(t)
	_, codes := enroll(t, s, now)
	ctx := context.Background()
	for _, c := range codes {
		if len(c) != 14 || c[4] != '-' || c[9] != '-' {
			t.Fatalf("recovery code format %q", c)
		}
	}
	v, err := s.Verify(ctx, env, user, " "+codes[0][:5]+"  "+codes[0][5:]+" ", false)
	if err != nil || v.Proof != mfa.ProofRecovery {
		t.Fatalf("recovery = %+v %v", v, err)
	}
	if _, err := s.Verify(ctx, env, user, codes[0], false); status(err) != 401 {
		t.Fatalf("reused recovery = %v", err)
	}
	if repo.audits[len(repo.audits)-1] != mfa.ActionRecovery {
		t.Fatalf("audit = %v", repo.audits)
	}
}

func TestPendingLoginAttemptsAndSingleUse(t *testing.T) {
	s, repo, now := setup(t)
	secret, _ := enroll(t, s, now)
	ctx := context.Background()
	boundary := authentication.Context{EnvironmentID: env}
	token, err := s.Begin(ctx, boundary, user, []string{"pwd"}, false, "")
	if err != nil || len(token) < 20 || token[:7] != "ik_mfa_" {
		t.Fatalf("begin = %q %v", token, err)
	}
	if _, err := s.Complete(ctx, "not-a-token", "123456", nil); status(err) != 401 {
		t.Fatalf("bad token = %v", err)
	}
	for i := 0; i < config.MFAAttempts; i++ {
		if _, err := s.Complete(ctx, token, "000000", nil); status(err) != 401 {
			t.Fatalf("wrong code %d = %v", i, err)
		}
	}
	// Attempts exhausted: even the right code fails and the login is gone.
	if _, err := s.Complete(ctx, token, code(t, secret, *now), nil); status(err) != 401 {
		t.Fatalf("after attempts = %v", err)
	}
	if len(repo.pending) != 0 {
		t.Fatal("exhausted pending login kept")
	}

	token, _ = s.Begin(ctx, boundary, user, []string{"pwd"}, false, "")
	done, err := s.Complete(ctx, token, code(t, secret, *now), nil)
	if err != nil || done.User != user || len(done.AMR) != 3 || done.AMR[0] != "pwd" || done.AMR[2] != "mfa" {
		t.Fatalf("complete = %+v %v", done, err)
	}
	if _, err := s.Complete(ctx, token, code(t, secret, now.Add(30*time.Second)), nil); status(err) != 401 {
		t.Fatalf("completed login reused = %v", err)
	}
}

// A session that cannot be created leaves the pending login and the
// enrollment untouched: the recovery codes are never lost.
func TestCompleteRollsBackWhenIssueFails(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	token, _ := s.Begin(ctx, authentication.Context{EnvironmentID: env}, user, []string{"pwd"}, true, "")
	e, err := s.Enroll(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	fail := func(authentication.Completed) error { return errx.Forbidden("no access") }
	if _, err := s.Complete(ctx, token, code(t, e.Secret, *now), fail); status(err) != 403 {
		t.Fatalf("complete with failing issue = %v", err)
	}
	if repo.factor.Active() || len(repo.pending) != 1 || len(repo.recovery) != 0 {
		t.Fatalf("state after failed issue: factor active=%v pending=%d recovery=%d", repo.factor.Active(), len(repo.pending), len(repo.recovery))
	}
	var issued authentication.Completed
	done, err := s.Complete(ctx, token, code(t, e.Secret, *now), func(d authentication.Completed) error { issued = d; return nil })
	if err != nil || issued.User != user || len(done.RecoveryCodes) != config.RecoveryCodes || !repo.factor.Active() {
		t.Fatalf("retry = %+v %v", done, err)
	}
}

// Wrong codes lock the factor across pending logins, hosted checks and
// self-service calls; a correct code resets the count.
func TestLockoutSpansLogins(t *testing.T) {
	s, repo, now := setup(t)
	secret, _ := enroll(t, s, now)
	ctx := context.Background()
	boundary := authentication.Context{EnvironmentID: env}
	for i := 0; i < config.MFAFailures-1; i++ {
		if i%2 == 0 {
			token, _ := s.Begin(ctx, boundary, user, []string{"pwd"}, false, "")
			if _, err := s.Complete(ctx, token, "000000", nil); status(err) != 401 {
				t.Fatalf("wrong %d = %v", i, err)
			}
		} else if _, err := s.Verify(ctx, env, user, "000000", false); status(err) != 401 {
			t.Fatalf("wrong %d = %v", i, err)
		}
	}
	if repo.factor.Failures != config.MFAFailures-1 || repo.factor.LockedUntil != nil {
		t.Fatalf("failures = %d locked = %v", repo.factor.Failures, repo.factor.LockedUntil)
	}
	if _, err := s.Regenerate(ctx, mfa.Mutation{Environment: env}, user, "000000"); status(err) != 422 {
		t.Fatalf("self-service wrong code = %v", err)
	}
	if repo.factor.LockedUntil == nil || repo.audits[len(repo.audits)-1] != mfa.ActionLocked {
		t.Fatalf("not locked: %+v %v", repo.factor, repo.audits)
	}
	// Locked: even the right code is refused, on every path.
	if _, err := s.Verify(ctx, env, user, code(t, secret, *now), false); status(err) != 429 {
		t.Fatalf("locked verify = %v", err)
	}
	token, _ := s.Begin(ctx, boundary, user, []string{"pwd"}, false, "")
	if _, err := s.Complete(ctx, token, code(t, secret, *now), nil); status(err) != 429 {
		t.Fatalf("locked complete = %v", err)
	}
	*now = now.Add(config.MFALockout + time.Second)
	if _, err := s.Complete(ctx, token, code(t, secret, *now), nil); err != nil {
		t.Fatalf("after lockout = %v", err)
	}
	if repo.factor.Failures != 0 || repo.factor.LockedUntil != nil {
		t.Fatalf("not reset: %+v", repo.factor)
	}
}

func TestLockoutDuration(t *testing.T) {
	base, max := 15*time.Minute, time.Hour
	for failures, want := range map[int]time.Duration{9: 0, 10: base, 11: 0, 20: 2 * base, 30: 4 * base, 40: max, 1000: max} {
		if got := mfa.Lockout(failures, 10, base, max); got != want {
			t.Errorf("Lockout(%d) = %v, want %v", failures, got, want)
		}
	}
}

func TestEnrollRefusesExhaustedLogin(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	token, _ := s.Begin(ctx, authentication.Context{EnvironmentID: env}, user, []string{"pwd"}, true, "")
	if _, err := s.Enroll(ctx, token); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < config.MFAAttempts; i++ {
		s.Complete(ctx, token, "000000", nil)
	}
	if _, err := s.Enroll(ctx, token); status(err) != 401 {
		t.Fatalf("enroll after attempts = %v", err)
	}
}

func TestPendingEnrollment(t *testing.T) {
	s, _, now := setup(t)
	ctx := context.Background()
	boundary := authentication.Context{EnvironmentID: env}
	plainLogin, _ := s.Begin(ctx, boundary, user, []string{"pwd"}, false, "")
	if _, err := s.Enroll(ctx, plainLogin); status(err) != 422 {
		t.Fatalf("enroll on a non-enrolling login = %v", err)
	}
	token, _ := s.Begin(ctx, boundary, user, []string{"email"}, true, "")
	e, err := s.Enroll(ctx, token)
	if err != nil || e.Secret == "" {
		t.Fatalf("enroll = %+v %v", e, err)
	}
	done, err := s.Complete(ctx, token, code(t, e.Secret, *now), nil)
	if err != nil || len(done.RecoveryCodes) != config.RecoveryCodes || done.AMR[0] != "email" {
		t.Fatalf("complete enrollment = %+v %v", done, err)
	}
}

func TestUnconfirmedFactorDoesNotSatisfyLogin(t *testing.T) {
	s, _, now := setup(t)
	ctx := context.Background()
	e, _ := s.Start(ctx, env, user)
	if _, err := s.Verify(ctx, env, user, code(t, e.Secret, *now), false); status(err) != 401 {
		t.Fatalf("unconfirmed factor accepted: %v", err)
	}
	// Enrolling shows the same unconfirmed secret again.
	again, err := s.Enrolling(ctx, env, user)
	if err != nil || again.Secret != e.Secret {
		t.Fatalf("enrolling = %+v %v", again, err)
	}
}

func TestRemoveRegenerateAndReset(t *testing.T) {
	s, repo, now := setup(t)
	secret, old := enroll(t, s, now)
	ctx := context.Background()
	m := mfa.Mutation{Environment: env}
	if _, err := s.Regenerate(ctx, m, user, "000000"); status(err) != 422 {
		t.Fatalf("regenerate wrong code = %v", err)
	}
	fresh, err := s.Regenerate(ctx, m, user, code(t, secret, *now))
	if err != nil || len(fresh) != config.RecoveryCodes {
		t.Fatalf("regenerate = %v %v", fresh, err)
	}
	if _, err := s.Verify(ctx, env, user, old[1], false); status(err) != 401 {
		t.Fatalf("old recovery code still works: %v", err)
	}
	if err := s.Remove(ctx, m, user, fresh[0]); err != nil || repo.factor != nil {
		t.Fatalf("remove = %v", err)
	}
	if err := s.Remove(ctx, m, user, fresh[1]); status(err) != 404 {
		t.Fatalf("remove twice = %v", err)
	}
	if err := s.Reset(ctx, m, user); status(err) != 404 {
		t.Fatalf("reset nothing = %v", err)
	}
	*now = now.Add(time.Minute)
	enroll(t, s, now)
	if err := s.Reset(ctx, m, user); err != nil || repo.factor != nil {
		t.Fatalf("reset = %v", err)
	}
	want := []string{mfa.ActionEnrolled, mfa.ActionRegenerated, mfa.ActionRecovery, mfa.ActionRemoved, mfa.ActionEnrolled, mfa.ActionReset}
	if len(repo.audits) != len(want) {
		t.Fatalf("audits = %v", repo.audits)
	}
	for i := range want {
		if repo.audits[i] != want[i] {
			t.Fatalf("audits = %v, want %v", repo.audits, want)
		}
	}
}

func TestPolicyRequirement(t *testing.T) {
	cases := []struct {
		name      string
		p         mfa.Policy
		federated bool
		needed    bool
		enroll    bool
	}{
		{"nothing", mfa.Policy{}, false, false, false},
		{"enrolled", mfa.Policy{Enrolled: true}, false, true, false},
		{"required", mfa.Policy{Required: true}, false, true, true},
		{"enrolled and required", mfa.Policy{Enrolled: true, Required: true}, false, true, false},
		{"federated trusts idp", mfa.Policy{Enrolled: true, Required: true}, true, false, false},
		{"federated opted in", mfa.Policy{Required: true, RequiredFederated: true}, true, true, true},
		{"federated opted in, enrolled", mfa.Policy{Enrolled: true, RequiredFederated: true}, true, true, false},
	}
	for _, c := range cases {
		r := c.p.Requirement(c.federated)
		if r.Needed != c.needed || r.Enroll != c.enroll {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

func TestStaleEnrollmentCannotBeConfirmed(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	e, err := s.Start(ctx, env, user)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(config.MFAEnrollTTL + time.Minute)
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, code(t, e.Secret, *now)); status(err) != 422 || repo.factor.Active() {
		t.Fatalf("stale confirm = %v (active %v)", err, repo.factor.Active())
	}
}

func TestFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if err := mfa.Fresh(now.Add(-time.Minute).Unix(), now); err != nil {
		t.Fatalf("recent sign-in = %v", err)
	}
	for _, at := range []int64{0, now.Add(-config.MFAFreshAuth - time.Second).Unix()} {
		var e *errx.Error
		if err := mfa.Fresh(at, now); !errx.As(err, &e) || e.Code != "REAUTHENTICATION_REQUIRED" || e.HTTPStatus != 403 {
			t.Fatalf("auth_time %d = %v", at, err)
		}
	}
}

func TestCodeHelpers(t *testing.T) {
	if mfa.NormalizeCode(" AbCd-efgh 2345\t") != "abcdefgh2345" || !mfa.IsTOTPCode("012345") || mfa.IsTOTPCode("") || mfa.IsTOTPCode("12a456") || mfa.IsTOTPCode("123456789012") {
		t.Fatal("normalize/IsTOTPCode")
	}
	if a := mfa.AMR(mfa.ProofRecovery); len(a) != 1 || a[0] != "mfa" {
		t.Fatalf("recovery amr = %v", a)
	}
	if !bytes.Equal((&secrets{}).Hash("x"), (&secrets{}).Hash("x")) {
		t.Fatal("hash")
	}
}
