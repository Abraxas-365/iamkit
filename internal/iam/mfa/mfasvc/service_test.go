package mfasvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfatotp"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// memory is an in-memory mfa.Repository for one user. Begin snapshots the
// state; Rollback without Commit restores it.
type memory struct {
	factors  []mfa.Factor
	lock     mfa.Lock
	recovery map[string]bool // hash -> used
	pending  map[string]*mfa.Pending
	audits   []string
	saved    *memory
	clock    *time.Time
	// allowed is the environment's (and organization's) allowed kinds;
	// orgAllowed, when set, narrows them for boundaries with an
	// organization; required makes the boundary require a second factor.
	allowed    []string
	orgAllowed []string
	required   bool
	phone      string
	ceremonies map[string]mfa.Ceremony
}

func newMemory() *memory {
	now := time.Now()
	return &memory{recovery: map[string]bool{}, pending: map[string]*mfa.Pending{}, clock: &now, allowed: []string{mfa.KindTOTP, mfa.KindEmail, mfa.KindSMS}}
}

func (m *memory) snapshot() *memory {
	c := &memory{lock: m.lock, recovery: map[string]bool{}, pending: map[string]*mfa.Pending{}, audits: append([]string{}, m.audits...), clock: m.clock, factors: append([]mfa.Factor{}, m.factors...), phone: m.phone, ceremonies: map[string]mfa.Ceremony{}}
	for k, v := range m.ceremonies {
		c.ceremonies[k] = v
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

// factor returns the user's factor of kind (nil: none).
func (m *memory) factor(kind string) *mfa.Factor {
	for i := range m.factors {
		if m.factors[i].Kind == kind {
			return &m.factors[i]
		}
	}
	return nil
}

func (m *memory) byID(id identity.FactorID) *mfa.Factor {
	for i := range m.factors {
		if m.factors[i].ID == id {
			return &m.factors[i]
		}
	}
	return nil
}

func (m *memory) Begin(context.Context) (mfa.Transaction, error) {
	m.saved = m.snapshot()
	return m, nil
}
func (m *memory) Summary(context.Context, identity.EnvironmentID, identity.UserID) (mfa.Summary, error) {
	out := mfa.Summary{Factors: append([]mfa.Factor{}, m.factors...)}
	for _, used := range m.recovery {
		if !used {
			out.RecoveryCodes++
		}
	}
	return out, nil
}
func (m *memory) Policy(_ context.Context, b authentication.Context, _ identity.UserID) (mfa.Policy, error) {
	allowed := m.allowed
	if m.orgAllowed != nil && !b.OrganizationID.IsZero() {
		allowed = []string{}
		for _, k := range m.allowed {
			if slices.Contains(m.orgAllowed, k) {
				allowed = append(allowed, k)
			}
		}
	}
	p := mfa.Policy{Active: []string{}, Allowed: allowed, Required: m.required}
	for _, f := range m.factors {
		if f.Active() {
			p.Active = append(p.Active, f.Kind)
		}
	}
	return p, nil
}
func (m *memory) Allowed(context.Context, identity.EnvironmentID) ([]string, error) {
	return m.allowed, nil
}
func (m *memory) Account(context.Context, identity.EnvironmentID, identity.UserID) (mfa.Account, error) {
	return mfa.Account{Email: "alice@example.com", Issuer: "Acme"}, nil
}
func (m *memory) SaveUnconfirmed(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, factor identity.FactorID, sealed string) error {
	if f := m.factor(mfa.KindTOTP); f != nil && f.Active() {
		return errx.Conflict("an authenticator is already enrolled")
	}
	// Its own transaction: survives a rollback of an enclosing one.
	for _, s := range []*memory{m, m.saved} {
		if s != nil {
			s.factors = slices.DeleteFunc(s.factors, func(f mfa.Factor) bool { return f.Kind == mfa.KindTOTP })
			s.factors = append(s.factors, mfa.Factor{ID: factor, Kind: mfa.KindTOTP, Secret: &sealed, Created: *m.clock})
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
func (m *memory) Factors(context.Context, identity.EnvironmentID, identity.UserID) ([]mfa.Factor, error) {
	return append([]mfa.Factor{}, m.factors...), nil
}
func (m *memory) Lock(context.Context, identity.EnvironmentID, identity.UserID) (mfa.Lock, error) {
	return m.lock, nil
}
func (m *memory) SetLock(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, l mfa.Lock) error {
	m.lock = l
	return nil
}
func (m *memory) UseStep(_ context.Context, id identity.FactorID, step int64) error {
	m.byID(id).LastStep = step
	return nil
}
func (m *memory) Confirm(_ context.Context, id identity.FactorID, step int64) error {
	now := *m.clock
	f := m.byID(id)
	f.Confirmed, f.LastStep = &now, step
	return nil
}
func (m *memory) SaveCodeFactor(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, id identity.FactorID, kind, phone string) (mfa.Factor, error) {
	if f := m.factor(kind); f != nil {
		if f.Active() {
			return mfa.Factor{}, errx.Conflict("already enrolled")
		}
		f.Phone, f.Created, f.Code, f.CodeExpires, f.CodeAttempts = phone, *m.clock, nil, nil, 0
		return *f, nil
	}
	f := mfa.Factor{ID: id, Kind: kind, Phone: phone, Created: *m.clock}
	m.factors = append(m.factors, f)
	return f, nil
}
func (m *memory) SetCode(_ context.Context, id identity.FactorID, c mfa.Code) error {
	f := m.byID(id)
	f.Code, f.CodeExpires, f.CodeSent, f.CodesSent, f.CodesWindow, f.CodeAttempts = c.Hash, &c.Expires, &c.Sent, c.Count, &c.Window, 0
	return nil
}
func (m *memory) UseCode(_ context.Context, id identity.FactorID) error {
	f := m.byID(id)
	f.Code, f.CodeExpires = nil, nil
	return nil
}
func (m *memory) FailCode(_ context.Context, id identity.FactorID, limit int) error {
	f := m.byID(id)
	f.CodeAttempts++
	if f.CodeAttempts >= limit {
		f.Code, f.CodeExpires = nil, nil
	}
	return nil
}
func (m *memory) ConfirmCode(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, id identity.FactorID) error {
	now := *m.clock
	f := m.byID(id)
	f.Confirmed, f.Code, f.CodeExpires = &now, nil, nil
	if f.Phone != "" {
		m.phone = f.Phone
	}
	return nil
}
func (m *memory) DeleteFactor(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, id identity.FactorID) error {
	m.factors = slices.DeleteFunc(m.factors, func(f mfa.Factor) bool { return f.ID == id })
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
	removed := len(m.factors) > 0 || len(m.recovery) > 0
	m.factors, m.recovery, m.lock = nil, map[string]bool{}, mfa.Lock{}
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
func (m *memory) SaveCeremony(_ context.Context, hash []byte, c mfa.Ceremony) error {
	for _, s := range []*memory{m, m.saved} {
		if s != nil {
			if s.ceremonies == nil {
				s.ceremonies = map[string]mfa.Ceremony{}
			}
			s.ceremonies[string(hash)] = c
		}
	}
	return nil
}
func (m *memory) TakeCeremony(_ context.Context, hash []byte, environment identity.EnvironmentID, purpose string) (mfa.Ceremony, bool, error) {
	c, ok := m.ceremonies[string(hash)]
	delete(m.ceremonies, string(hash))
	if !ok || c.Environment != environment || c.Purpose != purpose || !c.Expires.After(*m.clock) {
		return mfa.Ceremony{}, false, nil
	}
	return c, true, nil
}
func (m *memory) SaveWebAuthn(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, f mfa.Factor, c mfa.Credential) error {
	for _, existing := range m.factors {
		if got, ok := existing.WebAuthn(); ok && bytes.Equal(got.ID, c.ID) {
			return errx.Conflict("this security key is already registered")
		}
	}
	f.Data, _ = json.Marshal(c)
	m.factors = append(m.factors, f)
	return nil
}
func (m *memory) UseWebAuthn(_ context.Context, id identity.FactorID, c mfa.Credential) error {
	f := m.byID(id)
	f.Data, _ = json.Marshal(c)
	return nil
}
func (m *memory) RenameFactor(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, id identity.FactorID, name string) (mfa.Factor, error) {
	f := m.byID(id)
	if f == nil || f.Kind != mfa.KindWebAuthn {
		return mfa.Factor{}, errx.NotFound("security key not found")
	}
	f.Name = name
	return *f, nil
}
func (m *memory) Commit() error { m.saved = nil; return nil }
func (m *memory) Rollback() error {
	if m.saved != nil {
		s := m.saved
		m.factors, m.lock, m.recovery, m.pending, m.audits, m.phone, m.ceremonies, m.saved = s.factors, s.lock, s.recovery, s.pending, s.audits, s.phone, s.ceremonies, nil
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

// outbox records sent codes; fail makes the next send fail.
type outbox struct {
	sent []sent
	fail error
}

type sent struct{ channel, to, purpose, code string }

func (o *outbox) Email(_ context.Context, _ identity.EnvironmentID, email, purpose, code string) error {
	if o.fail != nil {
		return o.fail
	}
	o.sent = append(o.sent, sent{"email", email, purpose, code})
	return nil
}
func (o *outbox) SMS(_ context.Context, _ identity.EnvironmentID, phone, purpose, code string) error {
	if o.fail != nil {
		return o.fail
	}
	o.sent = append(o.sent, sent{"sms", phone, purpose, code})
	return nil
}
func (o *outbox) last() sent { return o.sent[len(o.sent)-1] }

var (
	env      = identity.MustParseEnvironmentID("11111111-1111-4111-8111-111111111111")
	user     = identity.MustParseUserID("22222222-2222-4222-8222-222222222222")
	boundary = authentication.Context{EnvironmentID: env}
	pwd      = []string{"pwd"}
)

func setup(t *testing.T) (*Service, *memory, *time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	repo := newMemory()
	repo.clock = &now
	return New(repo, mfatotp.TOTP{}, plain{}, &secrets{}, func() time.Time { return now }), repo, &now
}

func setupSender(t *testing.T) (*Service, *memory, *time.Time, *outbox) {
	t.Helper()
	s, repo, now := setup(t)
	out := &outbox{}
	s.SetSender(out)
	return s, repo, now, out
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

func errCode(err error) string {
	var e *errx.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// enroll starts and confirms a TOTP factor, returning its secret and
// recovery codes.
func enroll(t *testing.T, s *Service, now *time.Time) (string, []string) {
	t.Helper()
	ctx := context.Background()
	e, err := s.Start(ctx, boundary, user)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "", code(t, e.Secret, *now))
	if err != nil || len(codes) != config.RecoveryCodes {
		t.Fatalf("confirm = %v %v", codes, err)
	}
	*now = now.Add(config.TOTPPeriod * time.Second)
	return e.Secret, codes
}

// verify is a hosted-style check of a password login.
func verify(s *Service, c string) (mfa.Verification, error) {
	return s.Verify(context.Background(), boundary, user, pwd, authentication.CodeProof(c), false)
}

func TestEnrollConfirmAndReplay(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	e, err := s.Start(ctx, boundary, user)
	if err != nil || e.Secret == "" || e.URI == "" || repo.factor(mfa.KindTOTP).Sealed() == e.Secret {
		t.Fatalf("start = %+v %v", e, err)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "totp", "000000"); status(err) != 422 {
		t.Fatalf("wrong confirm = %v", err)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "totp", "abcd-efgh-2345"); status(err) != 422 {
		t.Fatalf("recovery code cannot confirm: %v", err)
	}
	c := code(t, e.Secret, *now)
	codes, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "totp", c)
	if err != nil || len(codes) != config.RecoveryCodes || !repo.factor(mfa.KindTOTP).Active() {
		t.Fatalf("confirm = %v %v", codes, err)
	}
	if last := repo.audits[len(repo.audits)-1]; last != mfa.ActionEnrolled {
		t.Fatalf("audit = %v", repo.audits)
	}
	// The confirming code cannot be replayed, and a second enrollment conflicts.
	if _, err := verify(s, c); status(err) != 401 {
		t.Fatalf("replayed code = %v", err)
	}
	if _, err := s.Start(ctx, boundary, user); status(err) != 409 {
		t.Fatalf("second start = %v", err)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "totp", c); status(err) != 422 {
		t.Fatalf("confirm when active = %v", err)
	}
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "fax", c); status(err) != 400 {
		t.Fatalf("unknown kind = %v", err)
	}
}

func TestStartNeedsCipher(t *testing.T) {
	s := New(newMemory(), mfatotp.TOTP{}, plain{off: true}, &secrets{}, nil)
	if _, err := s.Start(context.Background(), boundary, user); status(err) != 422 {
		t.Fatalf("start without key = %v", err)
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	s, repo, now := setup(t)
	_, codes := enroll(t, s, now)
	for _, c := range codes {
		if len(c) != 14 || c[4] != '-' || c[9] != '-' {
			t.Fatalf("recovery code format %q", c)
		}
	}
	v, err := verify(s, " "+codes[0][:5]+"  "+codes[0][5:]+" ")
	if err != nil || v.Proof != mfa.ProofRecovery {
		t.Fatalf("recovery = %+v %v", v, err)
	}
	if _, err := verify(s, codes[0]); status(err) != 401 {
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
	token, err := s.Begin(ctx, boundary, user, pwd, false, "")
	if err != nil || len(token) < 20 || token[:7] != "ik_mfa_" {
		t.Fatalf("begin = %q %v", token, err)
	}
	if _, err := s.Complete(ctx, "not-a-token", authentication.CodeProof("123456"), nil); status(err) != 401 {
		t.Fatalf("bad token = %v", err)
	}
	for i := 0; i < config.MFAAttempts; i++ {
		if _, err := s.Complete(ctx, token, authentication.CodeProof("000000"), nil); status(err) != 401 {
			t.Fatalf("wrong code %d = %v", i, err)
		}
	}
	// Attempts exhausted: even the right code fails and the login is gone.
	if _, err := s.Complete(ctx, token, authentication.CodeProof(code(t, secret, *now)), nil); status(err) != 401 {
		t.Fatalf("after attempts = %v", err)
	}
	if len(repo.pending) != 0 {
		t.Fatal("exhausted pending login kept")
	}

	token, _ = s.Begin(ctx, boundary, user, pwd, false, "")
	done, err := s.Complete(ctx, token, authentication.CodeProof(code(t, secret, *now)), nil)
	if err != nil || done.User != user || len(done.AMR) != 3 || done.AMR[0] != "pwd" || done.AMR[2] != "mfa" {
		t.Fatalf("complete = %+v %v", done, err)
	}
	if _, err := s.Complete(ctx, token, authentication.CodeProof(code(t, secret, now.Add(30*time.Second))), nil); status(err) != 401 {
		t.Fatalf("completed login reused = %v", err)
	}
}

// A session that cannot be created leaves the pending login and the
// enrollment untouched: the recovery codes are never lost.
func TestCompleteRollsBackWhenIssueFails(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	token, _ := s.Begin(ctx, boundary, user, pwd, true, "")
	e, err := s.Enroll(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	fail := func(authentication.Completed) error { return errx.Forbidden("no access") }
	if _, err := s.Complete(ctx, token, authentication.CodeProof(code(t, e.Secret, *now)), fail); status(err) != 403 {
		t.Fatalf("complete with failing issue = %v", err)
	}
	if repo.factor(mfa.KindTOTP).Active() || len(repo.pending) != 1 || len(repo.recovery) != 0 {
		t.Fatalf("state after failed issue: pending=%d recovery=%d", len(repo.pending), len(repo.recovery))
	}
	var issued authentication.Completed
	done, err := s.Complete(ctx, token, authentication.CodeProof(code(t, e.Secret, *now)), func(d authentication.Completed) error { issued = d; return nil })
	if err != nil || issued.User != user || len(done.RecoveryCodes) != config.RecoveryCodes || !repo.factor(mfa.KindTOTP).Active() {
		t.Fatalf("retry = %+v %v", done, err)
	}
}

// Wrong codes lock the factor across pending logins, hosted checks and
// self-service calls; a correct code resets the count.
func TestLockoutSpansLogins(t *testing.T) {
	s, repo, now := setup(t)
	secret, _ := enroll(t, s, now)
	ctx := context.Background()
	for i := 0; i < config.MFAFailures-1; i++ {
		if i%2 == 0 {
			token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
			if _, err := s.Complete(ctx, token, authentication.CodeProof("000000"), nil); status(err) != 401 {
				t.Fatalf("wrong %d = %v", i, err)
			}
		} else if _, err := verify(s, "000000"); status(err) != 401 {
			t.Fatalf("wrong %d = %v", i, err)
		}
	}
	if repo.lock.Failures != config.MFAFailures-1 || repo.lock.LockedUntil != nil {
		t.Fatalf("failures = %d locked = %v", repo.lock.Failures, repo.lock.LockedUntil)
	}
	if _, err := s.Regenerate(ctx, mfa.Mutation{Environment: env}, user, authentication.CodeProof("000000")); status(err) != 422 {
		t.Fatalf("self-service wrong code = %v", err)
	}
	if repo.lock.LockedUntil == nil || repo.audits[len(repo.audits)-1] != mfa.ActionLocked {
		t.Fatalf("not locked: %+v %v", repo.lock, repo.audits)
	}
	// Locked: even the right code is refused, on every path.
	if _, err := verify(s, code(t, secret, *now)); status(err) != 429 {
		t.Fatalf("locked verify = %v", err)
	}
	token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	if _, err := s.Complete(ctx, token, authentication.CodeProof(code(t, secret, *now)), nil); status(err) != 429 {
		t.Fatalf("locked complete = %v", err)
	}
	*now = now.Add(config.MFALockout + time.Second)
	if _, err := s.Complete(ctx, token, authentication.CodeProof(code(t, secret, *now)), nil); err != nil {
		t.Fatalf("after lockout = %v", err)
	}
	if repo.lock.Failures != 0 || repo.lock.LockedUntil != nil {
		t.Fatalf("not reset: %+v", repo.lock)
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
	token, _ := s.Begin(ctx, boundary, user, pwd, true, "")
	if _, err := s.Enroll(ctx, token); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < config.MFAAttempts; i++ {
		s.Complete(ctx, token, authentication.CodeProof("000000"), nil)
	}
	if _, err := s.Enroll(ctx, token); status(err) != 401 {
		t.Fatalf("enroll after attempts = %v", err)
	}
}

func TestPendingEnrollment(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	plainLogin, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	if _, err := s.Enroll(ctx, plainLogin); status(err) != 422 {
		t.Fatalf("enroll on a non-enrolling login = %v", err)
	}
	token, _ := s.Begin(ctx, boundary, user, []string{"email"}, true, "")
	e, err := s.Enroll(ctx, token)
	if err != nil || e.Secret == "" {
		t.Fatalf("enroll = %+v %v", e, err)
	}
	done, err := s.Complete(ctx, token, authentication.CodeProof(code(t, e.Secret, *now)), nil)
	if err != nil || len(done.RecoveryCodes) != config.RecoveryCodes || done.AMR[0] != "email" {
		t.Fatalf("complete enrollment = %+v %v", done, err)
	}
	// TOTP not allowed: a login cannot enroll an authenticator.
	repo.allowed = []string{mfa.KindEmail}
	token, _ = s.Begin(ctx, boundary, user, pwd, true, "")
	if _, err := s.Enroll(ctx, token); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("enroll disallowed totp = %v", err)
	}
}

func TestUnconfirmedFactorDoesNotSatisfyLogin(t *testing.T) {
	s, _, now := setup(t)
	ctx := context.Background()
	e, _ := s.Start(ctx, boundary, user)
	if _, err := verify(s, code(t, e.Secret, *now)); status(err) != 401 {
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
	if _, err := s.Regenerate(ctx, m, user, authentication.CodeProof("000000")); status(err) != 422 {
		t.Fatalf("regenerate wrong code = %v", err)
	}
	fresh, err := s.Regenerate(ctx, m, user, authentication.CodeProof(code(t, secret, *now)))
	if err != nil || len(fresh) != config.RecoveryCodes {
		t.Fatalf("regenerate = %v %v", fresh, err)
	}
	if _, err := verify(s, old[1]); status(err) != 401 {
		t.Fatalf("old recovery code still works: %v", err)
	}
	if err := s.Remove(ctx, m, user, "", authentication.CodeProof(fresh[0])); err != nil || len(repo.factors) != 0 {
		t.Fatalf("remove = %v", err)
	}
	if err := s.Remove(ctx, m, user, "totp", authentication.CodeProof(fresh[1])); status(err) != 404 {
		t.Fatalf("remove twice = %v", err)
	}
	if err := s.Reset(ctx, m, user); status(err) != 404 {
		t.Fatalf("reset nothing = %v", err)
	}
	*now = now.Add(time.Minute)
	enroll(t, s, now)
	if err := s.Reset(ctx, m, user); err != nil || len(repo.factors) != 0 {
		t.Fatalf("reset = %v", err)
	}
	want := []string{mfa.ActionEnrolled, mfa.ActionRegenerated, mfa.ActionRecovery, mfa.ActionRemoved, mfa.ActionEnrolled, mfa.ActionReset}
	if !slices.Equal(repo.audits, want) {
		t.Fatalf("audits = %v, want %v", repo.audits, want)
	}
}

func TestPolicyRequirement(t *testing.T) {
	all := []string{mfa.KindTOTP, mfa.KindEmail, mfa.KindSMS}
	totp := []string{mfa.KindTOTP}
	cases := []struct {
		name      string
		p         mfa.Policy
		federated bool
		amr       []string
		needed    bool
		enroll    bool
		factors   []string
	}{
		{"nothing", mfa.Policy{Allowed: all}, false, pwd, false, false, nil},
		{"enrolled", mfa.Policy{Active: totp, Allowed: all}, false, pwd, true, false, []string{"totp", "recovery"}},
		{"required", mfa.Policy{Allowed: all, Required: true}, false, pwd, true, true, []string{"totp", "email"}},
		{"enrolled and required", mfa.Policy{Active: totp, Allowed: all, Required: true}, false, pwd, true, false, []string{"totp", "recovery"}},
		{"federated trusts idp", mfa.Policy{Active: totp, Allowed: all, Required: true}, true, pwd, false, false, nil},
		{"federated opted in", mfa.Policy{Allowed: all, Required: true, RequiredFederated: true}, true, pwd, true, true, []string{"totp", "email"}},
		{"federated opted in, enrolled", mfa.Policy{Active: totp, Allowed: all, RequiredFederated: true}, true, pwd, true, false, []string{"totp", "recovery"}},
		// The email factor never follows an email-code first factor.
		{"email after email code", mfa.Policy{Active: []string{"email"}, Allowed: all}, false, []string{"email"}, true, true, []string{"totp"}},
		{"email after password", mfa.Policy{Active: []string{"email", "sms"}, Allowed: all}, false, pwd, true, false, []string{"sms", "email", "recovery"}},
		// A factor the boundary does not allow does not count: enroll another.
		{"disallowed factor", mfa.Policy{Active: []string{"sms"}, Allowed: totp}, false, pwd, true, true, []string{"totp"}},
	}
	for _, c := range cases {
		r := c.p.Requirement(c.federated, c.amr)
		if r.Needed != c.needed || r.Enroll != c.enroll || !slices.Equal(r.Factors, c.factors) {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

func TestStaleEnrollmentCannotBeConfirmed(t *testing.T) {
	s, repo, now := setup(t)
	ctx := context.Background()
	e, err := s.Start(ctx, boundary, user)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(config.MFAEnrollTTL + time.Minute)
	if _, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, "totp", code(t, e.Secret, *now)); status(err) != 422 || repo.factor(mfa.KindTOTP).Active() {
		t.Fatalf("stale confirm = %v", err)
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
	if a := mfa.AMR(mfa.ProofEmail); !slices.Equal(a, []string{"otp", "mfa"}) {
		t.Fatalf("email amr = %v", a)
	}
	if a := mfa.AMR(mfa.ProofSMS); !slices.Equal(a, []string{"sms", "mfa"}) {
		t.Fatalf("sms amr = %v", a)
	}
	if !bytes.Equal((&secrets{}).Hash("x"), (&secrets{}).Hash("x")) {
		t.Fatal("hash")
	}
	if mfa.MaskEmail("alice@example.com") != "a•••@example.com" || mfa.MaskPhone("+14155550100") != "+1••••••••00" {
		t.Fatalf("masks %q %q", mfa.MaskEmail("alice@example.com"), mfa.MaskPhone("+14155550100"))
	}
}

// ── Email and SMS factors ────────────────────────────────────────────

// enrollCode enrolls an email or SMS factor through self-service.
func enrollCode(t *testing.T, s *Service, out *outbox, kind, phone string) []string {
	t.Helper()
	ctx := context.Background()
	sent, err := s.StartCode(ctx, boundary, user, kind, phone)
	if err != nil || sent.Factor != kind || sent.Destination == "" {
		t.Fatalf("start %s = %+v %v", kind, sent, err)
	}
	codes, err := s.Confirm(ctx, mfa.Mutation{Environment: env}, user, kind, out.last().code)
	if err != nil {
		t.Fatalf("confirm %s = %v", kind, err)
	}
	return codes
}

func TestEmailFactorEnrollAndLogin(t *testing.T) {
	s, repo, now, out := setupSender(t)
	ctx := context.Background()
	codes := enrollCode(t, s, out, mfa.KindEmail, "")
	if len(codes) != config.RecoveryCodes || !repo.factor(mfa.KindEmail).Active() {
		t.Fatalf("email enroll = %v", codes)
	}
	if first := out.sent[0]; first.channel != "email" || first.to != "alice@example.com" || first.purpose != mfa.PurposeLogin || len(first.code) != 6 {
		t.Fatalf("sent = %+v", first)
	}
	// Login: a code is sent on request and completes the pending login.
	token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	*now = now.Add(config.FactorCodeCooldown)
	sent, err := s.Challenge(ctx, token, mfa.KindEmail)
	if err != nil || sent.Destination != "a•••@example.com" || !sent.ExpiresAt.Equal(now.Add(config.FactorCodeTTL).UTC()) {
		t.Fatalf("challenge = %+v %v", sent, err)
	}
	if _, err := s.Challenge(ctx, token, mfa.KindSMS); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("challenge without sms factor = %v", err)
	}
	c := out.last().code
	done, err := s.Complete(ctx, token, authentication.CodeProof(c), nil)
	if err != nil || !slices.Equal(done.AMR, []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("complete = %+v %v", done, err)
	}
	// The code is single use.
	token, _ = s.Begin(ctx, boundary, user, pwd, false, "")
	if _, err := s.Complete(ctx, token, authentication.CodeProof(c), nil); status(err) != 401 {
		t.Fatalf("reused email code = %v", err)
	}
	// An email-code login cannot use the email factor.
	token, _ = s.Begin(ctx, boundary, user, []string{"email"}, true, "")
	*now = now.Add(config.FactorCodeCooldown)
	if _, err := s.Challenge(ctx, token, mfa.KindEmail); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("email after email = %v", err)
	}
}

func TestCodeExpiresAndSendLimits(t *testing.T) {
	s, repo, now, out := setupSender(t)
	ctx := context.Background()
	enrollCode(t, s, out, mfa.KindEmail, "")
	token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	if _, err := s.Challenge(ctx, token, mfa.KindEmail); errCode(err) != "CODE_COOLDOWN" || status(err) != 429 {
		t.Fatalf("cooldown = %v", err)
	}
	*now = now.Add(config.FactorCodeCooldown)
	if _, err := s.Challenge(ctx, token, mfa.KindEmail); err != nil {
		t.Fatal(err)
	}
	c := out.last().code
	*now = now.Add(config.FactorCodeTTL + time.Second)
	if _, err := s.Complete(ctx, token, authentication.CodeProof(c), nil); status(err) != 401 {
		t.Fatalf("expired code = %v", err)
	}
	// Hourly cap: the enrollment code plus sends up to the limit.
	for i := repo.factor(mfa.KindEmail).CodesSent; i < config.FactorCodesPerHour; i++ {
		*now = now.Add(config.FactorCodeCooldown)
		if _, err := s.SendProof(ctx, env, user, mfa.KindEmail); err != nil {
			t.Fatalf("send %d = %v", i, err)
		}
	}
	*now = now.Add(config.FactorCodeCooldown)
	if _, err := s.SendProof(ctx, env, user, mfa.KindEmail); errCode(err) != "CODE_LIMIT" {
		t.Fatalf("hourly cap = %v", err)
	}
	*now = now.Add(time.Hour)
	if _, err := s.SendProof(ctx, env, user, mfa.KindEmail); err != nil {
		t.Fatalf("after an hour = %v", err)
	}
}

// A failed delivery keeps the previous code and counts no send.
func TestFailedDeliveryKeepsState(t *testing.T) {
	s, repo, now, out := setupSender(t)
	enrollCode(t, s, out, mfa.KindEmail, "")
	before := *repo.factor(mfa.KindEmail)
	*now = now.Add(config.FactorCodeCooldown)
	out.fail = errx.External("provider down")
	if _, err := s.SendProof(context.Background(), env, user, mfa.KindEmail); status(err) != 502 {
		t.Fatalf("failed send = %v", err)
	}
	if after := repo.factor(mfa.KindEmail); after.CodesSent != before.CodesSent || !after.CodeSent.Equal(*before.CodeSent) {
		t.Fatalf("send counted: %+v", after)
	}
}

// Wrong codes discard a live code after config.MFAAttempts entries.
func TestWrongCodesDiscardLiveCode(t *testing.T) {
	s, repo, now, out := setupSender(t)
	ctx := context.Background()
	enrollCode(t, s, out, mfa.KindEmail, "")
	*now = now.Add(config.FactorCodeCooldown)
	if _, err := s.SendProof(ctx, env, user, mfa.KindEmail); err != nil {
		t.Fatal(err)
	}
	c := out.last().code
	wrong := "000000"
	if c == wrong {
		wrong = "111111"
	}
	for i := 0; i < config.MFAAttempts; i++ {
		verify(s, wrong)
	}
	if repo.factor(mfa.KindEmail).CodeLive(*now) {
		t.Fatal("code survived wrong entries")
	}
	if _, err := verify(s, c); status(err) != 401 {
		t.Fatalf("discarded code = %v", err)
	}
}

func TestSMSFactorVerifiesPhone(t *testing.T) {
	s, repo, now, out := setupSender(t)
	ctx := context.Background()
	if _, err := s.StartCode(ctx, boundary, user, mfa.KindSMS, "12345"); status(err) != 400 {
		t.Fatalf("bad phone = %v", err)
	}
	enrollCode(t, s, out, mfa.KindSMS, "+1 (415) 555-0100")
	if first := out.sent[0]; first.channel != "sms" || first.to != "+14155550100" || first.purpose != mfa.PurposePhone {
		t.Fatalf("sms = %+v", first)
	}
	if repo.phone != "+14155550100" {
		t.Fatalf("phone = %q", repo.phone)
	}
	token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	*now = now.Add(config.FactorCodeCooldown)
	sent, err := s.Challenge(ctx, token, mfa.KindSMS)
	if err != nil || sent.Destination != "+1••••••••00" || out.last().purpose != mfa.PurposeLogin {
		t.Fatalf("challenge = %+v %v", sent, err)
	}
	done, err := s.Complete(ctx, token, authentication.CodeProof(out.last().code), nil)
	if err != nil || !slices.Equal(done.AMR, []string{"pwd", "sms", "mfa"}) {
		t.Fatalf("complete = %+v %v", done, err)
	}
}

// Factors the environment does not allow cannot be added, and code factors
// need a sender.
func TestFactorKindsAllowed(t *testing.T) {
	s, repo, _, _ := setupSender(t)
	ctx := context.Background()
	repo.allowed = []string{mfa.KindTOTP}
	if _, err := s.StartCode(ctx, boundary, user, mfa.KindEmail, ""); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("disallowed email = %v", err)
	}
	unsent, repo2, _ := setup(t)
	_ = repo2
	if _, err := unsent.StartCode(ctx, boundary, user, mfa.KindEmail, ""); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("no sender = %v", err)
	}
	if _, err := unsent.StartCode(ctx, boundary, user, mfa.KindTOTP, ""); status(err) != 400 {
		t.Fatalf("totp via StartCode = %v", err)
	}
}

// Self-service enrollment honours the allowed kinds of the environment and
// of the organization the user signed in to, for every factor kind.
func TestSelfServiceStartHonoursAllowedFactors(t *testing.T) {
	s, repo, _, _ := setupSender(t)
	repo.allowed = append(repo.allowed, mfa.KindWebAuthn)
	s.SetRelying(mfawebauthn.New(origin, nil))
	ctx := context.Background()
	org := authentication.Context{EnvironmentID: env, OrganizationID: identity.MustParseOrganizationID("44444444-4444-4444-8444-444444444444")}

	// The environment leaves out TOTP: no authenticator app.
	repo.allowed = []string{mfa.KindEmail, mfa.KindWebAuthn}
	if _, err := s.Start(ctx, boundary, user); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("totp off in the environment = %v", err)
	}
	// The environment allows every kind; the organization keeps only TOTP.
	repo.allowed = []string{mfa.KindTOTP, mfa.KindEmail, mfa.KindSMS, mfa.KindWebAuthn}
	repo.orgAllowed = []string{mfa.KindTOTP}
	if _, err := s.StartCode(ctx, org, user, mfa.KindEmail, ""); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("email off in the organization = %v", err)
	}
	if _, err := s.StartCode(ctx, org, user, mfa.KindSMS, "+14155550100"); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("sms off in the organization = %v", err)
	}
	if _, err := s.StartWebAuthn(ctx, org, user, mfa.StartRegistration{Name: "Key"}); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("webauthn off in the organization = %v", err)
	}
	if _, err := s.Start(ctx, org, user); err != nil {
		t.Fatalf("totp allowed by both = %v", err)
	}
	// The organization keeps only email: no authenticator app there.
	repo.orgAllowed = []string{mfa.KindEmail}
	if _, err := s.Start(ctx, org, user); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("totp off in the organization = %v", err)
	}
}

// A login that must enroll may send a code to the user's email address;
// the code confirms the email factor and returns the first recovery codes.
func TestLoginEnrollsEmailFactor(t *testing.T) {
	s, repo, _, out := setupSender(t)
	ctx := context.Background()
	repo.required = true
	req, err := s.Requirement(ctx, boundary, user, false, pwd)
	if err != nil || !req.Needed || !req.Enroll || !slices.Equal(req.Factors, []string{"totp", "email"}) {
		t.Fatalf("requirement = %+v %v", req, err)
	}
	token, _ := s.Begin(ctx, boundary, user, pwd, true, "")
	if _, err := s.Challenge(ctx, token, mfa.KindEmail); err != nil {
		t.Fatalf("enroll challenge = %v", err)
	}
	done, err := s.Complete(ctx, token, authentication.CodeProof(out.last().code), nil)
	if err != nil || len(done.RecoveryCodes) != config.RecoveryCodes || !repo.factor(mfa.KindEmail).Active() {
		t.Fatalf("complete = %+v %v", done, err)
	}
	// A second active factor keeps the existing recovery codes.
	codes := enrollCode(t, s, out, mfa.KindSMS, "+14155550100")
	if len(codes) != 0 {
		t.Fatalf("second factor issued recovery codes: %v", codes)
	}
}

// Without a sender, code factors drop out of the requirement.
func TestRequirementWithoutSender(t *testing.T) {
	s, repo, _ := setup(t)
	repo.required = true
	req, err := s.Requirement(context.Background(), boundary, user, false, pwd)
	if err != nil || !slices.Equal(req.Factors, []string{"totp"}) {
		t.Fatalf("requirement = %+v %v", req, err)
	}
}

// Removing one of several factors keeps the rest and the recovery codes.
func TestRemoveOneOfSeveral(t *testing.T) {
	s, repo, now, out := setupSender(t)
	ctx := context.Background()
	secret, _ := enroll(t, s, now)
	enrollCode(t, s, out, mfa.KindEmail, "")
	if err := s.Remove(ctx, mfa.Mutation{Environment: env}, user, mfa.KindEmail, authentication.CodeProof(code(t, secret, *now))); err != nil {
		t.Fatalf("remove email = %v", err)
	}
	if repo.factor(mfa.KindEmail) != nil || repo.factor(mfa.KindTOTP) == nil || len(repo.recovery) != config.RecoveryCodes {
		t.Fatalf("after remove: %+v recovery=%d", repo.factors, len(repo.recovery))
	}
}
