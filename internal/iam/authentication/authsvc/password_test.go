package authsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type policyRepository struct {
	authentication.PasswordPolicyRepository
	policy *authentication.PasswordPolicy
	// member are the requirements of the user's organizations.
	member []authentication.PasswordRequirements
}

func (r policyRepository) MemberRequirements(context.Context, identity.EnvironmentID, identity.UserID) ([]authentication.PasswordRequirements, error) {
	return r.member, nil
}

func (r policyRepository) ChallengeRequirements(context.Context, identity.EnvironmentID, identity.ChallengeID) ([]authentication.PasswordRequirements, error) {
	return r.member, nil
}

func (r policyRepository) GetPasswordPolicy(context.Context, identity.EnvironmentID) (authentication.PasswordPolicy, error) {
	if r.policy == nil {
		return authentication.PasswordPolicy{}, errx.NotFound("none")
	}
	return *r.policy, nil
}

type breaches struct {
	breached bool
	err      error
}

func (b breaches) Breached(context.Context, string) (bool, error) { return b.breached, b.err }

func withPolicy(s *Service, p authentication.PasswordPolicy, b authentication.Breaches) *Service {
	s.SetPasswordPolicies(NewPasswordPolicies(policyRepository{policy: &p}, b))
	return s
}

func code(err error) string {
	var e *errx.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Wrong passwords are counted and committed; the threshold locks the
// account, and a locked account refuses even the right password with the
// same 401, counting nothing more.
func TestLoginLockout(t *testing.T) {
	user := identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	tx := &testTransaction{user: user}
	policy := authentication.DefaultPasswordPolicy()
	policy.LockoutThreshold = 3
	wrong := withPolicy(New(testRepository{tx}, testPasswords{mismatch: true}, testSecrets{}, nil), policy, nil)
	var first string
	for i := 1; i <= 3; i++ {
		tx.committed = false
		_, err := wrong.Login(context.Background(), testBoundary(), "user@example.com", "password", "")
		var e *errx.Error
		if !errors.As(err, &e) || e.HTTPStatus != 401 || !tx.committed {
			t.Fatalf("attempt %d: %v committed=%v", i, err, tx.committed)
		}
		if first == "" {
			first = e.Message
		} else if e.Message != first {
			t.Fatalf("lockout changed the message: %q", e.Message)
		}
	}
	if tx.failures != 3 || tx.lockedUntil == nil || len(tx.audited) != 1 || tx.audited[0] != authentication.ActionUserLocked {
		t.Fatalf("failures=%d locked=%v audited=%v", tx.failures, tx.lockedUntil, tx.audited)
	}
	right := withPolicy(New(testRepository{tx}, testPasswords{}, testSecrets{}, nil), policy, nil)
	tx.committed = false
	_, err := right.Login(context.Background(), testBoundary(), "user@example.com", "password", "")
	var e *errx.Error
	if !errors.As(err, &e) || e.Message != first || tx.committed || tx.failures != 3 {
		t.Fatalf("locked login: %v committed=%v failures=%d", err, tx.committed, tx.failures)
	}
	past := time.Now().Add(-time.Second)
	tx.lockedUntil = &past
	if _, err := right.Login(context.Background(), testBoundary(), "user@example.com", "password", ""); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
	if tx.failures != 0 || tx.lockedUntil != nil {
		t.Fatalf("right password must clear the count: %d %v", tx.failures, tx.lockedUntil)
	}
}

// Without a threshold, failures are still counted but never lock.
func TestLoginCountsWithoutLocking(t *testing.T) {
	tx := &testTransaction{user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")}
	s := New(testRepository{tx}, testPasswords{mismatch: true}, testSecrets{}, nil)
	for range 10 {
		_, _ = s.Login(context.Background(), testBoundary(), "user@example.com", "password", "")
	}
	if tx.failures != 10 || tx.lockedUntil != nil {
		t.Fatalf("failures=%d locked=%v", tx.failures, tx.lockedUntil)
	}
}

func TestLoginExpiredPassword(t *testing.T) {
	policy := authentication.DefaultPasswordPolicy()
	policy.MaxAgeDays, policy.RequireDigit = 30, true
	tx := &testTransaction{user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), changed: time.Now().Add(-31 * 24 * time.Hour)}
	s := withPolicy(New(testRepository{tx}, testPasswords{}, testSecrets{}, nil), policy, nil)
	_, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", "")
	if code(err) != authentication.CodePasswordChangeRequired || tx.newHash != "" {
		t.Fatalf("want PASSWORD_CHANGE_REQUIRED, got %v", err)
	}
	_, err = s.Login(context.Background(), testBoundary(), "user@example.com", "password", "no digits here")
	if code(err) != authentication.CodePasswordPolicy || tx.newHash != "" {
		t.Fatalf("want PASSWORD_POLICY, got %v", err)
	}
	// The mismatch-free fake reports every password equal to the current one.
	_, err = s.Login(context.Background(), testBoundary(), "user@example.com", "password", "new password 1")
	if rule(err) != authentication.RuleReused {
		t.Fatalf("want reused, got %v", err)
	}
}

func TestLoginReplacesExpiredPassword(t *testing.T) {
	policy := authentication.DefaultPasswordPolicy()
	policy.MaxAgeDays = 30
	tx := &testTransaction{user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), changed: time.Now().Add(-31 * 24 * time.Hour)}
	s := withPolicy(New(testRepository{tx}, newPasswords{}, testSecrets{}, nil), policy, nil)
	if _, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if tx.newHash != "hash:a brand new password" || !tx.committed {
		t.Fatalf("new hash %q committed=%v", tx.newHash, tx.committed)
	}
}

// newPasswords matches only the current password ("password").
type newPasswords struct{}

func (newPasswords) Hash(p string) (string, error)   { return "hash:" + p, nil }
func (newPasswords) Compare(_, password string) bool { return password == "password" }

func TestBreachCheck(t *testing.T) {
	policy := authentication.DefaultPasswordPolicy()
	policy.BreachCheck = true
	env := testBoundary().EnvironmentID
	breached := NewPasswordPolicies(policyRepository{policy: &policy}, breaches{breached: true})
	if rule(breached.CheckPassword(context.Background(), env, "correct horse battery")) != authentication.RuleBreached {
		t.Fatal("breached password accepted")
	}
	down := NewPasswordPolicies(policyRepository{policy: &policy}, breaches{err: errx.External("down")})
	if err := down.CheckPassword(context.Background(), env, "correct horse battery"); err != nil {
		t.Fatalf("an unreachable breach service must fail open: %v", err)
	}
	policy.BreachCheck = false
	off := NewPasswordPolicies(policyRepository{policy: &policy}, breaches{breached: true})
	if err := off.CheckPassword(context.Background(), env, "correct horse battery"); err != nil {
		t.Fatalf("breach check off: %v", err)
	}
}

func TestDefaultPolicyWhenNoneSaved(t *testing.T) {
	p := NewPasswordPolicies(policyRepository{}, nil)
	got, err := p.PasswordPolicy(context.Background(), testBoundary().EnvironmentID)
	if err != nil || got.Custom || got != authentication.DefaultPasswordPolicy() {
		t.Fatalf("%+v %v", got, err)
	}
}

func rule(err error) string {
	var e *errx.Error
	if !errors.As(err, &e) {
		return ""
	}
	r, _ := e.Details["rule"].(string)
	return r
}
