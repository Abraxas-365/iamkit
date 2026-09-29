package authsvc

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type signInRepository struct {
	authentication.SignInPolicyRepository
	policy *authentication.SignInPolicy
}

func (r signInRepository) GetSignInPolicy(context.Context, identity.EnvironmentID) (authentication.SignInPolicy, error) {
	if r.policy == nil {
		return authentication.SignInPolicy{}, errx.NotFound("none")
	}
	return *r.policy, nil
}

func withSignIn(s *Service, p authentication.SignInPolicy) *Service {
	s.SetSignInPolicies(NewSignInPolicies(signInRepository{policy: &p}))
	return s
}

// A method the environment refuses answers METHOD_NOT_ALLOWED before any
// account lookup: known and unknown emails get the same answer.
func TestLoginMethodNotAllowed(t *testing.T) {
	policy := authentication.DefaultSignInPolicy()
	policy.AllowPassword, policy.AllowPasswordReset = false, false
	for name, tx := range map[string]*testTransaction{
		"known":   {user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")},
		"unknown": {lookup: errx.Unauthorized("no such user")},
	} {
		s := withSignIn(New(testRepository{tx}, testPasswords{}, testSecrets{}, nil), policy)
		_, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", "")
		if code(err) != authentication.CodeMethodNotAllowed || tx.failures != 0 {
			t.Fatalf("%s: %v failures=%d", name, err, tx.failures)
		}
	}
}

// The organization narrows the environment's methods.
func TestLoginOrganizationMethod(t *testing.T) {
	tx := &testTransaction{user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), methods: &authentication.Methods{EmailCode: true}}
	s := New(testRepository{tx}, testPasswords{}, testSecrets{}, nil)
	if _, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", ""); code(err) != authentication.CodeMethodNotAllowed {
		t.Fatalf("want METHOD_NOT_ALLOWED, got %v", err)
	}
	tx.methods = &authentication.Methods{Password: true}
	if _, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", ""); err != nil {
		t.Fatalf("allowed method: %v", err)
	}
}

type testDelivery struct{}

func (testDelivery) Send(context.Context, authentication.Message) error { return nil }

func TestPasswordResetDisabled(t *testing.T) {
	policy := authentication.DefaultSignInPolicy()
	policy.AllowPasswordReset = false
	s := withSignIn(New(testRepository{&testTransaction{}}, testPasswords{}, testSecrets{}, testDelivery{}), policy)
	env := testBoundary().EnvironmentID
	if _, err := s.InitiateChallenge(context.Background(), env, "user@example.com", "password_reset", ""); code(err) != authentication.CodePasswordResetDisabled {
		t.Fatalf("initiate: %v", err)
	}
	_, err := s.VerifyChallenge(context.Background(), authentication.Context{EnvironmentID: env}, identity.NewChallengeID(), "12345678", "password_reset", "a new password")
	if code(err) != authentication.CodePasswordResetDisabled {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignInPolicyValidate(t *testing.T) {
	p := authentication.DefaultSignInPolicy()
	p.AllowPassword = false
	if p.Validate() == nil {
		t.Fatal("reset without password accepted")
	}
	p.AllowPasswordReset, p.AllowEmailCode, p.AllowSocial = false, false, false
	if err := p.Validate(); err != nil {
		t.Fatalf("SSO-only environment refused: %v", err)
	}
	got, err := NewSignInPolicies(signInRepository{}).SignInPolicy(context.Background(), testBoundary().EnvironmentID)
	if err != nil || got.Custom || !reflect.DeepEqual(got, authentication.DefaultSignInPolicy()) {
		t.Fatalf("default: %+v %v", got, err)
	}
	p.AllowedFactors = []string{"totp", "fax"}
	if p.Validate() == nil {
		t.Fatal("unknown factor accepted")
	}
	p.AllowedFactors = nil
	if p.Validate() == nil {
		t.Fatal("no factor accepted")
	}
}

// A member's password expires with the shortest max age of the
// environment and their organizations.
func TestLoginMemberExpiry(t *testing.T) {
	env := authentication.DefaultPasswordPolicy()
	tx := &testTransaction{user: identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), changed: time.Now().Add(-10 * 24 * time.Hour)}
	s := New(testRepository{tx}, testPasswords{}, testSecrets{}, nil)
	s.SetPasswordPolicies(NewPasswordPolicies(policyRepository{policy: &env, member: []authentication.PasswordRequirements{{MaxAgeDays: 90}, {MaxAgeDays: 7}}}, nil))
	if _, err := s.Login(context.Background(), testBoundary(), "user@example.com", "password", ""); code(err) != authentication.CodePasswordChangeRequired {
		t.Fatalf("want PASSWORD_CHANGE_REQUIRED, got %v", err)
	}
}
