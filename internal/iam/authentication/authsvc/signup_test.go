package authsvc

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// signupStore is an in-memory SignupRepository.
type signupStore struct {
	methods  authentication.Methods
	exists   bool
	recent   int
	sso      bool
	pending  map[identity.ChallengeID]*authentication.PendingSignup
	joined   []authentication.Joining
	joinErr  error
	commits  int
	failures int
}

func newSignupStore() *signupStore {
	return &signupStore{methods: authentication.Methods{Password: true, EmailCode: true, Social: true}, pending: map[identity.ChallengeID]*authentication.PendingSignup{}}
}

func (s *signupStore) BeginSignup(context.Context) (authentication.SignupTransaction, error) {
	return &signupTx{store: s, created: map[identity.ChallengeID]*authentication.PendingSignup{}}, nil
}

type signupTx struct {
	store     *signupStore
	created   map[identity.ChallengeID]*authentication.PendingSignup
	failed    []identity.ChallengeID
	joined    []authentication.Joining
	committed bool
}

func (t *signupTx) AccountExists(context.Context, identity.EnvironmentID, string) (bool, error) {
	return t.store.exists, nil
}
func (t *signupTx) RecentSignups(context.Context, identity.EnvironmentID, string) (int, error) {
	return t.store.recent, nil
}
func (t *signupTx) CreateSignup(_ context.Context, s authentication.PendingSignup) error {
	t.created[s.ID] = &s
	return nil
}
func (t *signupTx) PendingSignup(_ context.Context, _ identity.EnvironmentID, signup identity.ChallengeID) (authentication.PendingSignup, error) {
	p, ok := t.store.pending[signup]
	if !ok || time.Now().After(p.Expires) {
		return authentication.PendingSignup{}, errx.Unauthorized("invalid challenge")
	}
	return *p, nil
}
func (t *signupTx) FailSignup(_ context.Context, signup identity.ChallengeID) error {
	t.failed = append(t.failed, signup)
	return nil
}
func (t *signupTx) Join(_ context.Context, j authentication.Joining) error {
	if t.store.joinErr != nil {
		return t.store.joinErr
	}
	t.joined = append(t.joined, j)
	return nil
}
func (t *signupTx) SSORequired(context.Context, identity.EnvironmentID, string) (bool, error) {
	return t.store.sso, nil
}
func (t *signupTx) SignupMethods(context.Context, identity.EnvironmentID, identity.OrganizationID) (authentication.Methods, error) {
	return t.store.methods, nil
}
func (t *signupTx) Commit() error {
	t.committed = true
	t.store.commits++
	for id, p := range t.created {
		t.store.pending[id] = p
	}
	for _, id := range t.failed {
		t.store.pending[id].Attempts++
		t.store.failures++
	}
	for _, j := range t.joined {
		delete(t.store.pending, j.Signup)
		t.store.joined = append(t.store.joined, j)
	}
	return nil
}
func (t *signupTx) Rollback() error { return nil }

var (
	signupOrg   = identity.MustParseOrganizationID("11111111-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	signupGroup = identity.MustParseGroupID("22222222-bbbb-4ccc-8ddd-eeeeeeeeeeee")
)

func signupPolicy() authentication.SignInPolicy {
	p := authentication.DefaultSignInPolicy()
	p.AllowSignup, p.SignupOrganization, p.SignupGroup = true, signupOrg, signupGroup
	return p
}

func signupService(store *signupStore, policy authentication.SignInPolicy, delivery authentication.Delivery) *Service {
	s := withSignIn(New(testRepository{&testTransaction{}}, testPasswords{}, testSecrets{}, delivery), policy)
	s.SetSignups(store)
	return s
}

func signupInput() authentication.Signup {
	return authentication.Signup{Environment: testBoundary().EnvironmentID, Email: "New@Example.com", Name: " Ada ", Password: "a long enough password"}
}

// message is the errx message of err ("" otherwise).
func message(err error) string {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Message
	}
	return ""
}

// A sign-up emails a code and parks the account; the code creates it in
// the sign-up organization and group.
func TestSignup(t *testing.T) {
	store := newSignupStore()
	delivery := &recordingDelivery{}
	s := signupService(store, signupPolicy(), delivery)
	env := testBoundary().EnvironmentID
	id, err := s.Signup(context.Background(), signupInput())
	if err != nil {
		t.Fatal(err)
	}
	s.WaitDeliveries(time.Second)
	pending := store.pending[id]
	if pending == nil || pending.Email != "new@example.com" || pending.Name != "Ada" || pending.PasswordHash != "hash" {
		t.Fatalf("pending: %+v", pending)
	}
	if len(delivery.got) != 1 || delivery.got[0].Purpose != authentication.PurposeEmailVerification || delivery.got[0].Code != "12345678" {
		t.Fatalf("delivery: %+v", delivery.got)
	}
	if _, err = s.CompleteSignup(context.Background(), env, id, "87654321"); err == nil || store.failures != 1 {
		t.Fatalf("wrong code: %v failures=%d", err, store.failures)
	}
	out, err := s.CompleteSignup(context.Background(), env, id, "12345678")
	if err != nil {
		t.Fatal(err)
	}
	if out.Organization != signupOrg || out.Email != "new@example.com" || out.Method != authentication.MethodPassword || out.User.IsZero() {
		t.Fatalf("signed up: %+v", out)
	}
	if len(store.joined) != 1 || store.joined[0].Group != signupGroup || store.joined[0].User != out.User || store.joined[0].PasswordHash != "hash" {
		t.Fatalf("joined: %+v", store.joined)
	}
	if v := out.Verified(); v.User != out.User || v.Method != authentication.MethodPassword {
		t.Fatalf("verified: %+v", v)
	}
}

// Without a password the account signs in with email codes, when allowed.
func TestSignupPasswordless(t *testing.T) {
	store := newSignupStore()
	s := signupService(store, signupPolicy(), &recordingDelivery{})
	input := signupInput()
	input.Password = ""
	id, err := s.Signup(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.CompleteSignup(context.Background(), input.Environment, id, "12345678")
	if err != nil || out.Method != authentication.MethodCode || store.joined[0].PasswordHash != "" {
		t.Fatalf("%+v %v", out, err)
	}
	store.methods = authentication.Methods{Password: true}
	if _, err = s.Signup(context.Background(), input); message(err) != "password is required" {
		t.Fatalf("email codes refused: %v", err)
	}
}

// An email with an account gets the same answer and no email.
func TestSignupExistingAccount(t *testing.T) {
	store := newSignupStore()
	store.exists = true
	delivery := &recordingDelivery{}
	s := signupService(store, signupPolicy(), delivery)
	id, err := s.Signup(context.Background(), signupInput())
	if err != nil || id.IsZero() || len(delivery.got) != 0 || len(store.pending) != 0 {
		t.Fatalf("id=%v err=%v sent=%d pending=%d", id, err, len(delivery.got), len(store.pending))
	}
	store.exists, store.recent = false, 5
	if id, err = s.Signup(context.Background(), signupInput()); err != nil || id.IsZero() || len(delivery.got) != 0 {
		t.Fatalf("rate limited: %v sent=%d", err, len(delivery.got))
	}
}

// Sign-up off (or without a method for the account) answers
// SIGNUP_DISABLED before anything else; so does a sign-up in flight when
// it is turned off.
func TestSignupDisabled(t *testing.T) {
	env := testBoundary().EnvironmentID
	off := signupPolicy()
	off.AllowSignup = false
	store := newSignupStore()
	s := signupService(store, off, &recordingDelivery{})
	if _, err := s.Signup(context.Background(), authentication.Signup{Environment: env}); code(err) != authentication.CodeSignupDisabled {
		t.Fatalf("off: %v", err)
	}
	if _, err := s.CompleteSignup(context.Background(), env, identity.NewChallengeID(), "12345678"); code(err) != authentication.CodeSignupDisabled {
		t.Fatalf("off verify: %v", err)
	}
	store.methods = authentication.Methods{Social: true}
	s = signupService(store, signupPolicy(), &recordingDelivery{})
	if _, err := s.Signup(context.Background(), signupInput()); code(err) != authentication.CodeSignupDisabled {
		t.Fatalf("organization without methods: %v", err)
	}
	unwired := withSignIn(New(testRepository{&testTransaction{}}, testPasswords{}, testSecrets{}, testDelivery{}), signupPolicy())
	if _, err := unwired.Signup(context.Background(), signupInput()); code(err) != authentication.CodeSignupDisabled {
		t.Fatalf("unwired: %v", err)
	}
}

// A password where the organization refuses passwords is a bad request;
// an enforced-SSO domain is sent to its SSO.
func TestSignupRefusals(t *testing.T) {
	store := newSignupStore()
	store.methods = authentication.Methods{EmailCode: true}
	s := signupService(store, signupPolicy(), &recordingDelivery{})
	if _, err := s.Signup(context.Background(), signupInput()); err == nil || code(err) == authentication.CodeSignupDisabled {
		t.Fatalf("password refused: %v", err)
	}
	store.methods, store.sso = authentication.Methods{Password: true, EmailCode: true}, true
	if _, err := s.Signup(context.Background(), signupInput()); code(err) != "SSO_REQUIRED" {
		t.Fatalf("sso: %v", err)
	}
	input := signupInput()
	input.Name = " "
	store.sso = false
	if _, err := s.Signup(context.Background(), input); message(err) != "name is required" {
		t.Fatalf("name: %v", err)
	}
}

// Five wrong codes end the sign-up; an email taken meanwhile answers
// ACCOUNT_EXISTS.
func TestCompleteSignupLimits(t *testing.T) {
	store := newSignupStore()
	s := signupService(store, signupPolicy(), &recordingDelivery{})
	env := testBoundary().EnvironmentID
	id, err := s.Signup(context.Background(), signupInput())
	if err != nil {
		t.Fatal(err)
	}
	store.pending[id].Attempts = 5
	if _, err = s.CompleteSignup(context.Background(), env, id, "12345678"); err == nil || len(store.joined) != 0 {
		t.Fatalf("spent: %v", err)
	}
	store.pending[id].Attempts = 0
	store.joinErr = authentication.ErrAccountExists()
	if _, err = s.CompleteSignup(context.Background(), env, id, "12345678"); code(err) != authentication.CodeAccountExists {
		t.Fatalf("taken: %v", err)
	}
	if _, err = s.CompleteSignup(context.Background(), env, id, "123"); err == nil {
		t.Fatal("short code accepted")
	}
}

func TestSignupValidate(t *testing.T) {
	ok := signupInput()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*authentication.Signup){
		"email":    func(s *authentication.Signup) { s.Email = "nope" },
		"name":     func(s *authentication.Signup) { s.Name = "" },
		"long":     func(s *authentication.Signup) { s.Name = string(make([]rune, 201)) },
		"password": func(s *authentication.Signup) { s.Password = string(make([]byte, 73)) },
	} {
		in := signupInput()
		change(&in)
		if err := in.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSignInPolicySignupValidate(t *testing.T) {
	p := authentication.DefaultSignInPolicy()
	p.AllowSignup = true
	if p.Validate() == nil {
		t.Fatal("signup without organization accepted")
	}
	p.SignupOrganization = signupOrg
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.AllowPassword, p.AllowPasswordReset, p.AllowEmailCode = false, false, false
	if p.Validate() == nil {
		t.Fatal("signup without a method accepted")
	}
	p = authentication.DefaultSignInPolicy()
	p.SignupGroup = signupGroup
	if p.Validate() == nil {
		t.Fatal("group without organization accepted")
	}
}
