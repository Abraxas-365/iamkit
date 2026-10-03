package mfasvc

import (
	"context"
	"slices"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa/adapters/mfawebauthn/softkey"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

const origin = "https://iam.example"

var otherEnv = identity.MustParseEnvironmentID("33333333-3333-4333-8333-333333333333")

func setupKeys(t *testing.T) (*Service, *memory) {
	t.Helper()
	s, repo, _ := setup(t)
	repo.allowed = append(repo.allowed, mfa.KindWebAuthn)
	s.SetRelying(mfawebauthn.New(origin, nil))
	return s, repo
}

// registerKey registers a security key (or passkey) for the user.
func registerKey(t *testing.T, s *Service, name string, passkey bool) (*softkey.Key, mfa.Registration) {
	t.Helper()
	ctx := context.Background()
	start, err := s.StartWebAuthn(ctx, boundary, user, mfa.StartRegistration{Name: name, Passkey: passkey})
	if err != nil {
		t.Fatal(err)
	}
	key, answer, err := softkey.Create(start.Options, origin, passkey)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := s.FinishWebAuthn(ctx, mfa.Mutation{Environment: env}, user, start.Session, answer)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return key, reg
}

func TestSecurityKeyRegistrationAndLogin(t *testing.T) {
	s, repo := setupKeys(t)
	ctx := context.Background()
	key, reg := registerKey(t, s, " YubiKey ", false)
	if reg.Factor.Name != "YubiKey" || reg.Factor.Passkey || len(reg.RecoveryCodes) != 10 || !slices.Contains(repo.audits, mfa.ActionEnrolled) {
		t.Fatalf("registration %+v", reg)
	}
	// The ceremony is single use.
	start, _ := s.StartWebAuthn(ctx, boundary, user, mfa.StartRegistration{Name: "Second"})
	_, answer, _ := softkey.Create(start.Options, origin, false)
	if _, err := s.FinishWebAuthn(ctx, mfa.Mutation{Environment: env}, user, "ik_wa_unknown", answer); status(err) != 422 {
		t.Fatalf("unknown ceremony: %v", err)
	}

	// The login offers the key and accepts its assertion.
	req, err := s.Requirement(ctx, boundary, user, false, pwd)
	if err != nil || !slices.Contains(req.Factors, mfa.KindWebAuthn) {
		t.Fatalf("requirement %+v %v", req, err)
	}
	token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	options, err := s.Assert(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ = key.Get(options.Options, origin)
	done, err := s.Complete(ctx, token, authentication.Proof{Session: options.Session, Credential: answer}, nil)
	if err != nil || !slices.Equal(done.AMR, []string{"pwd", "hwk", "mfa"}) {
		t.Fatalf("complete %+v %v", done, err)
	}
	stored, _ := repo.factor(mfa.KindWebAuthn).WebAuthn()
	if stored.SignCount != 1 {
		t.Fatalf("counter not stored: %d", stored.SignCount)
	}

	// A replayed ceremony fails and counts as a wrong code.
	token, _ = s.Begin(ctx, boundary, user, pwd, false, "")
	if _, err = s.Complete(ctx, token, authentication.Proof{Session: options.Session, Credential: answer}, nil); status(err) != 401 || repo.lock.Failures != 1 {
		t.Fatalf("replay: %v (failures %d)", err, repo.lock.Failures)
	}

	// Rename, then remove with the key itself as proof.
	f, err := s.RenameWebAuthn(ctx, env, user, reg.Factor.ID, "Desk key")
	if err != nil || f.Name != "Desk key" {
		t.Fatalf("rename %+v %v", f, err)
	}
	if _, err = s.RenameWebAuthn(ctx, env, user, reg.Factor.ID, ""); status(err) != 400 {
		t.Fatalf("empty name: %v", err)
	}
	prove, err := s.ProveWebAuthn(ctx, env, user)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ = key.Get(prove.Options, origin)
	if err = s.RemoveWebAuthn(ctx, mfa.Mutation{Environment: env}, user, reg.Factor.ID, authentication.Proof{Session: prove.Session, Credential: answer}); err != nil || len(repo.factors) != 0 || len(repo.recovery) != 0 {
		t.Fatalf("remove: %v %+v", err, repo.factors)
	}
}

// A counter that goes backwards means a cloned key: refused and audited.
func TestCloneDetection(t *testing.T) {
	s, repo := setupKeys(t)
	ctx := context.Background()
	key, _ := registerKey(t, s, "Key", false)
	f := repo.factor(mfa.KindWebAuthn)
	c, _ := f.WebAuthn()
	c.SignCount = 50
	_ = repo.UseWebAuthn(ctx, f.ID, c)
	token, _ := s.Begin(ctx, boundary, user, pwd, false, "")
	options, _ := s.Assert(ctx, token)
	answer, _ := key.Get(options.Options, origin)
	if _, err := s.Complete(ctx, token, authentication.Proof{Session: options.Session, Credential: answer}, nil); status(err) != 401 {
		t.Fatalf("clone accepted: %v", err)
	}
	if !slices.Contains(repo.audits, mfa.ActionCloneDetected) {
		t.Fatalf("audits %v", repo.audits)
	}
	if stored, _ := repo.factor(mfa.KindWebAuthn).WebAuthn(); stored.SignCount != 50 {
		t.Fatal("a cloned key's counter must not move")
	}
}

func TestPasskeySignIn(t *testing.T) {
	s, repo := setupKeys(t)
	ctx := context.Background()
	// A plain security key cannot sign in without a password.
	plainKey, _ := registerKey(t, s, "Key", false)
	options, err := s.BeginPasskey(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := plainKey.Get(options.Options, origin)
	if _, err = s.FinishPasskey(ctx, env, options.Session, answer); status(err) != 401 {
		t.Fatalf("security key as passkey: %v", err)
	}

	passkey, reg := registerKey(t, s, "Phone", true)
	if !reg.Factor.Passkey || len(reg.RecoveryCodes) != 0 {
		t.Fatalf("passkey registration %+v", reg)
	}
	options, _ = s.BeginPasskey(ctx, env)
	answer, _ = passkey.Get(options.Options, origin)
	got, err := s.FinishPasskey(ctx, env, options.Session, answer)
	if err != nil || got != user {
		t.Fatalf("passkey sign-in %v %v", got, err)
	}
	if _, err = s.FinishPasskey(ctx, env, options.Session, answer); status(err) != 401 {
		t.Fatal("passkey ceremony reused")
	}
	// Another environment's ceremony does not answer here.
	options, _ = s.BeginPasskey(ctx, env)
	answer, _ = passkey.Get(options.Options, origin)
	if _, err = s.FinishPasskey(ctx, otherEnv, options.Session, answer); status(err) != 401 {
		t.Fatalf("foreign environment: %v", err)
	}

	// Without the webauthn kind allowed, passkeys are off.
	repo.allowed = []string{mfa.KindTOTP}
	if _, err = s.BeginPasskey(ctx, env); errCode(err) != "FACTOR_NOT_ALLOWED" {
		t.Fatalf("webauthn not allowed: %v", err)
	}
}

func TestWebAuthnUnavailable(t *testing.T) {
	s, repo, _ := setup(t)
	repo.allowed = append(repo.allowed, mfa.KindWebAuthn)
	s.SetRelying(mfawebauthn.New("", nil))
	if _, err := s.StartWebAuthn(context.Background(), boundary, user, mfa.StartRegistration{Name: "Key"}); err == nil {
		t.Fatal("registration without a relying party")
	}
	if _, err := s.BeginPasskey(context.Background(), env); err == nil {
		t.Fatal("passkey without a relying party")
	}
}
