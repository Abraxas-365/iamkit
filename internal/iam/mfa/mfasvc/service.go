// Package mfasvc implements second-factor enrollment, verification and the
// multi-factor step of logins.
package mfasvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository mfa.Repository
	totp       mfa.TOTP
	cipher     mfa.Cipher
	secrets    mfa.Secrets
	now        mfa.Clock
}

func New(repository mfa.Repository, totp mfa.TOTP, cipher mfa.Cipher, secrets mfa.Secrets, now mfa.Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, totp: totp, cipher: cipher, secrets: secrets, now: now}
}

var (
	_ mfa.Logins                  = (*Service)(nil)
	_ mfa.Commands                = (*Service)(nil)
	_ mfa.Queries                 = (*Service)(nil)
	_ authentication.SecondFactor = (*Service)(nil)
)

func invalidCode() error { return errx.Unauthorized("invalid verification code") }

// wrongCode answers a wrong code on an authenticated self-service route:
// 422, so clients do not mistake it for an expired access token.
func wrongCode() error {
	e := errx.Business("invalid verification code")
	e.Code = "INVALID_CODE"
	return e
}

// ── Login step ───────────────────────────────────────────────────────

func (s *Service) Requirement(ctx context.Context, boundary authentication.Context, user identity.UserID, federated bool) (authentication.Requirement, error) {
	policy, err := s.repository.Policy(ctx, boundary, user)
	if err != nil {
		return authentication.Requirement{}, err
	}
	return policy.Requirement(federated), nil
}

func (s *Service) Begin(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, enroll bool, passwordHash string) (string, error) {
	raw, hash, err := s.secrets.Generate("ik_mfa_")
	if err != nil {
		return "", err
	}
	err = s.repository.SavePending(ctx, hash, mfa.Pending{Boundary: boundary, User: user, AMR: amr, Enroll: enroll, Expires: s.now().Add(config.MFALoginTTL), PasswordHash: passwordHash})
	return raw, err
}

func (s *Service) pendingHash(token string) ([]byte, error) {
	if !strings.HasPrefix(token, "ik_mfa_") {
		return nil, errx.Unauthorized("sign in again")
	}
	return s.secrets.Hash(token), nil
}

func (s *Service) Enroll(ctx context.Context, token string) (authentication.Enrollment, error) {
	hash, err := s.pendingHash(token)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	defer tx.Rollback()
	p, err := tx.Pending(ctx, hash)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	if !p.Enroll {
		return authentication.Enrollment{}, errx.Business("this login does not need enrollment")
	}
	if p.Attempts >= config.MFAAttempts {
		return authentication.Enrollment{}, errx.Unauthorized("sign in again")
	}
	e, err := s.Start(ctx, p.Boundary.EnvironmentID, p.User)
	return authentication.Enrollment{Secret: e.Secret, URI: e.URI}, err
}

// Complete counts wrong codes against the pending login and consumes it on
// success or once the attempts run out. issue runs inside the verification:
// a login whose session cannot be created leaves the pending login, the
// factor and the recovery codes as they were.
func (s *Service) Complete(ctx context.Context, token, code string, issue func(done authentication.Completed) error) (authentication.Completed, error) {
	hash, err := s.pendingHash(token)
	if err != nil {
		return authentication.Completed{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Completed{}, err
	}
	defer tx.Rollback()
	p, err := tx.Pending(ctx, hash)
	if err != nil {
		return authentication.Completed{}, err
	}
	if p.Attempts >= config.MFAAttempts {
		if err = tx.DeletePending(ctx, hash); err == nil {
			err = tx.Commit()
		}
		if err != nil {
			return authentication.Completed{}, err
		}
		return authentication.Completed{}, errx.Unauthorized("sign in again")
	}
	m := mfa.Mutation{Environment: p.Boundary.EnvironmentID, Actor: p.User.String(), Target: p.User.String()}
	v, ok, err := s.check(ctx, tx, m, p.User, code, p.Enroll)
	if err != nil {
		return authentication.Completed{}, err
	}
	if !ok {
		if err = tx.FailPending(ctx, hash); err == nil {
			err = tx.Commit()
		}
		if err != nil {
			return authentication.Completed{}, err
		}
		return authentication.Completed{}, invalidCode()
	}
	if err = tx.DeletePending(ctx, hash); err != nil {
		return authentication.Completed{}, err
	}
	done := authentication.Completed{Boundary: p.Boundary, User: p.User, AMR: append(append([]string{}, p.AMR...), mfa.AMR(v.Proof)...), RecoveryCodes: v.RecoveryCodes, PasswordHash: p.PasswordHash}
	if issue != nil {
		// issue commits its own session transaction while this one (and a
		// pooled connection) stays open. Should the commit below then fail,
		// an unused session is left behind; its tokens were never returned.
		if err = issue(done); err != nil {
			return authentication.Completed{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return authentication.Completed{}, err
	}
	return done, nil
}

func (s *Service) Verify(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, code string, enroll bool) (mfa.Verification, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return mfa.Verification{}, err
	}
	defer tx.Rollback()
	v, ok, err := s.check(ctx, tx, mfa.Mutation{Environment: environment, Actor: user.String(), Target: user.String()}, user, code, enroll)
	if err != nil {
		return mfa.Verification{}, err
	}
	if !ok {
		if err = tx.Commit(); err != nil {
			return mfa.Verification{}, err
		}
		return mfa.Verification{}, invalidCode()
	}
	return v, tx.Commit()
}

// Enrolling returns the authenticator a login enrolls: the unconfirmed
// factor recently shown (the page may be rendered again, e.g. after a wrong
// code, and the user has scanned it), else a new one.
func (s *Service) Enrolling(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.Enrollment, error) {
	summary, err := s.repository.Summary(ctx, environment, user)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	for _, f := range summary.Factors {
		if f.Kind == mfa.KindTOTP && f.Enrollable(s.now()) && s.cipher != nil && s.cipher.Enabled() {
			secret, err := s.cipher.Open(f.Secret)
			if err != nil {
				return authentication.Enrollment{}, err
			}
			account, err := s.repository.Account(ctx, environment, user)
			if err != nil {
				return authentication.Enrollment{}, err
			}
			return authentication.Enrollment{Secret: string(secret), URI: s.totp.URI(string(secret), account)}, nil
		}
	}
	e, err := s.Start(ctx, environment, user)
	return authentication.Enrollment{Secret: e.Secret, URI: e.URI}, err
}

// check verifies a TOTP or recovery code inside tx; ok is false for a
// wrong code. With confirm, an unconfirmed factor is confirmed by its first
// code, returning the first recovery codes. Wrong codes against an active
// factor count towards its lockout whichever flow they came from, so a new
// pending login or hosted ticket does not buy an attacker more guesses; the
// caller must commit tx when ok is false.
func (s *Service) check(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, raw string, confirm bool) (mfa.Verification, bool, error) {
	code := mfa.NormalizeCode(raw)
	factor, found, err := tx.Factor(ctx, m.Environment, user)
	if err != nil || !found {
		return mfa.Verification{}, false, err
	}
	now := s.now()
	if factor.Active() && factor.Locked(now) {
		e := errx.TooManyRequests("too many wrong verification codes; try again later")
		e.Code = "MFA_LOCKED"
		return mfa.Verification{}, false, e
	}
	v, ok, err := s.verify(ctx, tx, m, user, factor, code, confirm)
	if err != nil || !factor.Active() {
		return v, ok, err
	}
	if ok {
		if factor.Failures > 0 || factor.LockedUntil != nil {
			err = tx.SetFailures(ctx, factor.ID, 0, nil)
		}
		return v, ok, err
	}
	failures := factor.Failures + 1
	var until *time.Time
	if d := mfa.Lockout(failures, config.MFAFailures, config.MFALockout, config.MFALockoutMax); d > 0 {
		t := now.Add(d)
		until = &t
		m.Action = mfa.ActionLocked
		if err = tx.Audit(ctx, m); err != nil {
			return v, false, err
		}
	}
	return v, false, tx.SetFailures(ctx, factor.ID, failures, until)
}

func (s *Service) verify(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, factor mfa.Factor, code string, confirm bool) (mfa.Verification, bool, error) {
	if code == "" {
		return mfa.Verification{}, false, nil
	}
	if !mfa.IsTOTPCode(code) {
		if !factor.Active() {
			return mfa.Verification{}, false, nil
		}
		used, err := tx.UseRecovery(ctx, m.Environment, user, s.secrets.Hash(code))
		if err != nil || !used {
			return mfa.Verification{}, false, err
		}
		m.Action = mfa.ActionRecovery
		return mfa.Verification{Proof: mfa.ProofRecovery}, true, tx.Audit(ctx, m)
	}
	if !factor.Active() && (!confirm || !factor.Enrollable(s.now())) {
		return mfa.Verification{}, false, nil
	}
	secret, err := s.cipher.Open(factor.Secret)
	if err != nil {
		return mfa.Verification{}, false, err
	}
	step, valid := s.totp.Verify(string(secret), code, factor.LastStep, s.now())
	if !valid {
		return mfa.Verification{}, false, nil
	}
	if factor.Active() {
		return mfa.Verification{Proof: mfa.ProofTOTP}, true, tx.UseStep(ctx, factor.ID, step)
	}
	if err = tx.Confirm(ctx, factor.ID, step); err != nil {
		return mfa.Verification{}, false, err
	}
	codes, err := s.replaceRecovery(ctx, tx, m.Environment, user)
	if err != nil {
		return mfa.Verification{}, false, err
	}
	m.Action = mfa.ActionEnrolled
	return mfa.Verification{Proof: mfa.ProofTOTP, RecoveryCodes: codes}, true, tx.Audit(ctx, m)
}

// replaceRecovery issues a new set of recovery codes: 10 groups of
// base32-ish characters, e.g. "k3pq-7xnm-2dfa".
func (s *Service) replaceRecovery(ctx context.Context, tx mfa.Transaction, environment identity.EnvironmentID, user identity.UserID) ([]string, error) {
	codes := make([]string, 0, config.RecoveryCodes)
	hashes := make([][]byte, 0, config.RecoveryCodes)
	for range config.RecoveryCodes {
		code, err := s.recoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, s.secrets.Hash(mfa.NormalizeCode(code)))
	}
	return codes, tx.ReplaceRecovery(ctx, environment, user, hashes)
}

func (s *Service) recoveryCode() (string, error) {
	raw, _, err := s.secrets.Generate("")
	if err != nil {
		return "", err
	}
	// raw is base64url of 32 random bytes; keep 12 lowercase letters/digits.
	var b strings.Builder
	for _, r := range strings.ToLower(raw) {
		if (r >= 'a' && r <= 'z') || (r >= '2' && r <= '9') {
			if r == 'l' || r == 'o' {
				continue
			}
			b.WriteRune(r)
			if b.Len() == 14 {
				break
			}
			if b.Len() == 4 || b.Len() == 9 {
				b.WriteByte('-')
			}
		}
	}
	if b.Len() < 14 {
		return s.recoveryCode()
	}
	return b.String(), nil
}

// ── Self-service and operator ────────────────────────────────────────

func (s *Service) Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Summary, error) {
	if environment.IsZero() || user.IsZero() {
		return mfa.Summary{}, errx.Validation("user_id is required")
	}
	return s.repository.Summary(ctx, environment, user)
}

func (s *Service) Start(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Enrollment, error) {
	if environment.IsZero() || user.IsZero() {
		return mfa.Enrollment{}, errx.Validation("user_id is required")
	}
	if s.cipher == nil || !s.cipher.Enabled() {
		return mfa.Enrollment{}, errx.Business("multi-factor authentication needs IAMKIT_ENCRYPTION_KEY")
	}
	account, err := s.repository.Account(ctx, environment, user)
	if err != nil {
		return mfa.Enrollment{}, err
	}
	secret, err := s.totp.Secret()
	if err != nil {
		return mfa.Enrollment{}, err
	}
	sealed, err := s.cipher.Seal([]byte(secret))
	if err != nil {
		return mfa.Enrollment{}, err
	}
	id := identity.NewFactorID()
	if err = s.repository.SaveUnconfirmed(ctx, environment, user, id, sealed); err != nil {
		return mfa.Enrollment{}, err
	}
	return mfa.Enrollment{Factor: id, Secret: secret, URI: s.totp.URI(secret, account)}, nil
}

func (s *Service) Confirm(ctx context.Context, m mfa.Mutation, user identity.UserID, code string) ([]string, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	factor, ok, err := tx.Factor(ctx, m.Environment, user)
	if err != nil {
		return nil, err
	}
	if !ok || factor.Active() {
		return nil, errx.Business("start an authenticator enrollment first")
	}
	code = mfa.NormalizeCode(code)
	if !mfa.IsTOTPCode(code) {
		return nil, wrongCode()
	}
	v, ok, err := s.check(ctx, tx, m, user, code, true)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, wrongCode()
	}
	return v.RecoveryCodes, tx.Commit()
}

// proven checks a possession proof for a destructive self-service change.
// A wrong code fails the request but its lockout count is committed.
func (s *Service) proven(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, code string) error {
	factor, ok, err := tx.Factor(ctx, m.Environment, user)
	if err != nil {
		return err
	}
	if !ok || !factor.Active() {
		return errx.NotFound("no authenticator is enrolled")
	}
	_, ok, err = s.check(ctx, tx, m, user, code, false)
	if err == nil && !ok {
		if err = tx.Commit(); err == nil {
			err = wrongCode()
		}
	}
	return err
}

func (s *Service) Remove(ctx context.Context, m mfa.Mutation, user identity.UserID, code string) error {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.proven(ctx, tx, m, user, code); err != nil {
		return err
	}
	if _, err = tx.DeleteFactors(ctx, m.Environment, user); err != nil {
		return err
	}
	m.Action = mfa.ActionRemoved
	if err = tx.Audit(ctx, m); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Regenerate(ctx context.Context, m mfa.Mutation, user identity.UserID, code string) ([]string, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.proven(ctx, tx, m, user, code); err != nil {
		return nil, err
	}
	codes, err := s.replaceRecovery(ctx, tx, m.Environment, user)
	if err != nil {
		return nil, err
	}
	m.Action = mfa.ActionRegenerated
	if err = tx.Audit(ctx, m); err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

func (s *Service) Reset(ctx context.Context, m mfa.Mutation, user identity.UserID) error {
	if user.IsZero() {
		return errx.Validation("user_id is required")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	removed, err := tx.DeleteFactors(ctx, m.Environment, user)
	if err != nil {
		return err
	}
	if !removed {
		return errx.NotFound("user has no factors")
	}
	m.Action = mfa.ActionReset
	if err = tx.Audit(ctx, m); err != nil {
		return err
	}
	return tx.Commit()
}
