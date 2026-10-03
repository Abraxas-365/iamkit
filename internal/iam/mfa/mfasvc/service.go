// Package mfasvc implements second-factor enrollment, verification and the
// multi-factor step of logins.
package mfasvc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"slices"
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
	sender     mfa.Sender
	relying    mfa.Relying
	now        mfa.Clock
}

func New(repository mfa.Repository, totp mfa.TOTP, cipher mfa.Cipher, secrets mfa.Secrets, now mfa.Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{repository: repository, totp: totp, cipher: cipher, secrets: secrets, now: now}
}

// SetSender enables the email and SMS factors (nil: they cannot be used).
func (s *Service) SetSender(sender mfa.Sender) { s.sender = sender }

var (
	_ mfa.Logins                  = (*Service)(nil)
	_ mfa.Commands                = (*Service)(nil)
	_ mfa.Queries                 = (*Service)(nil)
	_ authentication.SecondFactor = (*Service)(nil)
)

func invalidCode() error { return mfa.ErrInvalidCode() }

// wrongCode answers a wrong code on an authenticated self-service route:
// 422, so clients do not mistake it for an expired access token.
func wrongCode() error {
	e := errx.Business("invalid verification code")
	e.Code = "INVALID_CODE"
	return e
}

func factorNotAllowed(kind string) error {
	e := errx.Business("the " + kind + " factor is not allowed here")
	e.Code = "FACTOR_NOT_ALLOWED"
	return e
}

// scope is which factors a code check accepts: the active factors of the
// prove kinds, unconfirmed factors of the confirm kinds (their first code
// enrolls them) and, with recovery, a recovery code.
type scope struct {
	prove    []string
	confirm  []string
	recovery bool
}

// selfScope accepts every active factor and recovery codes: a user proving
// possession to change their own factors.
var selfScope = scope{prove: mfa.Kinds, recovery: true}

// loginScope is what a login into a boundary accepts, given the first
// factor's references.
func loginScope(policy mfa.Policy, amr []string, enroll bool) scope {
	out := scope{prove: policy.Usable(amr)}
	out.recovery = len(out.prove) > 0
	if enroll {
		out.confirm = policy.Enrollable(amr)
	}
	return out
}

// ── Login step ───────────────────────────────────────────────────────

func (s *Service) Requirement(ctx context.Context, boundary authentication.Context, user identity.UserID, federated bool, amr []string) (authentication.Requirement, error) {
	policy, err := s.repository.Policy(ctx, boundary, user)
	if err != nil {
		return authentication.Requirement{}, err
	}
	req := policy.Requirement(federated, amr)
	// Without delivery, code factors can prove nothing; without a relying
	// party, neither can security keys.
	req.Factors = slices.DeleteFunc(req.Factors, func(k string) bool {
		return (s.sender == nil && (k == mfa.KindEmail || k == mfa.KindSMS)) || (!s.keys() && k == mfa.KindWebAuthn)
	})
	return req, nil
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

// pending locks a usable pending login.
func (s *Service) pending(ctx context.Context, tx mfa.Transaction, token string) (mfa.Pending, error) {
	hash, err := s.pendingHash(token)
	if err != nil {
		return mfa.Pending{}, err
	}
	p, err := tx.Pending(ctx, hash)
	if err != nil {
		return mfa.Pending{}, err
	}
	if p.Attempts >= config.MFAAttempts {
		return mfa.Pending{}, errx.Unauthorized("sign in again")
	}
	return p, nil
}

func (s *Service) Enroll(ctx context.Context, token string) (authentication.Enrollment, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	defer tx.Rollback()
	p, err := s.pending(ctx, tx, token)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	if !p.Enroll {
		return authentication.Enrollment{}, errx.Business("this login does not need enrollment")
	}
	policy, err := s.repository.Policy(ctx, p.Boundary, p.User)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	if !slices.Contains(policy.Enrollable(p.AMR), mfa.KindTOTP) {
		return authentication.Enrollment{}, factorNotAllowed(mfa.KindTOTP)
	}
	e, err := s.start(ctx, p.Boundary.EnvironmentID, p.User)
	return authentication.Enrollment{Secret: e.Secret, URI: e.URI}, err
}

// Challenge sends the code of a pending login's email or SMS factor; a
// login that must enroll may send one to the user's email address.
func (s *Service) Challenge(ctx context.Context, token, factor string) (authentication.CodeSent, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	defer tx.Rollback()
	p, err := s.pending(ctx, tx, token)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	out, err := s.challenge(ctx, tx, p.Boundary, p.User, p.AMR, factor, p.Enroll)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	return out, tx.Commit()
}

func (s *Service) Send(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, factor string, enroll bool) (authentication.CodeSent, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	defer tx.Rollback()
	out, err := s.challenge(ctx, tx, boundary, user, amr, factor, enroll)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	return out, tx.Commit()
}

// challenge sends a login code: to the user's active factor of kind when
// the login accepts it, or — when the login enrolls and may add kind (email
// only) — to a new unconfirmed factor.
func (s *Service) challenge(ctx context.Context, tx mfa.Transaction, boundary authentication.Context, user identity.UserID, amr []string, kind string, enroll bool) (authentication.CodeSent, error) {
	if kind != mfa.KindEmail && kind != mfa.KindSMS {
		return authentication.CodeSent{}, errx.Validation("factor must be email or sms")
	}
	if s.sender == nil {
		return authentication.CodeSent{}, factorNotAllowed(kind)
	}
	policy, err := s.repository.Policy(ctx, boundary, user)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	factors, err := tx.Factors(ctx, boundary.EnvironmentID, user)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	f, found := mfa.Find(factors, kind)
	switch {
	case found && f.Active() && slices.Contains(policy.Usable(amr), kind):
		return s.send(ctx, tx, boundary.EnvironmentID, user, f, mfa.PurposeLogin)
	case enroll && kind == mfa.KindEmail && slices.Contains(policy.Enrollable(amr), kind) && !(found && f.Active()):
		if f, err = tx.SaveCodeFactor(ctx, boundary.EnvironmentID, user, identity.NewFactorID(), kind, ""); err != nil {
			return authentication.CodeSent{}, err
		}
		return s.send(ctx, tx, boundary.EnvironmentID, user, f, mfa.PurposeLogin)
	}
	return authentication.CodeSent{}, factorNotAllowed(kind)
}

// send delivers a new code for an email or SMS factor and stores its hash.
// Delivery happens before the commit: a failed delivery keeps the previous
// code and does not count against the send limits.
func (s *Service) send(ctx context.Context, tx mfa.Transaction, environment identity.EnvironmentID, user identity.UserID, f mfa.Factor, purpose string) (authentication.CodeSent, error) {
	now := s.now()
	count, window, err := f.Send(now)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	code, err := sixDigits()
	if err != nil {
		return authentication.CodeSent{}, err
	}
	expires := now.Add(config.FactorCodeTTL)
	if err = tx.SetCode(ctx, f.ID, mfa.Code{Hash: s.codeHash(f.ID, code), Expires: expires, Sent: now, Count: count, Window: window}); err != nil {
		return authentication.CodeSent{}, err
	}
	out := authentication.CodeSent{Factor: f.Kind, ExpiresAt: expires.UTC()}
	if f.Kind == mfa.KindSMS {
		out.Destination = mfa.MaskPhone(f.Phone)
		err = s.sender.SMS(ctx, environment, f.Phone, purpose, code)
	} else {
		account, accountErr := s.repository.Account(ctx, environment, user)
		if accountErr != nil {
			return authentication.CodeSent{}, accountErr
		}
		out.Destination = mfa.MaskEmail(account.Email)
		err = s.sender.Email(ctx, environment, account.Email, purpose, code)
	}
	return out, err
}

// codeHash binds a sent code to its factor.
func (s *Service) codeHash(factor identity.FactorID, code string) []byte {
	return s.secrets.Hash(factor.String() + ":" + code)
}

func sixDigits() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", errx.Wrap(err, "generate verification code", errx.TypeInternal)
	}
	return fmt.Sprintf("%06d", n), nil
}

// Complete counts wrong codes against the pending login and consumes it on
// success or once the attempts run out. issue runs inside the verification:
// a login whose session cannot be created leaves the pending login, the
// factor and the recovery codes as they were.
func (s *Service) Complete(ctx context.Context, token string, proof authentication.Proof, issue func(done authentication.Completed) error) (authentication.Completed, error) {
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
	policy, err := s.repository.Policy(ctx, p.Boundary, p.User)
	if err != nil {
		return authentication.Completed{}, err
	}
	m := mfa.Mutation{Environment: p.Boundary.EnvironmentID, Actor: p.User.String(), Target: p.User.String()}
	v, ok, err := s.check(ctx, tx, m, p.User, proof, loginScope(policy, p.AMR, p.Enroll))
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

func (s *Service) Verify(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, proof authentication.Proof, enroll bool) (mfa.Verification, error) {
	policy, err := s.repository.Policy(ctx, boundary, user)
	if err != nil {
		return mfa.Verification{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return mfa.Verification{}, err
	}
	defer tx.Rollback()
	m := mfa.Mutation{Environment: boundary.EnvironmentID, Actor: user.String(), Target: user.String()}
	v, ok, err := s.check(ctx, tx, m, user, proof, loginScope(policy, amr, enroll))
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
			secret, err := s.cipher.Open(f.Sealed())
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
	e, err := s.start(ctx, environment, user)
	return authentication.Enrollment{Secret: e.Secret, URI: e.URI}, err
}

// check verifies a code inside tx; ok is false for a wrong code. An
// unconfirmed factor of a confirm kind is confirmed by its first code,
// returning the first recovery codes. Wrong codes count towards the user's
// lockout (shared by every factor) whichever flow they came from, so a new
// pending login or hosted ticket does not buy an attacker more guesses; the
// caller must commit tx when ok is false.
func (s *Service) check(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, proof authentication.Proof, sc scope) (mfa.Verification, bool, error) {
	factors, err := tx.Factors(ctx, m.Environment, user)
	if err != nil || len(factors) == 0 {
		return mfa.Verification{}, false, err
	}
	lock, err := tx.Lock(ctx, m.Environment, user)
	if err != nil {
		return mfa.Verification{}, false, err
	}
	now := s.now()
	active := mfa.AnyActive(factors)
	if lock.Locked(now) {
		e := errx.TooManyRequests("too many wrong verification codes; try again later")
		e.Code = "MFA_LOCKED"
		return mfa.Verification{}, false, e
	}
	var v mfa.Verification
	var ok bool
	if proof.WebAuthn() {
		v, ok, err = s.verifyKey(ctx, tx, m, user, factors, proof, sc)
	} else {
		v, ok, err = s.verify(ctx, tx, m, user, factors, mfa.NormalizeCode(proof.Code), sc)
	}
	if err != nil {
		return v, ok, err
	}
	if ok {
		if lock.Failures > 0 || lock.LockedUntil != nil {
			err = tx.SetLock(ctx, m.Environment, user, mfa.Lock{})
		}
		return v, ok, err
	}
	// A wrong code also counts against every live emailed or texted code,
	// which is dropped after config.MFAAttempts wrong entries.
	for _, f := range factors {
		if f.Coded() && f.CodeLive(now) {
			if err = tx.FailCode(ctx, f.ID, config.MFAAttempts); err != nil {
				return v, false, err
			}
		}
	}
	if !active {
		return v, false, nil
	}
	next := mfa.Lock{Failures: lock.Failures + 1}
	if d := mfa.Lockout(next.Failures, config.MFAFailures, config.MFALockout, config.MFALockoutMax); d > 0 {
		t := now.Add(d)
		next.LockedUntil = &t
		m.Action = mfa.ActionLocked
		if err = tx.Audit(ctx, m); err != nil {
			return v, false, err
		}
	}
	return v, false, tx.SetLock(ctx, m.Environment, user, next)
}

func (s *Service) verify(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, factors []mfa.Factor, code string, sc scope) (mfa.Verification, bool, error) {
	if code == "" {
		return mfa.Verification{}, false, nil
	}
	active := mfa.AnyActive(factors)
	if !mfa.IsTOTPCode(code) {
		if !active || !sc.recovery {
			return mfa.Verification{}, false, nil
		}
		used, err := tx.UseRecovery(ctx, m.Environment, user, s.secrets.Hash(code))
		if err != nil || !used {
			return mfa.Verification{}, false, err
		}
		m.Action = mfa.ActionRecovery
		return mfa.Verification{Proof: mfa.ProofRecovery}, true, tx.Audit(ctx, m)
	}
	now := s.now()
	for _, f := range factors {
		switch {
		case f.Active() && !slices.Contains(sc.prove, f.Kind):
			continue
		case !f.Active() && (!slices.Contains(sc.confirm, f.Kind) || !f.Enrollable(now)):
			continue
		}
		var proof string
		var step int64
		switch f.Kind {
		case mfa.KindTOTP:
			secret, err := s.cipher.Open(f.Sealed())
			if err != nil {
				return mfa.Verification{}, false, err
			}
			var valid bool
			if step, valid = s.totp.Verify(string(secret), code, f.LastStep, now); !valid {
				continue
			}
			proof = mfa.ProofTOTP
			if f.Active() {
				return mfa.Verification{Proof: proof}, true, tx.UseStep(ctx, f.ID, step)
			}
			if err = tx.Confirm(ctx, f.ID, step); err != nil {
				return mfa.Verification{}, false, err
			}
		case mfa.KindEmail, mfa.KindSMS:
			if !f.CodeLive(now) || subtle.ConstantTimeCompare(f.Code, s.codeHash(f.ID, code)) != 1 {
				continue
			}
			proof = mfa.ProofEmail
			if f.Kind == mfa.KindSMS {
				proof = mfa.ProofSMS
			}
			if f.Active() {
				return mfa.Verification{Proof: proof}, true, tx.UseCode(ctx, f.ID)
			}
			if err := tx.ConfirmCode(ctx, m.Environment, user, f.ID); err != nil {
				return mfa.Verification{}, false, err
			}
		default:
			continue
		}
		// Recovery codes come with the first confirmed factor; later factors
		// keep the codes the user already has.
		var codes []string
		if !active {
			var err error
			if codes, err = s.replaceRecovery(ctx, tx, m.Environment, user); err != nil {
				return mfa.Verification{}, false, err
			}
		}
		m.Action = mfa.ActionEnrolled
		return mfa.Verification{Proof: proof, RecoveryCodes: codes}, true, tx.Audit(ctx, m)
	}
	return mfa.Verification{}, false, nil
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

// kind defaults an omitted factor kind to TOTP (the only kind before
// email and SMS factors).
func kind(k string) (string, error) {
	switch k {
	case "":
		return mfa.KindTOTP, nil
	case mfa.KindTOTP, mfa.KindEmail, mfa.KindSMS:
		return k, nil
	}
	return "", errx.Validation("factor must be totp, email or sms")
}

// allowed checks that the environment and the boundary's organization let
// users add factors of kind (a zero organization reads the environment's
// rules only).
func (s *Service) allowed(ctx context.Context, boundary authentication.Context, user identity.UserID, kind string) error {
	policy, err := s.repository.Policy(ctx, boundary, user)
	if err != nil {
		return err
	}
	switch {
	case !slices.Contains(policy.Allowed, kind),
		(kind == mfa.KindEmail || kind == mfa.KindSMS) && s.sender == nil,
		kind == mfa.KindWebAuthn && !s.keys():
		return factorNotAllowed(kind)
	}
	return nil
}

// Start begins a self-service authenticator enrollment for a user signed in
// to boundary.
func (s *Service) Start(ctx context.Context, boundary authentication.Context, user identity.UserID) (mfa.Enrollment, error) {
	if boundary.EnvironmentID.IsZero() || user.IsZero() {
		return mfa.Enrollment{}, errx.Validation("user_id is required")
	}
	if err := s.allowed(ctx, boundary, user, mfa.KindTOTP); err != nil {
		return mfa.Enrollment{}, err
	}
	return s.start(ctx, boundary.EnvironmentID, user)
}

// start creates the unconfirmed TOTP factor; login enrollment checks the
// policy itself before calling it.
func (s *Service) start(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Enrollment, error) {
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

func (s *Service) StartCode(ctx context.Context, boundary authentication.Context, user identity.UserID, k, phone string) (authentication.CodeSent, error) {
	environment := boundary.EnvironmentID
	if environment.IsZero() || user.IsZero() {
		return authentication.CodeSent{}, errx.Validation("user_id is required")
	}
	if k != mfa.KindEmail && k != mfa.KindSMS {
		return authentication.CodeSent{}, errx.Validation("factor must be email or sms")
	}
	if k == mfa.KindSMS {
		var err error
		if phone, err = identity.Phone(phone); err != nil {
			return authentication.CodeSent{}, err
		}
	} else {
		phone = ""
	}
	if err := s.allowed(ctx, boundary, user, k); err != nil {
		return authentication.CodeSent{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	defer tx.Rollback()
	f, err := tx.SaveCodeFactor(ctx, environment, user, identity.NewFactorID(), k, phone)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	purpose := mfa.PurposeLogin
	if k == mfa.KindSMS {
		purpose = mfa.PurposePhone
	}
	out, err := s.send(ctx, tx, environment, user, f, purpose)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	return out, tx.Commit()
}

func (s *Service) Confirm(ctx context.Context, m mfa.Mutation, user identity.UserID, k, code string) ([]string, error) {
	k, err := kind(k)
	if err != nil {
		return nil, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	factors, err := tx.Factors(ctx, m.Environment, user)
	if err != nil {
		return nil, err
	}
	if factor, ok := mfa.Find(factors, k); !ok || factor.Active() {
		if k == mfa.KindTOTP {
			return nil, errx.Business("start an authenticator enrollment first")
		}
		return nil, errx.Business("start an " + k + " enrollment first")
	}
	code = mfa.NormalizeCode(code)
	if !mfa.IsTOTPCode(code) {
		return nil, wrongCode()
	}
	v, ok, err := s.check(ctx, tx, m, user, authentication.CodeProof(code), scope{confirm: []string{k}})
	if err != nil {
		return nil, err
	}
	if !ok {
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return nil, wrongCode()
	}
	return v.RecoveryCodes, tx.Commit()
}

// SendProof sends a code to an active email or SMS factor so the user can
// prove possession for a self-service change.
func (s *Service) SendProof(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, k string) (authentication.CodeSent, error) {
	if k != mfa.KindEmail && k != mfa.KindSMS {
		return authentication.CodeSent{}, errx.Validation("factor must be email or sms")
	}
	if s.sender == nil {
		return authentication.CodeSent{}, factorNotAllowed(k)
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	defer tx.Rollback()
	factors, err := tx.Factors(ctx, environment, user)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	f, found := mfa.Find(factors, k)
	if !found || !f.Active() {
		return authentication.CodeSent{}, errx.NotFound("no " + k + " factor is enrolled")
	}
	out, err := s.send(ctx, tx, environment, user, f, mfa.PurposeLogin)
	if err != nil {
		return authentication.CodeSent{}, err
	}
	return out, tx.Commit()
}

// proven checks a possession proof for a destructive self-service change.
// A wrong code fails the request but its lockout count is committed.
func (s *Service) proven(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, proof authentication.Proof) error {
	factors, err := tx.Factors(ctx, m.Environment, user)
	if err != nil {
		return err
	}
	if !mfa.AnyActive(factors) {
		return errx.NotFound("no authenticator is enrolled")
	}
	_, ok, err := s.check(ctx, tx, m, user, proof, selfScope)
	if err == nil && !ok {
		if err = tx.Commit(); err == nil {
			err = wrongCode()
		}
	}
	return err
}

// Remove deletes the user's factor of a kind. The recovery codes and
// lockout go with it when no other active factor remains.
func (s *Service) Remove(ctx context.Context, m mfa.Mutation, user identity.UserID, k string, proof authentication.Proof) error {
	k, err := kind(k)
	if err != nil {
		return err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.proven(ctx, tx, m, user, proof); err != nil {
		return err
	}
	factors, err := tx.Factors(ctx, m.Environment, user)
	if err != nil {
		return err
	}
	target, found := mfa.Find(factors, k)
	others := false
	for _, f := range factors {
		others = others || (f.Active() && f.ID != target.ID)
	}
	switch {
	case !found && k == mfa.KindTOTP:
		return errx.NotFound("no authenticator is enrolled")
	case !found:
		return errx.NotFound("no " + k + " factor is enrolled")
	case !others:
		_, err = tx.DeleteFactors(ctx, m.Environment, user)
	default:
		err = tx.DeleteFactor(ctx, m.Environment, user, target.ID)
	}
	if err != nil {
		return err
	}
	m.Action = mfa.ActionRemoved
	if err = tx.Audit(ctx, m); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Regenerate(ctx context.Context, m mfa.Mutation, user identity.UserID, proof authentication.Proof) ([]string, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.proven(ctx, tx, m, user, proof); err != nil {
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
