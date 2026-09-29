package mfasvc

import (
	"context"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var _ mfa.Passkeys = (*Service)(nil)

// SetRelying enables security keys and passkeys (nil: unavailable).
func (s *Service) SetRelying(relying mfa.Relying) { s.relying = relying }

func (s *Service) keys() bool { return s.relying != nil && s.relying.Enabled() }

// ceremony stores a started ceremony under a new ik_wa_ id.
func (s *Service) ceremony(ctx context.Context, c mfa.Ceremony, options []byte) (authentication.WebAuthnOptions, error) {
	raw, hash, err := s.secrets.Generate("ik_wa_")
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	c.Expires = s.now().Add(config.WebAuthnCeremonyTTL)
	if err = s.repository.SaveCeremony(ctx, hash, c); err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return authentication.WebAuthnOptions{Session: raw, Options: options, ExpiresAt: c.Expires.UTC()}, nil
}

// take consumes a ceremony of the environment and purpose; false for an
// unknown, expired or foreign one.
func (s *Service) take(ctx context.Context, tx mfa.Transaction, environment identity.EnvironmentID, session, purpose string) (mfa.Ceremony, bool, error) {
	if !strings.HasPrefix(session, "ik_wa_") {
		return mfa.Ceremony{}, false, nil
	}
	return tx.TakeCeremony(ctx, s.secrets.Hash(session), environment, purpose)
}

// StartWebAuthn begins registering a key: the environment must allow the
// webauthn factor and the user may hold config.WebAuthnKeys keys.
func (s *Service) StartWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, input mfa.StartRegistration) (authentication.WebAuthnOptions, error) {
	if environment.IsZero() || user.IsZero() {
		return authentication.WebAuthnOptions{}, errx.Validation("user_id is required")
	}
	if err := input.Validate(); err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	input = input.Normalized()
	if err := s.allowed(ctx, environment, mfa.KindWebAuthn); err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	summary, err := s.repository.Summary(ctx, environment, user)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	count := 0
	for _, f := range summary.Factors {
		if f.Kind == mfa.KindWebAuthn {
			count++
		}
	}
	if count >= config.WebAuthnKeys {
		return authentication.WebAuthnOptions{}, errx.Business("too many security keys; remove one first")
	}
	account, err := s.repository.Account(ctx, environment, user)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	ch, err := s.relying.Register(mfa.HolderFor(user, account, summary.Factors, false), input.Passkey)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.ceremony(ctx, mfa.Ceremony{Environment: environment, User: user, Purpose: mfa.CeremonyRegister, State: ch.State, Name: input.Name, Passkey: input.Passkey}, ch.Options)
}

// FinishWebAuthn verifies the attestation and stores the key, confirmed.
// A failed attestation still consumes the ceremony.
func (s *Service) FinishWebAuthn(ctx context.Context, m mfa.Mutation, user identity.UserID, session string, credential []byte) (mfa.Registration, error) {
	if !s.keys() {
		return mfa.Registration{}, mfa.ErrWebAuthnUnavailable()
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return mfa.Registration{}, err
	}
	defer tx.Rollback()
	c, found, err := s.take(ctx, tx, m.Environment, session, mfa.CeremonyRegister)
	if err != nil {
		return mfa.Registration{}, err
	}
	if !found || c.User != user {
		return mfa.Registration{}, errx.Business("start a security key registration first")
	}
	factors, err := tx.Factors(ctx, m.Environment, user)
	if err != nil {
		return mfa.Registration{}, err
	}
	account, err := s.repository.Account(ctx, m.Environment, user)
	if err != nil {
		return mfa.Registration{}, err
	}
	created, err := s.relying.Created(mfa.HolderFor(user, account, factors, false), c.State, credential)
	if err != nil {
		if cerr := tx.Commit(); cerr != nil {
			return mfa.Registration{}, cerr
		}
		return mfa.Registration{}, keyRejected()
	}
	now := s.now()
	f := mfa.Factor{ID: identity.NewFactorID(), Kind: mfa.KindWebAuthn, Name: c.Name, Confirmed: &now, Created: now,
		// A passkey must have verified the user; a security key asked for
		// as a passkey that did not stays a second factor.
		Passkey: c.Passkey && created.UserVerified}
	if err = tx.SaveWebAuthn(ctx, m.Environment, user, f, created); err != nil {
		return mfa.Registration{}, err
	}
	out := mfa.Registration{Factor: f}
	if !mfa.AnyActive(factors) {
		if out.RecoveryCodes, err = s.replaceRecovery(ctx, tx, m.Environment, user); err != nil {
			return mfa.Registration{}, err
		}
	}
	m.Action = mfa.ActionEnrolled
	if err = tx.Audit(ctx, m); err != nil {
		return mfa.Registration{}, err
	}
	return out, tx.Commit()
}

// keyRejected answers a failed attestation on an authenticated route (422,
// not 401: the access token is fine).
func keyRejected() error {
	e := errx.Business("the security key could not be verified")
	e.Code = "INVALID_CODE"
	return e
}

// assert starts an assertion with the user's active keys.
func (s *Service) assert(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factors []mfa.Factor) (authentication.WebAuthnOptions, error) {
	if !s.keys() {
		return authentication.WebAuthnOptions{}, mfa.ErrWebAuthnUnavailable()
	}
	holder := mfa.HolderFor(user, mfa.Account{}, factors, false)
	if len(holder.Credentials) == 0 {
		return authentication.WebAuthnOptions{}, errx.NotFound("no security key is enrolled")
	}
	ch, err := s.relying.Assert(holder, false)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.ceremony(ctx, mfa.Ceremony{Environment: environment, User: user, Purpose: mfa.CeremonyLogin, State: ch.State}, ch.Options)
}

func (s *Service) ProveWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.WebAuthnOptions, error) {
	if environment.IsZero() || user.IsZero() {
		return authentication.WebAuthnOptions{}, errx.Validation("user_id is required")
	}
	summary, err := s.repository.Summary(ctx, environment, user)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.assert(ctx, environment, user, summary.Factors)
}

// Assert starts the security key prompt of a pending login.
func (s *Service) Assert(ctx context.Context, token string) (authentication.WebAuthnOptions, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	defer tx.Rollback()
	p, err := s.pending(ctx, tx, token)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	if err = tx.Rollback(); err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.AssertFor(ctx, p.Boundary, p.User, p.AMR)
}

// AssertFor starts a security key prompt for a login into boundary.
func (s *Service) AssertFor(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string) (authentication.WebAuthnOptions, error) {
	policy, err := s.repository.Policy(ctx, boundary, user)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	if !slices.Contains(policy.Usable(amr), mfa.KindWebAuthn) {
		return authentication.WebAuthnOptions{}, factorNotAllowed(mfa.KindWebAuthn)
	}
	summary, err := s.repository.Summary(ctx, boundary.EnvironmentID, user)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.assert(ctx, boundary.EnvironmentID, user, summary.Factors)
}

// verifyKey checks a security key assertion inside check; ok is false for
// an unusable, unknown or failed assertion (counted like a wrong code).
func (s *Service) verifyKey(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, user identity.UserID, factors []mfa.Factor, proof authentication.Proof, sc scope) (mfa.Verification, bool, error) {
	c, found, err := s.take(ctx, tx, m.Environment, proof.Session, mfa.CeremonyLogin)
	if err != nil || !found || c.User != user || !slices.Contains(sc.prove, mfa.KindWebAuthn) || !s.keys() {
		return mfa.Verification{}, false, err
	}
	a, err := s.relying.Asserted(mfa.HolderFor(user, mfa.Account{}, factors, false), c.State, proof.Credential)
	if err != nil {
		return mfa.Verification{}, false, nil
	}
	return s.used(ctx, tx, m, factors, a)
}

// used records a verified assertion: a counter that went backwards means
// a cloned key, refused and audited; otherwise the key's counter moves on.
func (s *Service) used(ctx context.Context, tx mfa.Transaction, m mfa.Mutation, factors []mfa.Factor, a mfa.Assertion) (mfa.Verification, bool, error) {
	f, found := mfa.CredentialFactor(factors, a.Credential.ID)
	if !found || !f.Active() {
		return mfa.Verification{}, false, nil
	}
	if a.Clone {
		m.Action = mfa.ActionCloneDetected
		return mfa.Verification{}, false, tx.Audit(ctx, m)
	}
	return mfa.Verification{Proof: mfa.ProofWebAuthn}, true, tx.UseWebAuthn(ctx, f.ID, a.Credential)
}

// BeginPasskey starts a passkey sign-in: any discoverable credential of
// the environment may answer.
func (s *Service) BeginPasskey(ctx context.Context, environment identity.EnvironmentID) (authentication.WebAuthnOptions, error) {
	if environment.IsZero() {
		return authentication.WebAuthnOptions{}, errx.Validation("environment is required")
	}
	if !s.keys() {
		return authentication.WebAuthnOptions{}, mfa.ErrWebAuthnUnavailable()
	}
	kinds, err := s.repository.Allowed(ctx, environment)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	if !slices.Contains(kinds, mfa.KindWebAuthn) {
		return authentication.WebAuthnOptions{}, factorNotAllowed(mfa.KindWebAuthn)
	}
	ch, err := s.relying.Assert(mfa.Holder{}, true)
	if err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.ceremony(ctx, mfa.Ceremony{Environment: environment, Purpose: mfa.CeremonyPasskey, State: ch.State}, ch.Options)
}

// FinishPasskey verifies a passkey assertion and returns its user. Every
// failure is the same 401; the ceremony is consumed either way.
func (s *Service) FinishPasskey(ctx context.Context, environment identity.EnvironmentID, session string, credential []byte) (identity.UserID, error) {
	if !s.keys() {
		return identity.UserID{}, mfa.ErrWebAuthnUnavailable()
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return identity.UserID{}, err
	}
	defer tx.Rollback()
	c, found, err := s.take(ctx, tx, environment, session, mfa.CeremonyPasskey)
	if err != nil {
		return identity.UserID{}, err
	}
	fail := func() (identity.UserID, error) {
		if err := tx.Commit(); err != nil {
			return identity.UserID{}, err
		}
		return identity.UserID{}, passkeyRejected()
	}
	if !found {
		return fail()
	}
	handle, err := s.relying.Handle(credential)
	if err != nil {
		return fail()
	}
	user, err := mfa.HandleUser(handle)
	if err != nil {
		return fail()
	}
	factors, err := tx.Factors(ctx, environment, user)
	if err != nil {
		return identity.UserID{}, err
	}
	lock, err := tx.Lock(ctx, environment, user)
	if err != nil {
		return identity.UserID{}, err
	}
	if lock.Locked(s.now()) {
		return fail()
	}
	a, err := s.relying.Asserted(mfa.HolderFor(user, mfa.Account{}, factors, true), c.State, credential)
	if err != nil || !a.Credential.UserVerified {
		return fail()
	}
	m := mfa.Mutation{Environment: environment, Actor: user.String(), Target: user.String()}
	_, ok, err := s.used(ctx, tx, m, factors, a)
	if err != nil {
		return identity.UserID{}, err
	}
	if !ok {
		return fail()
	}
	return user, tx.Commit()
}

func passkeyRejected() error { return errx.Unauthorized("the passkey could not be verified") }

func (s *Service) RenameWebAuthn(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, name string) (mfa.Factor, error) {
	name, err := mfa.ValidateFactorName(name)
	if err != nil {
		return mfa.Factor{}, err
	}
	return s.repository.RenameFactor(ctx, environment, user, factor, name)
}

// RemoveWebAuthn deletes one key; the recovery codes and lockout go with
// it when no other active factor remains.
func (s *Service) RemoveWebAuthn(ctx context.Context, m mfa.Mutation, user identity.UserID, factor identity.FactorID, proof authentication.Proof) error {
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
	found, others := false, false
	for _, f := range factors {
		if f.ID == factor && f.Kind == mfa.KindWebAuthn {
			found = true
		} else if f.Active() {
			others = true
		}
	}
	switch {
	case !found:
		return errx.NotFound("security key not found")
	case !others:
		_, err = tx.DeleteFactors(ctx, m.Environment, user)
	default:
		err = tx.DeleteFactor(ctx, m.Environment, user, factor)
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
