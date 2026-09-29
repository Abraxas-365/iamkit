package authsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var _ authentication.PasskeyCommands = (*Service)(nil)

// passkeysOff answers passkey requests of a server without WebAuthn.
func passkeysOff() error {
	e := errx.Forbidden("passkey sign-in is not available")
	e.Code = authentication.CodeMethodNotAllowed
	return e
}

// BeginPasskey starts a passkey sign-in when the environment allows it.
func (s *Service) BeginPasskey(ctx context.Context, environment identity.EnvironmentID) (authentication.WebAuthnOptions, error) {
	if s.passkeys == nil {
		return authentication.WebAuthnOptions{}, passkeysOff()
	}
	if environment.IsZero() {
		return authentication.WebAuthnOptions{}, errx.Validation("environment_id is required")
	}
	if err := s.environmentAllows(ctx, environment, authentication.MethodPasskey); err != nil {
		return authentication.WebAuthnOptions{}, err
	}
	return s.passkeys.BeginPasskey(ctx, environment)
}

// passkeyUser verifies the assertion and locks nothing: the user comes
// from the credential, and must be active.
func (s *Service) passkeyUser(ctx context.Context, tx authentication.Transaction, environment identity.EnvironmentID, session string, credential []byte) (identity.UserID, string, error) {
	if s.passkeys == nil {
		return identity.UserID{}, "", passkeysOff()
	}
	if err := s.environmentAllows(ctx, environment, authentication.MethodPasskey); err != nil {
		return identity.UserID{}, "", err
	}
	user, err := s.passkeys.FinishPasskey(ctx, environment, session, credential)
	if err != nil {
		return identity.UserID{}, "", err
	}
	email, err := tx.ActiveEmail(ctx, environment, user)
	if err != nil {
		return identity.UserID{}, "", credentialFailure(err)
	}
	return user, email, nil
}

// VerifyPasskey checks a passkey without creating a session (hosted
// pages). Like a password, a passkey is refused for an email any
// organization enforces SSO for, unless the user may bypass it there.
func (s *Service) VerifyPasskey(ctx context.Context, environment identity.EnvironmentID, session string, credential []byte) (authentication.Verified, error) {
	if environment.IsZero() {
		return authentication.Verified{}, invalidCredentials()
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Verified{}, err
	}
	defer tx.Rollback()
	user, email, err := s.passkeyUser(ctx, tx, environment, session, credential)
	if err != nil {
		return authentication.Verified{}, err
	}
	if err = requireNoSSO(ctx, tx, authentication.Context{EnvironmentID: environment}, email); err != nil {
		return authentication.Verified{}, err
	}
	return authentication.Verified{User: user, Email: email, Method: authentication.MethodPasskey, AMR: authentication.PasskeyAMR()}, nil
}

// PasskeyLogin signs in headlessly with a passkey. A passkey verified the
// user, so no second factor follows.
func (s *Service) PasskeyLogin(ctx context.Context, boundary authentication.Context, session string, credential []byte) (authentication.Result, error) {
	if err := boundary.Validate(); err != nil {
		return authentication.Result{}, invalidCredentials()
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Result{}, err
	}
	defer tx.Rollback()
	if err = s.allowed(ctx, tx, boundary, authentication.MethodPasskey); err != nil {
		return authentication.Result{}, err
	}
	user, email, err := s.passkeyUser(ctx, tx, boundary.EnvironmentID, session, credential)
	if err != nil {
		return authentication.Result{}, err
	}
	if err = requireNoSSO(ctx, tx, boundary, email); err != nil {
		return authentication.Result{}, err
	}
	out, err := s.signIn(ctx, tx, boundary, user, authentication.MethodPasskey, false, "")
	return out, credentialFailure(err)
}
