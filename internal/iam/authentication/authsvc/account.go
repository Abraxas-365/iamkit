package authsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Account implements authentication.AccountCommands over the sign-in
// service (Service.ChangePassword already is the hosted expired-password
// step of authentication.Authenticator, so the self-service commands live
// on their own type).
type Account struct{ *Service }

// Accounts returns the self-service account commands.
func (s *Service) Accounts() *Account { return &Account{s} }

var _ authentication.AccountCommands = (*Account)(nil)

// ChangePassword is the self-service password change: a person's own
// session (no API key, machine user or impersonation) that signed in
// within config.MFAFreshAuth, typing the current password (a wrong one
// counts toward the lockout like at sign-in), choosing a new one that
// passes the member policy and the breach check. The user's other sessions
// end; the current one stays.
func (a *Account) ChangePassword(ctx context.Context, token authentication.Token, input authentication.PasswordChange) (authentication.PasswordChanged, error) {
	s := a.Service
	var out authentication.PasswordChanged
	if token.Purpose != authentication.PurposeApplication || token.APIKey != nil || token.Subject.IsZero() || token.SessionID.IsZero() {
		return out, errx.Forbidden("a user access token is required")
	}
	if token.Impersonated() {
		return out, errx.Forbidden("impersonated sessions cannot change the password")
	}
	if err := input.Validate(); err != nil {
		return out, err
	}
	if err := authentication.Fresh(token.AuthTime, time.Now(), "sign in again to change your password"); err != nil {
		return out, err
	}
	policy, err := s.policy(ctx, token.EnvironmentID)
	if err != nil {
		return out, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	account, err := tx.AccountPassword(ctx, token.EnvironmentID, token.Subject)
	if err != nil {
		if unauthorizedErr(err) {
			// Machine users and deactivated accounts hold no password.
			return out, errx.Forbidden("a user access token is required")
		}
		return out, err
	}
	if account.Hash == "" {
		return out, authentication.ErrNoPassword()
	}
	// Compare always runs, so the answer's timing says nothing.
	matches, _ := s.passwords.Compare(account.Hash, input.Current)
	if err = s.checkPassword(ctx, tx, token.EnvironmentID, policy, account, matches); err != nil {
		if unauthorizedErr(err) {
			return out, authentication.ErrInvalidCurrentPassword()
		}
		return out, err
	}
	if policy, err = s.memberPolicy(ctx, token.EnvironmentID, account.ID, policy); err != nil {
		return out, err
	}
	hash, err := s.newPassword(ctx, policy, account.Hash, input.New)
	if err != nil {
		return out, commitThen(tx, err)
	}
	revoked, err := tx.ChangeOwnPassword(ctx, token.EnvironmentID, token.Subject, token.SessionID, hash)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	out.SessionsRevoked = revoked
	return out, nil
}

// SwitchOrganization moves the refresh token's session into another
// organization of the user. The new session is a copy (application,
// resource, amr, authenticated_at, expiry, client information): switching
// never makes a weaker sign-in look stronger. What the target organization
// asks beyond what the session proved — its own single sign-on (SSO
// enforced), a second factor, a sign-in method it allows — answers 403
// REAUTHENTICATION_REQUIRED with the organization and the reason, and the
// application signs in again through authorize with the organization hint.
// The old session and refresh token end.
func (a *Account) SwitchOrganization(ctx context.Context, input authentication.Switch) (authentication.Issued, error) {
	s := a.Service
	boundary := input.Boundary
	out := authentication.Issued{Context: boundary}
	if input.Validate() != nil || !strings.HasPrefix(input.Token, "ik_refresh_") {
		return out, errx.Unauthorized("invalid refresh token")
	}
	target := boundary
	target.OrganizationID = input.Organization
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	hash := s.secrets.Hash(input.Token)
	row, err := tx.Refresh(ctx, boundary, hash)
	if err != nil {
		return out, err
	}
	if row.Revoked || !row.Expires.After(time.Now()) {
		return out, errx.Unauthorized("invalid refresh token")
	}
	if row.Used {
		if err = tx.RevokeSession(ctx, row.ID); err != nil {
			return out, err
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, errx.Unauthorized("refresh token replay revoked session")
	}
	if row.Impersonated {
		return out, errx.Forbidden("impersonated sessions cannot switch organization")
	}
	if row.OAuthClient {
		return out, errx.Forbidden("OAuth sessions cannot switch organization")
	}
	// Access first: nothing below tells who is no member.
	access, err := tx.Resolve(ctx, target, row.User)
	if err != nil {
		if unauthorizedErr(err) {
			return out, errx.Forbidden("you do not have access to this application in that organization")
		}
		return out, err
	}
	if err = s.switchAllowed(ctx, tx, target, row); err != nil {
		return out, err
	}
	session := identity.NewSessionID()
	if err = tx.SwitchSession(ctx, row.ID, target, row.User, session); err != nil {
		return out, err
	}
	// The old refresh token goes with its session (SwitchSession ended it).
	refresh, err := s.saveRefresh(ctx, tx, row.User, session, row.Expires)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return authentication.Issued{Context: target, User: row.User, Session: session, Refresh: refresh, Access: access, AMR: row.AMR, Authenticated: row.Authenticated}, nil
}

// switchAllowed checks what the target organization asks of the session:
// a sign-in method it allows, no enforced single sign-on, and the second
// factor it (or the user) requires.
func (s *Service) switchAllowed(ctx context.Context, tx authentication.Transaction, target authentication.Context, row authentication.Session) error {
	needs := func(reason string) error { return authentication.ErrSwitchNeedsSignIn(target.OrganizationID, reason) }
	method := methodOf(row.AMR)
	if method == authentication.MethodSSO {
		// Single sign-on of the current organization (or a social
		// connection) is no sign-in to the target organization's own
		// identity provider: for it, a social-style login at best.
		method = authentication.MethodSocial
	}
	if err := s.allowed(ctx, tx, target, method); err != nil {
		if e, ok := err.(*errx.Error); ok && e.Code == authentication.CodeMethodNotAllowed {
			return needs("method")
		}
		return err
	}
	email, err := tx.ActiveEmail(ctx, target.EnvironmentID, row.User)
	if err != nil {
		return err
	}
	required, err := tx.SSORequired(ctx, target, email)
	if err != nil {
		return err
	}
	if required {
		return needs("sso")
	}
	if s.second != nil && !authentication.HasMFA(row.AMR) {
		req, err := s.second.Requirement(ctx, target, row.User, false, row.AMR)
		if err != nil {
			return err
		}
		if req.Needed {
			return needs("mfa")
		}
	}
	return nil
}
