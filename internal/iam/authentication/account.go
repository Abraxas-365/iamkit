package authentication

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Self-service account changes behind the account widgets
// (@iamkit/react <UserSecurity/>, <OrganizationSwitcher/>).

// PasswordChange is POST /identity/v1/me/password: the user's current
// password and the new one. The new password passes the member policy and
// the breach check; the token must be fresh (config.MFAFreshAuth); the
// user's other sessions end; event user.password_changed with
// data.method self_service.
type PasswordChange struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

// Validate checks the shape (the policy is checked by the service).
func (p PasswordChange) Validate() error {
	if p.Current == "" || p.New == "" {
		return errx.Validation("current_password and new_password are required")
	}
	if len(p.Current) > 1024 || len(p.New) > 1024 {
		return errx.Validation("password is too long")
	}
	return nil
}

// PasswordChanged is the answer: how many other sessions ended.
type PasswordChanged struct {
	SessionsRevoked int `json:"sessions_revoked"`
}

// PasswordMethodSelfService is user.password_changed data.method of a
// self-service change.
const PasswordMethodSelfService = "self_service"

// ErrNoPassword: the account signs in without a password (SSO, passkey,
// codes); 422 NO_PASSWORD.
func ErrNoPassword() error {
	e := errx.Business("the account has no password to change")
	e.Code = "NO_PASSWORD"
	return e
}

// ErrInvalidCurrentPassword: the current password typed is wrong (or the
// account is locked by wrong passwords, which count like at sign-in); 422
// INVALID_CURRENT_PASSWORD, never 401, so a client does not mistake it for
// an expired access token.
func ErrInvalidCurrentPassword() error {
	e := errx.Business("the current password is incorrect")
	e.Code = "INVALID_CURRENT_PASSWORD"
	return e
}

// ErrReauthenticationRequired refuses a session that signed in longer ago
// than config.MFAFreshAuth (403 REAUTHENTICATION_REQUIRED).
func ErrReauthenticationRequired(message string) error {
	e := errx.Forbidden(message)
	e.Code = "REAUTHENTICATION_REQUIRED"
	return e
}

// Fresh checks that authTime (Unix seconds, 0 when unknown) is within
// config.MFAFreshAuth.
func Fresh(authTime int64, now time.Time, message string) error {
	if authTime != 0 && now.Sub(time.Unix(authTime, 0)) <= config.MFAFreshAuth {
		return nil
	}
	return ErrReauthenticationRequired(message)
}

// Switch is POST /identity/v1/refresh with organization_id: the refresh
// token's session is spent and a new session opens in Organization (same
// user, application and resource, same amr and authenticated_at), after
// re-checking the target organization's methods, SSO enforcement, MFA
// policy and resource access. When the target needs SSO or a second factor
// the current session lacks, 403 REAUTHENTICATION_REQUIRED (details:
// organization_id, reason sso|mfa|method) tells the app to re-run
// authorize with the organization_id hint. Event user.organization_switched.
type Switch struct {
	// Boundary is the current session's boundary (as for a plain refresh).
	Boundary     Context
	Token        string
	Organization identity.OrganizationID
}

// Validate checks the request shape.
func (s Switch) Validate() error {
	if err := s.Boundary.Validate(); err != nil {
		return err
	}
	if s.Organization.IsZero() {
		return errx.Validation("organization_id must be a valid UUID")
	}
	if s.Organization == s.Boundary.OrganizationID {
		return errx.Validation("organization_id is the session's organization already")
	}
	return nil
}

// ErrSwitchNeedsSignIn is the 403 of a switch the current session cannot
// satisfy (reason: sso, mfa or method).
func ErrSwitchNeedsSignIn(organization identity.OrganizationID, reason string) error {
	e := errx.Forbidden("sign in to this organization again")
	e.Code = "REAUTHENTICATION_REQUIRED"
	e.Details = map[string]any{"organization_id": organization.String(), "reason": reason}
	e.Public = true
	return e
}

// AccountCommands are the self-service changes (authsvc).
type AccountCommands interface {
	ChangePassword(ctx context.Context, token Token, input PasswordChange) (PasswordChanged, error)
	SwitchOrganization(ctx context.Context, input Switch) (Issued, error)
}
