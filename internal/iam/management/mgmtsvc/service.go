package mgmtsvc

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository management.Repository
	sessions   management.SessionRepository
	secrets    management.Secrets
	passwords  management.Passwords
	// mode is who may use a password (zero: everyone).
	mode management.PasswordMode
}

func New(repository management.Repository, sessions management.SessionRepository, secrets management.Secrets, passwords management.Passwords) *Service {
	return &Service{repository: repository, sessions: sessions, secrets: secrets, passwords: passwords}
}

// WithPasswordMode restricts password sign-in and password changes to what
// the deployment allows; see management.PasswordMode.
func (s *Service) WithPasswordMode(mode management.PasswordMode) *Service {
	s.mode = mode
	return s
}
func (s *Service) Bootstrap(ctx context.Context, email, name string) (string, error) {
	email, err := identity.Email(email)
	if err != nil {
		return "", errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	if name == "" {
		return "", errx.Validation("workspace name required")
	}
	raw, hash, err := s.secrets.Generate("ik_mgmt_")
	if err != nil {
		return "", errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	if err = s.repository.Bootstrap(ctx, email, name, hash, time.Now().Add(config.APIKeyTTL)); err != nil {
		return "", err
	}
	return raw, nil
}
func (s *Service) RecoverOwner(ctx context.Context, workspace identity.WorkspaceID, email string) (string, error) {
	if workspace.IsZero() {
		return "", errx.Validation("workspace UUID required")
	}
	email, err := identity.Email(email)
	if err != nil {
		return "", errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	raw, hash, err := s.secrets.Generate("ik_mgmt_")
	if err != nil {
		return "", errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	if err = s.repository.RecoverOwner(ctx, workspace, email, hash, time.Now().Add(config.APIKeyTTL)); err != nil {
		return "", err
	}
	return raw, nil
}
func (s *Service) Authenticate(ctx context.Context, raw string) (management.Principal, error) {
	if len(raw) < 9 || !strings.HasPrefix(raw, "ik_mgmt_") {
		return management.Principal{}, errx.Unauthorized("management credential required")
	}
	p, err := s.repository.Authenticate(ctx, s.secrets.Hash(raw))
	if err != nil {
		return management.Principal{}, err
	}
	p.Method = management.MethodKey
	return p, nil
}
func (s *Service) AuthenticateSession(ctx context.Context, raw string) (management.Principal, error) {
	if raw == "" {
		return management.Principal{}, errx.Unauthorized("management credential required")
	}
	return s.sessions.AuthenticateSession(ctx, s.secrets.Hash(raw))
}
func (s *Service) EnvironmentAllowed(ctx context.Context, p management.Principal, environment identity.EnvironmentID) bool {
	allowed, err := s.repository.EnvironmentAllowed(ctx, p.WorkspaceID, environment)
	return err == nil && allowed
}
func (s *Service) Login(ctx context.Context, email, password, newPassword string) (string, management.Principal, error) {
	if s.mode == management.PasswordDisabled {
		return "", management.Principal{}, management.ErrPasswordLoginDisabled()
	}
	email, err := identity.Email(email)
	if err != nil || len(password) > config.PasswordMaxLength {
		return "", management.Principal{}, errx.Unauthorized("invalid credentials")
	}
	account, err := s.sessions.PasswordByEmail(ctx, email)
	if errx.IsServerError(err) {
		return "", management.Principal{}, err
	}
	if err != nil {
		s.passwords.Compare("", password)
		return "", management.Principal{}, errx.Unauthorized("invalid credentials")
	}
	if !s.passwords.Compare(account.Hash, password) {
		return "", management.Principal{}, errx.Unauthorized("invalid credentials")
	}
	p := account.Principal
	// Checked only after the password matched: a wrong password looks the
	// same for every email, so nobody learns who must use single sign-on.
	if !s.mode.Permits(account.Allowed) {
		slog.WarnContext(ctx, "operator.password_refused", "operator", p.OperatorID.String(), "workspace", p.WorkspaceID.String(), "reason", "sso required")
		return "", management.Principal{}, management.ErrSSORequired()
	}
	if account.MustChange {
		if newPassword == "" {
			return "", management.Principal{}, management.ErrPasswordChangeRequired()
		}
		if newPassword == password {
			return "", management.Principal{}, errx.Validation("new password must differ from the current one")
		}
		// No session exists yet: every other one ends.
		if err = s.store(ctx, p.OperatorID, newPassword, false, identity.SessionID{}); err != nil {
			return "", management.Principal{}, err
		}
		slog.InfoContext(ctx, "operator.password_changed", "operator", p.OperatorID.String(), "workspace", p.WorkspaceID.String(), "reason", "must change")
	}
	raw, secretHash, err := s.secrets.Generate("ik_sess_")
	if err != nil {
		return "", management.Principal{}, errx.Wrap(err, "session creation failed", errx.TypeInternal)
	}
	p.Method, p.Session = management.MethodPassword, identity.NewSessionID()
	now := time.Now()
	p.AuthTime = &now
	if err = s.sessions.CreateSession(ctx, p.Session, p, secretHash, now.Add(config.OperatorSessionTTL)); err != nil {
		return "", management.Principal{}, err
	}
	if s.mode == management.PasswordBreakGlass {
		// Emergency access bypasses the identity provider: always visible.
		slog.WarnContext(ctx, "operator.break_glass_login", "operator", p.OperatorID.String(), "workspace", p.WorkspaceID.String())
	} else {
		slog.InfoContext(ctx, "operator.login", "operator", p.OperatorID.String(), "workspace", p.WorkspaceID.String(), "method", "password")
	}
	return raw, p, nil
}
func (s *Service) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return errx.Validation("invalid session")
	}
	return s.sessions.RevokeSessionByHash(ctx, s.secrets.Hash(raw))
}

// usable reports whether the deployment lets the operator use a password.
func (s *Service) usable(account management.PasswordAccount) error {
	switch {
	case s.mode == management.PasswordDisabled:
		return management.ErrPasswordLoginDisabled()
	case !s.mode.Permits(account.Allowed):
		return management.ErrSSORequired()
	}
	return nil
}

// SetPassword changes the caller's own password. Proof, one of: a
// management key; the current password; or, when no password is set or
// the session came from single sign-on, a sign-in within
// config.OperatorFreshAuth. Every other session of the operator ends.
func (s *Service) SetPassword(ctx context.Context, p management.Principal, current, password string) error {
	if s.mode == management.PasswordDisabled {
		return management.ErrPasswordLoginDisabled()
	}
	account, err := s.sessions.OperatorPassword(ctx, p.WorkspaceID, p.OperatorID)
	if err != nil {
		return err
	}
	if err = s.usable(account); err != nil {
		return err
	}
	switch {
	case current != "":
		if len(current) > config.PasswordMaxLength || !s.passwords.Compare(account.Hash, current) {
			return management.ErrReauthenticationRequired("current password is incorrect")
		}
	case p.Method == management.MethodKey:
	case account.Hash != "" && p.Method != management.MethodSSO:
		return management.ErrReauthenticationRequired("enter your current password")
	case !p.Fresh(time.Now(), config.OperatorFreshAuth):
		return management.ErrReauthenticationRequired("sign in again to set a password")
	}
	if err = s.store(ctx, p.OperatorID, password, false, p.Session); err != nil {
		return err
	}
	slog.InfoContext(ctx, "operator.password_changed", "operator", p.OperatorID.String(), "workspace", p.WorkspaceID.String(), "method", p.Method)
	return nil
}

// SetTemporaryPassword sets a password someone else chose (the bootstrap
// IAMKIT_BOOTSTRAP_PASSWORD): the operator must replace it at the first
// sign-in. Not exposed over HTTP.
func (s *Service) SetTemporaryPassword(ctx context.Context, p management.Principal, password string) error {
	return s.store(ctx, p.OperatorID, password, true, identity.SessionID{})
}

func (s *Service) store(ctx context.Context, operator identity.OperatorID, password string, mustChange bool, keep identity.SessionID) error {
	if len(password) < config.PasswordMinLength || len(password) > config.PasswordMaxLength {
		return errx.Validation("password must be 12-72 characters long")
	}
	hash, err := s.passwords.Hash(password)
	if err != nil {
		return err
	}
	return s.sessions.SetPassword(ctx, operator, hash, mustChange, keep)
}

// PasswordStatus is the caller's own password state.
func (s *Service) PasswordStatus(ctx context.Context, p management.Principal) (management.PasswordStatus, error) {
	account, err := s.sessions.OperatorPassword(ctx, p.WorkspaceID, p.OperatorID)
	if err != nil {
		return management.PasswordStatus{}, err
	}
	mode := s.mode
	if mode == "" {
		mode = management.PasswordEnabled
	}
	set := account.Hash != ""
	fresh := p.Method == management.MethodKey || ((!set || p.Method == management.MethodSSO) && p.Fresh(time.Now(), config.OperatorFreshAuth))
	return management.PasswordStatus{Set: set, Usable: s.usable(account) == nil, Fresh: fresh, Mode: mode}, nil
}

// Preferences are the caller's console settings.
func (s *Service) Preferences(ctx context.Context, p management.Principal) (management.Preferences, error) {
	return s.sessions.Preferences(ctx, p.OperatorID)
}

// SetPreferences replaces the caller's console settings (not audited: they
// change only how the console looks to that operator).
func (s *Service) SetPreferences(ctx context.Context, p management.Principal, input management.Preferences) error {
	if err := input.Validate(); err != nil {
		return err
	}
	return s.sessions.SetPreferences(ctx, p.OperatorID, input)
}
