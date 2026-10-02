package authsvc

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var _ authentication.SignupCommands = (*Service)(nil)

// SetSignups enables self-registration (without it every sign-up is
// refused as disabled).
func (s *Service) SetSignups(r authentication.SignupRepository) { s.signups = r }

// signupMethods are the methods new accounts may use: the environment's
// narrowed by the sign-up organization's (none when sign-up is off or the
// organization is not active).
func signupMethods(ctx context.Context, tx authentication.SignupTransaction, environment identity.EnvironmentID, policy authentication.SignInPolicy) (authentication.Methods, error) {
	if !policy.AllowSignup || policy.SignupOrganization.IsZero() {
		return authentication.Methods{}, nil
	}
	organization, err := tx.SignupMethods(ctx, environment, policy.SignupOrganization)
	if err != nil {
		return authentication.Methods{}, err
	}
	return authentication.Methods{
		Password:  policy.AllowPassword && organization.Password,
		EmailCode: policy.AllowEmailCode && organization.EmailCode,
	}, nil
}

// signupMethod is the first factor of a new account: password when it has
// one, else email codes.
func signupMethod(passwordHash string) string {
	if passwordHash != "" {
		return authentication.MethodPassword
	}
	return authentication.MethodCode
}

// Signup emails a code confirming the address. Refusals that depend only on
// configuration (sign-up off, a method not allowed, a password the policy
// rejects, an email domain whose organization enforces single sign-on) are
// answered; an email with an account gets the same answer as a new one and
// no email, so sign-up never reveals which addresses have accounts.
func (s *Service) Signup(ctx context.Context, input authentication.Signup) (identity.ChallengeID, error) {
	if input.Environment.IsZero() {
		return identity.ChallengeID{}, errx.Validation("environment_id is required")
	}
	if s.signups == nil {
		return identity.ChallengeID{}, authentication.ErrSignupDisabled()
	}
	if s.deliverySvc == nil && s.delivery == nil {
		return identity.ChallengeID{}, errx.External("email delivery is not configured")
	}
	policy, err := s.signInPolicy(ctx, input.Environment)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	tx, err := s.signups.BeginSignup(ctx)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	defer tx.Rollback()
	methods, err := signupMethods(ctx, tx, input.Environment, policy)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if !methods.Password && !methods.EmailCode {
		return identity.ChallengeID{}, authentication.ErrSignupDisabled()
	}
	if err = input.Validate(); err != nil {
		return identity.ChallengeID{}, err
	}
	var accepted *time.Time
	if policy.TermsRequired() {
		if !input.AcceptTerms {
			return identity.ChallengeID{}, authentication.ErrTermsRequired()
		}
		now := time.Now()
		accepted = &now
	}
	email, _ := identity.Email(input.Email)
	var hash string
	switch {
	case input.Password != "" && !methods.Password:
		return identity.ChallengeID{}, errx.Validation("password sign-in is not allowed; leave password empty to sign in with email codes")
	case input.Password == "" && !methods.EmailCode:
		return identity.ChallengeID{}, errx.Validation("password is required")
	case input.Password != "":
		// The account starts in the sign-up organization: its requirements
		// tighten the environment's policy.
		if hash, err = s.signupPassword(ctx, input.Environment, policy.SignupOrganization, input.Password); err != nil {
			return identity.ChallengeID{}, err
		}
	}
	required, err := tx.SSORequired(ctx, input.Environment, email)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if required {
		return identity.ChallengeID{}, errSSORequired()
	}
	id := identity.NewChallengeID()
	exists, err := tx.AccountExists(ctx, input.Environment, email)
	if err != nil || exists {
		return id, err
	}
	recent, err := tx.RecentSignups(ctx, input.Environment, email)
	if err != nil || recent >= 5 {
		return id, err
	}
	code, err := s.secrets.Code()
	if err != nil {
		return identity.ChallengeID{}, err
	}
	pending := authentication.PendingSignup{ID: id, Environment: input.Environment, Email: email, Name: strings.TrimSpace(input.Name),
		PasswordHash: hash, Hash: s.secrets.Hash(id.String() + ":" + code), Expires: time.Now().Add(config.ChallengeTTL), TermsAccepted: accepted}
	if err = tx.CreateSignup(ctx, pending); err != nil {
		return identity.ChallengeID{}, err
	}
	message := authentication.Message{Email: email, Purpose: authentication.PurposeEmailVerification, Code: code, Locale: i18n.Match(input.Locale)}
	if err = s.send(ctx, input.Environment, message); err != nil {
		slog.ErrorContext(ctx, "sign-up delivery failed", "signup", id, "environment", input.Environment, "err", err)
		return id, nil
	}
	return id, tx.Commit()
}

// signupPassword checks a new account's password against the environment's
// policy tightened by the sign-up organization's, and hashes it.
func (s *Service) signupPassword(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, password string) (string, error) {
	if s.policies != nil {
		if err := s.policies.CheckMemberPassword(ctx, environment, organization, password); err != nil {
			return "", err
		}
		return s.passwords.Hash(password)
	}
	return s.newPassword(ctx, authentication.DefaultPasswordPolicy(), "", password)
}

// send delivers message through the environment's email configuration.
func (s *Service) send(ctx context.Context, environment identity.EnvironmentID, message authentication.Message) error {
	if s.deliverySvc != nil {
		return s.deliverySvc.Send(ctx, environment, message)
	}
	return s.delivery.Send(ctx, message)
}

// CompleteSignup checks the emailed code and creates the account. Five
// wrong codes end the sign-up. The configuration is checked again: turning
// sign-up off (or the new account's method) stops sign-ups in flight.
func (s *Service) CompleteSignup(ctx context.Context, environment identity.EnvironmentID, signup identity.ChallengeID, code string) (authentication.SignedUp, error) {
	if environment.IsZero() || signup.IsZero() || len(code) != 8 {
		return authentication.SignedUp{}, errx.Unauthorized("invalid challenge")
	}
	if s.signups == nil {
		return authentication.SignedUp{}, authentication.ErrSignupDisabled()
	}
	policy, err := s.signInPolicy(ctx, environment)
	if err != nil {
		return authentication.SignedUp{}, err
	}
	tx, err := s.signups.BeginSignup(ctx)
	if err != nil {
		return authentication.SignedUp{}, err
	}
	defer tx.Rollback()
	methods, err := signupMethods(ctx, tx, environment, policy)
	if err != nil {
		return authentication.SignedUp{}, err
	}
	if !methods.Password && !methods.EmailCode {
		return authentication.SignedUp{}, authentication.ErrSignupDisabled()
	}
	row, err := tx.PendingSignup(ctx, environment, signup)
	if err != nil {
		return authentication.SignedUp{}, err
	}
	if row.Attempts >= 5 {
		return authentication.SignedUp{}, errx.Unauthorized("invalid challenge")
	}
	if subtle.ConstantTimeCompare(row.Hash, s.secrets.Hash(signup.String()+":"+code)) != 1 {
		if err = tx.FailSignup(ctx, signup); err != nil {
			return authentication.SignedUp{}, err
		}
		if err = tx.Commit(); err != nil {
			return authentication.SignedUp{}, err
		}
		return authentication.SignedUp{}, errx.Unauthorized("invalid challenge")
	}
	method := signupMethod(row.PasswordHash)
	if !methods.Allows(method) {
		return authentication.SignedUp{}, authentication.ErrMethodNotAllowed()
	}
	required, err := tx.SSORequired(ctx, environment, row.Email)
	if err != nil {
		return authentication.SignedUp{}, err
	}
	if required {
		return authentication.SignedUp{}, errSSORequired()
	}
	if s.usage != nil {
		if err = s.usage.Admit(ctx, environment, usage.LimitUsers); err != nil {
			return authentication.SignedUp{}, err
		}
	}
	if s.actions != nil {
		if _, err = s.actions.Run(ctx, environment, action.PreRegistration, func() action.Input {
			return action.Input{Organization: &policy.SignupOrganization, Method: []string{method}, User: &action.UserInput{Email: row.Email, Name: row.Name}}
		}); err != nil {
			return authentication.SignedUp{}, err
		}
	}
	user := identity.NewUserID()
	err = tx.Join(ctx, authentication.Joining{Signup: signup, User: user, Environment: environment, Organization: policy.SignupOrganization,
		Group: policy.SignupGroup, Email: row.Email, Name: row.Name, PasswordHash: row.PasswordHash, TermsAccepted: row.TermsAccepted})
	if err != nil {
		return authentication.SignedUp{}, err
	}
	if err = tx.Commit(); err != nil {
		return authentication.SignedUp{}, err
	}
	return authentication.SignedUp{User: user, Organization: policy.SignupOrganization, Email: row.Email, Method: method}, nil
}
