package authsvc

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
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
func (s *Service) Signup(ctx context.Context, input authentication.Signup) (authentication.SignupResult, error) {
	if input.Environment.IsZero() {
		return authentication.SignupResult{}, errx.Validation("environment_id is required")
	}
	if s.signups == nil {
		return authentication.SignupResult{}, authentication.ErrSignupDisabled()
	}
	if s.deliverySvc == nil && s.delivery == nil {
		return authentication.SignupResult{}, errx.External("email delivery is not configured")
	}
	// Restrictions (ip, country, email domain) apply to sign-ups too.
	if err := s.screen(ctx, authentication.Context{EnvironmentID: input.Environment}, input.Email, risk.MethodSignup); err != nil {
		return authentication.SignupResult{}, err
	}
	policy, err := s.signInPolicy(ctx, input.Environment)
	if err != nil {
		return authentication.SignupResult{}, err
	}
	tx, err := s.signups.BeginSignup(ctx)
	if err != nil {
		return authentication.SignupResult{}, err
	}
	defer tx.Rollback()
	methods, err := signupMethods(ctx, tx, input.Environment, policy)
	if err != nil {
		return authentication.SignupResult{}, err
	}
	if !methods.Password && !methods.EmailCode {
		return authentication.SignupResult{}, authentication.ErrSignupDisabled()
	}
	if err = input.Validate(); err != nil {
		return authentication.SignupResult{}, err
	}
	var accepted *time.Time
	if policy.TermsRequired() {
		if !input.AcceptTerms {
			return authentication.SignupResult{}, authentication.ErrTermsRequired()
		}
		now := time.Now()
		accepted = &now
	}
	email, _ := identity.Email(input.Email)
	var hash string
	switch {
	case input.Password != "" && !methods.Password:
		return authentication.SignupResult{}, errx.Validation("password sign-in is not allowed; leave password empty to sign in with email codes")
	case input.Password == "" && !methods.EmailCode:
		return authentication.SignupResult{}, errx.Validation("password is required")
	case input.Password != "":
		// The account starts in the sign-up organization: its requirements
		// tighten the environment's policy.
		if hash, err = s.signupPassword(ctx, input.Environment, policy.SignupOrganization, input.Password); err != nil {
			return authentication.SignupResult{}, err
		}
	}
	required, err := tx.SSORequired(ctx, input.Environment, email)
	if err != nil {
		return authentication.SignupResult{}, err
	}
	if required {
		return authentication.SignupResult{}, errSSORequired()
	}
	if err = s.emailAdmitted(ctx, input.Environment); err != nil {
		return authentication.SignupResult{}, err
	}
	var entry identity.WaitlistEntryID
	if policy.WaitlistOn() && !policy.AutoApproves(email) {
		// The waitlist gates this address: only an approval token for it
		// lets the sign-up continue; without a valid one (none, unknown,
		// expired, used, or for another address) the request joins the
		// list, answered like any other.
		found, err := s.waitlistToken(ctx, tx, input.Environment, input.WaitlistToken)
		if err != nil {
			return authentication.SignupResult{}, err
		}
		if found.Email != email {
			return s.joinWaitlist(ctx, tx, input, email)
		}
		entry = found.ID
	}
	id := identity.NewChallengeID()
	answer := authentication.SignupResult{Challenge: id, Status: authentication.SignupCodeSent}
	exists, err := tx.AccountExists(ctx, input.Environment, email)
	if err != nil || exists {
		return answer, err
	}
	recent, err := tx.RecentSignups(ctx, input.Environment, email)
	if err != nil || recent >= 5 {
		return answer, err
	}
	code, err := s.secrets.Code()
	if err != nil {
		return authentication.SignupResult{}, err
	}
	pending := authentication.PendingSignup{ID: id, Environment: input.Environment, Email: email, Name: strings.TrimSpace(input.Name),
		PasswordHash: hash, Hash: s.secrets.Hash(id.String() + ":" + code), Expires: time.Now().Add(config.ChallengeTTL), TermsAccepted: accepted, WaitlistEntry: entry}
	if err = tx.CreateSignup(ctx, pending); err != nil {
		return authentication.SignupResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return authentication.SignupResult{}, err
	}
	message := authentication.Message{Email: email, Purpose: authentication.PurposeEmailVerification, Code: code, Locale: i18n.Match(input.Locale)}
	s.deliverLater(ctx, input.Environment, message, "signup", id, "environment", input.Environment, "purpose", message.Purpose)
	return answer, nil
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
	if err = s.screen(ctx, authentication.Context{EnvironmentID: environment}, row.Email, risk.MethodSignup); err != nil {
		return authentication.SignedUp{}, err
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
	// A sign-up begun before the waitlist was turned on (or for a domain no
	// longer auto-approved) has no entry: it must not slip past the gate.
	if policy.WaitlistOn() && row.WaitlistEntry.IsZero() && !policy.AutoApproves(row.Email) {
		return authentication.SignedUp{}, errx.Unauthorized("invalid challenge")
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
			return action.Input{Organization: &policy.SignupOrganization, Method: []string{authentication.MethodAMR(method)}, User: &action.UserInput{Email: row.Email, Name: row.Name}}
		}); err != nil {
			return authentication.SignedUp{}, err
		}
	}
	user := identity.NewUserID()
	err = tx.Join(ctx, authentication.Joining{Signup: signup, User: user, Environment: environment, Organization: policy.SignupOrganization,
		Group: policy.SignupGroup, Email: row.Email, Name: row.Name, PasswordHash: row.PasswordHash, TermsAccepted: row.TermsAccepted, WaitlistEntry: row.WaitlistEntry})
	if err != nil {
		return authentication.SignedUp{}, err
	}
	if err = tx.Commit(); err != nil {
		return authentication.SignedUp{}, err
	}
	return authentication.SignedUp{User: user, Organization: policy.SignupOrganization, Email: row.Email, Method: method}, nil
}
