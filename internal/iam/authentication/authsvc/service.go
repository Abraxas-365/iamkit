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
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository  authentication.Repository
	passwords   authentication.Passwords
	secrets     authentication.Secrets
	delivery    authentication.Delivery
	deliverySvc *DeliveryService
	second      authentication.SecondFactor
	passkeys    authentication.Passkeys
	policies    *PasswordPolicies
	signIns     *SignInPolicies
	signups     authentication.SignupRepository
}

func New(repository authentication.Repository, passwords authentication.Passwords, secrets authentication.Secrets, delivery authentication.Delivery) *Service {
	return &Service{repository: repository, passwords: passwords, secrets: secrets, delivery: delivery}
}
func (s *Service) SetDeliveryService(ds *DeliveryService) { s.deliverySvc = ds }

// SetPasswordPolicies applies environment password policies (without them
// every environment uses the default).
func (s *Service) SetPasswordPolicies(p *PasswordPolicies) { s.policies = p }

// SetSignInPolicies applies environment sign-in policies (without them
// every method is allowed).
func (s *Service) SetSignInPolicies(p *SignInPolicies) { s.signIns = p }

// SetPasskeys enables passkey sign-in.
func (s *Service) SetPasskeys(passkeys authentication.Passkeys) { s.passkeys = passkeys }

// SetSecondFactor enables multi-factor authentication of logins.
func (s *Service) SetSecondFactor(second authentication.SecondFactor) { s.second = second }

var _ authentication.MFACommands = (*Service)(nil)

func (s *Service) Login(ctx context.Context, boundary authentication.Context, email, password, newPassword string) (authentication.Result, error) {
	var out authentication.Result
	email, err := identity.Email(email)
	if err != nil || boundary.Validate() != nil || len(password) > config.PasswordMaxLength {
		return out, invalidCredentials()
	}
	policy, err := s.policy(ctx, boundary.EnvironmentID)
	if err != nil {
		return out, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	// Checked before the password so a blocked login reveals neither whether
	// the account exists nor whether the password was right.
	if err = s.allowed(ctx, tx, boundary, authentication.MethodPassword); err != nil {
		return out, err
	}
	if err = requireNoSSO(ctx, tx, boundary, email); err != nil {
		return out, err
	}
	account, lookup := tx.PasswordUser(ctx, boundary, email)
	// Compare always runs (dummy hash when unknown) so timing is uniform.
	matches := s.passwords.Compare(account.Hash, password)
	if lookup != nil {
		return out, credentialFailure(lookup)
	}
	if err = s.checkPassword(ctx, tx, boundary.EnvironmentID, policy, account, matches); err != nil {
		return out, credentialFailure(err)
	}
	// Expiry and new passwords follow the user's organizations too; lockout
	// (above) only the environment.
	if policy, err = s.memberPolicy(ctx, boundary.EnvironmentID, account.ID, policy); err != nil {
		return out, err
	}
	var hash string
	if policy.Expired(account.Changed, time.Now()) {
		if newPassword == "" {
			return out, commitThen(tx, authentication.ErrPasswordChangeRequired())
		}
		if hash, err = s.newPassword(ctx, policy, account.Hash, newPassword); err != nil {
			return out, commitThen(tx, err)
		}
	}
	out, err = s.signIn(ctx, tx, boundary, account.ID, authentication.MethodPassword, false, hash)
	return out, credentialFailure(err)
}

// commitThen keeps what tx recorded (a cleared failure count) and returns
// err.
func commitThen(tx authentication.Transaction, err error) error {
	if cerr := tx.Commit(); cerr != nil {
		return cerr
	}
	return err
}

// SignIn finishes a login whose first factor passed: it checks access to
// the boundary, then either parks the login for its second factor or
// creates the session. tx is committed or left for the caller to roll back.
func (s *Service) SignIn(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, method string) (authentication.Result, error) {
	return s.signIn(ctx, tx, boundary, user, method, false, "")
}

// SignInFederated finishes a headless single sign-on. Only an
// organization's own connection (organizationSSO) satisfies its SSO
// enforcement and may stand in for its second factor; a user of an
// environment (social) connection is held to both like a password login.
func (s *Service) SignInFederated(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, email string, organizationSSO bool) (authentication.Result, error) {
	if !organizationSSO {
		if err := s.allowed(ctx, tx, boundary, authentication.MethodSocial); err != nil {
			return authentication.Result{}, err
		}
		if err := requireNoSSO(ctx, tx, boundary, email); err != nil {
			return authentication.Result{}, err
		}
	}
	return s.signIn(ctx, tx, boundary, user, authentication.MethodSSO, organizationSSO, "")
}

// signIn finishes the login. passwordHash replaces an expired password: in
// tx before the session (so a refused session keeps the old one), or once
// the second factor passed.
func (s *Service) signIn(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, method string, federated bool, passwordHash string) (authentication.Result, error) {
	amr := authentication.FirstFactorAMR(method)
	// A passkey verified the user on the key: it is multi-factor already.
	if s.second != nil && !authentication.HasMFA(amr) {
		// Access first, so the MFA answer never reveals a membership the
		// user does not have.
		if _, err := tx.Resolve(ctx, boundary, user); err != nil {
			return authentication.Result{}, err
		}
		req, err := s.second.Requirement(ctx, boundary, user, federated, amr)
		if err != nil {
			return authentication.Result{}, err
		}
		if req.Needed {
			// Commit first: it keeps a consumed challenge consumed and
			// releases row locks the pending-login insert would wait on.
			if err = tx.Commit(); err != nil {
				return authentication.Result{}, err
			}
			token, err := s.second.Begin(ctx, boundary, user, amr, req.Enroll, passwordHash)
			if err != nil {
				return authentication.Result{}, err
			}
			return authentication.Result{MFA: &authentication.MFA{Token: token, Factors: req.Factors, EnrollmentRequired: req.Enroll}}, nil
		}
	}
	if passwordHash != "" {
		if err := tx.SetPassword(ctx, boundary.EnvironmentID, user, passwordHash); err != nil {
			return authentication.Result{}, err
		}
	}
	issued, err := s.NewSession(ctx, tx, boundary, user, amr)
	return authentication.Result{Issued: issued}, err
}

// VerifyMFA completes a login with its second factor.
func (s *Service) VerifyMFA(ctx context.Context, token string, proof authentication.Proof) (authentication.Issued, error) {
	if s.second == nil {
		return authentication.Issued{}, errx.NotFound("multi-factor authentication is not enabled")
	}
	var out authentication.Issued
	// The session is created before the second-factor transaction commits:
	// when it fails, the pending login, the confirmed factor and its
	// recovery codes roll back and the user can try again.
	done, err := s.second.Complete(ctx, token, proof, func(done authentication.Completed) error {
		tx, err := s.repository.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if done.PasswordHash != "" {
			if err = tx.SetPassword(ctx, done.Boundary.EnvironmentID, done.User, done.PasswordHash); err != nil {
				return err
			}
		}
		out, err = s.NewSession(ctx, tx, done.Boundary, done.User, done.AMR)
		return credentialFailure(err)
	})
	if err != nil {
		return authentication.Issued{}, err
	}
	out.RecoveryCodes = done.RecoveryCodes
	return out, nil
}

// EnrollMFA starts the authenticator of a login whose organization requires
// a second factor the user does not have yet.
func (s *Service) EnrollMFA(ctx context.Context, token string) (authentication.Enrollment, error) {
	if s.second == nil {
		return authentication.Enrollment{}, errx.NotFound("multi-factor authentication is not enabled")
	}
	return s.second.Enroll(ctx, token)
}

// ChallengeMFA sends the emailed or texted code of a pending login.
func (s *Service) ChallengeMFA(ctx context.Context, token, factor string) (authentication.CodeSent, error) {
	if s.second == nil {
		return authentication.CodeSent{}, errx.NotFound("multi-factor authentication is not enabled")
	}
	return s.second.Challenge(ctx, token, factor)
}

// AssertMFA starts the security key prompt of a pending login.
func (s *Service) AssertMFA(ctx context.Context, token string) (authentication.WebAuthnOptions, error) {
	if s.second == nil {
		return authentication.WebAuthnOptions{}, errx.NotFound("multi-factor authentication is not enabled")
	}
	return s.second.Assert(ctx, token)
}

// invalidCredentials is the single response for every login credential
// failure — unknown email, wrong password, or no access to the boundary — so
// callers cannot enumerate accounts or memberships.
func invalidCredentials() error { return errx.Unauthorized("invalid credentials or access token") }

// credentialFailure collapses 401 authorization errors into invalidCredentials
// and passes every other error (403, internal, …) through unchanged.
func credentialFailure(err error) error {
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeAuthorization && e.HTTPStatus == 401 {
		return invalidCredentials()
	}
	return err
}

// requireNoSSO rejects password and email-code login where the boundary
// organization enforces SSO. Clients find the connection with /discover.
func requireNoSSO(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, email string) error {
	required, err := tx.SSORequired(ctx, boundary, email)
	if err != nil {
		return err
	}
	if required {
		return errSSORequired()
	}
	return nil
}

// errSSORequired refuses an email whose organization requires single
// sign-on.
func errSSORequired() error {
	e := errx.Forbidden("this organization requires single sign-on")
	e.Code = "SSO_REQUIRED"
	return e
}

func (s *Service) NewSession(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, amr []string) (authentication.Issued, error) {
	sessionID := identity.NewSessionID()
	// Whole seconds: auth_time is a Unix time, and the stored value must
	// match the first token's claim exactly.
	now := time.Now().Truncate(time.Second)
	out := authentication.Issued{Context: boundary, User: user, Session: sessionID, AMR: amr, Authenticated: now}
	access, err := tx.Resolve(ctx, boundary, user)
	if err != nil {
		return out, err
	}
	out.Access = access
	expires := now.Add(config.SessionTTL)
	if err = tx.CreateSession(ctx, boundary, user, sessionID, now, expires, amr); err != nil {
		return out, err
	}
	out.Refresh, err = s.saveRefresh(ctx, tx, user, sessionID, expires)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Service) saveRefresh(ctx context.Context, tx authentication.Transaction, user identity.UserID, session identity.SessionID, expires time.Time) (string, error) {
	raw, hash, err := s.secrets.Generate("ik_refresh_")
	if err != nil {
		return "", err
	}
	if err = tx.SaveRefresh(ctx, hash, user, session, expires); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Service) Refresh(ctx context.Context, boundary authentication.Context, token string) (authentication.Issued, error) {
	out := authentication.Issued{Context: boundary}
	if boundary.Validate() != nil || !strings.HasPrefix(token, "ik_refresh_") {
		return out, errx.Unauthorized("invalid refresh token")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	row, err := tx.Refresh(ctx, boundary, s.secrets.Hash(token))
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
	out.Access, err = tx.Resolve(ctx, boundary, row.User)
	if err != nil {
		return out, err
	}
	if err = tx.UseRefresh(ctx, s.secrets.Hash(token)); err != nil {
		return out, err
	}
	out.User, out.Session, out.AMR, out.Authenticated = row.User, row.ID, row.AMR, row.Authenticated
	out.Refresh, err = s.saveRefresh(ctx, tx, row.User, row.ID, row.Expires)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Service) InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose, locale string) (identity.ChallengeID, error) {
	email, err := identity.Email(email)
	if err != nil || environment.IsZero() || (purpose != "login" && purpose != "password_reset" && purpose != "email_verification") {
		return identity.ChallengeID{}, errx.Validation("invalid challenge request")
	}
	// An unavailable language is ignored: the environment default applies.
	locale = i18n.Match(locale)
	if s.deliverySvc == nil && s.delivery == nil {
		return identity.ChallengeID{}, errx.External("email delivery is not configured")
	}
	// Refused before any account lookup: the answer reveals none.
	switch purpose {
	case "password_reset":
		if err = s.resetAllowed(ctx, environment); err != nil {
			return identity.ChallengeID{}, err
		}
	case "login":
		if err = s.environmentAllows(ctx, environment, authentication.MethodCode); err != nil {
			return identity.ChallengeID{}, err
		}
	}
	id := identity.NewChallengeID()
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	defer tx.Rollback()
	user, err := tx.EligibleChallengeUser(ctx, environment, email, purpose)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if user.IsZero() {
		return id, nil
	}
	recent, err := tx.RecentChallenges(ctx, user, purpose)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if recent >= 5 {
		return id, nil
	}
	code, err := s.secrets.Code()
	if err != nil {
		return identity.ChallengeID{}, err
	}
	if err = tx.CreateChallenge(ctx, id, user, purpose, environment, s.secrets.Hash(id.String()+":"+code)); err != nil {
		return identity.ChallengeID{}, err
	}
	message := authentication.Message{Email: email, Purpose: purpose, Code: code, Locale: locale}
	var sendErr error
	if s.deliverySvc != nil {
		sendErr = s.deliverySvc.Send(ctx, environment, message)
	} else {
		sendErr = s.delivery.Send(ctx, message)
	}
	if sendErr != nil {
		slog.ErrorContext(ctx, "challenge delivery failed",
			"challenge", id,
			"environment", environment,
			"purpose", purpose,
			"err", sendErr,
		)
		return id, nil
	}
	return id, tx.Commit()
}

func (s *Service) VerifyChallenge(ctx context.Context, boundary authentication.Context, challengeID identity.ChallengeID, code, purpose, password string) (authentication.Result, error) {
	var out authentication.Result
	if boundary.EnvironmentID.IsZero() || challengeID.IsZero() || len(code) != 8 {
		return out, errx.Unauthorized("invalid challenge")
	}
	if purpose == "login" && boundary.Validate() != nil {
		return out, errx.Validation("login context required")
	}
	var hash string
	var err error
	if purpose == "password_reset" {
		if err = s.resetAllowed(ctx, boundary.EnvironmentID); err != nil {
			return out, err
		}
		// Checked before the transaction: the breach check must not hold row
		// locks. A reset has no current password to compare against. The
		// policy is the user's (their organizations tighten it).
		policy, err := s.policy(ctx, boundary.EnvironmentID)
		if err != nil {
			return out, err
		}
		if s.policies != nil {
			if policy, err = s.policies.ChallengePolicy(ctx, boundary.EnvironmentID, challengeID); err != nil {
				return out, err
			}
		}
		if hash, err = s.newPassword(ctx, policy, "", password); err != nil {
			return out, err
		}
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if purpose == "login" {
		if err = s.allowed(ctx, tx, boundary, authentication.MethodCode); err != nil {
			return out, err
		}
	}
	row, err := tx.Challenge(ctx, challengeID, identity.UserID{}, purpose)
	if err != nil {
		return out, err
	}
	if row.Attempts >= 5 {
		return out, errx.Unauthorized("invalid challenge")
	}
	if purpose == "login" {
		if err = requireNoSSO(ctx, tx, boundary, row.Email); err != nil {
			return out, err
		}
	}
	if subtle.ConstantTimeCompare(row.Hash, s.secrets.Hash(challengeID.String()+":"+code)) != 1 {
		if err = tx.FailChallenge(ctx, challengeID); err != nil {
			return out, err
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, errx.Unauthorized("invalid challenge")
	}
	if err = tx.CompleteChallenge(ctx, challengeID, row.User, purpose, boundary.EnvironmentID, hash); err != nil {
		return out, err
	}
	if purpose == "login" {
		return s.SignIn(ctx, tx, boundary, row.User, authentication.MethodCode)
	}
	return out, tx.Commit()
}
