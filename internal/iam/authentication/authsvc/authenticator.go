package authsvc

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var _ authentication.Authenticator = (*Service)(nil)

// VerifyPassword checks email and password without creating a session.
// The organization is not known yet, so an email whose domain any
// organization enforces SSO for is refused before the password is compared
// (as Login does), unless the user may bypass SSO there.
func (s *Service) VerifyPassword(ctx context.Context, environment identity.EnvironmentID, email, password string) (authentication.Verified, error) {
	email, err := identity.Email(email)
	if err != nil || environment.IsZero() || len(password) > config.PasswordMaxLength {
		return authentication.Verified{}, invalidCredentials()
	}
	policy, err := s.policy(ctx, environment)
	if err != nil {
		return authentication.Verified{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Verified{}, err
	}
	defer tx.Rollback()
	// The organization is not chosen yet: only the environment's policy
	// applies here; Organizations and Issue apply the organization's.
	if err = s.allowed(ctx, tx, authentication.Context{EnvironmentID: environment}, authentication.MethodPassword); err != nil {
		return authentication.Verified{}, err
	}
	if err = requireNoSSO(ctx, tx, authentication.Context{EnvironmentID: environment}, email); err != nil {
		return authentication.Verified{}, err
	}
	account, lookup := tx.PasswordUser(ctx, authentication.Context{EnvironmentID: environment}, email)
	// Compare always runs (dummy hash when unknown) so timing is uniform.
	matches := s.passwords.Compare(account.Hash, password)
	if lookup != nil {
		return authentication.Verified{}, credentialFailure(lookup)
	}
	if err = s.checkPassword(ctx, tx, environment, policy, account, matches); err != nil {
		return authentication.Verified{}, credentialFailure(err)
	}
	if err = tx.Commit(); err != nil {
		return authentication.Verified{}, err
	}
	// Expiry follows the user's organizations too; lockout only the
	// environment.
	if policy, err = s.memberPolicy(ctx, environment, account.ID, policy); err != nil {
		return authentication.Verified{}, err
	}
	return authentication.Verified{User: account.ID, Email: email, Method: authentication.MethodPassword,
		PasswordExpired: policy.Expired(account.Changed, time.Now())}, nil
}

// ChangePassword replaces the expired password of a verified login. The
// new one must follow the policy and differ from the current one.
func (s *Service) ChangePassword(ctx context.Context, environment identity.EnvironmentID, verified authentication.Verified, password string) (authentication.Verified, error) {
	if !verified.PasswordExpired || verified.User.IsZero() || environment.IsZero() {
		return verified, errx.Validation("no password change is pending")
	}
	policy, err := s.policy(ctx, environment)
	if err != nil {
		return verified, err
	}
	if policy, err = s.memberPolicy(ctx, environment, verified.User, policy); err != nil {
		return verified, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return verified, err
	}
	defer tx.Rollback()
	account, err := tx.PasswordUser(ctx, authentication.Context{EnvironmentID: environment}, verified.Email)
	if err != nil || account.ID != verified.User {
		return verified, invalidCredentials()
	}
	hash, err := s.newPassword(ctx, policy, account.Hash, password)
	if err != nil {
		return verified, err
	}
	if err = tx.SetPassword(ctx, environment, verified.User, hash); err != nil {
		return verified, err
	}
	if err = tx.Commit(); err != nil {
		return verified, err
	}
	verified.PasswordExpired = false
	return verified, nil
}

// VerifyCode consumes a login challenge without creating a session.
func (s *Service) VerifyCode(ctx context.Context, environment identity.EnvironmentID, challenge identity.ChallengeID, code string) (authentication.Verified, error) {
	if environment.IsZero() || challenge.IsZero() || len(code) != 8 {
		return authentication.Verified{}, errx.Unauthorized("invalid challenge")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Verified{}, err
	}
	defer tx.Rollback()
	if err = s.allowed(ctx, tx, authentication.Context{EnvironmentID: environment}, authentication.MethodCode); err != nil {
		return authentication.Verified{}, err
	}
	row, err := tx.Challenge(ctx, challenge, identity.UserID{}, "login")
	if err != nil {
		return authentication.Verified{}, err
	}
	if row.Attempts >= 5 || row.Environment != environment {
		return authentication.Verified{}, errx.Unauthorized("invalid challenge")
	}
	if err = requireNoSSO(ctx, tx, authentication.Context{EnvironmentID: environment}, row.Email); err != nil {
		return authentication.Verified{}, err
	}
	if subtle.ConstantTimeCompare(row.Hash, s.secrets.Hash(challenge.String()+":"+code)) != 1 {
		if err = tx.FailChallenge(ctx, challenge); err != nil {
			return authentication.Verified{}, err
		}
		if err = tx.Commit(); err != nil {
			return authentication.Verified{}, err
		}
		return authentication.Verified{}, errx.Unauthorized("invalid challenge")
	}
	if err = tx.CompleteChallenge(ctx, challenge, row.User, "login", environment, ""); err != nil {
		return authentication.Verified{}, err
	}
	if err = tx.Commit(); err != nil {
		return authentication.Verified{}, err
	}
	return authentication.Verified{User: row.User, Email: row.Email, Method: authentication.MethodCode}, nil
}

// Organizations drops the organizations that do not allow the method the
// user verified with; when that leaves none of several, the method is the
// reason (ErrMethodNotAllowed) rather than missing access.
func (s *Service) Organizations(ctx context.Context, target authentication.Target, verified authentication.Verified) ([]authentication.Organization, error) {
	if target.Environment.IsZero() || target.Application.IsZero() || target.Resource.IsZero() || verified.User.IsZero() {
		return nil, errx.Validation("invalid login target")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	all, err := tx.AccessibleOrganizations(ctx, target, verified.User)
	if err != nil {
		return nil, err
	}
	method := verified.PolicyMethod()
	out := make([]authentication.Organization, 0, len(all))
	for _, o := range all {
		if o.Methods.Allows(method) {
			out = append(out, o)
		}
	}
	if len(out) == 0 && len(all) > 0 {
		return nil, authentication.ErrMethodNotAllowed()
	}
	return out, nil
}

// Issue creates the session for a verified user in the chosen organization.
// A user verified by organization SSO may only enter that organization.
func (s *Service) Issue(ctx context.Context, boundary authentication.Context, verified authentication.Verified) (authentication.Issued, error) {
	if err := boundary.Validate(); err != nil {
		return authentication.Issued{}, err
	}
	if verified.User.IsZero() {
		return authentication.Issued{}, invalidCredentials()
	}
	if verified.PasswordExpired {
		return authentication.Issued{}, authentication.ErrPasswordChangeRequired()
	}
	if !verified.Organization.IsZero() && verified.Organization != boundary.OrganizationID {
		return authentication.Issued{}, errx.Forbidden("signed in with another organization's single sign-on")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Issued{}, err
	}
	defer tx.Rollback()
	if method := verified.PolicyMethod(); method != "" {
		if err = s.allowed(ctx, tx, boundary, method); err != nil {
			return authentication.Issued{}, err
		}
	}
	// Only the organization's own single sign-on satisfies its enforcement;
	// environment connections (social providers) do not.
	if verified.Method != authentication.MethodSSO || verified.Organization.IsZero() {
		if err = requireNoSSO(ctx, tx, boundary, verified.Email); err != nil {
			return authentication.Issued{}, err
		}
	}
	// Hosted pages verify the second factor before issuing; this is the
	// backstop should a caller skip that step.
	if s.second != nil && !authentication.HasMFA(verified.AMR) {
		req, err := s.second.Requirement(ctx, boundary, verified.User, verified.FederatedFor(boundary.OrganizationID))
		if err != nil {
			return authentication.Issued{}, err
		}
		if req.Needed {
			return authentication.Issued{}, errx.Forbidden("a second factor is required")
		}
	}
	out, err := s.NewSession(ctx, tx, boundary, verified.User, verified.Methods())
	if unauthorizedErr(err) {
		return out, errx.Forbidden("you do not have access to this application in the selected organization")
	}
	return out, err
}

func unauthorizedErr(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeAuthorization && e.HTTPStatus == 401
}
