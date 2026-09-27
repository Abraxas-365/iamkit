package authsvc

import (
	"context"
	"crypto/subtle"

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
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Verified{}, err
	}
	defer tx.Rollback()
	if err = requireNoSSO(ctx, tx, authentication.Context{EnvironmentID: environment}, email); err != nil {
		return authentication.Verified{}, err
	}
	user, hash, lookup := tx.PasswordUser(ctx, authentication.Context{EnvironmentID: environment}, email)
	// Compare always runs (dummy hash when unknown) so timing is uniform.
	matches := s.passwords.Compare(hash, password)
	if lookup != nil {
		return authentication.Verified{}, credentialFailure(lookup)
	}
	if !matches {
		return authentication.Verified{}, invalidCredentials()
	}
	return authentication.Verified{User: user, Email: email, Method: authentication.MethodPassword}, nil
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

func (s *Service) Organizations(ctx context.Context, target authentication.Target, user identity.UserID) ([]authentication.Organization, error) {
	if target.Environment.IsZero() || target.Application.IsZero() || target.Resource.IsZero() || user.IsZero() {
		return nil, errx.Validation("invalid login target")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return tx.AccessibleOrganizations(ctx, target, user)
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
	if !verified.Organization.IsZero() && verified.Organization != boundary.OrganizationID {
		return authentication.Issued{}, errx.Forbidden("signed in with another organization's single sign-on")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return authentication.Issued{}, err
	}
	defer tx.Rollback()
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
		req, err := s.second.Requirement(ctx, boundary, verified.User, verified.Federated())
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
