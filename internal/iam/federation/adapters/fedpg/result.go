package fedpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ReturnAllowed reports whether an active OAuth client of the active
// application lists origin.
func (r *Repository) ReturnAllowed(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, origin string) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM oauth_clients oc JOIN applications a ON a.id=oc.application_id AND a.environment_id=oc.environment_id
		WHERE oc.environment_id=$1 AND oc.application_id=$2 AND oc.allowed_origins @> ARRAY[$3]::text[] AND oc.active AND a.active)`, environment, application, origin)
	return ok, failure(err)
}

// ParkResult stores a verified sign-in for ResultTTL; expired rows are
// pruned on the way.
func (r *Repository) ParkResult(ctx context.Context, handle []byte, res federation.Result) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM federation_results WHERE expires_at<now()`); err != nil {
		return failure(err)
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO federation_results(handle_hash,environment_id,organization_id,application_id,resource_id,user_id,email,organization_sso,no_access,challenge,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+make_interval(secs => $11))`,
		handle, res.Boundary.EnvironmentID, res.Boundary.OrganizationID, res.Boundary.ApplicationID, res.Boundary.ResourceID, res.User, res.Email, res.OrganizationSSO, res.NoAccess, res.Challenge, federation.ResultTTL.Seconds())
	return failure(err)
}

func (r *Repository) TakeResult(ctx context.Context, handle []byte) (federation.Result, error) {
	var row struct {
		Environment     identity.EnvironmentID  `db:"environment_id"`
		Organization    identity.OrganizationID `db:"organization_id"`
		Application     identity.ApplicationID  `db:"application_id"`
		Resource        identity.ResourceID     `db:"resource_id"`
		User            identity.UserID         `db:"user_id"`
		Email           string                  `db:"email"`
		OrganizationSSO bool                    `db:"organization_sso"`
		NoAccess        bool                    `db:"no_access"`
		Challenge       string                  `db:"challenge"`
	}
	err := r.db.GetContext(ctx, &row, `DELETE FROM federation_results WHERE handle_hash=$1 AND expires_at>now()
		RETURNING environment_id,organization_id,application_id,resource_id,user_id,email,organization_sso,no_access,challenge`, handle)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.Result{}, errx.Unauthorized("invalid or expired federation result")
	}
	if err != nil {
		return federation.Result{}, failure(err)
	}
	return federation.Result{
		Boundary: authentication.Context{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource},
		User:     row.User, Email: row.Email, OrganizationSSO: row.OrganizationSSO, NoAccess: row.NoAccess, Challenge: row.Challenge,
	}, nil
}

func (r *Repository) ActiveUser(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.Transaction, federation.Account, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, federation.Account{}, failure(err)
	}
	var account federation.Account
	err = tx.GetContext(ctx, &account, `SELECT id, email FROM users WHERE id=$1 AND environment_id=$2 AND active FOR UPDATE`, user, environment)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return nil, federation.Account{}, errx.Unauthorized("invalid or expired federation result")
		}
		return nil, federation.Account{}, failure(err)
	}
	return authpg.Wrap(tx), account, nil
}
