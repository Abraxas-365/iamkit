// Package hostedpg persists hosted login state and branding in PostgreSQL.
package hostedpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ hosted.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "hosted login persistence failed", errx.TypeInternal)
}

func (r *Repository) SaveLogin(ctx context.Context, hash []byte, environment identity.EnvironmentID, l hosted.Login, expires time.Time) error {
	v := l.Verified
	// Re-saving the same user's login (a step, or the first factor again on
	// this ticket) never lowers the second-factor attempts already spent.
	_, err := r.db.ExecContext(ctx, `INSERT INTO hosted_logins(ticket_hash,environment_id,user_id,email,method,organization_id,expires_at,amr,chosen_organization_id,mfa_attempts) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (ticket_hash) DO UPDATE SET environment_id=EXCLUDED.environment_id, user_id=EXCLUDED.user_id, email=EXCLUDED.email, method=EXCLUDED.method, organization_id=EXCLUDED.organization_id, expires_at=EXCLUDED.expires_at, amr=EXCLUDED.amr, chosen_organization_id=EXCLUDED.chosen_organization_id,
		mfa_attempts=CASE WHEN hosted_logins.user_id=EXCLUDED.user_id THEN GREATEST(hosted_logins.mfa_attempts,EXCLUDED.mfa_attempts) ELSE EXCLUDED.mfa_attempts END`,
		hash, environment, v.User, v.Email, v.Method, v.Organization, expires, pq.StringArray(append([]string{}, v.AMR...)), l.Chosen, l.Attempts)
	return failure(err)
}

func (r *Repository) Login(ctx context.Context, hash []byte, environment identity.EnvironmentID) (hosted.Login, error) {
	var row struct {
		User         identity.UserID         `db:"user_id"`
		Email        string                  `db:"email"`
		Method       string                  `db:"method"`
		Organization identity.OrganizationID `db:"organization_id"`
		AMR          pq.StringArray          `db:"amr"`
		Chosen       identity.OrganizationID `db:"chosen_organization_id"`
		Attempts     int                     `db:"mfa_attempts"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT user_id,email,method,organization_id,amr,chosen_organization_id,mfa_attempts FROM hosted_logins WHERE ticket_hash=$1 AND environment_id=$2 AND expires_at>now()`, hash, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return hosted.Login{}, hosted.ErrLoginExpired()
	}
	if err != nil {
		return hosted.Login{}, failure(err)
	}
	return hosted.Login{Verified: authentication.Verified{User: row.User, Email: row.Email, Method: row.Method, Organization: row.Organization, AMR: []string(row.AMR)}, Chosen: row.Chosen, Attempts: row.Attempts}, nil
}

func (r *Repository) Attempt(ctx context.Context, hash []byte, limit int) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE hosted_logins SET mfa_attempts=mfa_attempts+1 WHERE ticket_hash=$1 AND expires_at>now() AND mfa_attempts<$2`, hash, limit)
	if err != nil {
		return false, failure(err)
	}
	n, err := res.RowsAffected()
	return n == 1, failure(err)
}

// DeleteLogin removes the login, and every expired one with it.
func (r *Repository) DeleteLogin(ctx context.Context, hash []byte) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM hosted_logins WHERE ticket_hash=$1 OR expires_at<now()`, hash)
	return failure(err)
}
