package imppg

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation"
	"github.com/jmoiron/sqlx"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "impersonation persistence failed", errx.TypeInternal)
}
func (r *Repository) Create(ctx context.Context, t impersonation.Target) (authentication.Access, error) {
	var access authentication.Access
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return access, failure(err)
	}
	defer tx.Rollback()
	var active bool
	err = tx.GetContext(ctx, &active, `SELECT active FROM users WHERE id=$1 AND environment_id=$2 FOR UPDATE`, t.User, t.Context.EnvironmentID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !active) {
		return access, errx.NotFound("active user not found")
	}
	if err != nil {
		return access, failure(err)
	}
	access, err = authpg.Resolve(ctx, tx, t.Context, t.User)
	if err != nil {
		return access, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,actor_id,impersonation_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.Session, t.Context.EnvironmentID, t.Context.OrganizationID, t.User, t.Context.ApplicationID, t.Context.ResourceID, t.Expires, t.Actor, t.Reason)
	if err != nil {
		return access, failure(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,'impersonate',$3)`, t.Context.EnvironmentID, t.Actor, t.Session)
	if err != nil {
		return access, failure(err)
	}
	return access, failure(tx.Commit())
}

var _ impersonation.Repository = (*Repository)(nil)
