package sacctpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "service account persistence failed", errx.TypeInternal)
}
func (r *Repository) Catalog(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]string, error) {
	var out pq.StringArray
	err := r.db.GetContext(ctx, &out, `SELECT permissions FROM resources WHERE id=$1 AND environment_id=$2`, resource, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("resource not found")
	}
	return []string(out), failure(err)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, input serviceaccount.Input, out serviceaccount.Credential, hash []byte) error {
	if input.Permissions == nil {
		input.Permissions = []string{}
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO service_accounts(id,environment_id,application_id,resource_id,name,permissions,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, out.ID, environment, input.Application, input.Resource, input.Name, pq.Array(input.Permissions), hash, out.Expires)
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("service account requires application/resource binding")
	}
	return failure(err)
}
func (r *Repository) Revoke(ctx context.Context, environment identity.EnvironmentID, id identity.AccountID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE service_accounts SET revoked_at=now() WHERE id=$1 AND environment_id=$2`, id, environment)
	return failure(err)
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID) ([]serviceaccount.Account, error) {
	var rows []serviceaccount.Account
	err := r.db.SelectContext(ctx, &rows, `SELECT sa.id, sa.name, sa.application_id, a.name AS application_name, sa.resource_id, res.name AS resource_name, sa.permissions, sa.expires_at, sa.revoked_at FROM service_accounts sa JOIN applications a ON a.id=sa.application_id JOIN resources res ON res.id=sa.resource_id WHERE sa.environment_id=$1 ORDER BY sa.name`, environment)
	if err != nil {
		return nil, failure(err)
	}
	return rows, nil
}

var _ serviceaccount.Repository = (*Repository)(nil)
