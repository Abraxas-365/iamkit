package mgmtpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }
func (r *Repository) Bootstrap(ctx context.Context, email, name string, hash []byte, expires time.Time) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(734982341)`); err != nil {
		return errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	var count int
	if err = tx.GetContext(ctx, &count, `SELECT count(*) FROM workspaces`); err != nil {
		return errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	if count != 0 {
		return errx.Conflict("installation already bootstrapped")
	}
	workspace, operator := uuid.NewString(), uuid.NewString()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO workspaces(id,name) VALUES($1,$2)`, []any{workspace, name}},
		{`INSERT INTO operators(id,email) VALUES($1,$2)`, []any{operator, email}},
		{`INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES($1,$2,'owner')`, []any{workspace, operator}},
		{`INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, []any{uuid.NewString(), workspace, operator, hash, expires}},
	} {
		if _, err = tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
		}
	}
	if err = tx.Commit(); err != nil {
		return errx.Wrap(err, "bootstrap failed", errx.TypeInternal)
	}
	return nil
}
func (r *Repository) RecoverOwner(ctx context.Context, workspace, email string, hash []byte, expires time.Time) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	defer tx.Rollback()
	var operator string
	err = tx.GetContext(ctx, &operator, `SELECT m.operator_id FROM workspace_members m JOIN operators o ON o.id=m.operator_id WHERE m.workspace_id=$1 AND o.email=$2 AND m.role='owner' AND m.active FOR UPDATE OF m`, workspace, email)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.Wrap(err, "active owner not found", errx.TypeNotFound)
	}
	if err != nil {
		return errx.Wrap(err, "owner lookup failed", errx.TypeInternal)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE management_keys SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2`, workspace, operator); err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), workspace, operator, hash, expires); err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	if err = tx.Commit(); err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	return nil
}
func (r *Repository) Authenticate(ctx context.Context, hash []byte) (management.Principal, error) {
	var row struct {
		Workspace string `db:"workspace_id"`
		Operator  string `db:"operator_id"`
		Role      string `db:"role"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT k.workspace_id,k.operator_id,m.role FROM management_keys k JOIN workspace_members m USING(workspace_id,operator_id) WHERE k.secret_hash=$1 AND m.active AND k.revoked_at IS NULL AND k.expires_at>now()`, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return management.Principal{}, errx.Wrap(err, "invalid management credential", errx.TypeAuthorization)
	}
	if err != nil {
		return management.Principal{}, errx.Wrap(err, "management authentication failed", errx.TypeInternal)
	}
	return management.Principal{WorkspaceID: row.Workspace, OperatorID: row.Operator, Role: row.Role}, nil
}
func (r *Repository) EnvironmentAllowed(ctx context.Context, workspace, environment string) (bool, error) {
	var allowed bool
	err := r.db.GetContext(ctx, &allowed, `SELECT EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.workspace_id=$2)`, environment, workspace)
	if err != nil {
		return false, errx.Wrap(err, "check environment boundary", errx.TypeInternal)
	}
	return allowed, nil
}

var _ management.Repository = (*Repository)(nil)
