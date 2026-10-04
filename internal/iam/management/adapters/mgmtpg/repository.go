package mgmtpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
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
		{`INSERT INTO workspace_members(workspace_id,operator_id,role,password_allowed) VALUES($1,$2,'owner',true)`, []any{workspace, operator}},
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
func (r *Repository) RecoverOwner(ctx context.Context, workspace identity.WorkspaceID, email string, hash []byte, expires time.Time) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	defer tx.Rollback()
	var operator string
	err = tx.GetContext(ctx, &operator, `SELECT m.operator_id FROM workspace_members m JOIN operators o ON o.id=m.operator_id WHERE m.workspace_id=$1 AND o.email=$2 AND m.role='owner' AND m.active FOR UPDATE OF m`, workspace, email)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("no active owner with that email in that workspace")
	}
	if err != nil {
		return errx.Wrap(err, "owner lookup failed", errx.TypeInternal)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE management_keys SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2`, workspace, operator); err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operator_sessions SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2 AND revoked_at IS NULL`, workspace, operator); err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operators SET password_hash='', password_must_change=false WHERE id=$1`, operator); err != nil {
		return errx.Wrap(err, "owner recovery failed", errx.TypeInternal)
	}
	// Recovery is how an owner gets back in when single sign-on fails, so
	// the recovered owner may set a password in break-glass mode.
	if _, err = tx.ExecContext(ctx, `UPDATE workspace_members SET password_allowed=true WHERE workspace_id=$1 AND operator_id=$2`, workspace, operator); err != nil {
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
		Workspace identity.WorkspaceID `db:"workspace_id"`
		Operator  identity.OperatorID  `db:"operator_id"`
		Role      string               `db:"role"`
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
func (r *Repository) EnvironmentAllowed(ctx context.Context, workspace identity.WorkspaceID, environment identity.EnvironmentID) (bool, error) {
	var allowed bool
	err := r.db.GetContext(ctx, &allowed, `SELECT EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.workspace_id=$2)`, environment, workspace)
	if err != nil {
		return false, errx.Wrap(err, "check environment boundary", errx.TypeInternal)
	}
	return allowed, nil
}

var _ management.Repository = (*Repository)(nil)
var _ management.SessionRepository = (*Repository)(nil)

func (r *Repository) PasswordByEmail(ctx context.Context, email string) (management.PasswordAccount, error) {
	var row struct {
		Workspace    identity.WorkspaceID `db:"workspace_id"`
		Operator     identity.OperatorID  `db:"operator_id"`
		Role         string               `db:"role"`
		PasswordHash string               `db:"password_hash"`
		Allowed      bool                 `db:"password_allowed"`
		MustChange   bool                 `db:"password_must_change"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT m.workspace_id, m.operator_id, m.role, o.password_hash, m.password_allowed, o.password_must_change FROM operators o JOIN workspace_members m ON m.operator_id=o.id JOIN workspaces w ON w.id=m.workspace_id WHERE o.email=$1 AND m.active ORDER BY `+memberOrder+` LIMIT 1`, email)
	if errors.Is(err, sql.ErrNoRows) {
		return management.PasswordAccount{}, errx.Unauthorized("invalid credentials")
	}
	if err != nil {
		return management.PasswordAccount{}, failure(err)
	}
	p := management.Principal{WorkspaceID: row.Workspace, OperatorID: row.Operator, Role: row.Role}
	return management.PasswordAccount{Principal: p, Hash: row.PasswordHash, Allowed: row.Allowed, MustChange: row.MustChange}, nil
}
func (r *Repository) OperatorPassword(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID) (management.PasswordAccount, error) {
	var row struct {
		PasswordHash string `db:"password_hash"`
		Allowed      bool   `db:"password_allowed"`
		MustChange   bool   `db:"password_must_change"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT o.password_hash, m.password_allowed, o.password_must_change FROM operators o JOIN workspace_members m ON m.operator_id=o.id WHERE m.workspace_id=$1 AND o.id=$2 AND m.active`, workspace, operator)
	if errors.Is(err, sql.ErrNoRows) {
		return management.PasswordAccount{}, errx.Unauthorized("management credential required")
	}
	if err != nil {
		return management.PasswordAccount{}, failure(err)
	}
	return management.PasswordAccount{Hash: row.PasswordHash, Allowed: row.Allowed, MustChange: row.MustChange}, nil
}
func (r *Repository) Preferences(ctx context.Context, operator identity.OperatorID) (management.Preferences, error) {
	var out management.Preferences
	err := r.db.GetContext(ctx, &out.Locale, `SELECT locale FROM operators WHERE id=$1`, operator)
	if errors.Is(err, sql.ErrNoRows) {
		return management.Preferences{}, errx.Unauthorized("management credential required")
	}
	return out, failure(err)
}
func (r *Repository) SetPreferences(ctx context.Context, operator identity.OperatorID, input management.Preferences) error {
	_, err := r.db.ExecContext(ctx, `UPDATE operators SET locale=$2 WHERE id=$1`, operator, input.Locale)
	return failure(err)
}
func (r *Repository) CreateSession(ctx context.Context, id identity.SessionID, p management.Principal, hash []byte, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO operator_sessions(id,workspace_id,operator_id,secret_hash,expires_at,method,authenticated_at) VALUES($1,$2,$3,$4,$5,$6,now())`, id, p.WorkspaceID, p.OperatorID, hash, expires, p.Method)
	return failure(err)
}
func (r *Repository) AuthenticateSession(ctx context.Context, hash []byte) (management.Principal, error) {
	var row struct {
		Session   identity.SessionID   `db:"id"`
		Workspace identity.WorkspaceID `db:"workspace_id"`
		Operator  identity.OperatorID  `db:"operator_id"`
		Role      string               `db:"role"`
		Method    string               `db:"method"`
		AuthTime  time.Time            `db:"authenticated_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT s.id, s.workspace_id, s.operator_id, m.role, s.method, s.authenticated_at FROM operator_sessions s JOIN workspace_members m USING(workspace_id,operator_id) WHERE s.secret_hash=$1 AND m.active AND s.revoked_at IS NULL AND s.expires_at>now()`, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return management.Principal{}, errx.Unauthorized("invalid session")
	}
	if err != nil {
		return management.Principal{}, failure(err)
	}
	return management.Principal{WorkspaceID: row.Workspace, OperatorID: row.Operator, Role: row.Role, Method: row.Method, Session: row.Session, AuthTime: &row.AuthTime}, nil
}
func (r *Repository) RevokeSessionByHash(ctx context.Context, hash []byte) error {
	_, err := r.db.ExecContext(ctx, `UPDATE operator_sessions SET revoked_at=now() WHERE secret_hash=$1 AND revoked_at IS NULL`, hash)
	return failure(err)
}
func (r *Repository) SetPassword(ctx context.Context, operatorID identity.OperatorID, hash string, mustChange bool, keep identity.SessionID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE operators SET password_hash=$1, password_must_change=$2 WHERE id=$3`, hash, mustChange, operatorID); err != nil {
		return failure(err)
	}
	// keep is zero for a login or a key: then every session ends.
	if _, err = tx.ExecContext(ctx, `UPDATE operator_sessions SET revoked_at=now() WHERE operator_id=$1 AND revoked_at IS NULL AND id IS DISTINCT FROM $2`, operatorID, nullable(keep)); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

// nullable maps a zero session ID to NULL.
func nullable(id identity.SessionID) any {
	if id.IsZero() {
		return nil
	}
	return id
}
func (r *Repository) ResetPassword(ctx context.Context, operatorID identity.OperatorID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE operators SET password_hash='', password_must_change=false WHERE id=$1`, operatorID)
	return failure(err)
}
