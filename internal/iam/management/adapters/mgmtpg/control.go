package mgmtpg

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "management persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("conflicting management resource")
	}
	return failure(err)
}
func (r *Repository) CreateKey(ctx context.Context, p management.Principal, id identity.KeyID, hash []byte, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, id, p.WorkspaceID, p.OperatorID, hash, expires)
	return failure(err)
}
func (r *Repository) Keys(ctx context.Context, p management.Principal) ([]management.Key, error) {
	var rows []struct {
		ID       identity.KeyID      `db:"id"`
		Operator identity.OperatorID `db:"operator_id"`
		Expires  time.Time           `db:"expires_at"`
		Revoked  *time.Time          `db:"revoked_at"`
	}
	err := r.db.SelectContext(ctx, &rows, `SELECT id,operator_id,expires_at,revoked_at FROM management_keys WHERE workspace_id=$1 AND (operator_id=$2 OR $3='owner') ORDER BY expires_at DESC`, p.WorkspaceID, p.OperatorID, p.Role)
	if err != nil {
		return nil, failure(err)
	}
	out := make([]management.Key, 0, len(rows))
	for _, row := range rows {
		out = append(out, management.Key{ID: row.ID, Operator: row.Operator, Expires: row.Expires, Revoked: row.Revoked})
	}
	return out, nil
}
func (r *Repository) RevokeKey(ctx context.Context, p management.Principal, id identity.KeyID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE management_keys SET revoked_at=now() WHERE id=$1 AND workspace_id=$2 AND (operator_id=$3 OR $4='owner')`, id, p.WorkspaceID, p.OperatorID, p.Role)
	return failure(err)
}
func (r *Repository) Delegate(ctx context.Context, p management.Principal, email, role string, key identity.KeyID, hash []byte, expires time.Time) (identity.OperatorID, bool, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return identity.OperatorID{}, false, failure(err)
	}
	defer tx.Rollback()
	// Reactivation hands back access: re-check that the caller is still an
	// active owner (its role was read when the request authenticated). The
	// owners are locked in SetOperatorRole's order, so the two never deadlock.
	var owners []identity.OperatorID
	if err = tx.SelectContext(ctx, &owners, `SELECT operator_id FROM workspace_members WHERE workspace_id=$1 AND role='owner' AND active ORDER BY operator_id FOR SHARE`, p.WorkspaceID); err != nil {
		return identity.OperatorID{}, false, failure(err)
	}
	if !slices.Contains(owners, p.OperatorID) {
		return identity.OperatorID{}, false, errx.Forbidden("insufficient permissions")
	}
	var id identity.OperatorID
	if err = tx.GetContext(ctx, &id, `INSERT INTO operators(id,email) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET email=EXCLUDED.email RETURNING id`, uuid.NewString(), email); err != nil {
		return identity.OperatorID{}, false, failure(err)
	}
	var member struct {
		Role   string `db:"role"`
		Active bool   `db:"active"`
	}
	reactivated := false
	err = tx.GetContext(ctx, &member, `SELECT role, active FROM workspace_members WHERE workspace_id=$1 AND operator_id=$2 FOR UPDATE`, p.WorkspaceID, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.ExecContext(ctx, `INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES($1,$2,$3)`, p.WorkspaceID, id, role); err != nil {
			return identity.OperatorID{}, false, conflict(err)
		}
	case err != nil:
		return identity.OperatorID{}, false, failure(err)
	case member.Active && member.Role != role:
		return identity.OperatorID{}, false, management.ErrOperatorExists()
	case !member.Active:
		reactivated = true
		if err = reactivate(ctx, tx, p.WorkspaceID, id, role); err != nil {
			return identity.OperatorID{}, false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, key, p.WorkspaceID, id, hash, expires); err != nil {
		return identity.OperatorID{}, false, failure(err)
	}
	return id, reactivated, failure(tx.Commit())
}

// reactivate makes a disabled member active again with role and nothing
// left of before: the email may now belong to someone else, or access was
// removed for a reason. Earlier keys and sessions stay ended and emergency
// access returns to off. The operator's password and linked identities are
// account-wide, so they are cleared only when no other workspace uses them.
func reactivate(ctx context.Context, tx *sqlx.Tx, workspace identity.WorkspaceID, operator identity.OperatorID, role string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE workspace_members SET active=true, role=$3, password_allowed=false WHERE workspace_id=$1 AND operator_id=$2`, workspace, operator, role); err != nil {
		return failure(err)
	}
	for _, statement := range []string{
		`UPDATE management_keys SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2 AND revoked_at IS NULL`,
		`UPDATE operator_sessions SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2 AND revoked_at IS NULL`,
	} {
		if _, err := tx.ExecContext(ctx, statement, workspace, operator); err != nil {
			return failure(err)
		}
	}
	var shared bool
	if err := tx.GetContext(ctx, &shared, `SELECT EXISTS(SELECT 1 FROM workspace_members WHERE operator_id=$1 AND workspace_id<>$2 AND active)`, operator, workspace); err != nil {
		return failure(err)
	}
	if shared {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM operator_identities WHERE operator_id=$1`, operator); err != nil {
		return failure(err)
	}
	_, err := tx.ExecContext(ctx, `UPDATE operators SET password_hash='', password_must_change=false WHERE id=$1`, operator)
	return failure(err)
}

func (r *Repository) SetOperatorRole(ctx context.Context, p management.Principal, operator identity.OperatorID, role string) (string, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return "", failure(err)
	}
	defer tx.Rollback()
	// Lock the owners first, in one order, so two owners demoting each other
	// at once cannot both pass the last-owner check. NO KEY UPDATE leaves
	// sign-ins and new keys (foreign keys to the membership) unblocked.
	var owners []identity.OperatorID
	if err = tx.SelectContext(ctx, &owners, `SELECT operator_id FROM workspace_members WHERE workspace_id=$1 AND role='owner' AND active ORDER BY operator_id FOR NO KEY UPDATE`, p.WorkspaceID); err != nil {
		return "", failure(err)
	}
	// The caller's role was read when the request authenticated; another
	// owner may have demoted them since.
	if !slices.Contains(owners, p.OperatorID) {
		return "", errx.Forbidden("insufficient permissions")
	}
	var member struct {
		Role   string `db:"role"`
		Active bool   `db:"active"`
	}
	err = tx.GetContext(ctx, &member, `SELECT role, active FROM workspace_members WHERE workspace_id=$1 AND operator_id=$2 FOR NO KEY UPDATE`, p.WorkspaceID, operator)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errx.NotFound("resource not found")
	}
	if err != nil {
		return "", failure(err)
	}
	if !member.Active {
		return "", errx.Conflict("operator is disabled; invite them again to reactivate")
	}
	if member.Role == role {
		return member.Role, nil
	}
	if member.Role == management.RoleOwner && len(owners) <= 1 {
		return "", management.ErrLastOwner()
	}
	// Roles are read from the membership on every request, so the change
	// applies to the operator's current sessions and keys at once.
	if _, err = tx.ExecContext(ctx, `UPDATE workspace_members SET role=$3 WHERE workspace_id=$1 AND operator_id=$2`, p.WorkspaceID, operator, role); err != nil {
		return "", failure(err)
	}
	// Impersonation is for owners: a former owner's impersonation sessions
	// end, so a later promotion cannot revive them.
	if member.Role == management.RoleOwner {
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE actor_id=$2 AND revoked_at IS NULL AND environment_id IN (SELECT e.id FROM environments e JOIN projects pr ON pr.id=e.project_id WHERE pr.workspace_id=$1)`, p.WorkspaceID, operator); err != nil {
			return "", failure(err)
		}
	}
	return member.Role, failure(tx.Commit())
}
func (r *Repository) DisableOperator(ctx context.Context, p management.Principal, id identity.OperatorID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE workspace_members SET active=false WHERE workspace_id=$1 AND operator_id=$2 AND role!='owner'`, p.WorkspaceID, id)
	if err != nil {
		return failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE management_keys SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2`, p.WorkspaceID, id); err != nil {
		return failure(err)
	}
	// Sessions are ended too, not only hidden behind the inactive
	// membership, so a later reactivation never revives them.
	if _, err = tx.ExecContext(ctx, `UPDATE operator_sessions SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2 AND revoked_at IS NULL`, p.WorkspaceID, id); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) SetPasswordAccess(ctx context.Context, workspace identity.WorkspaceID, operator identity.OperatorID, allowed bool) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE workspace_members SET password_allowed=$3 WHERE workspace_id=$1 AND operator_id=$2`, workspace, operator, allowed)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return failure(err)
	} else if n == 0 {
		return errx.NotFound("resource not found")
	}
	// Removing access ends the sessions opened with the emergency password;
	// single sign-on sessions stay.
	if !allowed {
		if _, err = tx.ExecContext(ctx, `UPDATE operator_sessions SET revoked_at=now() WHERE workspace_id=$1 AND operator_id=$2 AND method='password' AND revoked_at IS NULL`, workspace, operator); err != nil {
			return failure(err)
		}
	}
	return failure(tx.Commit())
}
func (r *Repository) CreateProject(ctx context.Context, workspace identity.WorkspaceID, id identity.ProjectID, name string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO projects(id,workspace_id,name) VALUES($1,$2,$3)`, id, workspace, name)
	return failure(err)
}
func (r *Repository) named(ctx context.Context, query string, args ...any) ([]management.Named, error) {
	var rows []struct {
		ID   string `db:"id"`
		Name string `db:"name"`
	}
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, failure(err)
	}
	out := make([]management.Named, 0, len(rows))
	for _, row := range rows {
		out = append(out, management.Named{ID: row.ID, Name: row.Name})
	}
	return out, nil
}
func (r *Repository) Projects(ctx context.Context, workspace identity.WorkspaceID) ([]management.Named, error) {
	return r.named(ctx, `SELECT id,name FROM projects WHERE workspace_id=$1 ORDER BY id`, workspace)
}

var iamResourcePermissions = pq.StringArray(authorization.IAMResourcePermissions)

func (r *Repository) CreateEnvironment(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID, id identity.EnvironmentID, name string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO environments(id,project_id,name) SELECT $1,id,$2 FROM projects WHERE id=$3 AND workspace_id=$4`, id, name, project, workspace)
	if err != nil {
		return conflict(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	resource := uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO resources(id,environment_id,name,prefix,audience,permissions) VALUES($1,$2,'IAM','iam',$3,$4)`,
		resource, id, "urn:iamkit:environment:"+id.String(), iamResourcePermissions)
	if err != nil {
		return failure(err)
	}
	// The built-in organization administration roles (authorization.SystemRoles).
	for _, role := range authorization.SystemRoles {
		if _, err = tx.ExecContext(ctx, `INSERT INTO roles(id,environment_id,resource_id,name,permissions,system_role) VALUES($1,$2,$3,$4,$5,$6)`,
			uuid.NewString(), id, resource, role.Name, pq.StringArray(role.Permissions), role.Key); err != nil {
			return failure(err)
		}
	}
	return failure(tx.Commit())
}
func (r *Repository) Environments(ctx context.Context, workspace identity.WorkspaceID, project identity.ProjectID) ([]management.Named, error) {
	return r.named(ctx, `SELECT e.id,e.name FROM environments e JOIN projects p ON p.id=e.project_id WHERE p.id=$1 AND p.workspace_id=$2 ORDER BY e.id`, project, workspace)
}
func (r *Repository) Operators(ctx context.Context, workspace identity.WorkspaceID) ([]management.Operator, error) {
	var rows []struct {
		ID        identity.OperatorID `db:"id"`
		Email     string              `db:"email"`
		Role      string              `db:"role"`
		Active    bool                `db:"active"`
		Allowed   bool                `db:"password_allowed"`
		Providers pq.StringArray      `db:"providers"`
		LastSSO   *time.Time          `db:"last_sso"`
	}
	err := r.db.SelectContext(ctx, &rows, `SELECT o.id, o.email, m.role, m.active, m.password_allowed,
		  COALESCE((SELECT array_agg(i.provider ORDER BY i.created_at) FROM operator_identities i WHERE i.operator_id=o.id), '{}') AS providers,
		  (SELECT max(i.last_login_at) FROM operator_identities i WHERE i.operator_id=o.id) AS last_sso
		FROM workspace_members m JOIN operators o ON o.id=m.operator_id WHERE m.workspace_id=$1 ORDER BY o.email`, workspace)
	if err != nil {
		return nil, failure(err)
	}
	out := make([]management.Operator, 0, len(rows))
	for _, row := range rows {
		out = append(out, management.Operator{ID: row.ID, Email: row.Email, Role: row.Role, Active: row.Active, PasswordAllowed: row.Allowed, Providers: []string(row.Providers), LastSSO: row.LastSSO})
	}
	return out, nil
}

var _ management.ControlRepository = (*Repository)(nil)
