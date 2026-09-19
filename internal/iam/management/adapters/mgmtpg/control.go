package mgmtpg

import (
	"context"
	"errors"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"time"
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
func (r *Repository) CreateKey(ctx context.Context, p management.Principal, id string, hash []byte, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, id, p.WorkspaceID, p.OperatorID, hash, expires)
	return failure(err)
}
func (r *Repository) Keys(ctx context.Context, p management.Principal) ([]management.Key, error) {
	var rows []struct {
		ID       string     `db:"id"`
		Operator string     `db:"operator_id"`
		Expires  time.Time  `db:"expires_at"`
		Revoked  *time.Time `db:"revoked_at"`
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
func (r *Repository) RevokeKey(ctx context.Context, p management.Principal, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE management_keys SET revoked_at=now() WHERE id=$1 AND workspace_id=$2 AND (operator_id=$3 OR $4='owner')`, id, p.WorkspaceID, p.OperatorID, p.Role)
	return failure(err)
}
func (r *Repository) Delegate(ctx context.Context, p management.Principal, email, role, key string, hash []byte, expires time.Time) (string, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return "", failure(err)
	}
	defer tx.Rollback()
	id := uuid.NewString()
	if err = tx.GetContext(ctx, &id, `INSERT INTO operators(id,email) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET email=EXCLUDED.email RETURNING id`, id, email); err != nil {
		return "", failure(err)
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES($1,$2,$3) ON CONFLICT(workspace_id,operator_id) DO UPDATE SET role=EXCLUDED.role WHERE workspace_members.active AND workspace_members.role=EXCLUDED.role`, p.WorkspaceID, id, role)
	if err != nil {
		return "", conflict(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", failure(err)
	}
	if n == 0 {
		return "", errx.Conflict("operator is disabled or has a different role")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, key, p.WorkspaceID, id, hash, expires); err != nil {
		return "", failure(err)
	}
	return id, failure(tx.Commit())
}
func (r *Repository) DisableOperator(ctx context.Context, p management.Principal, id string) error {
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
	return failure(tx.Commit())
}
func (r *Repository) CreateProject(ctx context.Context, workspace, id, name string) error {
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
func (r *Repository) Projects(ctx context.Context, workspace string) ([]management.Named, error) {
	return r.named(ctx, `SELECT id,name FROM projects WHERE workspace_id=$1 ORDER BY id`, workspace)
}
var iamResourcePermissions = pq.StringArray{
	"iam:users:read", "iam:users:write",
	"iam:orgs:read", "iam:orgs:write",
	"iam:members:read", "iam:members:write",
	"iam:apps:read", "iam:apps:write",
	"iam:resources:read", "iam:resources:write",
	"iam:roles:read", "iam:roles:write",
	"iam:grants:read", "iam:grants:write",
	"iam:service-accounts:read", "iam:service-accounts:write",
}

func (r *Repository) CreateEnvironment(ctx context.Context, workspace, project, id, name string) error {
	res, err := r.db.ExecContext(ctx, `INSERT INTO environments(id,project_id,name) SELECT $1,id,$2 FROM projects WHERE id=$3 AND workspace_id=$4`, id, name, project, workspace)
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
	_, err = r.db.ExecContext(ctx, `INSERT INTO resources(id,environment_id,name,prefix,audience,permissions) VALUES($1,$2,'IAM','iam',$3,$4)`,
		uuid.NewString(), id, "urn:iamkit:environment:"+id, iamResourcePermissions)
	if err != nil {
		return failure(err)
	}
	return nil
}
func (r *Repository) Environments(ctx context.Context, workspace, project string) ([]management.Named, error) {
	return r.named(ctx, `SELECT e.id,e.name FROM environments e JOIN projects p ON p.id=e.project_id WHERE p.id=$1 AND p.workspace_id=$2 ORDER BY e.id`, project, workspace)
}
func (r *Repository) Operators(ctx context.Context, workspace string) ([]management.Operator, error) {
	var rows []struct {
		ID     string `db:"id"`
		Email  string `db:"email"`
		Role   string `db:"role"`
		Active bool   `db:"active"`
	}
	err := r.db.SelectContext(ctx, &rows, `SELECT o.id, o.email, m.role, m.active FROM workspace_members m JOIN operators o ON o.id=m.operator_id WHERE m.workspace_id=$1 ORDER BY o.email`, workspace)
	if err != nil {
		return nil, failure(err)
	}
	out := make([]management.Operator, 0, len(rows))
	for _, row := range rows {
		out = append(out, management.Operator{ID: row.ID, Email: row.Email, Role: row.Role, Active: row.Active})
	}
	return out, nil
}

var _ management.ControlRepository = (*Repository)(nil)
