package authzpg

import (
	"context"
	"database/sql"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/lib/pq"
)

func (r *Repository) Catalog(ctx context.Context, environment, id string) ([]string, error) {
	var catalog pq.StringArray
	err := r.db.GetContext(ctx, &catalog, `SELECT permissions FROM resources WHERE environment_id=$1 AND id=$2`, environment, id)
	if err == sql.ErrNoRows {
		return nil, errx.NotFound("resource not found")
	}
	return []string(catalog), failure(err)
}
func (r *Repository) Roles(ctx context.Context, environment, id string) ([]authorization.RoleView, error) {
	type row struct {
		ID          string         `db:"id"`
		Name        string         `db:"name"`
		Resource    string         `db:"resource_id"`
		Permissions pq.StringArray `db:"permissions"`
	}
	rows := []row{}
	query, args := `SELECT id,name,resource_id,permissions FROM roles WHERE environment_id=$1`, []any{environment}
	if id != "" {
		query += " AND id=$2"
		args = append(args, id)
	}
	query += " ORDER BY id"
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, failure(err)
	}
	out := make([]authorization.RoleView, 0, len(rows))
	for _, row := range rows {
		out = append(out, authorization.RoleView{ID: row.ID, Name: row.Name, Resource: row.Resource, Permissions: []string(row.Permissions)})
	}
	return out, nil
}
func (r *Repository) Grants(ctx context.Context, environment, id string) ([]authorization.GrantView, error) {
	type row struct {
		ID           string         `db:"id"`
		Organization string         `db:"organization_id"`
		User         string         `db:"user_id"`
		Resource     string         `db:"resource_id"`
		Permissions  pq.StringArray `db:"permissions"`
	}
	rows := []row{}
	query, args := `SELECT id,organization_id,user_id,resource_id,permissions FROM grants WHERE environment_id=$1`, []any{environment}
	if id != "" {
		query += " AND id=$2"
		args = append(args, id)
	}
	query += " ORDER BY id"
	if err := r.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, failure(err)
	}
	out := make([]authorization.GrantView, 0, len(rows))
	for _, row := range rows {
		out = append(out, authorization.GrantView{ID: row.ID, Organization: row.Organization, User: row.User, Resource: row.Resource, Permissions: []string(row.Permissions)})
	}
	return out, nil
}
func (r *Repository) mutate(ctx context.Context, m authorization.Mutation, query string, args ...any) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, query, args...)
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) SaveRole(ctx context.Context, m authorization.Mutation, id string, input authorization.Role, creating bool) error {
	if !creating {
		return r.mutate(ctx, m, `UPDATE roles SET name=$3,permissions=$4 WHERE environment_id=$1 AND id=$2 AND resource_id=$5`, m.Environment, id, input.Name, array(input.Permissions), input.Resource)
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO roles(id,environment_id,resource_id,name,permissions) VALUES($1,$2,$3,$4,$5)`, id, m.Environment, input.Resource, input.Name, array(input.Permissions))
	return conflict(err)
}
func (r *Repository) DeleteRole(ctx context.Context, m authorization.Mutation, id string) error {
	return r.mutate(ctx, m, `DELETE FROM roles WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}
func (r *Repository) AssignRole(ctx context.Context, m authorization.Mutation, input authorization.RoleAssignment) error {
	return r.mutate(ctx, m, `INSERT INTO role_assignments(environment_id,organization_id,user_id,resource_id,role_id) SELECT environment_id,$2,$3,resource_id,id FROM roles WHERE environment_id=$1 AND id=$4`, m.Environment, input.Organization, input.User, input.Role)
}
func (r *Repository) UnassignRole(ctx context.Context, m authorization.Mutation, input authorization.RoleAssignment) error {
	return r.mutate(ctx, m, `DELETE FROM role_assignments WHERE environment_id=$1 AND role_id=$2 AND organization_id=$3 AND user_id=$4`, m.Environment, input.Role, input.Organization, input.User)
}
func (r *Repository) PutGrant(ctx context.Context, environment, id string, input authorization.Grant) (string, error) {
	err := r.db.GetContext(ctx, &id, `INSERT INTO grants(id,environment_id,organization_id,user_id,resource_id,permissions) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organization_id,user_id,resource_id) DO UPDATE SET permissions=EXCLUDED.permissions RETURNING id`, id, environment, input.Organization, input.User, input.Resource, array(input.Permissions))
	return id, conflict(err)
}
func (r *Repository) DeleteGrant(ctx context.Context, environment, id string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var row struct {
		Organization string `db:"organization_id"`
		User         string `db:"user_id"`
		Resource     string `db:"resource_id"`
	}
	err = tx.GetContext(ctx, &row, `DELETE FROM grants WHERE id=$1 AND environment_id=$2 RETURNING organization_id,user_id,resource_id`, id, environment)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3 AND resource_id=$4`, environment, row.Organization, row.User, row.Resource); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

var _ authorization.Grants = (*Repository)(nil)
