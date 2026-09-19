package authzpg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/lib/pq"
)

func (r *Repository) Catalog(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID) ([]string, error) {
	var catalog pq.StringArray
	err := r.db.GetContext(ctx, &catalog, `SELECT permissions FROM resources WHERE environment_id=$1 AND id=$2`, environment, id)
	if err == sql.ErrNoRows {
		return nil, errx.NotFound("resource not found")
	}
	return []string(catalog), failure(err)
}
func (r *Repository) ListRoles(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID, page query.Pagination) (query.Paginated[authorization.RoleView], error) {
	base := `FROM roles r JOIN resources res ON res.id=r.resource_id WHERE r.environment_id=$1`
	args := []any{environment}
	n := 1
	if !id.IsZero() {
		n++
		base += fmt.Sprintf(" AND r.id=$%d", n)
		args = append(args, id)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (r.name ILIKE $%d OR res.name ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[authorization.RoleView]{}, failure(err)
	}
	type roleRow struct {
		ID           identity.RoleID     `db:"id"`
		Name         string              `db:"name"`
		Resource     identity.ResourceID `db:"resource_id"`
		ResourceName string              `db:"resource_name"`
		Permissions  pq.StringArray      `db:"permissions"`
	}
	dbRows := []roleRow{}
	sel := fmt.Sprintf("SELECT r.id, r.name, r.resource_id, res.name AS resource_name, r.permissions %s ORDER BY r.name LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &dbRows, sel, args...); err != nil {
		return query.Paginated[authorization.RoleView]{}, failure(err)
	}
	rows := make([]authorization.RoleView, len(dbRows))
	for i, row := range dbRows {
		rows[i] = authorization.RoleView{ID: row.ID, Name: row.Name, Resource: row.Resource, ResourceName: row.ResourceName, Permissions: []string(row.Permissions)}
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) ListGrants(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID, page query.Pagination) (query.Paginated[authorization.GrantView], error) {
	base := `FROM grants g JOIN organizations o ON o.id=g.organization_id JOIN users u ON u.id=g.user_id JOIN resources res ON res.id=g.resource_id WHERE g.environment_id=$1`
	args := []any{environment}
	n := 1
	if !id.IsZero() {
		n++
		base += fmt.Sprintf(" AND g.id=$%d", n)
		args = append(args, id)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (o.name ILIKE $%d OR u.name ILIKE $%d OR res.name ILIKE $%d)", n, n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[authorization.GrantView]{}, failure(err)
	}
	type grantRow struct {
		ID               identity.GrantID        `db:"id"`
		Organization     identity.OrganizationID `db:"organization_id"`
		OrganizationName string                  `db:"organization_name"`
		User             identity.UserID         `db:"user_id"`
		UserName         string                  `db:"user_name"`
		Resource         identity.ResourceID     `db:"resource_id"`
		ResourceName     string                  `db:"resource_name"`
		Permissions      pq.StringArray          `db:"permissions"`
	}
	dbRows := []grantRow{}
	sel := fmt.Sprintf("SELECT g.id, g.organization_id, o.name AS organization_name, g.user_id, u.name AS user_name, g.resource_id, res.name AS resource_name, g.permissions %s ORDER BY g.id LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &dbRows, sel, args...); err != nil {
		return query.Paginated[authorization.GrantView]{}, failure(err)
	}
	rows := make([]authorization.GrantView, len(dbRows))
	for i, row := range dbRows {
		rows[i] = authorization.GrantView{ID: row.ID, Organization: row.Organization, OrganizationName: row.OrganizationName, User: row.User, UserName: row.UserName, Resource: row.Resource, ResourceName: row.ResourceName, Permissions: []string(row.Permissions)}
	}
	return query.NewPaginated(rows, total, page), nil
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
func (r *Repository) SaveRole(ctx context.Context, m authorization.Mutation, id identity.RoleID, input authorization.Role, creating bool) error {
	if !creating {
		return r.mutate(ctx, m, `UPDATE roles SET name=$3,permissions=$4 WHERE environment_id=$1 AND id=$2 AND resource_id=$5`, m.Environment, id, input.Name, array(input.Permissions), input.Resource)
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO roles(id,environment_id,resource_id,name,permissions) VALUES($1,$2,$3,$4,$5)`, id, m.Environment, input.Resource, input.Name, array(input.Permissions))
	return conflict(err)
}
func (r *Repository) DeleteRole(ctx context.Context, m authorization.Mutation, id identity.RoleID) error {
	return r.mutate(ctx, m, `DELETE FROM roles WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}
func (r *Repository) AssignRole(ctx context.Context, m authorization.Mutation, input authorization.RoleAssignment) error {
	return r.mutate(ctx, m, `INSERT INTO role_assignments(environment_id,organization_id,user_id,resource_id,role_id) SELECT environment_id,$2,$3,resource_id,id FROM roles WHERE environment_id=$1 AND id=$4`, m.Environment, input.Organization, input.User, input.Role)
}
func (r *Repository) UnassignRole(ctx context.Context, m authorization.Mutation, input authorization.RoleAssignment) error {
	return r.mutate(ctx, m, `DELETE FROM role_assignments WHERE environment_id=$1 AND role_id=$2 AND organization_id=$3 AND user_id=$4`, m.Environment, input.Role, input.Organization, input.User)
}
func (r *Repository) RoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter authorization.RoleAssignmentFilter, page query.Pagination) (query.Paginated[authorization.RoleAssignmentView], error) {
	base := `FROM role_assignments a
		JOIN organizations o ON o.id=a.organization_id
		JOIN users u ON u.id=a.user_id
		JOIN resources res ON res.id=a.resource_id
		JOIN roles ro ON ro.id=a.role_id
		WHERE a.environment_id=$1`
	args := []any{environment}
	n := 1

	if !filter.RoleID.IsZero() {
		n++
		base += fmt.Sprintf(" AND a.role_id=$%d", n)
		args = append(args, filter.RoleID)
	}
	if !filter.OrganizationID.IsZero() {
		n++
		base += fmt.Sprintf(" AND a.organization_id=$%d", n)
		args = append(args, filter.OrganizationID)
	}
	if !filter.UserID.IsZero() {
		n++
		base += fmt.Sprintf(" AND a.user_id=$%d", n)
		args = append(args, filter.UserID)
	}
	if !filter.ResourceID.IsZero() {
		n++
		base += fmt.Sprintf(" AND a.resource_id=$%d", n)
		args = append(args, filter.ResourceID)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (ro.name ILIKE $%d OR o.name ILIKE $%d OR u.name ILIKE $%d OR u.email ILIKE $%d OR res.name ILIKE $%d)", n, n, n, n, n)
		args = append(args, like)
	}

	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT COUNT(*) "+base, args...); err != nil {
		return query.Paginated[authorization.RoleAssignmentView]{}, failure(err)
	}

	sel := fmt.Sprintf(`SELECT a.organization_id, o.name AS organization_name,
		a.user_id, u.name AS user_name, u.email AS user_email,
		a.resource_id, res.name AS resource_name,
		a.role_id, ro.name AS role_name %s ORDER BY ro.name LIMIT %d OFFSET %d`, base, page.Limit, page.Offset)
	rows := []authorization.RoleAssignmentView{}
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[authorization.RoleAssignmentView]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) PutGrant(ctx context.Context, environment identity.EnvironmentID, id identity.GrantID, input authorization.Grant) (identity.GrantID, error) {
	err := r.db.GetContext(ctx, &id, `INSERT INTO grants(id,environment_id,organization_id,user_id,resource_id,permissions) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organization_id,user_id,resource_id) DO UPDATE SET permissions=EXCLUDED.permissions RETURNING id`, id, environment, input.Organization, input.User, input.Resource, array(input.Permissions))
	return id, conflict(err)
}
func (r *Repository) DeleteGrant(ctx context.Context, environment identity.EnvironmentID, id identity.GrantID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var row struct {
		Organization identity.OrganizationID `db:"organization_id"`
		User         identity.UserID         `db:"user_id"`
		Resource     identity.ResourceID     `db:"resource_id"`
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

var _ authorization.GrantRepository = (*Repository)(nil)
