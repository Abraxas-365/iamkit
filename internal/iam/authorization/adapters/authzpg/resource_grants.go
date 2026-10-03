package authzpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func (r *Repository) FindResource(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) (authorization.Resource, error) {
	return r.Find(ctx, environment, resource)
}

func (r *Repository) CountRoles(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, roles []identity.RoleID) (int, error) {
	var n int
	err := r.db.GetContext(ctx, &n, `SELECT count(*) FROM roles WHERE environment_id=$1 AND resource_id=$2 AND id=ANY($3::uuid[])`, environment, resource, roleArray(roles))
	return n, failure(err)
}

func roleArray(roles []identity.RoleID) any {
	if roles == nil {
		return nil
	}
	out := make(pq.StringArray, len(roles))
	for i, role := range roles {
		out[i] = role.String()
	}
	return out
}

func audit(ctx context.Context, tx *sqlx.Tx, m authorization.Mutation) error {
	return auditChange(ctx, tx, m, change{})
}

// change is what an event needs beyond the mutation's target: the subject
// id of a create route (the new row; empty = the target's) and data.
type change struct {
	subject string
	data    map[string]any
}

func auditChange(ctx context.Context, tx *sqlx.Tx, m authorization.Mutation, c change) error {
	return failure(eventpg.AuditSubject(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, c.subject, c.data))
}

// grantChange names a resource grant's resource, grantee and granted roles
// (null = every role) in its events; organization_id stays the scope of
// the route (the owner administering it), if any.
func grantChange(id identity.ResourceGrantID, resource identity.ResourceID, grantee identity.OrganizationID, roles any) change {
	return change{id.String(), map[string]any{"resource_id": resource.String(), "granted_organization_id": grantee.String(), "role_ids": roles}}
}

// endUngranted ends the sessions of organizations that no longer reach the
// resource: when it requires a grant, every organization other than the
// owner without a grant of all roles (partial grants are re-resolved at the
// next sign-in).
const endUngranted = `UPDATE sessions s SET revoked_at=now()
	FROM resources res
	WHERE res.id=$2 AND res.environment_id=$1 AND res.require_grant
	  AND s.environment_id=$1 AND s.resource_id=$2 AND s.revoked_at IS NULL
	  AND s.organization_id IS DISTINCT FROM res.owner_organization_id
	  AND NOT EXISTS (SELECT 1 FROM resource_grants g WHERE g.resource_id=$2 AND g.organization_id=s.organization_id AND g.role_ids IS NULL)`

// endOrganization ends one organization's sessions for a resource that
// requires a grant (unless it owns it).
const endOrganization = `UPDATE sessions s SET revoked_at=now()
	FROM resources res
	WHERE res.id=$2 AND res.environment_id=$1 AND res.require_grant
	  AND res.owner_organization_id IS DISTINCT FROM $3
	  AND s.environment_id=$1 AND s.resource_id=$2 AND s.organization_id=$3 AND s.revoked_at IS NULL`

func (r *Repository) SetResourceAccess(ctx context.Context, m authorization.Mutation, resource identity.ResourceID, input authorization.ResourceAccess) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE resources SET owner_organization_id=$3, require_grant=$4 WHERE environment_id=$1 AND id=$2`, m.Environment, resource, input.OwnerOrganization, input.RequireGrant)
	if err != nil {
		var pg *pq.Error
		if errors.As(err, &pg) && pg.Code == "23503" {
			return errx.NotFound("organization not found")
		}
		return conflict(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("resource not found")
	}
	// The owner needs no grant of its own resource.
	if input.OwnerOrganization != nil {
		if _, err = tx.ExecContext(ctx, `DELETE FROM resource_grants WHERE resource_id=$1 AND organization_id=$2`, resource, *input.OwnerOrganization); err != nil {
			return failure(err)
		}
	}
	if _, err = tx.ExecContext(ctx, endUngranted, m.Environment, resource); err != nil {
		return failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) PutResourceGrant(ctx context.Context, m authorization.Mutation, id identity.ResourceGrantID, input authorization.ResourceGrantInput) (identity.ResourceGrantID, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return id, failure(err)
	}
	defer tx.Rollback()
	var before struct {
		ID    identity.ResourceGrantID `db:"id"`
		Roles pq.StringArray           `db:"role_ids"`
	}
	err = tx.GetContext(ctx, &before, `SELECT id, role_ids FROM resource_grants WHERE resource_id=$1 AND organization_id=$2 FOR UPDATE`, input.Resource, input.Organization)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return id, failure(err)
	}
	if existed {
		id = before.ID
		if _, err = tx.ExecContext(ctx, `UPDATE resource_grants SET role_ids=$2, updated_at=now() WHERE id=$1`, id, roleArray(input.Roles)); err != nil {
			return id, failure(err)
		}
		if narrowed(before.Roles, input.Roles) {
			if _, err = tx.ExecContext(ctx, endOrganization, m.Environment, input.Resource, input.Organization); err != nil {
				return id, failure(err)
			}
		}
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO resource_grants(id,environment_id,resource_id,organization_id,role_ids) VALUES($1,$2,$3,$4,$5)`, id, m.Environment, input.Resource, input.Organization, roleArray(input.Roles))
		if err != nil {
			var pg *pq.Error
			if errors.As(err, &pg) && pg.Code == "23503" {
				return id, errx.NotFound("organization not found")
			}
			return id, conflict(err)
		}
	}
	roles := []string{}
	for _, role := range input.Roles {
		roles = append(roles, role.String())
	}
	var granted any = roles
	if input.Roles == nil {
		granted = nil
	}
	if err = auditChange(ctx, tx, m, grantChange(id, input.Resource, input.Organization, granted)); err != nil {
		return id, err
	}
	return id, failure(tx.Commit())
}

// narrowed reports whether after grants less than before (nil = all roles).
func narrowed(before pq.StringArray, after []identity.RoleID) bool {
	if after == nil {
		return false
	}
	if before == nil {
		return true
	}
	kept := make(map[string]bool, len(after))
	for _, role := range after {
		kept[role.String()] = true
	}
	for _, role := range before {
		if !kept[role] {
			return true
		}
	}
	return false
}

func (r *Repository) DeleteResourceGrant(ctx context.Context, m authorization.Mutation, id identity.ResourceGrantID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var row struct {
		Resource     identity.ResourceID     `db:"resource_id"`
		Organization identity.OrganizationID `db:"organization_id"`
	}
	err = tx.GetContext(ctx, &row, `DELETE FROM resource_grants WHERE id=$1 AND environment_id=$2 RETURNING resource_id, organization_id`, id, m.Environment)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("resource grant not found")
	}
	if err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, endOrganization, m.Environment, row.Resource, row.Organization); err != nil {
		return failure(err)
	}
	c := grantChange(id, row.Resource, row.Organization, nil)
	delete(c.data, "role_ids")
	if err = auditChange(ctx, tx, m, c); err != nil {
		return err
	}
	return failure(tx.Commit())
}

type resourceGrantRow struct {
	ID               identity.ResourceGrantID `db:"id"`
	Resource         identity.ResourceID      `db:"resource_id"`
	ResourceName     string                   `db:"resource_name"`
	Organization     identity.OrganizationID  `db:"organization_id"`
	OrganizationName string                   `db:"organization_name"`
	Roles            pq.StringArray           `db:"role_ids"`
	Created          time.Time                `db:"created_at"`
	Updated          time.Time                `db:"updated_at"`
}

func (row resourceGrantRow) toDomain() authorization.ResourceGrant {
	out := authorization.ResourceGrant{ID: row.ID, Resource: row.Resource, ResourceName: row.ResourceName, Organization: row.Organization,
		OrganizationName: row.OrganizationName, Created: row.Created, Updated: row.Updated}
	if row.Roles != nil {
		out.Roles = make([]identity.RoleID, 0, len(row.Roles))
		for _, raw := range row.Roles {
			if role, err := identity.ParseRoleID(raw); err == nil {
				out.Roles = append(out.Roles, role)
			}
		}
	}
	return out
}

const resourceGrantSelect = `SELECT g.id, g.resource_id, res.name AS resource_name, g.organization_id, o.name AS organization_name,
	g.role_ids::text[] AS role_ids, g.created_at, g.updated_at`
const resourceGrantFrom = ` FROM resource_grants g
	JOIN resources res ON res.id=g.resource_id
	JOIN organizations o ON o.id=g.organization_id
	WHERE g.environment_id=$1`

func (r *Repository) ListResourceGrants(ctx context.Context, environment identity.EnvironmentID, filter authorization.ResourceGrantFilter, page query.Pagination) (query.Paginated[authorization.ResourceGrant], error) {
	base := resourceGrantFrom
	args := []any{environment}
	add := func(clause string, value any) {
		args = append(args, value)
		base += fmt.Sprintf(clause, len(args))
	}
	if !filter.Resource.IsZero() {
		add(" AND g.resource_id=$%d", filter.Resource)
	}
	if !filter.Organization.IsZero() {
		add(" AND g.organization_id=$%d", filter.Organization)
	}
	if !filter.Owner.IsZero() {
		add(" AND res.owner_organization_id=$%d", filter.Owner)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		add(" AND (res.name ILIKE $%[1]d OR o.name ILIKE $%[1]d)", like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*)"+base, args...); err != nil {
		return query.Paginated[authorization.ResourceGrant]{}, failure(err)
	}
	rows := []resourceGrantRow{}
	sel := fmt.Sprintf("%s%s ORDER BY res.name, o.name LIMIT %d OFFSET %d", resourceGrantSelect, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[authorization.ResourceGrant]{}, failure(err)
	}
	out := make([]authorization.ResourceGrant, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *Repository) FindResourceGrant(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceGrantID) (authorization.ResourceGrant, error) {
	var row resourceGrantRow
	err := r.db.GetContext(ctx, &row, resourceGrantSelect+resourceGrantFrom+` AND g.id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.ResourceGrant{}, errx.NotFound("resource grant not found")
	}
	return row.toDomain(), failure(err)
}

var _ authorization.ResourceGrantRepository = (*Repository)(nil)
