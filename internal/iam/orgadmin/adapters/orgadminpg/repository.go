// Package orgadminpg reads what organization administration needs: the IAM
// resource's roles, the organization's owners and its audit events.
package orgadminpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

var _ orgadmin.Repository = (*Repository)(nil)

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }

func failure(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("resource not found")
	}
	return errx.Wrap(err, "persistence failed", errx.TypeInternal)
}

type roleRow struct {
	orgadmin.Role
	Permissions pq.StringArray `db:"permissions"`
}

// roleColumns selects a roleRow for roles r of resources res, with granted
// computed for the organization bound to placeholder org (e.g. "$2").
func roleColumns(org string) string {
	return `r.id, r.name, r.resource_id, res.name AS resource_name, r.permissions, coalesce(r.system_role,'') AS system_role, res.prefix='iam' AS iam,
		(res.prefix<>'iam' AND (res.owner_organization_id IS NOT DISTINCT FROM ` + org + ` OR EXISTS(SELECT 1 FROM resource_grants g
			WHERE g.resource_id=res.id AND g.organization_id=` + org + ` AND (g.role_ids IS NULL OR r.id=ANY(g.role_ids))))) AS granted`
}

func roles(rows []roleRow) []orgadmin.Role {
	out := make([]orgadmin.Role, len(rows))
	for i, row := range rows {
		out[i] = row.Role
		out[i].Permissions = []string(row.Permissions)
	}
	return out
}

func uuids[T interface{ String() string }](ids []T) pq.StringArray {
	out := make(pq.StringArray, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func (r *Repository) Roles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, ids []identity.RoleID) ([]orgadmin.Role, error) {
	rows := []roleRow{}
	err := r.db.SelectContext(ctx, &rows, `SELECT `+roleColumns("$2")+` FROM roles r JOIN resources res ON res.id=r.resource_id
		WHERE r.environment_id=$1 AND r.id=ANY($3::uuid[]) ORDER BY r.name`, environment, organization, uuids(ids))
	return roles(rows), failure(err)
}

func (r *Repository) GroupRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, groups []identity.GroupID) ([]orgadmin.Role, error) {
	rows := []roleRow{}
	err := r.db.SelectContext(ctx, &rows, `SELECT DISTINCT `+roleColumns("$2")+` FROM group_role_assignments ga
		JOIN roles r ON r.id=ga.role_id JOIN resources res ON res.id=r.resource_id
		WHERE ga.environment_id=$1 AND ga.organization_id=$2 AND ga.group_id=ANY($3::uuid[])`, environment, organization, uuids(groups))
	return roles(rows), failure(err)
}

func (r *Repository) AssignableRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[orgadmin.Role], error) {
	base := `FROM roles r JOIN resources res ON res.id=r.resource_id WHERE r.environment_id=$1 AND (res.prefix='iam'
		OR res.owner_organization_id=$2
		OR EXISTS(SELECT 1 FROM resource_grants g WHERE g.resource_id=res.id AND g.organization_id=$2 AND (g.role_ids IS NULL OR r.id=ANY(g.role_ids))))`
	args := []any{environment, organization}
	if like := query.EscapeLike(page.Search); like != "" {
		base += " AND (r.name ILIKE $3 OR res.name ILIKE $3)"
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[orgadmin.Role]{}, failure(err)
	}
	rows := []roleRow{}
	// IAM roles first (built-in ones leading), then by resource and name.
	sel := fmt.Sprintf("SELECT %s %s ORDER BY res.prefix<>'iam', r.system_role IS NULL, res.name, r.name LIMIT %d OFFSET %d", roleColumns("$2"), base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[orgadmin.Role]{}, failure(err)
	}
	return query.NewPaginated(roles(rows), total, page), nil
}

type resourceRow struct {
	ID           identity.ResourceID `db:"id"`
	Name         string              `db:"name"`
	Prefix       string              `db:"prefix"`
	Audience     string              `db:"audience"`
	Permissions  pq.StringArray      `db:"permissions"`
	RequireGrant bool                `db:"require_grant"`
}

func (r *Repository) OwnedResources(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[authorization.Resource], error) {
	base := `FROM resources WHERE environment_id=$1 AND owner_organization_id=$2`
	args := []any{environment, organization}
	if like := query.EscapeLike(page.Search); like != "" {
		base += " AND name ILIKE $3"
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	rows := []resourceRow{}
	sel := fmt.Sprintf("SELECT id, name, prefix, audience, permissions, require_grant %s ORDER BY name LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	out := make([]authorization.Resource, len(rows))
	for i, row := range rows {
		owner := organization
		out[i] = authorization.Resource{ID: row.ID, Name: row.Name, Prefix: row.Prefix, Audience: row.Audience,
			Permissions: []string(row.Permissions), OwnerOrganization: &owner, RequireGrant: row.RequireGrant}
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *Repository) Owners(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) ([]orgadmin.Owner, error) {
	out := []orgadmin.Owner{}
	err := r.db.SelectContext(ctx, &out, `WITH owner AS (
			SELECT r.id FROM roles r JOIN resources res ON res.id=r.resource_id
			WHERE r.environment_id=$1 AND res.prefix='iam' AND r.system_role='org_owner'),
		holders AS (
			SELECT a.user_id, true AS direct, false AS via_group FROM role_assignments a
			WHERE a.environment_id=$1 AND a.organization_id=$2 AND a.role_id IN (SELECT id FROM owner)
			UNION ALL
			SELECT gm.user_id, false, true FROM group_role_assignments g
			JOIN group_members gm ON gm.group_id=g.group_id
			WHERE g.environment_id=$1 AND g.organization_id=$2 AND g.role_id IN (SELECT id FROM owner))
		SELECT h.user_id, bool_or(h.direct) AS direct, bool_or(h.via_group) AS via_group FROM holders h
		JOIN memberships m ON m.environment_id=$1 AND m.organization_id=$2 AND m.user_id=h.user_id AND m.active
		JOIN users u ON u.id=h.user_id AND u.active
		GROUP BY h.user_id`, environment, organization)
	return out, failure(err)
}

func (r *Repository) Member(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3)`, environment, organization, user)
	return ok, failure(err)
}

func (r *Repository) Events(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, filter orgadmin.EventFilter, page query.Pagination) (query.Paginated[orgadmin.Event], error) {
	base := `FROM audit_events WHERE environment_id=$1 AND organization_id=$2`
	args := []any{environment, organization}
	n := 2
	if filter.Action != "" {
		n++
		base += fmt.Sprintf(" AND action LIKE $%d", n)
		args = append(args, filter.Action+"%")
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND action ILIKE $%d", n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[orgadmin.Event]{}, failure(err)
	}
	out := []orgadmin.Event{}
	// Operators appear by kind only: their emails are not the customer's.
	sel := fmt.Sprintf(`SELECT e.id, e.actor_id, e.actor_kind, e.action, e.target_id, e.created_at,
		CASE e.actor_kind
			WHEN 'user' THEN coalesce((SELECT email FROM users WHERE id=e.actor_id AND environment_id=e.environment_id),'')
			WHEN 'service_account' THEN coalesce((SELECT name FROM service_accounts WHERE id=e.actor_id AND environment_id=e.environment_id),'')
			ELSE '' END AS actor_label
		FROM (SELECT * %s ORDER BY id DESC LIMIT %d OFFSET %d) e ORDER BY e.id DESC`, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[orgadmin.Event]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}
