package authzpg

import (
	"context"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// AssignGroupRole binds role to a group of the organization; an unknown role,
// or a group outside the organization, matches no row (404).
func (r *Repository) AssignGroupRole(ctx context.Context, m authorization.Mutation, input authorization.GroupRoleAssignment) error {
	return r.mutate(ctx, m, `INSERT INTO group_role_assignments(group_id,environment_id,organization_id,resource_id,role_id)
		SELECT g.id,g.environment_id,g.organization_id,ro.resource_id,ro.id
		FROM groups g JOIN roles ro ON ro.environment_id=g.environment_id
		WHERE g.environment_id=$1 AND g.organization_id=$2 AND g.id=$3 AND ro.id=$4`,
		m.Environment, input.Organization, input.Group, input.Role)
}

func (r *Repository) UnassignGroupRole(ctx context.Context, m authorization.Mutation, input authorization.GroupRoleAssignment) error {
	return r.mutate(ctx, m, `DELETE FROM group_role_assignments WHERE environment_id=$1 AND organization_id=$2 AND group_id=$3 AND role_id=$4`,
		m.Environment, input.Organization, input.Group, input.Role)
}

func (r *Repository) GroupRoleAssignments(ctx context.Context, environment identity.EnvironmentID, filter authorization.GroupRoleAssignmentFilter, page query.Pagination) (query.Paginated[authorization.GroupRoleAssignmentView], error) {
	base := `FROM group_role_assignments a
		JOIN organizations o ON o.id=a.organization_id
		JOIN groups g ON g.id=a.group_id
		JOIN resources res ON res.id=a.resource_id
		JOIN roles ro ON ro.id=a.role_id
		WHERE a.environment_id=$1`
	args := []any{environment}
	add := func(clause string, v any) {
		args = append(args, v)
		base += fmt.Sprintf(clause, len(args))
	}
	if !filter.OrganizationID.IsZero() {
		add(" AND a.organization_id=$%d", filter.OrganizationID)
	}
	if !filter.GroupID.IsZero() {
		add(" AND a.group_id=$%d", filter.GroupID)
	}
	if !filter.RoleID.IsZero() {
		add(" AND a.role_id=$%d", filter.RoleID)
	}
	if !filter.ResourceID.IsZero() {
		add(" AND a.resource_id=$%d", filter.ResourceID)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		n := len(args)
		base += fmt.Sprintf(" AND (ro.name ILIKE $%d OR g.name ILIKE $%d OR o.name ILIKE $%d OR res.name ILIKE $%d)", n, n, n, n)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[authorization.GroupRoleAssignmentView]{}, failure(err)
	}
	sel := fmt.Sprintf(`SELECT a.organization_id,o.name AS organization_name,a.group_id,g.name AS group_name,
		a.resource_id,res.name AS resource_name,a.role_id,ro.name AS role_name
		%s ORDER BY lower(g.name),ro.name LIMIT %d OFFSET %d`, base, page.Limit, page.Offset)
	rows := []authorization.GroupRoleAssignmentView{}
	if err := r.db.SelectContext(ctx, &rows, sel, args...); err != nil {
		return query.Paginated[authorization.GroupRoleAssignmentView]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}

// EffectiveRoles returns direct and group-derived roles; it is bounded by the
// number of roles one member can hold, so it is not paginated.
func (r *Repository) EffectiveRoles(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID) ([]authorization.EffectiveRoleView, error) {
	rows := []authorization.EffectiveRoleView{}
	err := r.db.SelectContext(ctx, &rows, `
		SELECT ro.id AS role_id,ro.name AS role_name,res.id AS resource_id,res.name AS resource_name,
			'direct' AS source,NULL::uuid AS group_id,NULL::text AS group_name
		FROM role_assignments a JOIN roles ro ON ro.id=a.role_id JOIN resources res ON res.id=a.resource_id
		WHERE a.environment_id=$1 AND a.organization_id=$2 AND a.user_id=$3
		UNION ALL
		SELECT ro.id,ro.name,res.id,res.name,'group',g.id,g.name
		FROM group_members gm
		JOIN groups g ON g.id=gm.group_id
		JOIN group_role_assignments ga ON ga.group_id=gm.group_id
		JOIN roles ro ON ro.id=ga.role_id JOIN resources res ON res.id=ga.resource_id
		WHERE gm.environment_id=$1 AND gm.organization_id=$2 AND gm.user_id=$3
		ORDER BY resource_name,role_name,source,group_name`, environment, organization, user)
	return rows, failure(err)
}
