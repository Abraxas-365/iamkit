package orgpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/lib/pq"
)

var _ organization.GroupRepository = (*Repository)(nil)

const selectGroup = `SELECT g.id,g.name,g.description,g.connection_id,g.external_id,g.created_at,g.updated_at,
	(SELECT count(*) FROM group_members gm WHERE gm.group_id=g.id) AS member_count
	FROM groups g WHERE g.environment_id=$1 AND g.organization_id=$2`

func userIDs(ids []identity.UserID) any {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return pq.Array(out)
}

func groupConflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		return errx.Conflict("a group with this name already exists")
	}
	return conflict(err)
}

func (r *Repository) CreateGroup(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID, input organization.GroupInput) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO groups(id,environment_id,organization_id,name,description) VALUES($1,$2,$3,$4,$5)`, id, b.Environment, b.Organization, input.Name, input.Description); err != nil {
		return groupConflict(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) UpdateGroup(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID, input organization.GroupUpdate) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE groups SET name=coalesce($4,name),description=coalesce($5,description),updated_at=now(),version=version+1
		WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND connection_id IS NULL`, id, b.Environment, b.Organization, input.Name, input.Description)
	if err != nil {
		return groupConflict(err)
	}
	if err = affected(res, "group not found"); err != nil {
		return err
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) DeleteGroup(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID) error {
	return r.mutate(ctx, m, `DELETE FROM groups WHERE id=$3 AND environment_id=$1 AND organization_id=$2 AND connection_id IS NULL`, b.Environment, b.Organization, id)
}

// ChangeGroupMembers applies removals then additions as idempotent set
// operations. Every added user must be a member of the organization.
func (r *Repository) ChangeGroupMembers(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.GroupID, input organization.GroupMembers) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var found bool
	if err = tx.GetContext(ctx, &found, `SELECT true FROM groups WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND connection_id IS NULL FOR UPDATE`, id, b.Environment, b.Organization); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("group not found")
		}
		return failure(err)
	}
	if len(input.Remove) > 0 {
		if _, err = tx.ExecContext(ctx, `DELETE FROM group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[])`, id, userIDs(input.Remove)); err != nil {
			return failure(err)
		}
	}
	if len(input.Add) > 0 {
		var missing int
		if err = tx.GetContext(ctx, &missing, `SELECT count(*) FROM unnest($3::uuid[]) AS u(id)
			WHERE NOT EXISTS(SELECT 1 FROM memberships m WHERE m.environment_id=$1 AND m.organization_id=$2 AND m.user_id=u.id AND m.active)`, b.Environment, b.Organization, userIDs(input.Add)); err != nil {
			return failure(err)
		}
		if missing > 0 {
			return errx.Validation("every user must be an active member of the organization")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
			SELECT $1,$2,$3,u.id FROM unnest($4::uuid[]) AS u(id) ON CONFLICT DO NOTHING`, id, b.Environment, b.Organization, userIDs(input.Add)); err != nil {
			return conflict(err)
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE groups SET updated_at=now(),version=version+1 WHERE id=$1`, id); err != nil {
		return failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) ListGroups(ctx context.Context, b organization.Boundary, filter organization.GroupFilter, page query.Pagination) (query.Paginated[organization.Group], error) {
	where := ""
	args := []any{b.Environment, b.Organization}
	if !filter.User.IsZero() {
		args = append(args, filter.User)
		where += fmt.Sprintf(" AND EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.user_id=$%d)", len(args))
	}
	if !filter.Connection.IsZero() {
		args = append(args, filter.Connection)
		where += fmt.Sprintf(" AND g.connection_id=$%d", len(args))
	}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		where += fmt.Sprintf(" AND (g.name ILIKE $%d OR g.description ILIKE $%d)", len(args), len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM groups g WHERE g.environment_id=$1 AND g.organization_id=$2`+where, args...); err != nil {
		return query.Paginated[organization.Group]{}, failure(err)
	}
	out := []organization.Group{}
	if err := r.db.SelectContext(ctx, &out, fmt.Sprintf("%s%s ORDER BY lower(g.name),g.id LIMIT %d OFFSET %d", selectGroup, where, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[organization.Group]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *Repository) FindGroup(ctx context.Context, b organization.Boundary, id identity.GroupID) (organization.Group, error) {
	var g organization.Group
	err := r.db.GetContext(ctx, &g, selectGroup+` AND g.id=$3`, b.Environment, b.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return g, errx.NotFound("group not found")
	}
	return g, failure(err)
}

func (r *Repository) ListGroupMembers(ctx context.Context, b organization.Boundary, id identity.GroupID, page query.Pagination) (query.Paginated[organization.GroupMemberView], error) {
	base := `FROM group_members gm
		JOIN memberships m ON m.environment_id=gm.environment_id AND m.organization_id=gm.organization_id AND m.user_id=gm.user_id
		JOIN users u ON u.id=gm.user_id AND u.environment_id=gm.environment_id
		WHERE gm.environment_id=$1 AND gm.organization_id=$2 AND gm.group_id=$3`
	args := []any{b.Environment, b.Organization, id}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		base += fmt.Sprintf(" AND (u.name ILIKE $%d OR u.email ILIKE $%d)", len(args), len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[organization.GroupMemberView]{}, failure(err)
	}
	out := []organization.GroupMemberView{}
	sel := fmt.Sprintf(`SELECT gm.user_id,coalesce(m.display_name,u.name) AS user_name,u.email AS user_email,(m.active AND u.active) AS active,gm.created_at %s ORDER BY lower(u.email) LIMIT %d OFFSET %d`, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[organization.GroupMemberView]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}

func affected(res sql.Result, missing string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound(missing)
	}
	return nil
}
