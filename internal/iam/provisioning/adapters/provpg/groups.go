package provpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

var _ provisioning.GroupRepository = (*Repository)(nil)

// Groups are scoped to the connection: a directory never sees operator groups
// or another directory's groups.
const selectGroup = `SELECT g.id,g.name,coalesce(g.external_id,'') AS external_id,g.version,g.created_at,g.updated_at FROM groups g WHERE g.connection_id=$1 AND g.environment_id=$2 AND g.organization_id=$3`

// groupFilterSQL matches SCIM "eq" filters (field $%[1]d, value $%[2]d).
// displayName is case-insensitive; externalId is case-exact.
const groupFilterSQL = `($%[1]d='' OR ($%[1]d='displayName' AND lower(g.name)=lower($%[2]d)) OR ($%[1]d='externalId' AND g.external_id=$%[2]d) OR ($%[1]d='id' AND g.id::text=lower($%[2]d)))`

func groupConflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		return errx.Conflict("a group with this displayName or externalId already exists").WithDetail("scimType", "uniqueness")
	}
	return failure(err)
}

func uuids(ids []identity.UserID) any {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return pq.Array(out)
}

// checkMembers rejects users that are not live identities of this connection.
func checkMembers(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, ids []identity.UserID) error {
	if len(ids) == 0 {
		return nil
	}
	var missing int
	err := tx.GetContext(ctx, &missing, `SELECT count(*) FROM unnest($3::uuid[]) AS u(id)
		WHERE NOT EXISTS(SELECT 1 FROM provisioned_identities i
			JOIN memberships m ON m.user_id=i.user_id AND m.environment_id=i.environment_id AND m.organization_id=$4
			WHERE i.connection_id=$1 AND i.environment_id=$2 AND i.user_id=u.id AND i.deprovisioned_at IS NULL)`,
		p.Connection, p.Environment, uuids(ids), p.Organization)
	if err != nil {
		return failure(err)
	}
	if missing > 0 {
		return errx.Validation("members must reference users provisioned by this connection").WithDetail("scimType", "invalidValue")
	}
	return nil
}

func addMembers(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, group identity.GroupID, ids []identity.UserID) error {
	if len(ids) == 0 {
		return nil
	}
	if err := checkMembers(ctx, tx, p, ids); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
		SELECT $1,$2,$3,u.id FROM unnest($4::uuid[]) AS u(id) ON CONFLICT DO NOTHING`, group, p.Environment, p.Organization, uuids(ids))
	return failure(err)
}

func (r *Repository) CreateGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID, input provisioning.GroupInput) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var external *string
	if input.External != "" {
		external = &input.External
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO groups(id,environment_id,organization_id,name,connection_id,external_id) VALUES($1,$2,$3,$4,$5,$6)`,
		id, p.Environment, p.Organization, input.Name, p.Connection, external); err != nil {
		return groupConflict(err)
	}
	if err = addMembers(ctx, tx, p, id, input.Members); err != nil {
		return err
	}
	if err = groupEvent(ctx, tx, p, event.GroupCreated, id); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// groupEvent records a directory change of group; the actor is the SCIM
// credential.
func groupEvent(ctx context.Context, tx sqlx.ExecerContext, p provisioning.Principal, typ string, id identity.GroupID) error {
	return eventpg.Emit(ctx, tx, p.Environment, p.ID.String(), typ, event.Subject{Kind: "group", ID: id.String()},
		map[string]any{"organization_id": p.Organization.String(), "connection_id": p.Connection.String()})
}

// UpdateGroup applies a replace-set of members first, then removals, then
// additions. The group row is locked so concurrent PATCHes serialize.
func (r *Repository) UpdateGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID, input provisioning.GroupUpdate) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var found bool
	err = tx.GetContext(ctx, &found, `SELECT true FROM groups WHERE id=$4 AND connection_id=$1 AND environment_id=$2 AND organization_id=$3 FOR UPDATE`, p.Connection, p.Environment, p.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("group not found")
	}
	if err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE groups SET name=coalesce($2,name),external_id=CASE WHEN $3::text IS NULL THEN external_id ELSE nullif($3,'') END,updated_at=now(),version=version+1 WHERE id=$1`, id, input.Name, input.External); err != nil {
		return groupConflict(err)
	}
	if input.Members != nil {
		if err = checkMembers(ctx, tx, p, *input.Members); err != nil {
			return err
		}
		// SCIM never sees machine users, so a full replace keeps them.
		if _, err = tx.ExecContext(ctx, `DELETE FROM group_members gm WHERE gm.group_id=$1 AND NOT (gm.user_id=ANY($2::uuid[]))
			AND NOT EXISTS(SELECT 1 FROM users u WHERE u.id=gm.user_id AND u.environment_id=gm.environment_id AND u.kind='machine')`, id, uuids(*input.Members)); err != nil {
			return failure(err)
		}
		if err = addMembers(ctx, tx, p, id, *input.Members); err != nil {
			return err
		}
	}
	if len(input.Remove) > 0 {
		if _, err = tx.ExecContext(ctx, `DELETE FROM group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[])`, id, uuids(input.Remove)); err != nil {
			return failure(err)
		}
	}
	if err = addMembers(ctx, tx, p, id, input.Add); err != nil {
		return err
	}
	typ := event.GroupUpdated
	if input.Name == nil && input.External == nil {
		typ = event.GroupMembersChanged
	}
	if err = groupEvent(ctx, tx, p, typ, id); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// DeleteGroup removes the group with its members and role bindings.
func (r *Repository) DeleteGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE id=$4 AND connection_id=$1 AND environment_id=$2 AND organization_id=$3`, p.Connection, p.Environment, p.Organization, id)
		if err != nil {
			return failure(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return failure(err)
		}
		if n == 0 {
			return errx.NotFound("group not found")
		}
		return groupEvent(ctx, tx, p, event.GroupDeleted, id)
	})
}

func (r *Repository) FindGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID, members bool) (provisioning.Group, error) {
	var g provisioning.Group
	err := r.db.GetContext(ctx, &g, selectGroup+` AND g.id=$4`, p.Connection, p.Environment, p.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return g, errx.NotFound("group not found")
	}
	if err != nil {
		return g, failure(err)
	}
	if members {
		groups := []provisioning.Group{g}
		if err = r.members(ctx, groups); err != nil {
			return g, err
		}
		g = groups[0]
	}
	return g, nil
}

func (r *Repository) ListGroups(ctx context.Context, p provisioning.Principal, f provisioning.GroupFilter, page query.Pagination) (query.Paginated[provisioning.Group], error) {
	where := ` AND ` + fmt.Sprintf(groupFilterSQL, 4, 5)
	args := []any{p.Connection, p.Environment, p.Organization, f.Field, f.Value}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM groups g WHERE g.connection_id=$1 AND g.environment_id=$2 AND g.organization_id=$3`+where, args...); err != nil {
		return query.Paginated[provisioning.Group]{}, failure(err)
	}
	rows := []provisioning.Group{}
	if err := r.db.SelectContext(ctx, &rows, selectGroup+where+` ORDER BY g.created_at,g.id LIMIT $6 OFFSET $7`, append(args, page.Limit, page.Offset)...); err != nil {
		return query.Paginated[provisioning.Group]{}, failure(err)
	}
	if !f.ExcludeMembers {
		if err := r.members(ctx, rows); err != nil {
			return query.Paginated[provisioning.Group]{}, err
		}
	}
	return query.NewPaginated(rows, total, page), nil
}

// members loads the members of groups in one query.
func (r *Repository) members(ctx context.Context, groups []provisioning.Group) error {
	if len(groups) == 0 {
		return nil
	}
	ids := make([]string, 0, len(groups))
	index := make(map[identity.GroupID]int, len(groups))
	for i := range groups {
		groups[i].Members = []provisioning.GroupMember{}
		ids = append(ids, groups[i].ID.String())
		index[groups[i].ID] = i
	}
	rows := []provisioning.GroupMember{}
	err := r.db.SelectContext(ctx, &rows, `SELECT gm.group_id,gm.user_id,coalesce(m.display_name,u.name) AS display
		FROM group_members gm
		JOIN memberships m ON m.environment_id=gm.environment_id AND m.organization_id=gm.organization_id AND m.user_id=gm.user_id
		JOIN users u ON u.id=gm.user_id AND u.environment_id=gm.environment_id AND u.kind='human'
		WHERE gm.group_id=ANY($1::uuid[]) ORDER BY gm.created_at,gm.user_id`, pq.Array(ids))
	if err != nil {
		return failure(err)
	}
	for _, m := range rows {
		i := index[m.Group]
		groups[i].Members = append(groups[i].Members, m)
	}
	return nil
}
