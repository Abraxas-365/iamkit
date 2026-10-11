package fedpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// mappings reads a connection's group mappings, ordered by value.
func mappings(ctx context.Context, q sqlx.QueryerContext, environment identity.EnvironmentID, connection identity.ConnectionID) ([]federation.GroupMapping, error) {
	out := []federation.GroupMapping{}
	err := sqlx.SelectContext(ctx, q, &out, `SELECT value, group_id FROM federation_group_mappings WHERE connection_id=$1 AND environment_id=$2 ORDER BY value, group_id`, connection, environment)
	return out, failure(err)
}

func sameMappings(a, b []federation.GroupMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// saveMappings makes the stored mappings of c equal c.GroupMappings and
// reports whether that changed anything. Only operator-managed groups of the
// connection's organization qualify; anything else is a validation error.
func saveMappings(ctx context.Context, tx *sqlx.Tx, c federation.Connection) (bool, error) {
	current, err := mappings(ctx, tx, c.Environment, c.ID)
	if err != nil {
		return false, err
	}
	want := federation.NormalizeGroupMappings(c.GroupMappings)
	if want == nil {
		want = []federation.GroupMapping{}
	}
	if sameMappings(current, want) {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM federation_group_mappings WHERE connection_id=$1 AND environment_id=$2`, c.ID, c.Environment); err != nil {
		return false, failure(err)
	}
	if len(want) == 0 {
		return true, nil
	}
	values, groups := make([]string, len(want)), make([]string, len(want))
	for i, m := range want {
		values[i], groups[i] = m.Value, m.Group.String()
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO federation_group_mappings(connection_id,environment_id,organization_id,value,group_id)
		SELECT $1,$2,g.organization_id,m.value,g.id
		FROM unnest($4::text[],$5::uuid[]) AS m(value,group_id)
		JOIN groups g ON g.id=m.group_id AND g.environment_id=$2 AND g.organization_id=$3 AND g.connection_id IS NULL`,
		c.ID, c.Environment, c.Organization, pq.Array(values), pq.Array(groups))
	if err != nil {
		return false, conflict(err)
	}
	if n, _ := res.RowsAffected(); int(n) != len(want) {
		return false, errx.Validation("group_mappings[].group_id must be an operator-managed group of the organization (not a SCIM group)")
	}
	return true, nil
}

// mappingData is the audit data of a connection write that changed its
// group mappings.
func mappingData(c federation.Connection) map[string]any {
	list := make([]map[string]string, 0, len(c.GroupMappings))
	for _, m := range c.GroupMappings {
		list = append(list, map[string]string{"value": m.Value, "group_id": m.Group.String()})
	}
	return map[string]any{"group_mappings": list}
}

func (r *Repository) MissingOperatorGroups(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, groups []identity.GroupID) ([]identity.GroupID, error) {
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.String()
	}
	var missing []string
	err := r.db.SelectContext(ctx, &missing, `SELECT DISTINCT u.id::text FROM unnest($3::uuid[]) AS u(id)
		WHERE NOT EXISTS(SELECT 1 FROM groups g WHERE g.id=u.id AND g.environment_id=$1 AND g.organization_id=$2 AND g.connection_id IS NULL) ORDER BY 1`,
		environment, organization, pq.Array(ids))
	if err != nil {
		return nil, failure(err)
	}
	out := make([]identity.GroupID, 0, len(missing))
	for _, raw := range missing {
		id, err := identity.ParseGroupID(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// syncGroups reconciles the user's membership of the groups the connection
// maps, in tx: added to those mapped from a value in values, removed from
// the other mapped ones. Unmapped groups are never read or changed. A user
// who is not an active member of the organization is left alone.
func syncGroups(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, connection identity.ConnectionID, user identity.UserID, values []string) error {
	var member struct {
		Organization identity.OrganizationID `db:"organization_id"`
	}
	err := tx.GetContext(ctx, &member, `SELECT m.organization_id FROM federation_connections c
		JOIN memberships m ON m.environment_id=c.environment_id AND m.organization_id=c.organization_id AND m.user_id=$3 AND m.active
		WHERE c.id=$1 AND c.environment_id=$2 AND EXISTS(SELECT 1 FROM federation_group_mappings f WHERE f.connection_id=c.id)`, connection, environment, user)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return failure(err)
	}
	if values == nil {
		values = []string{}
	}
	var added []identity.GroupID
	err = tx.SelectContext(ctx, &added, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
		SELECT DISTINCT f.group_id,f.environment_id,f.organization_id,$3::uuid FROM federation_group_mappings f
		WHERE f.connection_id=$1 AND f.environment_id=$2 AND f.value=ANY($4::text[])
		ON CONFLICT DO NOTHING RETURNING group_id`, connection, environment, user, pq.Array(values))
	if err != nil {
		return failure(err)
	}
	var removed []identity.GroupID
	err = tx.SelectContext(ctx, &removed, `DELETE FROM group_members gm WHERE gm.user_id=$3 AND gm.environment_id=$2
		AND gm.group_id IN (SELECT f.group_id FROM federation_group_mappings f WHERE f.connection_id=$1 AND f.environment_id=$2)
		AND gm.group_id NOT IN (SELECT f.group_id FROM federation_group_mappings f WHERE f.connection_id=$1 AND f.environment_id=$2 AND f.value=ANY($4::text[]))
		RETURNING gm.group_id`, connection, environment, user, pq.Array(values))
	if err != nil {
		return failure(err)
	}
	for _, set := range []struct {
		change string
		groups []identity.GroupID
	}{{"added", added}, {"removed", removed}} {
		for _, group := range set.groups {
			if err = eventpg.Emit(ctx, tx, environment, user.String(), event.GroupMembersChanged, event.Subject{Kind: "group", ID: group.String()}, map[string]any{
				"organization_id": member.Organization.String(), "user_id": user.String(), "connection_id": connection.String(), "source": "sso", "change": set.change,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
