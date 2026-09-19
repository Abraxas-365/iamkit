package orgpg

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/jmoiron/sqlx"
)

func (r *Repository) Exists(ctx context.Context, b organization.Boundary) (bool, error) {
	var exists bool
	err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND environment_id=$2)`, b.Organization, b.Environment)
	return exists, failure(err)
}

var structureQueries = map[organization.StructureView]string{
	organization.Members:      `SELECT coalesce(json_agg(t),'[]') FROM (SELECT user_id,active,org_unit_id,manager_id FROM memberships WHERE environment_id=$1 AND organization_id=$2 ORDER BY user_id) t`,
	organization.Units:        `SELECT coalesce(json_agg(t),'[]') FROM (SELECT id,parent_id,name,kind FROM org_units WHERE environment_id=$1 AND organization_id=$2 ORDER BY id) t`,
	organization.Positions:    `SELECT coalesce(json_agg(t),'[]') FROM (SELECT id,name,code FROM positions WHERE environment_id=$1 AND organization_id=$2 ORDER BY id) t`,
	organization.Assignments:  `SELECT coalesce(json_agg(t),'[]') FROM (SELECT id,position_id,user_id,org_unit_id FROM position_assignments WHERE environment_id=$1 AND organization_id=$2 ORDER BY id) t`,
	organization.UnitDetail:   `SELECT row_to_json(t) FROM (SELECT id,parent_id,name,kind FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND id=$3)t`,
	organization.Ancestors:    `WITH RECURSIVE chain AS(SELECT id,parent_id,name,kind,0 depth FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND id=$3 UNION ALL SELECT u.id,u.parent_id,u.name,u.kind,c.depth+1 FROM org_units u JOIN chain c ON u.id=c.parent_id WHERE u.environment_id=$1 AND u.organization_id=$2) SELECT coalesce(json_agg(t),'[]') FROM (SELECT * FROM chain WHERE depth>0 ORDER BY depth)t`,
	organization.Descendants:  `WITH RECURSIVE tree AS(SELECT id,parent_id,name,kind,0 depth FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND id=$3 UNION ALL SELECT u.id,u.parent_id,u.name,u.kind,t.depth+1 FROM org_units u JOIN tree t ON u.parent_id=t.id WHERE u.environment_id=$1 AND u.organization_id=$2) SELECT coalesce(json_agg(t),'[]') FROM (SELECT * FROM tree WHERE depth>0 ORDER BY depth,id)t`,
	organization.Tree:         `WITH RECURSIVE tree AS(SELECT id,parent_id,name,kind,ARRAY[id] path FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND parent_id IS NULL UNION ALL SELECT u.id,u.parent_id,u.name,u.kind,t.path||u.id FROM org_units u JOIN tree t ON u.parent_id=t.id WHERE u.environment_id=$1 AND u.organization_id=$2) SELECT coalesce(json_agg(t),'[]') FROM(SELECT * FROM tree ORDER BY path)t`,
	organization.DeleteImpact: `WITH RECURSIVE tree AS(SELECT id FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND id=$3 UNION ALL SELECT u.id FROM org_units u JOIN tree t ON u.parent_id=t.id WHERE u.environment_id=$1 AND u.organization_id=$2) SELECT json_build_object('has_children',(SELECT count(*)>1 FROM tree),'affected_user_ids',(SELECT coalesce(json_agg(user_id),'[]') FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND org_unit_id IN(SELECT id FROM tree)),'assignment_ids',(SELECT coalesce(json_agg(id),'[]') FROM position_assignments WHERE environment_id=$1 AND organization_id=$2 AND org_unit_id IN(SELECT id FROM tree)))`,
	organization.Chart:        `SELECT coalesce(json_agg(t),'[]') FROM(SELECT m.user_id,m.manager_id,m.org_unit_id,coalesce(m.display_name,u.name) AS name,u.email FROM memberships m JOIN users u ON u.id=m.user_id AND u.environment_id=m.environment_id WHERE m.environment_id=$1 AND m.organization_id=$2 AND m.active ORDER BY m.user_id)t`,
}

func (r *Repository) View(ctx context.Context, b organization.Boundary, view organization.StructureView, id string) (json.RawMessage, error) {
	query, ok := structureQueries[view]
	if !ok {
		return nil, errx.Validation("unknown organization view")
	}
	args := []any{b.Environment, b.Organization}
	switch view {
	case organization.UnitDetail, organization.Ancestors, organization.Descendants, organization.DeleteImpact:
		args = append(args, id)
	}
	var raw []byte
	err := r.db.GetContext(ctx, &raw, query, args...)
	if err == sql.ErrNoRows {
		return nil, errx.NotFound("resource not found")
	}
	return json.RawMessage(raw), failure(err)
}
func audit(ctx context.Context, tx *sqlx.Tx, m organization.Mutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	return failure(err)
}
func (r *Repository) mutate(ctx context.Context, m organization.Mutation, query string, args ...any) error {
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
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}
func (r *Repository) SaveUnit(ctx context.Context, b organization.Boundary, m organization.Mutation, id string, input organization.Unit, creating bool) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT id FROM organizations WHERE environment_id=$1 AND id=$2 FOR UPDATE`, b.Environment, b.Organization); err != nil {
		return failure(err)
	}
	if input.Parent != nil {
		var cycle bool
		err = tx.GetContext(ctx, &cycle, `WITH RECURSIVE ancestors AS (SELECT id,parent_id FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND id=$3 UNION SELECT u.id,u.parent_id FROM org_units u JOIN ancestors a ON u.id=a.parent_id WHERE u.environment_id=$1 AND u.organization_id=$2) SELECT EXISTS(SELECT 1 FROM ancestors WHERE id=$4)`, b.Environment, b.Organization, *input.Parent, id)
		if err != nil {
			return failure(err)
		}
		if cycle || *input.Parent == id {
			return errx.Validation("unit hierarchy cycle")
		}
	}
	if creating {
		_, err = tx.ExecContext(ctx, `INSERT INTO org_units(id,environment_id,organization_id,parent_id,name,kind) VALUES($1,$2,$3,$4,$5,$6)`, id, b.Environment, b.Organization, input.Parent, input.Name, input.Kind)
	} else {
		var res sql.Result
		res, err = tx.ExecContext(ctx, `UPDATE org_units SET parent_id=$4,name=$5,kind=$6 WHERE id=$1 AND environment_id=$2 AND organization_id=$3`, id, b.Environment, b.Organization, input.Parent, input.Name, input.Kind)
		if err == nil {
			n, e := res.RowsAffected()
			if e != nil {
				return failure(e)
			}
			if n == 0 {
				return errx.NotFound("unit not found")
			}
		}
	}
	if err != nil {
		return conflict(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}
func (r *Repository) DeleteUnit(ctx context.Context, b organization.Boundary, m organization.Mutation, id string) error {
	return r.mutate(ctx, m, `DELETE FROM org_units WHERE environment_id=$1 AND organization_id=$2 AND id=$3`, b.Environment, b.Organization, id)
}
func (r *Repository) SetProfile(ctx context.Context, b organization.Boundary, m organization.Mutation, user string, input organization.Profile) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT id FROM organizations WHERE id=$1 AND environment_id=$2 FOR UPDATE`, b.Organization, b.Environment); err != nil {
		return failure(err)
	}
	if input.Manager != nil {
		var cycle bool
		err = tx.GetContext(ctx, &cycle, `WITH RECURSIVE chain AS (SELECT user_id,manager_id FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3 UNION SELECT m.user_id,m.manager_id FROM memberships m JOIN chain c ON m.user_id=c.manager_id WHERE m.environment_id=$1 AND m.organization_id=$2) SELECT EXISTS(SELECT 1 FROM chain WHERE user_id=$4)`, b.Environment, b.Organization, *input.Manager, user)
		if err != nil {
			return failure(err)
		}
		if cycle {
			return errx.Validation("manager hierarchy cycle")
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE memberships SET org_unit_id=$4,manager_id=$5 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, b.Environment, b.Organization, user, input.Unit, input.Manager)
	if err != nil {
		return conflict(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("member not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}
func (r *Repository) CreatePosition(ctx context.Context, b organization.Boundary, id string, input organization.Position) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO positions(id,environment_id,organization_id,name,code) VALUES($1,$2,$3,$4,$5)`, id, b.Environment, b.Organization, input.Name, input.Code)
	return conflict(err)
}
func (r *Repository) UpdatePosition(ctx context.Context, b organization.Boundary, m organization.Mutation, id string, input organization.Position) error {
	return r.mutate(ctx, m, `UPDATE positions SET name=$4,code=$5 WHERE environment_id=$1 AND organization_id=$2 AND id=$3`, b.Environment, b.Organization, id, input.Name, input.Code)
}
func (r *Repository) DeletePosition(ctx context.Context, b organization.Boundary, m organization.Mutation, id string) error {
	return r.mutate(ctx, m, `DELETE FROM positions WHERE environment_id=$1 AND organization_id=$2 AND id=$3`, b.Environment, b.Organization, id)
}
func (r *Repository) AssignPosition(ctx context.Context, b organization.Boundary, id string, input organization.Assignment) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO position_assignments(id,environment_id,organization_id,position_id,user_id,org_unit_id) VALUES($1,$2,$3,$4,$5,$6)`, id, b.Environment, b.Organization, input.Position, input.User, input.Unit)
	return conflict(err)
}
func (r *Repository) DeleteAssignment(ctx context.Context, b organization.Boundary, m organization.Mutation, id string) error {
	return r.mutate(ctx, m, `DELETE FROM position_assignments WHERE environment_id=$1 AND organization_id=$2 AND id=$3`, b.Environment, b.Organization, id)
}

var _ organization.StructureRepository = (*Repository)(nil)
