// Package auditlogpg persists the app audit log: the action catalog and
// the immutable events. Action changes are audited through eventpg in
// their own transaction; the events themselves never write IAMKit's own
// event log.
package auditlogpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Actions is the action catalog repository.
type Actions struct{ db *sqlx.DB }

func NewActions(db *sqlx.DB) *Actions { return &Actions{db} }

var _ auditlog.ActionRepository = (*Actions)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	var e *errx.Error
	if errx.As(err, &e) {
		return err
	}
	return errx.Wrap(err, "persistence failed", errx.TypeInternal)
}

type actionRow struct {
	ID          identity.AuditActionID `db:"id"`
	Environment identity.EnvironmentID `db:"environment_id"`
	Name        string                 `db:"name"`
	Description string                 `db:"description"`
	TargetTypes pq.StringArray         `db:"target_types"`
	Schema      []byte                 `db:"schema"`
	Version     int                    `db:"version"`
	CreatedAt   time.Time              `db:"created_at"`
	UpdatedAt   time.Time              `db:"updated_at"`
}

const actionColumns = `id, environment_id, name, description, target_types, schema, version, created_at, updated_at`

func (r actionRow) toDomain() auditlog.Action {
	a := auditlog.Action{ID: r.ID, Environment: r.Environment, Name: r.Name, Description: r.Description,
		TargetTypes: []string(r.TargetTypes), Version: r.Version, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if a.TargetTypes == nil {
		a.TargetTypes = []string{}
	}
	_ = json.Unmarshal(r.Schema, &a.Schema)
	return a
}

func schemaJSON(s auditlog.Schema) ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, errx.Wrap(err, "encode schema", errx.TypeInternal)
	}
	return raw, nil
}

func (r *Actions) CreateAction(ctx context.Context, m auditlog.Mutation, a auditlog.Action) error {
	schema, err := schemaJSON(a.Schema)
	if err != nil {
		return err
	}
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log_actions(id, environment_id, name, description, target_types, schema)
			VALUES($1,$2,$3,$4,$5,$6)`, a.ID, a.Environment, a.Name, a.Description, pq.StringArray(a.TargetTypes), schema); err != nil {
			var pg *pq.Error
			if errors.As(err, &pg) && pg.Code == "23505" {
				return errx.Conflict("an audit log action with this name already exists")
			}
			return failure(err)
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func (r *Actions) UpdateAction(ctx context.Context, m auditlog.Mutation, a auditlog.Action, bump bool) error {
	schema, err := schemaJSON(a.Schema)
	if err != nil {
		return err
	}
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE audit_log_actions SET description=$3, target_types=$4, schema=$5,
			version = version + CASE WHEN $6 THEN 1 ELSE 0 END, updated_at = now()
			WHERE environment_id=$1 AND id=$2`, a.Environment, a.ID, a.Description, pq.StringArray(a.TargetTypes), schema, bump)
		if err != nil {
			return failure(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return auditlog.ErrActionNotFound()
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func (r *Actions) DeleteAction(ctx context.Context, m auditlog.Mutation, id identity.AuditActionID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM audit_log_actions WHERE environment_id=$1 AND id=$2`, m.Environment, id)
		if err != nil {
			return failure(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return auditlog.ErrActionNotFound()
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func (r *Actions) FindAction(ctx context.Context, environment identity.EnvironmentID, id identity.AuditActionID) (auditlog.Action, error) {
	var row actionRow
	err := r.db.GetContext(ctx, &row, `SELECT `+actionColumns+` FROM audit_log_actions WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return auditlog.Action{}, auditlog.ErrActionNotFound()
	}
	return row.toDomain(), failure(err)
}

func (r *Actions) FindActionByName(ctx context.Context, environment identity.EnvironmentID, name string) (auditlog.Action, error) {
	var row actionRow
	err := r.db.GetContext(ctx, &row, `SELECT `+actionColumns+` FROM audit_log_actions WHERE environment_id=$1 AND name=$2`, environment, name)
	if errors.Is(err, sql.ErrNoRows) {
		return auditlog.Action{}, auditlog.ErrActionNotFound()
	}
	return row.toDomain(), failure(err)
}

func (r *Actions) ListActions(ctx context.Context, environment identity.EnvironmentID) ([]auditlog.Action, error) {
	rows := []actionRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+actionColumns+` FROM audit_log_actions WHERE environment_id=$1 ORDER BY name`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]auditlog.Action, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

func (r *Actions) CountActions(ctx context.Context, environment identity.EnvironmentID) (int, error) {
	var n int
	err := r.db.GetContext(ctx, &n, `SELECT count(*) FROM audit_log_actions WHERE environment_id=$1`, environment)
	return n, failure(err)
}
