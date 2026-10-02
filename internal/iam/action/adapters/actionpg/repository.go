// Package actionpg persists action targets, executions and the
// recent-calls log (migration 052).
package actionpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ action.Repository = (*Repository)(nil)

var errTargetNotFound = errx.NotFound("action target not found")

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

const targetColumns = `id, environment_id, name, url, kind, timeout_ms, interrupt_on_error, created_at, updated_at`

// audited runs change and the audit entry in one transaction; change
// reports whether it found its row.
func (r *Repository) audited(ctx context.Context, m action.Mutation, change func(tx *sqlx.Tx) (bool, error)) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		found, err := change(tx)
		if err != nil {
			return failure(err)
		}
		if !found {
			return errTargetNotFound
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func affected(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (r *Repository) CountTargets(ctx context.Context, environment identity.EnvironmentID) (int, error) {
	var n int
	err := r.db.GetContext(ctx, &n, `SELECT count(*) FROM action_targets WHERE environment_id = $1`, environment)
	return n, failure(err)
}

func (r *Repository) CreateTarget(ctx context.Context, m action.Mutation, t action.Target, sealed string) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `INSERT INTO action_targets (id, environment_id, name, url, kind, timeout_ms, interrupt_on_error, secret_sealed)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, t.ID, m.Environment, t.Name, t.URL, t.Kind, t.TimeoutMS, t.InterruptOnError, sealed))
	})
}

func (r *Repository) FindTarget(ctx context.Context, environment identity.EnvironmentID, id identity.TargetID) (action.Target, error) {
	var t action.Target
	err := r.db.GetContext(ctx, &t, `SELECT `+targetColumns+` FROM action_targets WHERE environment_id = $1 AND id = $2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return t, errTargetNotFound
	}
	return t, failure(err)
}

func (r *Repository) ListTargets(ctx context.Context, environment identity.EnvironmentID) ([]action.Target, error) {
	out := []action.Target{}
	err := r.db.SelectContext(ctx, &out, `SELECT `+targetColumns+` FROM action_targets WHERE environment_id = $1 ORDER BY created_at, id`, environment)
	return out, failure(err)
}

func (r *Repository) UpdateTarget(ctx context.Context, m action.Mutation, t action.Target) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `UPDATE action_targets SET name = $3, url = $4, kind = $5, timeout_ms = $6,
			interrupt_on_error = $7, updated_at = now() WHERE environment_id = $1 AND id = $2`,
			m.Environment, t.ID, t.Name, t.URL, t.Kind, t.TimeoutMS, t.InterruptOnError))
	})
}

func (r *Repository) DeleteTarget(ctx context.Context, m action.Mutation, id identity.TargetID) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `DELETE FROM action_targets WHERE environment_id = $1 AND id = $2`, m.Environment, id))
	})
}

func (r *Repository) RotateTargetSecret(ctx context.Context, m action.Mutation, id identity.TargetID, sealed string, previousExpires time.Time) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `UPDATE action_targets SET previous_sealed = secret_sealed,
			previous_expires_at = $3, secret_sealed = $4, updated_at = now()
			WHERE environment_id = $1 AND id = $2`, m.Environment, id, previousExpires, sealed))
	})
}

type boundRow struct {
	action.Target
	Sealed   string  `db:"secret_sealed"`
	Previous *string `db:"previous"`
}

func (b boundRow) bound() action.Bound {
	out := action.Bound{Target: b.Target, Sealed: []string{b.Sealed}}
	if b.Previous != nil {
		out.Sealed = append(out.Sealed, *b.Previous)
	}
	return out
}

const boundColumns = `t.id, t.environment_id, t.name, t.url, t.kind, t.timeout_ms, t.interrupt_on_error, t.created_at, t.updated_at, t.secret_sealed,
	CASE WHEN t.previous_expires_at > now() THEN t.previous_sealed END AS previous`

func (r *Repository) TargetSecrets(ctx context.Context, environment identity.EnvironmentID, id identity.TargetID) (action.Target, []string, error) {
	var row boundRow
	err := r.db.GetContext(ctx, &row, `SELECT `+boundColumns+` FROM action_targets t WHERE t.environment_id = $1 AND t.id = $2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return action.Target{}, nil, errTargetNotFound
	}
	if err != nil {
		return action.Target{}, nil, failure(err)
	}
	b := row.bound()
	return b.Target, b.Sealed, nil
}

func (r *Repository) Bound(ctx context.Context, environment identity.EnvironmentID, condition string) ([]action.Bound, error) {
	rows := []boundRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+boundColumns+`
		FROM action_executions e
		CROSS JOIN LATERAL unnest(e.target_ids) WITH ORDINALITY AS o(target_id, position)
		JOIN action_targets t ON t.id = o.target_id AND t.environment_id = e.environment_id
		WHERE e.environment_id = $1 AND e.condition = $2
		ORDER BY o.position`, environment, condition); err != nil {
		return nil, failure(err)
	}
	out := make([]action.Bound, len(rows))
	for i, row := range rows {
		out[i] = row.bound()
	}
	return out, nil
}

type executionRow struct {
	Condition string         `db:"condition"`
	Targets   pq.StringArray `db:"target_ids"`
	UpdatedAt time.Time      `db:"updated_at"`
}

func (e executionRow) toDomain() action.Execution {
	out := action.Execution{Condition: e.Condition, Targets: make([]identity.TargetID, 0, len(e.Targets)), UpdatedAt: e.UpdatedAt}
	for _, raw := range e.Targets {
		if id, err := identity.ParseTargetID(raw); err == nil {
			out.Targets = append(out.Targets, id)
		}
	}
	return out
}

func (r *Repository) SetExecution(ctx context.Context, m action.Mutation, condition string, targets []identity.TargetID) (action.Execution, error) {
	ids := make(pq.StringArray, len(targets))
	for i, t := range targets {
		ids[i] = t.String()
	}
	var row executionRow
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var n int
		if err := tx.GetContext(ctx, &n, `SELECT count(*) FROM action_targets WHERE environment_id = $1 AND id = ANY($2::uuid[])`, m.Environment, ids); err != nil {
			return failure(err)
		}
		if n != len(targets) {
			return errTargetNotFound
		}
		if err := tx.GetContext(ctx, &row, `INSERT INTO action_executions (environment_id, condition, target_ids) VALUES ($1, $2, $3::uuid[])
			ON CONFLICT (environment_id, condition) DO UPDATE SET target_ids = EXCLUDED.target_ids, updated_at = now()
			RETURNING condition, target_ids::text[] AS target_ids, updated_at`, m.Environment, condition, ids); err != nil {
			return failure(err)
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
	return row.toDomain(), err
}

func (r *Repository) DeleteExecution(ctx context.Context, m action.Mutation, condition string) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		found, err := affected(tx.ExecContext(ctx, `DELETE FROM action_executions WHERE environment_id = $1 AND condition = $2`, m.Environment, condition))
		if err != nil {
			return failure(err)
		}
		if !found {
			return errx.NotFound("the condition has no execution")
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func (r *Repository) ListExecutions(ctx context.Context, environment identity.EnvironmentID) ([]action.Execution, error) {
	rows := []executionRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT condition, target_ids::text[] AS target_ids, updated_at
		FROM action_executions WHERE environment_id = $1 ORDER BY condition`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]action.Execution, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

// RecordCall logs the call; a failure (or skip) also writes action.failed
// (actor system) so event webhooks and the activity log see it.
func (r *Repository) RecordCall(ctx context.Context, c action.Call) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO action_calls (environment_id, target_id, condition, outcome, status, duration_ms, error)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, c.Environment, c.Target, c.Condition, c.Outcome, c.Status, c.DurationMS, c.Error); err != nil {
			return failure(err)
		}
		if c.Outcome != action.OutcomeFailed && c.Outcome != action.OutcomeSkipped {
			return nil
		}
		return eventpg.Emit(ctx, tx, c.Environment, "", event.ActionFailed, event.Subject{Kind: "action_target", ID: c.Target.String()},
			map[string]any{"condition": c.Condition, "outcome": c.Outcome, "error": c.Error, "interrupted": c.Interrupted})
	})
}

func (r *Repository) ListCalls(ctx context.Context, environment identity.EnvironmentID, filter action.CallFilter, limit int) ([]action.Call, error) {
	out := []action.Call{}
	err := r.db.SelectContext(ctx, &out, `SELECT id, target_id, condition, outcome, status, duration_ms, error, created_at
		FROM action_calls WHERE environment_id = $1
		AND ($2::uuid IS NULL OR target_id = $2) AND ($3 = '' OR condition = $3) AND ($4 = '' OR outcome = $4)
		ORDER BY id DESC LIMIT $5`, environment, filter.Target, filter.Condition, filter.Outcome, limit)
	return out, failure(err)
}

func (r *Repository) PruneCalls(ctx context.Context, cutoff time.Time) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM action_calls WHERE created_at < $1`, cutoff)
	return failure(err)
}
