// Package usagepg stores environment limits and daily usage in PostgreSQL.
package usagepg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ usage.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "usage persistence failed", errx.TypeInternal)
}

type limitsRow struct {
	Users         sql.NullInt64 `db:"users_max"`
	Organizations sql.NullInt64 `db:"organizations_max"`
	Applications  sql.NullInt64 `db:"applications_max"`
	Requests      sql.NullInt64 `db:"requests_per_minute"`
	Emails        sql.NullInt64 `db:"emails_per_day"`
	SMS           sql.NullInt64 `db:"sms_per_day"`
	ActionCalls   sql.NullInt64 `db:"action_calls_per_minute"`
	UpdatedAt     time.Time     `db:"updated_at"`
}

func (r limitsRow) values() usage.Values {
	out := usage.Values{}
	for name, v := range map[string]sql.NullInt64{
		usage.LimitUsers: r.Users, usage.LimitOrganizations: r.Organizations, usage.LimitApplications: r.Applications,
		usage.LimitRequests: r.Requests, usage.LimitEmails: r.Emails, usage.LimitSMS: r.SMS, usage.LimitActionCalls: r.ActionCalls,
	} {
		if v.Valid {
			out[name] = v.Int64
		}
	}
	return out
}

func (r *Repository) Limits(ctx context.Context, environment identity.EnvironmentID) (usage.Stored, error) {
	var row limitsRow
	err := r.db.GetContext(ctx, &row, `SELECT users_max, organizations_max, applications_max, requests_per_minute,
		emails_per_day, sms_per_day, action_calls_per_minute, updated_at FROM environment_limits WHERE environment_id=$1`, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return usage.Stored{Values: usage.Values{}}, nil
	}
	if err != nil {
		return usage.Stored{}, failure(err)
	}
	at := row.UpdatedAt
	return usage.Stored{Values: row.values(), UpdatedAt: &at}, nil
}

func nullable(values usage.Values, name string) sql.NullInt64 {
	n, ok := values[name]
	return sql.NullInt64{Int64: n, Valid: ok}
}

func (r *Repository) SaveLimits(ctx context.Context, m usage.Mutation, values usage.Values) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO environment_limits(environment_id, users_max, organizations_max, applications_max,
			requests_per_minute, emails_per_day, sms_per_day, action_calls_per_minute) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (environment_id) DO UPDATE SET users_max=EXCLUDED.users_max, organizations_max=EXCLUDED.organizations_max,
			applications_max=EXCLUDED.applications_max, requests_per_minute=EXCLUDED.requests_per_minute,
			emails_per_day=EXCLUDED.emails_per_day, sms_per_day=EXCLUDED.sms_per_day,
			action_calls_per_minute=EXCLUDED.action_calls_per_minute, updated_at=now()`, m.Environment,
			nullable(values, usage.LimitUsers), nullable(values, usage.LimitOrganizations), nullable(values, usage.LimitApplications),
			nullable(values, usage.LimitRequests), nullable(values, usage.LimitEmails), nullable(values, usage.LimitSMS),
			nullable(values, usage.LimitActionCalls)); err != nil {
			return failure(err)
		}
		return failure(eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"limits": map[string]int64(values)}))
	})
}

// totals are the count queries of the total limits. Machine users count:
// they are users of the environment.
var totals = map[string]string{
	usage.LimitUsers:         `SELECT count(*) FROM users WHERE environment_id=$1`,
	usage.LimitOrganizations: `SELECT count(*) FROM organizations WHERE environment_id=$1`,
	usage.LimitApplications:  `SELECT count(*) FROM applications WHERE environment_id=$1`,
}

func (r *Repository) Total(ctx context.Context, environment identity.EnvironmentID, limit string) (int64, error) {
	q, ok := totals[limit]
	if !ok {
		return 0, errx.Internal("no total for limit " + limit)
	}
	var n int64
	return n, failure(r.db.GetContext(ctx, &n, q, environment))
}

func (r *Repository) Daily(ctx context.Context, environment identity.EnvironmentID, metric string, day time.Time) (int64, error) {
	var n int64
	err := r.db.GetContext(ctx, &n, `SELECT coalesce(sum(count),0) FROM usage_daily WHERE environment_id=$1 AND metric=$2 AND day=$3`, environment, metric, day)
	return n, failure(err)
}

func (r *Repository) Days(ctx context.Context, environment identity.EnvironmentID, from time.Time) ([]usage.Increment, error) {
	var rows []struct {
		Day    time.Time `db:"day"`
		Metric string    `db:"metric"`
		Count  int64     `db:"count"`
	}
	if err := r.db.SelectContext(ctx, &rows, `SELECT day, metric, count FROM usage_daily WHERE environment_id=$1 AND day>=$2 ORDER BY day, metric`, environment, from); err != nil {
		return nil, failure(err)
	}
	out := make([]usage.Increment, len(rows))
	for i, x := range rows {
		out[i] = usage.Increment{Environment: environment, Day: usage.UTCDay(x.Day), Metric: x.Metric, Count: x.Count}
	}
	return out, nil
}

// Add upserts every increment in one statement; increments of deleted
// environments are dropped.
func (r *Repository) Add(ctx context.Context, increments []usage.Increment) error {
	if len(increments) == 0 {
		return nil
	}
	envs, days, metrics, counts := make([]string, len(increments)), make([]string, len(increments)), make([]string, len(increments)), make([]int64, len(increments))
	for i, x := range increments {
		envs[i], days[i], metrics[i], counts[i] = x.Environment.String(), x.Day.Format(time.DateOnly), x.Metric, x.Count
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO usage_daily AS u (environment_id, day, metric, count)
		SELECT x.environment_id, x.day, x.metric, x.count
		FROM unnest($1::uuid[], $2::date[], $3::text[], $4::bigint[]) AS x(environment_id, day, metric, count)
		WHERE EXISTS (SELECT 1 FROM environments e WHERE e.id = x.environment_id)
		ON CONFLICT (environment_id, day, metric) DO UPDATE SET count = u.count + EXCLUDED.count`,
		pq.Array(envs), pq.Array(days), pq.Array(metrics), pq.Array(counts))
	return failure(err)
}

// rolledUp maps event types to the metric they count.
var rolledUp = map[string]string{
	event.SessionCreated: usage.MetricLogins,
	event.UserCreated:    usage.MetricUsersCreated,
}

// Rollup reads the next events under the locked cursor, adds the counted
// ones and moves the cursor, in one transaction: replicas take turns.
// Child sessions (token exchange) and impersonation are not sign-ins.
func (r *Repository) Rollup(ctx context.Context, settled time.Time, batch int) (int, error) {
	types := make([]string, 0, len(rolledUp))
	metrics := make([]string, 0, len(rolledUp))
	for t, m := range rolledUp {
		types, metrics = append(types, t), append(metrics, m)
	}
	var read int
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var cursor int64
		if err := tx.GetContext(ctx, &cursor, `SELECT event_id FROM usage_rollup_cursor FOR UPDATE`); err != nil {
			return failure(err)
		}
		var last struct {
			ID    sql.NullInt64 `db:"id"`
			Count int           `db:"n"`
		}
		if err := tx.GetContext(ctx, &last, `
			WITH batch AS (
				SELECT id, environment_id, type, created_at, data FROM events
				WHERE id > $1 AND created_at < $2 ORDER BY id LIMIT $3
			), counted AS (
				INSERT INTO usage_daily AS u (environment_id, day, metric, count)
				SELECT b.environment_id, (b.created_at AT TIME ZONE 'UTC')::date, m.metric, count(*)
				FROM batch b JOIN unnest($4::text[], $5::text[]) AS m(type, metric) ON m.type = b.type
				WHERE b.data->>'parent_session_id' IS NULL AND coalesce((b.data->>'impersonated')::boolean, false) = false
				GROUP BY 1, 2, 3
				ON CONFLICT (environment_id, day, metric) DO UPDATE SET count = u.count + EXCLUDED.count
			)
			SELECT max(id) AS id, count(*) AS n FROM batch`, cursor, settled, batch, pq.Array(types), pq.Array(metrics)); err != nil {
			return failure(err)
		}
		if !last.ID.Valid {
			return nil
		}
		read = last.Count
		_, err := tx.ExecContext(ctx, `UPDATE usage_rollup_cursor SET event_id=$1`, last.ID.Int64)
		return failure(err)
	})
	return read, err
}

// Prune removes daily usage older than before.
func (r *Repository) Prune(ctx context.Context, before time.Time) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM usage_daily WHERE day < $1`, usage.UTCDay(before))
	return failure(err)
}
