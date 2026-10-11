// Package logstreampg persists log streams and their delivery outbox
// (rows are queued by triggers on events and audit_log_events). Every
// query that takes a Scope filters by it in SQL, so an organization's
// administrator can never reach another organization's stream.
package logstreampg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Repository is the PostgreSQL logstream.Repository.
type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ logstream.Repository = (*Repository)(nil)

var errNotFound = errx.NotFound("log stream not found")

// inScope is the scope predicate on a log_streams alias s; the arguments
// $1 (environment), $2 (only) and $3 (organization) come from scopeArgs.
const inScope = `s.environment_id = $1 AND (NOT $2::boolean OR s.organization_id = $3::uuid)`

func scopeArgs(scope logstream.Scope) []any {
	var organization any
	if !scope.Organization.IsZero() {
		organization = scope.Organization.String()
	}
	return []any{scope.Environment, scope.Only, organization}
}

type streamRow struct {
	ID              identity.LogStreamID     `db:"id"`
	Environment     identity.EnvironmentID   `db:"environment_id"`
	Organization    *identity.OrganizationID `db:"organization_id"`
	Name            string                   `db:"name"`
	Destination     string                   `db:"destination"`
	Config          []byte                   `db:"config"`
	Sources         pq.StringArray           `db:"sources"`
	Active          bool                     `db:"active"`
	DisabledReason  string                   `db:"disabled_reason"`
	FailingSince    *time.Time               `db:"failing_since"`
	PreviousExpires *time.Time               `db:"previous_expires_at"`
	Pending         int                      `db:"pending"`
	CreatedAt       time.Time                `db:"created_at"`
	UpdatedAt       time.Time                `db:"updated_at"`
}

const streamColumns = `s.id, s.environment_id, s.organization_id, s.name, s.destination, s.config, s.sources, s.active,
	s.disabled_reason, s.failing_since, s.previous_expires_at, s.created_at, s.updated_at,
	(SELECT count(*) FROM log_stream_deliveries d WHERE d.stream_id = s.id AND d.status = 'pending') AS pending`

func (r streamRow) toDomain() (logstream.Stream, error) {
	s := logstream.Stream{ID: r.ID, Environment: r.Environment, Organization: r.Organization, Name: r.Name,
		Destination: r.Destination, Sources: []string(r.Sources), SecretSet: true, Active: r.Active,
		DisabledReason: r.DisabledReason, FailingSince: r.FailingSince, Pending: r.Pending,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if err := json.Unmarshal(r.Config, &s.Config); err != nil {
		return s, errx.Wrap(err, "decode log stream config", errx.TypeInternal)
	}
	if r.PreviousExpires != nil && r.PreviousExpires.After(time.Now()) {
		s.PreviousSecretExpiresAt = r.PreviousExpires
	}
	return s, nil
}

// failure maps constraint violations; raw driver errors never escape.
func failure(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pq.Error
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return errx.NotFound("organization not found")
	}
	var e *errx.Error
	if errors.As(err, &e) {
		return err
	}
	return errx.Wrap(err, "log stream persistence failed", errx.TypeInternal)
}

func affected(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// audited runs change and its audit entry in one transaction; change
// reports whether it found its row.
func (r *Repository) audited(ctx context.Context, m logstream.Mutation, data map[string]any, change func(tx *sqlx.Tx) (bool, error)) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		found, err := change(tx)
		if err != nil {
			return failure(err)
		}
		if !found {
			return errNotFound
		}
		if m.Only && !m.Organization.IsZero() {
			if data == nil {
				data = map[string]any{}
			}
			data["organization_id"] = m.Organization.String()
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, data)
	})
}

func (r *Repository) CountStreams(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (int, error) {
	var n int
	var err error
	if organization.IsZero() {
		err = r.db.GetContext(ctx, &n, `SELECT count(*) FROM log_streams WHERE environment_id = $1 AND organization_id IS NULL`, environment)
	} else {
		err = r.db.GetContext(ctx, &n, `SELECT count(*) FROM log_streams WHERE environment_id = $1 AND organization_id = $2`, environment, organization)
	}
	return n, failure(err)
}

func (r *Repository) CreateStream(ctx context.Context, m logstream.Mutation, id identity.LogStreamID, organization identity.OrganizationID, input logstream.Create, sealed string) error {
	raw, err := json.Marshal(input.Config)
	if err != nil {
		return errx.Wrap(err, "encode log stream config", errx.TypeInternal)
	}
	var org any
	if !organization.IsZero() {
		org = organization.String()
	}
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO log_streams (id, environment_id, organization_id, name, destination, config, secret_sealed, sources)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, m.Environment, org, input.Name, input.Destination, string(raw), sealed, pq.StringArray(input.Sources)); err != nil {
			return failure(err)
		}
		data := map[string]any{"destination": input.Destination}
		if org != nil {
			data["organization_id"] = organization.String()
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, data)
	})
}

func (r *Repository) UpdateStream(ctx context.Context, m logstream.Mutation, id identity.LogStreamID, input logstream.Update, sealed *string) error {
	var config, sources any
	if input.Config != nil {
		raw, err := json.Marshal(*input.Config)
		if err != nil {
			return errx.Wrap(err, "encode log stream config", errx.TypeInternal)
		}
		config = string(raw)
	}
	if input.Sources != nil {
		sources = pq.StringArray(*input.Sources)
	}
	// Re-enabling clears the failure clock so the stream is not disabled
	// again on the next maintenance round, and restarts the retry window
	// of what queued meanwhile, so the backlog is not given up at once.
	return r.audited(ctx, m, nil, func(tx *sqlx.Tx) (bool, error) {
		args := append(scopeArgs(m.Scope), id, input.Name, config, sources, sealed, input.Active)
		found, err := affected(tx.ExecContext(ctx, `UPDATE log_streams s SET
			name = COALESCE($5, s.name), config = COALESCE($6::jsonb, s.config), sources = COALESCE($7::text[], s.sources),
			secret_sealed = COALESCE($8, s.secret_sealed),
			active = COALESCE($9, s.active),
			disabled_reason = CASE WHEN $9::boolean IS NOT NULL THEN '' ELSE s.disabled_reason END,
			failing_since = CASE WHEN $9::boolean THEN NULL ELSE s.failing_since END,
			updated_at = now()
			WHERE `+inScope+` AND s.id = $4`, args...))
		if err != nil || !found || input.Active == nil || !*input.Active {
			return found, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE log_stream_deliveries SET attempts = 0, first_attempt_at = NULL, next_attempt_at = now()
			WHERE stream_id = $1 AND status = 'pending'`, id)
		return true, failure(err)
	})
}

func (r *Repository) DeleteStream(ctx context.Context, m logstream.Mutation, id identity.LogStreamID) error {
	return r.audited(ctx, m, nil, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `DELETE FROM log_streams s WHERE `+inScope+` AND s.id = $4`, append(scopeArgs(m.Scope), id)...))
	})
}

func (r *Repository) RotateSecret(ctx context.Context, m logstream.Mutation, id identity.LogStreamID, sealed string, previousExpires time.Time) error {
	return r.audited(ctx, m, nil, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `UPDATE log_streams s SET previous_sealed = s.secret_sealed,
			previous_expires_at = $5, secret_sealed = $6, updated_at = now()
			WHERE `+inScope+` AND s.id = $4 AND s.destination = 'https'`, append(scopeArgs(m.Scope), id, previousExpires, sealed)...))
	})
}

func (r *Repository) ListStreams(ctx context.Context, scope logstream.Scope) ([]logstream.Stream, error) {
	rows := []streamRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+streamColumns+` FROM log_streams s WHERE `+inScope+`
		ORDER BY s.created_at, s.id`, scopeArgs(scope)...); err != nil {
		return nil, failure(err)
	}
	out := make([]logstream.Stream, len(rows))
	for i, row := range rows {
		s, err := row.toDomain()
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func (r *Repository) FindStream(ctx context.Context, scope logstream.Scope, id identity.LogStreamID) (logstream.Stream, error) {
	var row streamRow
	err := r.db.GetContext(ctx, &row, `SELECT `+streamColumns+` FROM log_streams s WHERE `+inScope+` AND s.id = $4`, append(scopeArgs(scope), id)...)
	if errors.Is(err, sql.ErrNoRows) {
		return logstream.Stream{}, errNotFound
	}
	if err != nil {
		return logstream.Stream{}, failure(err)
	}
	return row.toDomain()
}

// secretsColumn lists the sealed secrets that sign now: the current one,
// then the rotated one during its overlap.
const secretsColumn = `CASE WHEN s.previous_sealed IS NOT NULL AND s.previous_expires_at > now()
	THEN ARRAY[s.secret_sealed, s.previous_sealed] ELSE ARRAY[s.secret_sealed] END`

func (r *Repository) StreamSecrets(ctx context.Context, scope logstream.Scope, id identity.LogStreamID) ([]string, error) {
	var secrets pq.StringArray
	err := r.db.GetContext(ctx, &secrets, `SELECT `+secretsColumn+` FROM log_streams s WHERE `+inScope+` AND s.id = $4`, append(scopeArgs(scope), id)...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return []string(secrets), failure(err)
}

func (r *Repository) RetryDelivery(ctx context.Context, m logstream.Mutation, id identity.LogStreamID, delivery int64) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		args := append(scopeArgs(m.Scope), id, delivery)
		found, err := affected(tx.ExecContext(ctx, `UPDATE log_stream_deliveries d SET status = 'pending', attempts = 0,
			next_attempt_at = now(), first_attempt_at = NULL, finished_at = NULL, response_status = NULL, last_error = ''
			FROM log_streams s
			WHERE s.id = d.stream_id AND `+inScope+` AND s.id = $4 AND d.status = 'failed'
			AND (d.id = $5 OR (d.batch IS NOT NULL AND d.batch = (SELECT x.batch FROM log_stream_deliveries x WHERE x.id = $5 AND x.stream_id = $4)))`, args...))
		if err != nil {
			return failure(err)
		}
		if !found {
			return errx.NotFound("failed log stream delivery not found")
		}
		data := map[string]any{"delivery_id": delivery}
		if m.Only && !m.Organization.IsZero() {
			data["organization_id"] = m.Organization.String()
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, data)
	})
}

type deliveryRow struct {
	ID             int64                `db:"id"`
	Stream         identity.LogStreamID `db:"stream_id"`
	Source         string               `db:"source"`
	Seq            int64                `db:"source_seq"`
	Batch          *int64               `db:"batch"`
	Status         string               `db:"status"`
	Attempts       int                  `db:"attempts"`
	NextAttemptAt  time.Time            `db:"next_attempt_at"`
	ResponseStatus *int                 `db:"response_status"`
	LastError      string               `db:"last_error"`
	QueuedAt       time.Time            `db:"queued_at"`
	FinishedAt     *time.Time           `db:"finished_at"`
}

func (r deliveryRow) toDomain() logstream.Delivery {
	d := logstream.Delivery{ID: r.ID, Stream: r.Stream, Source: r.Source, Seq: r.Seq, Batch: r.Batch, Status: r.Status,
		Attempts: r.Attempts, ResponseStatus: r.ResponseStatus, LastError: r.LastError, QueuedAt: r.QueuedAt, FinishedAt: r.FinishedAt}
	if r.Status == logstream.DeliveryPending {
		next := r.NextAttemptAt
		d.NextAttemptAt = &next
	}
	return d
}

func (r *Repository) ListDeliveries(ctx context.Context, scope logstream.Scope, id identity.LogStreamID, filter logstream.DeliveryFilter, page query.Pagination) (query.Paginated[logstream.Delivery], error) {
	page = page.Normalize()
	where := `FROM log_stream_deliveries d JOIN log_streams s ON s.id = d.stream_id WHERE ` + inScope + ` AND s.id = $4 AND ($5 = '' OR d.status = $5)`
	args := append(scopeArgs(scope), id, filter.Status)
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) `+where, args...); err != nil {
		return query.Paginated[logstream.Delivery]{}, failure(err)
	}
	rows := []deliveryRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT d.id, d.stream_id, d.source, d.source_seq, d.batch, d.status, d.attempts, d.next_attempt_at,
		d.response_status, d.last_error, d.queued_at, d.finished_at `+where+` ORDER BY d.id DESC LIMIT $6 OFFSET $7`,
		append(args, page.Limit, page.Offset)...); err != nil {
		return query.Paginated[logstream.Delivery]{}, failure(err)
	}
	items := make([]logstream.Delivery, len(rows))
	for i, row := range rows {
		items[i] = row.toDomain()
	}
	return query.NewPaginated(items, total, page), nil
}

func status(o logstream.Outcome) *int {
	if o.Status == 0 {
		return nil
	}
	return &o.Status
}

func (r *Repository) Delivered(ctx context.Context, stream identity.LogStreamID, rows []int64, outcome logstream.Outcome) error {
	_, err := r.db.ExecContext(ctx, `WITH d AS (
		UPDATE log_stream_deliveries SET status = 'delivered', finished_at = now(), response_status = $3, last_error = ''
		WHERE stream_id = $1 AND id = ANY($2) RETURNING stream_id)
	UPDATE log_streams SET failing_since = NULL WHERE id = $1 AND failing_since IS NOT NULL AND EXISTS (SELECT 1 FROM d)`,
		stream, pq.Array(rows), status(outcome))
	if err == nil {
		telemetry.Webhook(ctx, telemetry.WebhookDelivered)
	}
	return failure(err)
}

func (r *Repository) RetryLater(ctx context.Context, stream identity.LogStreamID, rows []int64, outcome logstream.Outcome, wait time.Duration) error {
	_, err := r.db.ExecContext(ctx, `WITH d AS (
		UPDATE log_stream_deliveries SET next_attempt_at = now() + make_interval(secs => $3), response_status = $4, last_error = $5
		WHERE stream_id = $1 AND id = ANY($2) RETURNING stream_id)
	UPDATE log_streams SET failing_since = now() WHERE id = $1 AND failing_since IS NULL AND EXISTS (SELECT 1 FROM d)`,
		stream, pq.Array(rows), wait.Seconds(), status(outcome), outcome.Error)
	if err == nil {
		telemetry.Webhook(ctx, telemetry.WebhookRetried)
	}
	return failure(err)
}

func (r *Repository) GiveUp(ctx context.Context, stream identity.LogStreamID, rows []int64, outcome logstream.Outcome) error {
	_, err := r.db.ExecContext(ctx, `WITH d AS (
		UPDATE log_stream_deliveries SET status = 'failed', finished_at = now(), response_status = $3, last_error = $4
		WHERE stream_id = $1 AND id = ANY($2) RETURNING stream_id)
	UPDATE log_streams SET failing_since = now() WHERE id = $1 AND failing_since IS NULL AND EXISTS (SELECT 1 FROM d)`,
		stream, pq.Array(rows), status(outcome), outcome.Error)
	if err == nil {
		telemetry.Webhook(ctx, telemetry.WebhookFailed)
	}
	return failure(err)
}

func (r *Repository) DisableFailing(ctx context.Context, cutoff time.Time) (int, error) {
	n := 0
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var disabled []struct {
			ID          identity.LogStreamID   `db:"id"`
			Environment identity.EnvironmentID `db:"environment_id"`
		}
		if err := tx.SelectContext(ctx, &disabled, `UPDATE log_streams SET active = false, disabled_reason = $2, updated_at = now()
			WHERE active AND failing_since < $1 RETURNING id, environment_id`, cutoff, logstream.DisabledFailing); err != nil {
			return failure(err)
		}
		for _, s := range disabled {
			if err := eventpg.System(ctx, tx, s.Environment, logstream.ActionDisableFailing, s.ID.String()); err != nil {
				return err
			}
		}
		n = len(disabled)
		return nil
	})
	return n, err
}

func (r *Repository) PruneDeliveries(ctx context.Context, cutoff time.Time) error {
	// A disabled stream keeps queuing (re-enabling resumes it); what waited
	// past the cutoff fails instead, so a dead stream cannot grow forever.
	// Operators can still retry it.
	if _, err := r.db.ExecContext(ctx, `UPDATE log_stream_deliveries d SET status = 'failed', finished_at = now(), last_error = $2
		FROM log_streams s WHERE s.id = d.stream_id AND NOT s.active AND d.status = 'pending' AND d.queued_at < $1`,
		cutoff, logstream.BacklogExpired); err != nil {
		return failure(err)
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM log_stream_deliveries WHERE status <> 'pending' AND finished_at < $1`, cutoff)
	return failure(err)
}

func (r *Repository) DeliveryLag(ctx context.Context) (time.Duration, error) {
	var seconds float64
	err := r.db.GetContext(ctx, &seconds, `SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(d.next_attempt_at)), 0)::float8
		FROM log_stream_deliveries d JOIN log_streams s ON s.id = d.stream_id AND s.active
		WHERE d.status = 'pending' AND d.next_attempt_at <= now()`)
	if err != nil {
		return 0, failure(err)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}
