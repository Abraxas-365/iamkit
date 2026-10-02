package eventpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Subscriptions persists event webhook subscriptions and their delivery
// outbox (migration 046; deliveries are queued by a trigger on events).
type Subscriptions struct{ db *sqlx.DB }

func NewSubscriptions(db *sqlx.DB) *Subscriptions { return &Subscriptions{db} }

var _ event.SubscriptionRepository = (*Subscriptions)(nil)

var errSubscriptionNotFound = errx.NotFound("webhook subscription not found")

type subscriptionRow struct {
	ID              identity.SubscriptionID `db:"id"`
	Environment     identity.EnvironmentID  `db:"environment_id"`
	Name            string                  `db:"name"`
	URL             string                  `db:"url"`
	Types           pq.StringArray          `db:"types"`
	Active          bool                    `db:"active"`
	DisabledReason  string                  `db:"disabled_reason"`
	FailingSince    *time.Time              `db:"failing_since"`
	PreviousExpires *time.Time              `db:"previous_expires_at"`
	Pending         int                     `db:"pending"`
	CreatedAt       time.Time               `db:"created_at"`
	UpdatedAt       time.Time               `db:"updated_at"`
}

func (r subscriptionRow) toDomain() event.Subscription {
	s := event.Subscription{ID: r.ID, Environment: r.Environment, Name: r.Name, URL: r.URL, Types: []string(r.Types),
		Active: r.Active, DisabledReason: r.DisabledReason, FailingSince: r.FailingSince, Pending: r.Pending,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if s.Types == nil {
		s.Types = []string{}
	}
	if r.PreviousExpires != nil && r.PreviousExpires.After(time.Now()) {
		s.PreviousSecretExpiresAt = r.PreviousExpires
	}
	return s
}

const subscriptionColumns = `s.id, s.environment_id, s.name, s.url, s.types, s.active, s.disabled_reason, s.failing_since,
	s.previous_expires_at, s.created_at, s.updated_at,
	(SELECT count(*) FROM event_deliveries d WHERE d.subscription_id = s.id AND d.status = 'pending') AS pending`

// audited runs change and the audit entry in one transaction; change
// reports whether it found its row.
func (r *Subscriptions) audited(ctx context.Context, m event.Mutation, change func(tx *sqlx.Tx) (bool, error)) error {
	return Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		found, err := change(tx)
		if err != nil {
			return failure(err)
		}
		if !found {
			return errSubscriptionNotFound
		}
		return Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func affected(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (r *Subscriptions) CountSubscriptions(ctx context.Context, environment identity.EnvironmentID) (int, error) {
	var n int
	err := r.db.GetContext(ctx, &n, `SELECT count(*) FROM event_subscriptions WHERE environment_id = $1`, environment)
	return n, failure(err)
}

func (r *Subscriptions) CreateSubscription(ctx context.Context, m event.Mutation, id identity.SubscriptionID, input event.SubscriptionCreate, sealed string) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `INSERT INTO event_subscriptions (id, environment_id, name, url, types, secret_sealed)
			VALUES ($1, $2, $3, $4, $5, $6)`, id, m.Environment, input.Name, input.URL, pq.StringArray(input.Types), sealed))
	})
}

func (r *Subscriptions) UpdateSubscription(ctx context.Context, m event.Mutation, id identity.SubscriptionID, input event.SubscriptionUpdate) error {
	var types any
	if input.Types != nil {
		types = pq.StringArray(*input.Types)
	}
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		// Re-enabling clears the failure clock so it is not disabled again
		// on the next round.
		return affected(tx.ExecContext(ctx, `UPDATE event_subscriptions SET
			name = COALESCE($3, name), url = COALESCE($4, url), types = COALESCE($5, types),
			active = COALESCE($6, active),
			disabled_reason = CASE WHEN $6 IS NOT NULL THEN '' ELSE disabled_reason END,
			failing_since = CASE WHEN $6::boolean THEN NULL ELSE failing_since END,
			updated_at = now()
			WHERE environment_id = $1 AND id = $2`, m.Environment, id, input.Name, input.URL, types, input.Active))
	})
}

func (r *Subscriptions) DeleteSubscription(ctx context.Context, m event.Mutation, id identity.SubscriptionID) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `DELETE FROM event_subscriptions WHERE environment_id = $1 AND id = $2`, m.Environment, id))
	})
}

func (r *Subscriptions) RotateSecret(ctx context.Context, m event.Mutation, id identity.SubscriptionID, sealed string, previousExpires time.Time) error {
	return r.audited(ctx, m, func(tx *sqlx.Tx) (bool, error) {
		return affected(tx.ExecContext(ctx, `UPDATE event_subscriptions SET previous_sealed = secret_sealed,
			previous_expires_at = $3, secret_sealed = $4, updated_at = now()
			WHERE environment_id = $1 AND id = $2`, m.Environment, id, previousExpires, sealed))
	})
}

func (r *Subscriptions) ListSubscriptions(ctx context.Context, environment identity.EnvironmentID) ([]event.Subscription, error) {
	rows := []subscriptionRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+subscriptionColumns+` FROM event_subscriptions s
		WHERE s.environment_id = $1 ORDER BY s.created_at, s.id`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]event.Subscription, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

func (r *Subscriptions) FindSubscription(ctx context.Context, environment identity.EnvironmentID, id identity.SubscriptionID) (event.Subscription, error) {
	var row subscriptionRow
	err := r.db.GetContext(ctx, &row, `SELECT `+subscriptionColumns+` FROM event_subscriptions s
		WHERE s.environment_id = $1 AND s.id = $2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return event.Subscription{}, errSubscriptionNotFound
	}
	return row.toDomain(), failure(err)
}

func (r *Subscriptions) SubscriptionSecrets(ctx context.Context, environment identity.EnvironmentID, id identity.SubscriptionID) (string, []string, error) {
	var row struct {
		URL     string         `db:"url"`
		Secrets pq.StringArray `db:"secrets"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT url, `+secretsColumn+` AS secrets FROM event_subscriptions s
		WHERE environment_id = $1 AND id = $2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, errSubscriptionNotFound
	}
	return row.URL, []string(row.Secrets), failure(err)
}

// secretsColumn lists the sealed secrets that sign now: the current one,
// then the rotated one during its overlap.
const secretsColumn = `CASE WHEN s.previous_sealed IS NOT NULL AND s.previous_expires_at > now()
	THEN ARRAY[s.secret_sealed, s.previous_sealed] ELSE ARRAY[s.secret_sealed] END`

// typeMatch is the trigger's subscription match (migration 046) for an
// events row e.
const typeMatch = `(s.types = '{}' OR e.type = ANY (s.types) OR split_part(e.type, '.', 1) || '.*' = ANY (s.types))`

func (r *Subscriptions) Replay(ctx context.Context, m event.Mutation, id identity.SubscriptionID, from int64) (int, error) {
	var n int
	err := Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var exists bool
		if err := tx.GetContext(ctx, &exists, `SELECT EXISTS (SELECT 1 FROM event_subscriptions WHERE environment_id = $1 AND id = $2)`, m.Environment, id); err != nil {
			return failure(err)
		}
		if !exists {
			return errSubscriptionNotFound
		}
		res, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO event_deliveries (subscription_id, environment_id, event_id, event_type)
			SELECT s.id, e.environment_id, e.id, e.type FROM events e JOIN event_subscriptions s ON s.id = $2
			WHERE e.environment_id = $1 AND e.id >= $3 AND %s ORDER BY e.id LIMIT %d`, typeMatch, event.MaxReplay), m.Environment, id, from)
		if err != nil {
			return failure(err)
		}
		rows, err := res.RowsAffected()
		if err != nil {
			return failure(err)
		}
		n = int(rows)
		return AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"from": from, "count": n})
	})
	return n, err
}

func (r *Subscriptions) RetryDelivery(ctx context.Context, m event.Mutation, id identity.SubscriptionID, delivery int64) error {
	err := Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		found, err := affected(tx.ExecContext(ctx, `UPDATE event_deliveries SET status = 'pending', attempts = 0,
			next_attempt_at = now(), first_attempt_at = NULL, finished_at = NULL
			WHERE environment_id = $1 AND subscription_id = $2 AND id = $3 AND status = 'failed'`, m.Environment, id, delivery))
		if err != nil {
			return failure(err)
		}
		if !found {
			return errx.NotFound("failed webhook delivery not found")
		}
		return AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"delivery_id": delivery})
	})
	return err
}

type deliveryRow struct {
	ID             int64                   `db:"id"`
	Subscription   identity.SubscriptionID `db:"subscription_id"`
	EventID        int64                   `db:"event_id"`
	EventType      string                  `db:"event_type"`
	Status         string                  `db:"status"`
	Attempts       int                     `db:"attempts"`
	NextAttemptAt  time.Time               `db:"next_attempt_at"`
	ResponseStatus *int                    `db:"response_status"`
	LastError      string                  `db:"last_error"`
	QueuedAt       time.Time               `db:"queued_at"`
	FinishedAt     *time.Time              `db:"finished_at"`
}

func (r deliveryRow) toDomain() event.Delivery {
	d := event.Delivery{ID: r.ID, Subscription: r.Subscription, EventID: r.EventID, EventType: r.EventType,
		Status: r.Status, Attempts: r.Attempts, ResponseStatus: r.ResponseStatus, LastError: r.LastError,
		QueuedAt: r.QueuedAt, FinishedAt: r.FinishedAt}
	if r.Status == event.DeliveryPending {
		next := r.NextAttemptAt
		d.NextAttemptAt = &next
	}
	return d
}

func (r *Subscriptions) ListDeliveries(ctx context.Context, environment identity.EnvironmentID, id identity.SubscriptionID, filter event.DeliveryFilter, page query.Pagination) (query.Paginated[event.Delivery], error) {
	page = page.Normalize()
	where := `environment_id = $1 AND subscription_id = $2 AND ($3 = '' OR status = $3)`
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM event_deliveries WHERE `+where, environment, id, filter.Status); err != nil {
		return query.Paginated[event.Delivery]{}, failure(err)
	}
	rows := []deliveryRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT id, subscription_id, event_id, event_type, status, attempts, next_attempt_at,
		response_status, last_error, queued_at, finished_at FROM event_deliveries WHERE `+where+`
		ORDER BY id DESC LIMIT $4 OFFSET $5`, environment, id, filter.Status, page.Limit, page.Offset); err != nil {
		return query.Paginated[event.Delivery]{}, failure(err)
	}
	items := make([]event.Delivery, len(rows))
	for i, row := range rows {
		items[i] = row.toDomain()
	}
	return query.NewPaginated(items, total, page), nil
}

type messageRow struct {
	Delivery     int64                    `db:"delivery"`
	Subscription identity.SubscriptionID  `db:"subscription_id"`
	Environment  identity.EnvironmentID   `db:"environment_id"`
	URL          string                   `db:"url"`
	Secrets      pq.StringArray           `db:"secrets"`
	Attempts     int                      `db:"attempts"`
	FirstAttempt time.Time                `db:"first_attempt_at"`
	EventID      sql.NullInt64            `db:"event_id"`
	Type         string                   `db:"type"`
	ActorKind    string                   `db:"actor_kind"`
	ActorID      string                   `db:"actor_id"`
	SubjectKind  string                   `db:"subject_kind"`
	SubjectID    string                   `db:"subject_id"`
	Organization *identity.OrganizationID `db:"organization_id"`
	Data         []byte                   `db:"data"`
	CreatedAt    time.Time                `db:"created_at"`
}

// ClaimDeliveries leases each active subscription's oldest pending
// delivery once it is due. The lock re-checks status and next_attempt_at
// on the latest row version, so a head another replica just leased (now
// in the future) or finished is skipped, and SKIP LOCKED passes over
// in-flight claims.
func (r *Subscriptions) ClaimDeliveries(ctx context.Context, limit int, lease time.Duration) ([]event.Message, error) {
	rows := []messageRow{}
	err := r.db.SelectContext(ctx, &rows, `WITH heads AS (
		SELECT DISTINCT ON (d.subscription_id) d.id
		FROM event_deliveries d JOIN event_subscriptions s ON s.id = d.subscription_id AND s.active
		WHERE d.status = 'pending'
		ORDER BY d.subscription_id, d.id
	), due AS (
		SELECT d.id FROM event_deliveries d JOIN heads h ON h.id = d.id
		WHERE d.status = 'pending' AND d.next_attempt_at <= now()
		ORDER BY d.next_attempt_at LIMIT $1 FOR UPDATE OF d SKIP LOCKED
	), claimed AS (
		UPDATE event_deliveries d SET attempts = d.attempts + 1, next_attempt_at = now() + make_interval(secs => $2),
			first_attempt_at = COALESCE(d.first_attempt_at, now())
		FROM due WHERE d.id = due.id
		RETURNING d.id, d.subscription_id, d.environment_id, d.event_id, d.attempts, d.first_attempt_at
	)
	SELECT c.id AS delivery, c.subscription_id, c.environment_id, c.attempts, c.first_attempt_at, s.url,
		`+secretsColumn+` AS secrets,
		e.id AS event_id, COALESCE(e.type, '') AS type, COALESCE(e.actor_kind, '') AS actor_kind, COALESCE(e.actor_id, '') AS actor_id,
		COALESCE(e.subject_kind, '') AS subject_kind, COALESCE(e.subject_id, '') AS subject_id, e.organization_id,
		COALESCE(e.data, '{}') AS data, COALESCE(e.created_at, now()) AS created_at
	FROM claimed c JOIN event_subscriptions s ON s.id = c.subscription_id
	LEFT JOIN events e ON e.id = c.event_id`, limit, lease.Seconds())
	if err != nil {
		return nil, failure(err)
	}
	out := make([]event.Message, len(rows))
	for i, x := range rows {
		m := event.Message{Delivery: x.Delivery, Subscription: x.Subscription, Environment: x.Environment,
			URL: x.URL, Secrets: []string(x.Secrets), Attempts: x.Attempts, FirstAttempt: x.FirstAttempt}
		if x.EventID.Valid {
			e := row{ID: x.EventID.Int64, Environment: x.Environment, Type: x.Type, ActorKind: x.ActorKind, ActorID: x.ActorID,
				SubjectKind: x.SubjectKind, SubjectID: x.SubjectID, Organization: x.Organization, Data: x.Data, CreatedAt: x.CreatedAt}.toDomain()
			m.Event = &e
		}
		out[i] = m
	}
	return out, nil
}

func status(o event.Outcome) *int {
	if o.Status == 0 {
		return nil
	}
	return &o.Status
}

func (r *Subscriptions) Delivered(ctx context.Context, delivery int64, outcome event.Outcome) error {
	_, err := r.db.ExecContext(ctx, `WITH d AS (
		UPDATE event_deliveries SET status = 'delivered', finished_at = now(), response_status = $2, last_error = ''
		WHERE id = $1 RETURNING subscription_id)
	UPDATE event_subscriptions SET failing_since = NULL FROM d WHERE id = d.subscription_id AND failing_since IS NOT NULL`,
		delivery, status(outcome))
	if err == nil {
		telemetry.Webhook(ctx, telemetry.WebhookDelivered)
	}
	return failure(err)
}

func (r *Subscriptions) RetryLater(ctx context.Context, delivery int64, outcome event.Outcome, wait time.Duration) error {
	_, err := r.db.ExecContext(ctx, `WITH d AS (
		UPDATE event_deliveries SET next_attempt_at = now() + make_interval(secs => $2), response_status = $3, last_error = $4
		WHERE id = $1 RETURNING subscription_id)
	UPDATE event_subscriptions SET failing_since = now() FROM d WHERE id = d.subscription_id AND failing_since IS NULL`,
		delivery, wait.Seconds(), status(outcome), outcome.Error)
	if err == nil {
		telemetry.Webhook(ctx, telemetry.WebhookRetried)
	}
	return failure(err)
}

func (r *Subscriptions) GiveUp(ctx context.Context, delivery int64, outcome event.Outcome) error {
	_, err := r.db.ExecContext(ctx, `WITH d AS (
		UPDATE event_deliveries SET status = 'failed', finished_at = now(), response_status = $2, last_error = $3
		WHERE id = $1 RETURNING subscription_id)
	UPDATE event_subscriptions SET failing_since = now() FROM d WHERE id = d.subscription_id AND failing_since IS NULL`,
		delivery, status(outcome), outcome.Error)
	if err == nil {
		telemetry.Webhook(ctx, telemetry.WebhookFailed)
	}
	return failure(err)
}

func (r *Subscriptions) DisableFailing(ctx context.Context, cutoff time.Time) (int, error) {
	n := 0
	err := Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var disabled []struct {
			ID          identity.SubscriptionID `db:"id"`
			Environment identity.EnvironmentID  `db:"environment_id"`
		}
		if err := tx.SelectContext(ctx, &disabled, `UPDATE event_subscriptions SET active = false, disabled_reason = $2, updated_at = now()
			WHERE active AND failing_since < $1 RETURNING id, environment_id`, cutoff, event.DisabledFailing); err != nil {
			return failure(err)
		}
		for _, s := range disabled {
			if err := System(ctx, tx, s.Environment, event.ActionWebhookDisable, s.ID.String()); err != nil {
				return err
			}
		}
		n = len(disabled)
		return nil
	})
	return n, err
}

func (r *Subscriptions) PruneDeliveries(ctx context.Context, cutoff time.Time) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM event_deliveries WHERE status <> 'pending' AND finished_at < $1`, cutoff)
	return failure(err)
}

func (r *Subscriptions) DeliveryLag(ctx context.Context) (time.Duration, error) {
	var seconds float64
	err := r.db.GetContext(ctx, &seconds, `SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(d.next_attempt_at)), 0)::float8
		FROM event_deliveries d JOIN event_subscriptions s ON s.id = d.subscription_id AND s.active
		WHERE d.status = 'pending' AND d.next_attempt_at <= now()`)
	if err != nil {
		return 0, failure(err)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}
