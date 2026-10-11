package auditlogpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Events is the event repository. It never writes IAMKit's own event log:
// app events are customer data.
type Events struct{ db *sqlx.DB }

func NewEvents(db *sqlx.DB) *Events { return &Events{db} }

var _ auditlog.EventRepository = (*Events)(nil)

func (r *Events) OrganizationExists(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM organizations WHERE environment_id=$1 AND id=$2)`, environment, organization)
	return ok, failure(err)
}

// Insert stores the event. Idempotency is race-safe on the unique index
// (environment_id, idempotency_key): a concurrent insert of the same key
// waits for the winner's commit, does nothing, and the winner's row is
// read back.
func (r *Events) Insert(ctx context.Context, e auditlog.Event, idem *auditlog.Idempotency) (auditlog.Inserted, error) {
	actor, err := json.Marshal(e.Actor)
	if err != nil {
		return auditlog.Inserted{}, failure(err)
	}
	targets, err := json.Marshal(e.Targets)
	if err != nil {
		return auditlog.Inserted{}, failure(err)
	}
	context_, err := json.Marshal(e.Context)
	if err != nil {
		return auditlog.Inserted{}, failure(err)
	}
	// Both NULL without a key (a nil []byte would be sent as empty bytea).
	var key, hash any
	if idem != nil {
		key, hash = idem.Key, idem.Hash
	}
	var created time.Time
	err = r.db.GetContext(ctx, &created, `INSERT INTO audit_log_events(id, environment_id, organization_id, action, version, occurred_at,
			actor, targets, context, metadata, idempotency_key, request_hash)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (environment_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
		RETURNING created_at`, e.ID, e.Environment, e.Organization, e.Action, e.Version, e.OccurredAt,
		actor, targets, context_, []byte(e.Metadata), key, hash)
	if errors.Is(err, sql.ErrNoRows) && idem != nil {
		prior, found, err := r.FindKey(ctx, e.Environment, idem.Key)
		if err != nil {
			return auditlog.Inserted{}, err
		}
		if !found {
			return auditlog.Inserted{}, failure(errors.New("idempotency key vanished"))
		}
		return prior, nil
	}
	if err != nil {
		return auditlog.Inserted{}, failure(err)
	}
	return auditlog.Inserted{Receipt: auditlog.Receipt{ID: e.ID, CreatedAt: created}}, nil
}

func (r *Events) FindKey(ctx context.Context, environment identity.EnvironmentID, key string) (auditlog.Inserted, bool, error) {
	var row struct {
		ID        identity.AuditEventID `db:"id"`
		CreatedAt time.Time             `db:"created_at"`
		Hash      []byte                `db:"request_hash"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT id, created_at, request_hash FROM audit_log_events WHERE environment_id=$1 AND idempotency_key=$2`, environment, key)
	if errors.Is(err, sql.ErrNoRows) {
		return auditlog.Inserted{}, false, nil
	}
	if err != nil {
		return auditlog.Inserted{}, false, failure(err)
	}
	return auditlog.Inserted{Receipt: auditlog.Receipt{ID: row.ID, CreatedAt: row.CreatedAt}, Replayed: true, Hash: row.Hash}, true, nil
}

type eventRow struct {
	Seq          int64                   `db:"seq"`
	ID           identity.AuditEventID   `db:"id"`
	Environment  identity.EnvironmentID  `db:"environment_id"`
	Organization identity.OrganizationID `db:"organization_id"`
	Action       string                  `db:"action"`
	Version      int                     `db:"version"`
	OccurredAt   time.Time               `db:"occurred_at"`
	Actor        []byte                  `db:"actor"`
	Targets      []byte                  `db:"targets"`
	Context      []byte                  `db:"context"`
	Metadata     []byte                  `db:"metadata"`
	CreatedAt    time.Time               `db:"created_at"`
}

const eventColumns = `seq, id, environment_id, organization_id, action, version, occurred_at, actor, targets, context, metadata, created_at`

func (r eventRow) toDomain() auditlog.Event {
	e := auditlog.Event{Seq: r.Seq, ID: r.ID, Environment: r.Environment, Organization: r.Organization, Action: r.Action,
		Version: r.Version, OccurredAt: r.OccurredAt, Metadata: json.RawMessage(r.Metadata), CreatedAt: r.CreatedAt}
	_ = json.Unmarshal(r.Actor, &e.Actor)
	_ = json.Unmarshal(r.Targets, &e.Targets)
	_ = json.Unmarshal(r.Context, &e.Context)
	if e.Targets == nil {
		e.Targets = []auditlog.Party{}
	}
	return e
}

func (r *Events) Find(ctx context.Context, environment identity.EnvironmentID, id identity.AuditEventID) (auditlog.Event, error) {
	var row eventRow
	err := r.db.GetContext(ctx, &row, `SELECT `+eventColumns+` FROM audit_log_events WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return auditlog.Event{}, auditlog.ErrEventNotFound()
	}
	if err != nil {
		return auditlog.Event{}, failure(err)
	}
	return row.toDomain(), nil
}

// List pages by seq (keyset), never by offset: the log only grows.
func (r *Events) List(ctx context.Context, environment identity.EnvironmentID, f auditlog.Filter, limit int) ([]auditlog.Event, error) {
	where := []string{"environment_id=$1"}
	args := []any{environment}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if !f.Organization.IsZero() {
		where = append(where, "organization_id="+arg(f.Organization))
	}
	if len(f.Actions) > 0 {
		where = append(where, "action=ANY("+arg(pq.StringArray(f.Actions))+")")
	}
	if f.ActorID != "" {
		where = append(where, "(actor->>'id')="+arg(f.ActorID))
	}
	if f.ActorType != "" {
		where = append(where, "(actor->>'type')="+arg(f.ActorType))
	}
	if f.TargetID != "" || f.TargetType != "" {
		// One containment test through the GIN index: both given means the
		// same target has both.
		target := map[string]string{}
		if f.TargetID != "" {
			target["id"] = f.TargetID
		}
		if f.TargetType != "" {
			target["type"] = f.TargetType
		}
		raw, err := json.Marshal([]map[string]string{target})
		if err != nil {
			return nil, failure(err)
		}
		where = append(where, "targets @> "+arg(string(raw))+"::jsonb")
	}
	if f.OccurredAfter != nil {
		where = append(where, "occurred_at>="+arg(*f.OccurredAfter))
	}
	if f.OccurredBefore != nil {
		where = append(where, "occurred_at<="+arg(*f.OccurredBefore))
	}
	order := "DESC"
	switch {
	case f.After != nil:
		where = append(where, "seq>"+arg(*f.After))
		order = "ASC"
	case f.Before > 0:
		where = append(where, "seq<"+arg(f.Before))
	}
	rows := []eventRow{}
	q := fmt.Sprintf(`SELECT %s FROM audit_log_events WHERE %s ORDER BY seq %s LIMIT %d`, eventColumns, strings.Join(where, " AND "), order, limit)
	if err := r.db.SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, failure(err)
	}
	out := make([]auditlog.Event, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

// Prune deletes events past the cutoff in one transaction; the immutability
// trigger allows it only under the transaction-local iamkit.audit_log_prune.
func (r *Events) Prune(ctx context.Context, cutoff time.Time, batch int) (int, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT set_config('iamkit.audit_log_prune', 'on', true)`); err != nil {
		return 0, failure(err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM audit_log_events WHERE seq IN (SELECT seq FROM audit_log_events WHERE created_at<$1 ORDER BY seq LIMIT $2)`, cutoff, batch)
	if err != nil {
		return 0, failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, failure(err)
	}
	return int(n), failure(tx.Commit())
}
