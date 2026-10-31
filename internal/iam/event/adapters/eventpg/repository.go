package eventpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Repository reads and prunes the event log.
type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

type row struct {
	ID           int64                    `db:"id"`
	Environment  identity.EnvironmentID   `db:"environment_id"`
	Type         string                   `db:"type"`
	ActorKind    string                   `db:"actor_kind"`
	ActorID      string                   `db:"actor_id"`
	SubjectKind  string                   `db:"subject_kind"`
	SubjectID    string                   `db:"subject_id"`
	Organization *identity.OrganizationID `db:"organization_id"`
	Data         []byte                   `db:"data"`
	CreatedAt    time.Time                `db:"created_at"`
	// Class is events.retention_class; empty (rows read without it) falls
	// back to the catalog.
	Class string `db:"retention_class"`
}

func (r row) toDomain() event.Event {
	class := r.Class
	if class == "" {
		class = event.RetentionClassOf(r.Type)
	}
	return event.Event{RetentionClass: class, ID: r.ID, Environment: r.Environment, Type: r.Type,
		Actor:        event.Actor{Kind: r.ActorKind, ID: r.ActorID},
		Subject:      event.Subject{Kind: r.SubjectKind, ID: r.SubjectID},
		Organization: r.Organization, Data: json.RawMessage(r.Data), OccurredAt: r.CreatedAt}
}

// List pages by id (keyset), never by offset: the log only grows.
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, f event.Filter, limit int) ([]event.Event, error) {
	where := []string{"environment_id=$1"}
	args := []any{environment}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if len(f.Types) > 0 {
		var exact, families []string
		for _, t := range f.Types {
			if family, ok := strings.CutSuffix(t, ".*"); ok {
				families = append(families, family)
			} else {
				exact = append(exact, t)
			}
		}
		where = append(where, fmt.Sprintf("(type=ANY(%s) OR split_part(type,'.',1)=ANY(%s))", arg(pq.StringArray(exact)), arg(pq.StringArray(families))))
	}
	if f.Subject != "" {
		where = append(where, "subject_id="+arg(f.Subject))
	}
	if f.SubjectKind != "" {
		where = append(where, "subject_kind="+arg(f.SubjectKind))
	}
	if !f.Organization.IsZero() {
		where = append(where, "organization_id="+arg(f.Organization))
	}
	order := "DESC"
	switch {
	case f.After != nil:
		where = append(where, "id>"+arg(*f.After))
		order = "ASC"
	case f.Before > 0:
		where = append(where, "id<"+arg(f.Before))
	}
	rows := []row{}
	q := fmt.Sprintf(`SELECT id,environment_id,type,actor_kind,actor_id,subject_kind,subject_id,organization_id,data,created_at,retention_class FROM events WHERE %s ORDER BY id %s LIMIT %d`,
		strings.Join(where, " AND "), order, limit)
	if err := r.db.SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, failure(err)
	}
	out := make([]event.Event, len(rows))
	for i, row := range rows {
		out[i] = row.toDomain()
	}
	return out, nil
}

// Environments lists every environment with its stored overrides.
func (r *Repository) Environments(ctx context.Context) ([]event.EnvironmentPolicy, error) {
	var rows []struct {
		Environment identity.EnvironmentID `db:"id"`
		Security    sql.NullInt64          `db:"security_retention_seconds"`
		Default     sql.NullInt64          `db:"default_retention_seconds"`
	}
	if err := r.db.SelectContext(ctx, &rows, `SELECT e.id, p.security_retention_seconds, p.default_retention_seconds
		FROM environments e LEFT JOIN event_retention_policies p ON p.environment_id = e.id`); err != nil {
		return nil, failure(err)
	}
	out := make([]event.EnvironmentPolicy, len(rows))
	for i, x := range rows {
		out[i] = event.EnvironmentPolicy{Environment: x.Environment, Policy: event.RetentionPolicy{SecuritySeconds: nullable(x.Security), DefaultSeconds: nullable(x.Default)}}
	}
	return out, nil
}

func nullable(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}

// Prune is one autocommit statement of at most batch rows: it holds no
// lock an insert waits for (inserts take none on the rows it deletes).
// The index (environment_id, retention_class, created_at) bounds the scan
// to the expired range of one environment and class.
func (r *Repository) Prune(ctx context.Context, environment identity.EnvironmentID, class string, cutoff time.Time, batch int) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM events WHERE id IN (
		SELECT id FROM events WHERE environment_id=$1 AND retention_class=$2 AND created_at<$3 LIMIT $4)`, environment, class, cutoff, batch)
	if err != nil {
		return 0, failure(err)
	}
	n, err := res.RowsAffected()
	return int(n), failure(err)
}

// Retention stores the environments' retention overrides.
type Retention struct{ db *sqlx.DB }

func NewRetention(db *sqlx.DB) *Retention { return &Retention{db} }

func (r *Retention) Policy(ctx context.Context, environment identity.EnvironmentID) (event.RetentionPolicy, error) {
	var x struct {
		Security sql.NullInt64 `db:"security_retention_seconds"`
		Default  sql.NullInt64 `db:"default_retention_seconds"`
	}
	err := r.db.GetContext(ctx, &x, `SELECT security_retention_seconds, default_retention_seconds FROM event_retention_policies WHERE environment_id=$1`, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return event.RetentionPolicy{}, nil
	}
	if err != nil {
		return event.RetentionPolicy{}, failure(err)
	}
	return event.RetentionPolicy{SecuritySeconds: nullable(x.Security), DefaultSeconds: nullable(x.Default)}, nil
}

func (r *Retention) SavePolicy(ctx context.Context, m event.Mutation, p event.RetentionPolicy) error {
	return Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO event_retention_policies(environment_id,security_retention_seconds,default_retention_seconds) VALUES($1,$2,$3)
			ON CONFLICT (environment_id) DO UPDATE SET security_retention_seconds=EXCLUDED.security_retention_seconds,
			default_retention_seconds=EXCLUDED.default_retention_seconds, updated_at=now()`, m.Environment, p.SecuritySeconds, p.DefaultSeconds); err != nil {
			return failure(err)
		}
		return AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{
			"security_retention_seconds": p.SecuritySeconds, "default_retention_seconds": p.DefaultSeconds})
	})
}

var (
	_ event.Repository          = (*Repository)(nil)
	_ event.RetentionRepository = (*Retention)(nil)
)
