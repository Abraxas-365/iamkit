package eventpg

import (
	"context"
	"encoding/json"
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
}

func (r row) toDomain() event.Event {
	return event.Event{ID: r.ID, Environment: r.Environment, Type: r.Type,
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
	q := fmt.Sprintf(`SELECT id,environment_id,type,actor_kind,actor_id,subject_kind,subject_id,organization_id,data,created_at FROM events WHERE %s ORDER BY id %s LIMIT %d`,
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

func (r *Repository) Prune(ctx context.Context, cutoff time.Time, batch int) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM events WHERE id IN (SELECT id FROM events WHERE created_at<$1 ORDER BY id LIMIT $2)`, cutoff, batch)
	if err != nil {
		return 0, failure(err)
	}
	n, err := res.RowsAffected()
	return int(n), failure(err)
}

var _ event.Repository = (*Repository)(nil)
