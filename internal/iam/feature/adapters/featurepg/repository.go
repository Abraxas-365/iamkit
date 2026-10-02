// Package featurepg stores environment feature overrides in PostgreSQL.
package featurepg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ feature.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "feature persistence failed", errx.TypeInternal)
}

type row struct {
	Name      string    `db:"name"`
	Enabled   bool      `db:"enabled"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (r row) override() feature.Override {
	return feature.Override{Name: r.Name, Enabled: r.Enabled, UpdatedAt: r.UpdatedAt}
}

func (r *Repository) Overrides(ctx context.Context, environment identity.EnvironmentID) ([]feature.Override, error) {
	var rows []row
	if err := r.db.SelectContext(ctx, &rows, `SELECT name, enabled, updated_at FROM environment_features WHERE environment_id=$1 ORDER BY name`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]feature.Override, len(rows))
	for i, x := range rows {
		out[i] = x.override()
	}
	return out, nil
}

func (r *Repository) Override(ctx context.Context, environment identity.EnvironmentID, name string) (*feature.Override, error) {
	var x row
	err := r.db.GetContext(ctx, &x, `SELECT name, enabled, updated_at FROM environment_features WHERE environment_id=$1 AND name=$2`, environment, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, failure(err)
	}
	out := x.override()
	return &out, nil
}

func (r *Repository) Save(ctx context.Context, m feature.Mutation, name string, enabled bool) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO environment_features(environment_id, name, enabled) VALUES($1,$2,$3)
			ON CONFLICT (environment_id, name) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=now()`, m.Environment, name, enabled); err != nil {
			return failure(err)
		}
		return failure(eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"enabled": enabled}))
	})
}

func (r *Repository) Delete(ctx context.Context, m feature.Mutation, name string) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM environment_features WHERE environment_id=$1 AND name=$2`, m.Environment, name)
		if err != nil {
			return failure(err)
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return failure(err)
		}
		return failure(eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target))
	})
}
