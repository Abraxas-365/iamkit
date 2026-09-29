// Package signingpg stores environment signing keys in PostgreSQL.
package signingpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ signing.Repository = (*Repository)(nil)

const columns = `id, environment_id, algorithm, state, created_at, activated_at, retire_after, retired_at, private_sealed, public_der`

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "signing key persistence failed", errx.TypeInternal)
}

func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("conflicting signing key")
	}
	return failure(err)
}

func audit(ctx context.Context, tx *sqlx.Tx, m signing.Mutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	return failure(err)
}

// change runs fn and the audit row in one transaction.
func (r *Repository) change(ctx context.Context, m signing.Mutation, fn func(tx *sqlx.Tx) error) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) Create(ctx context.Context, m signing.Mutation, key signing.Stored) error {
	return r.change(ctx, m, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO signing_keys(id, environment_id, algorithm, private_sealed, public_der, state) VALUES($1,$2,$3,$4,$5,$6)`,
			key.ID, m.Environment, key.Algorithm, key.Sealed, key.Public, key.State)
		return conflict(err)
	})
}

func (r *Repository) Activate(ctx context.Context, m signing.Mutation, key string, retireAfter time.Time) error {
	return r.change(ctx, m, func(tx *sqlx.Tx) error {
		// Serialize rotations of the environment.
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM environments WHERE id=$1 FOR UPDATE`, m.Environment); err != nil {
			return failure(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE signing_keys SET state='retiring', retire_after=$3 WHERE environment_id=$1 AND state='active' AND id<>$2`, m.Environment, key, retireAfter); err != nil {
			return failure(err)
		}
		res, err := tx.ExecContext(ctx, `UPDATE signing_keys SET state='active', activated_at=now(), retire_after=NULL WHERE environment_id=$1 AND id=$2 AND state IN ('next','retiring')`, m.Environment, key)
		if err != nil {
			return conflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errx.Conflict("the signing key cannot be activated")
		}
		return nil
	})
}

func (r *Repository) Retire(ctx context.Context, m signing.Mutation, key string) error {
	return r.change(ctx, m, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE signing_keys SET state='retired', retired_at=now() WHERE environment_id=$1 AND id=$2 AND state IN ('next','retiring')`, m.Environment, key)
		if err != nil {
			return failure(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errx.Conflict("the signing key cannot be retired")
		}
		return nil
	})
}

func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[signing.Stored], error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM signing_keys WHERE environment_id=$1`, environment); err != nil {
		return query.Paginated[signing.Stored]{}, failure(err)
	}
	rows := []signing.Stored{}
	err := r.db.SelectContext(ctx, &rows, `SELECT `+columns+` FROM signing_keys WHERE environment_id=$1
		ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'next' THEN 1 WHEN 'retiring' THEN 2 ELSE 3 END, created_at DESC LIMIT $2 OFFSET $3`,
		environment, page.Limit, page.Offset)
	if err != nil {
		return query.Paginated[signing.Stored]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}

func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, key string) (signing.Stored, error) {
	var row signing.Stored
	err := r.db.GetContext(ctx, &row, `SELECT `+columns+` FROM signing_keys WHERE environment_id=$1 AND id=$2`, environment, key)
	if errors.Is(err, sql.ErrNoRows) {
		return row, errx.NotFound("signing key not found")
	}
	return row, failure(err)
}

func (r *Repository) Published(ctx context.Context) ([]signing.Stored, error) {
	rows := []signing.Stored{}
	err := r.db.SelectContext(ctx, &rows, `SELECT `+columns+` FROM signing_keys WHERE state<>'retired' ORDER BY created_at`)
	return rows, failure(err)
}
