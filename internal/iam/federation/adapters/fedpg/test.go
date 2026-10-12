package fedpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// SaveTest stores the hash of a test ticket (federation_tests) and records
// the audit row of its issue in the same transaction. Expired tickets of
// the connection are dropped on the way.
func (r *Repository) SaveTest(ctx context.Context, m federation.Mutation, hash []byte, connection identity.ConnectionID, expires time.Time) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM federation_tests WHERE connection_id=$1 AND environment_id=$2 AND expires_at<now()`, connection, m.Environment); err != nil {
			return failure(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO federation_tests(ticket_hash,connection_id,environment_id,actor,expires_at) VALUES($1,$2,$3,$4,$5)`, hash, connection, m.Environment, m.Actor, expires); err != nil {
			return conflict(err)
		}
		return audit(ctx, tx, m)
	})
}

// UseTest spends a ticket in one statement: it must exist for this
// environment and connection, be unspent and unexpired.
func (r *Repository) UseTest(ctx context.Context, hash []byte, environment identity.EnvironmentID, connection identity.ConnectionID) (string, error) {
	var actor string
	err := r.db.GetContext(ctx, &actor, `UPDATE federation_tests SET consumed_at=now() WHERE ticket_hash=$1 AND environment_id=$2 AND connection_id=$3 AND consumed_at IS NULL AND expires_at>now() RETURNING actor`, hash, environment, connection)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errx.Unauthorized("invalid or expired test connection link")
	}
	return actor, failure(err)
}

// RecordTest emits connection.tested; the result's claims never reach it:
// only the outcome and the connection.
func (r *Repository) RecordTest(ctx context.Context, t federation.TestResult, actor string) error {
	data := map[string]any{"connection_id": t.Connection.String(), "success": t.Success}
	if !t.Organization.IsZero() {
		data["organization_id"] = t.Organization.String()
	}
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		return eventpg.Emit(ctx, tx, t.Environment, actor, event.ConnectionTested, event.Subject{Kind: "connection", ID: t.Connection.String()}, data)
	})
}

// PruneDrafts deletes the SAML drafts created before now-age (their pending
// test states and tickets go with them; the replay rows of their test
// sign-ins first, as saml_assertions does not cascade) and long spent or
// expired tickets.
func (r *Repository) PruneDrafts(ctx context.Context, age time.Duration) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM federation_tests WHERE expires_at<now() - interval '1 day'`); err != nil {
		return failure(err)
	}
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		const stale = `SELECT id FROM federation_connections WHERE draft AND NOT active AND created_at < now() - make_interval(secs => $1)`
		if _, err := tx.ExecContext(ctx, `DELETE FROM saml_assertions WHERE connection_id IN (`+stale+`)`, age.Seconds()); err != nil {
			return failure(err)
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM federation_connections WHERE id IN (`+stale+`)`, age.Seconds())
		return failure(err)
	})
}
