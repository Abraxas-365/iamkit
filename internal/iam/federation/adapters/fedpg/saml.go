package fedpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ParkAssertion keeps a posted SAML response for a pending state of a SAML
// connection. Unknown, consumed and expired states are refused, and a state
// keeps at most one response (a second post replaces the first).
func (r *Repository) ParkAssertion(ctx context.Context, state, handle []byte, response string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var expires time.Time
	err = tx.GetContext(ctx, &expires, `SELECT s.expires_at FROM federation_states s
		JOIN federation_connections c ON c.id=s.connection_id AND c.environment_id=s.environment_id AND c.active AND c.provider='saml'
		WHERE s.secret_hash=$1 AND s.consumed_at IS NULL AND s.expires_at>now() FOR UPDATE OF s`, state)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.Unauthorized("invalid or expired SAML RelayState")
	}
	if err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM saml_responses WHERE state_hash=$1 OR expires_at<now()`, state); err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO saml_responses(handle_hash,state_hash,response,expires_at) VALUES($1,$2,$3,$4)`, handle, state, response, expires); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

// TakeAssertion deletes and returns the response parked for the state
// under the handle.
func (r *Repository) TakeAssertion(ctx context.Context, state, handle []byte) (string, error) {
	var response string
	err := r.db.GetContext(ctx, &response, `DELETE FROM saml_responses WHERE handle_hash=$1 AND state_hash=$2 AND expires_at>now() RETURNING response`, handle, state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errx.Unauthorized("invalid or expired SAML response handle")
	}
	return response, failure(err)
}

// UseAssertion records an accepted assertion ID; the primary key refuses a
// replay. Expired IDs are pruned on the way.
func (r *Repository) UseAssertion(ctx context.Context, connection identity.ConnectionID, assertion string, expires time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM saml_assertions WHERE expires_at<now()`); err != nil {
		return failure(err)
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO saml_assertions(connection_id,assertion_id,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, connection, assertion, expires)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err)
		}
		return errx.Unauthorized("SAML assertion was already used")
	}
	return nil
}
