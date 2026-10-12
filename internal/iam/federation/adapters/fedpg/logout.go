package fedpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

var _ federation.LogoutRepository = (*Repository)(nil)

// LinkedSession reads the SAML link stored with a session
// (federation_sessions), ended or not.
func (r *Repository) LinkedSession(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID) (federation.LinkedSession, error) {
	var row struct {
		Connection   identity.ConnectionID `db:"connection_id"`
		NameID       string                `db:"name_id"`
		NameIDFormat string                `db:"name_id_format"`
		SessionIndex string                `db:"session_index"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT connection_id,name_id,name_id_format,session_index FROM federation_sessions WHERE session_id=$1 AND environment_id=$2`, session, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.LinkedSession{}, errx.NotFound("resource not found")
	}
	if err != nil {
		return federation.LinkedSession{}, failure(err)
	}
	return federation.LinkedSession{Session: session, Environment: environment, Link: authentication.FederationLink{Connection: row.Connection, NameID: row.NameID, NameIDFormat: row.NameIDFormat, SessionIndex: row.SessionIndex}}, nil
}

// EndLinkedSessions spends the LogoutRequest's ID, ends the live sessions
// of the connection linked to its NameID (narrowed to its SessionIndexes
// when it names any) and records connection.single_logout, in one
// transaction: a replay or a failure leaves nothing ended.
func (r *Repository) EndLinkedSessions(ctx context.Context, c federation.Connection, request federation.LogoutRequest, expires time.Time) (int, error) {
	var count int
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM saml_assertions WHERE expires_at<now()`); err != nil {
			return failure(err)
		}
		// The ID shares saml_assertions with assertion IDs; the prefix keeps
		// the two apart.
		res, err := tx.ExecContext(ctx, `INSERT INTO saml_assertions(connection_id,assertion_id,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.ID, "logout:"+request.ID, expires)
		if err != nil {
			return failure(err)
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return failure(err)
			}
			return errx.Unauthorized("SAML logout request was already used")
		}
		indexes := request.SessionIndexes
		if indexes == nil {
			indexes = []string{}
		}
		res, err = tx.ExecContext(ctx, `UPDATE sessions s SET revoked_at=now()
			FROM federation_sessions f
			WHERE f.session_id=s.id AND f.environment_id=$1 AND f.connection_id=$2 AND f.name_id=$3
			  AND (cardinality($4::text[])=0 OR f.session_index=ANY($4::text[]))
			  AND s.revoked_at IS NULL AND s.expires_at>now()`, c.Environment, c.ID, request.NameID, pq.StringArray(indexes))
		if err != nil {
			return failure(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return failure(err)
		}
		count = int(n)
		return eventpg.Emit(ctx, tx, c.Environment, "", event.ConnectionSingleLogout, event.Subject{Kind: "connection", ID: c.ID.String()},
			map[string]any{"connection_id": c.ID.String(), "organization_id": c.Organization.String(), "count": count})
	})
	return count, err
}

// SaveLogout parks an SP-initiated logout until the identity provider's
// LogoutResponse; expired ones are swept on the way.
func (r *Repository) SaveLogout(ctx context.Context, p federation.PendingLogout) error {
	_, err := r.db.ExecContext(ctx, `WITH sweep AS (DELETE FROM saml_logouts WHERE expires_at<now())
		INSERT INTO saml_logouts(request_id,environment_id,connection_id,redirect,expires_at) VALUES($1,$2,$3,$4,$5)`,
		p.RequestID, p.Environment, p.Connection, p.Redirect, p.Expires)
	return failure(err)
}

// TakeLogout spends the pending logout of a request ID on the connection.
func (r *Repository) TakeLogout(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, requestID string) (federation.PendingLogout, error) {
	p := federation.PendingLogout{RequestID: requestID, Environment: environment, Connection: connection}
	var row struct {
		Redirect string    `db:"redirect"`
		Expires  time.Time `db:"expires_at"`
	}
	err := r.db.GetContext(ctx, &row, `DELETE FROM saml_logouts WHERE request_id=$1 AND environment_id=$2 AND connection_id=$3 AND expires_at>now() RETURNING redirect,expires_at`, requestID, environment, connection)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.PendingLogout{}, errx.NotFound("resource not found")
	}
	if err != nil {
		return federation.PendingLogout{}, failure(err)
	}
	p.Redirect, p.Expires = row.Redirect, row.Expires
	return p, nil
}

// PruneLogouts deletes expired pending logouts.
func (r *Repository) PruneLogouts(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM saml_logouts WHERE expires_at<now()`)
	return failure(err)
}
