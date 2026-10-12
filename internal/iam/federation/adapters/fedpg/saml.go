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
	"github.com/lib/pq"
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
		JOIN federation_connections c ON c.id=s.connection_id AND c.environment_id=s.environment_id AND (c.active OR s.test) AND c.provider='saml'
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

// LoginClient finds an active OAuth client of the active application that
// takes third-party initiated logins and that the organization can use: its
// resource needs no grant (resources.require_grant), is owned by the
// organization, or was granted to it (the rule effective_grants applies).
func (r *Repository) LoginClient(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, client identity.ClientID) (federation.LoginClient, error) {
	var row struct {
		ID        identity.ClientID `db:"id"`
		URI       string            `db:"initiate_login_uri"`
		Redirects pq.StringArray    `db:"redirect_uris"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT oc.id, oc.initiate_login_uri, oc.redirect_uris
		FROM oauth_clients oc
		JOIN applications a ON a.id=oc.application_id AND a.environment_id=oc.environment_id
		JOIN resources res ON res.id=oc.resource_id AND res.environment_id=oc.environment_id
		WHERE oc.environment_id=$1 AND oc.id=$3 AND oc.active AND a.active AND oc.initiate_login_uri<>''
		  AND (NOT res.require_grant OR res.owner_organization_id=$2
		       OR EXISTS(SELECT 1 FROM resource_grants rg WHERE rg.resource_id=res.id AND rg.organization_id=$2))`, environment, organization, client)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.LoginClient{}, errx.NotFound("OAuth client not found")
	}
	if err != nil {
		return federation.LoginClient{}, failure(err)
	}
	return federation.LoginClient{ID: row.ID, InitiateLoginURI: row.URI, Redirects: []string(row.Redirects)}, nil
}

// AcceptInitiated spends the assertion of an IdP-initiated response and
// records the connection.idp_initiated event (actor: the system) in the same
// transaction, so a refused replay leaves no event.
func (r *Repository) AcceptInitiated(ctx context.Context, c federation.Connection, client identity.ClientID, assertion string, expires time.Time) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM saml_assertions WHERE expires_at<now()`); err != nil {
			return failure(err)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO saml_assertions(connection_id,assertion_id,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, c.ID, assertion, expires)
		if err != nil {
			return failure(err)
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			if err != nil {
				return failure(err)
			}
			return errx.Unauthorized("SAML assertion was already used")
		}
		return eventpg.Emit(ctx, tx, c.Environment, "", event.ConnectionIdPInitiated, event.Subject{Kind: "connection", ID: c.ID.String()},
			map[string]any{"connection_id": c.ID.String(), "organization_id": c.Organization.String(), "client_id": client.String()})
	})
}
