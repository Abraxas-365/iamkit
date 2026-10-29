package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// Dynamic client registrations (RFC 7591): oauth_registrations rows, global
// and inert until an authorization request materializes one as an
// oauth_clients row (insertExternal, source 'dcr').

var _ oauth.RegistrationRepository = (*Repository)(nil)

type registrationRow struct {
	ClientID        string         `db:"client_id"`
	Name            string         `db:"client_name"`
	ClientURI       string         `db:"client_uri"`
	Redirects       pq.StringArray `db:"redirect_uris"`
	Grants          pq.StringArray `db:"grant_types"`
	SoftwareID      string         `db:"software_id"`
	SoftwareVersion string         `db:"software_version"`
	CreatedAt       time.Time      `db:"created_at"`
}

func (r registrationRow) domain() oauth.Registered {
	return oauth.Registered{ClientID: r.ClientID, Name: r.Name, ClientURI: r.ClientURI, Redirects: []string(r.Redirects), GrantTypes: []string(r.Grants), SoftwareID: r.SoftwareID, SoftwareVersion: r.SoftwareVersion, CreatedAt: r.CreatedAt}
}

const registrationColumns = `client_id,client_name,client_uri,redirect_uris,grant_types,software_id,software_version,created_at`

func (r *Repository) Registration(ctx context.Context, clientID string) (oauth.Registered, bool, error) {
	var row registrationRow
	err := r.db.GetContext(ctx, &row, `SELECT `+registrationColumns+` FROM oauth_registrations WHERE client_id=$1`, clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.Registered{}, false, nil
	}
	if err != nil {
		return oauth.Registered{}, false, failure(err)
	}
	return row.domain(), true, nil
}

func (r *Repository) SaveRegistration(ctx context.Context, reg oauth.Registered, maxUnused int) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		// The cap is counted under a lock of its own, so concurrent
		// registrations cannot overshoot it.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('oauth-registrations-unused',0))`); err != nil {
			return failure(err)
		}
		var unused int
		if err := tx.GetContext(ctx, &unused, `SELECT count(*) FROM oauth_registrations WHERE last_used_at IS NULL`); err != nil {
			return failure(err)
		}
		if unused >= maxUnused {
			return oauth.ErrRegistrationsFull()
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO oauth_registrations(client_id,client_name,client_uri,redirect_uris,grant_types,software_id,software_version,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			reg.ClientID, reg.Name, reg.ClientURI, pq.StringArray(reg.Redirects), pq.StringArray(reg.GrantTypes), reg.SoftwareID, reg.SoftwareVersion, reg.CreatedAt)
		return failure(err)
	})
}

// markRegistrationUsed records, in the transaction that writes a client row
// from it, that a registration is in use: it no longer counts against the
// cap of unused ones and is pruned only once no row holds it. The row lock
// also orders it against a concurrent prune: a prune that waited re-reads
// last_used_at and keeps the row; a registration already pruned refuses
// the client.
func markRegistrationUsed(ctx context.Context, tx *sqlx.Tx, clientID string) error {
	res, err := tx.ExecContext(ctx, `UPDATE oauth_registrations SET last_used_at=now() WHERE client_id=$1`, clientID)
	if err != nil {
		return failure(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.Validation("unknown client_id")
	}
	return nil
}

func (r *Repository) PruneRegistrations(ctx context.Context, unusedBefore, idleBefore time.Time, limit int) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM oauth_registrations WHERE client_id IN (
		SELECT g.client_id FROM oauth_registrations g
		WHERE (g.last_used_at IS NULL AND g.created_at < $1)
		   OR (g.last_used_at IS NOT NULL AND g.last_used_at < $2 AND NOT EXISTS (SELECT 1 FROM oauth_clients c WHERE c.source='dcr' AND c.external_id=g.client_id))
		ORDER BY COALESCE(g.last_used_at, g.created_at) LIMIT $3 FOR UPDATE OF g SKIP LOCKED)
		AND ((last_used_at IS NULL AND created_at < $1) OR (last_used_at IS NOT NULL AND last_used_at < $2))`, unusedBefore, idleBefore, limit)
	if err != nil {
		return 0, failure(err)
	}
	n, err := res.RowsAffected()
	return int(n), failure(err)
}

func (r *Repository) DynamicRegistrationEnvironments(ctx context.Context) ([]identity.EnvironmentID, error) {
	var out []identity.EnvironmentID
	err := r.db.SelectContext(ctx, &out, `SELECT DISTINCT pr.environment_id FROM protected_resources pr JOIN applications a ON a.id=pr.application_id AND a.environment_id=pr.environment_id WHERE pr.allow_dynamic_registration AND pr.active AND a.active`)
	return out, failure(err)
}
