package orgadminpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// SetupLinks persists organization setup links (org_setup_links) and the
// bearers exchanged from them (org_setup_sessions).
type SetupLinks struct{ db *sqlx.DB }

var _ orgadmin.SetupLinkRepository = (*SetupLinks)(nil)

func NewSetupLinks(db *sqlx.DB) *SetupLinks { return &SetupLinks{db: db} }

func unauthorized() error { return errx.Unauthorized("invalid or expired setup link") }

func (r *SetupLinks) Create(ctx context.Context, m orgadmin.SetupMutation, link orgadmin.SetupLink, hash []byte) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		// Serialize creations per organization so the live-link cap holds.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('org_setup_links:' || $1::text))`, m.Organization); err != nil {
			return failure(err)
		}
		var live int
		if err := tx.GetContext(ctx, &live, `SELECT count(*) FROM org_setup_links WHERE environment_id=$1 AND organization_id=$2 AND revoked_at IS NULL AND expires_at > now()`, m.Environment, m.Organization); err != nil {
			return failure(err)
		}
		if live >= config.SetupLinkMaxPerOrg {
			return errx.Business("the organization has too many live setup links: revoke some first")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO org_setup_links(id,environment_id,organization_id,intents,secret_hash,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			link.ID, m.Environment, m.Organization, pq.Array(link.Intents), hash, link.ExpiresAt, link.CreatedBy)
		if err != nil {
			var pgErr *pq.Error
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				return errx.NotFound("organization not found")
			}
			return failure(err)
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target+"/"+link.ID.String())
	})
}

type linkRow struct {
	orgadmin.SetupLink
	Intents pq.StringArray `db:"intents"`
}

func (r *SetupLinks) List(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[orgadmin.SetupLink], error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM org_setup_links WHERE environment_id=$1 AND organization_id=$2`, environment, organization); err != nil {
		return query.Paginated[orgadmin.SetupLink]{}, failure(err)
	}
	var rows []linkRow
	if err := r.db.SelectContext(ctx, &rows, `SELECT id,intents,expires_at,revoked_at,created_by,created_at,last_used_at FROM org_setup_links
		WHERE environment_id=$1 AND organization_id=$2 ORDER BY created_at DESC, id LIMIT $3 OFFSET $4`, environment, organization, page.Limit, page.Offset); err != nil {
		return query.Paginated[orgadmin.SetupLink]{}, failure(err)
	}
	items := make([]orgadmin.SetupLink, 0, len(rows))
	for _, row := range rows {
		row.SetupLink.Intents = []string(row.Intents)
		items = append(items, row.SetupLink)
	}
	return query.NewPaginated(items, total, page), nil
}

func (r *SetupLinks) Revoke(ctx context.Context, m orgadmin.SetupMutation, link identity.SetupLinkID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE org_setup_links SET revoked_at=now() WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND revoked_at IS NULL`, link, m.Environment, m.Organization)
		if err != nil {
			return failure(err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return failure(err)
		} else if n == 0 {
			return errx.NotFound("setup link not found")
		}
		// Bearers die with the link even before validation joins it.
		if _, err = tx.ExecContext(ctx, `DELETE FROM org_setup_sessions WHERE link_id=$1 AND environment_id=$2`, link, m.Environment); err != nil {
			return failure(err)
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

func (r *SetupLinks) Exchange(ctx context.Context, hash, bearer []byte, ttl time.Duration) (orgadmin.SetupExchanged, error) {
	var out orgadmin.SetupExchanged
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var row struct {
			ID           identity.SetupLinkID    `db:"id"`
			Environment  identity.EnvironmentID  `db:"environment_id"`
			Organization identity.OrganizationID `db:"organization_id"`
			Intents      pq.StringArray          `db:"intents"`
			Name         string                  `db:"name"`
			Expires      time.Time               `db:"expires_at"`
		}
		err := tx.GetContext(ctx, &row, `UPDATE org_setup_links l SET last_used_at=now()
			FROM organizations o
			WHERE l.secret_hash=$1 AND l.revoked_at IS NULL AND l.expires_at > now()
			  AND o.id=l.organization_id AND o.environment_id=l.environment_id AND o.active
			RETURNING l.id,l.environment_id,l.organization_id,l.intents,o.name,l.expires_at`, hash)
		if errors.Is(err, sql.ErrNoRows) {
			return unauthorized()
		}
		if err != nil {
			return failure(err)
		}
		expires := time.Now().Add(ttl)
		if row.Expires.Before(expires) {
			expires = row.Expires
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO org_setup_sessions(token_hash,link_id,environment_id,expires_at) VALUES($1,$2,$3,$4)`, bearer, row.ID, row.Environment, expires); err != nil {
			return failure(err)
		}
		// Housekeeping: expired bearers are useless rows.
		if _, err = tx.ExecContext(ctx, `DELETE FROM org_setup_sessions WHERE link_id=$1 AND expires_at < now()`, row.ID); err != nil {
			return failure(err)
		}
		target := "/organizations/" + row.Organization.String() + "/setup-links/" + row.ID.String()
		if err = eventpg.Audit(ctx, tx, row.Environment, row.ID.String(), "org_setup_link.used", target); err != nil {
			return err
		}
		out = orgadmin.SetupExchanged{
			Grant:            orgadmin.SetupGrant{Link: row.ID, Environment: row.Environment, Organization: row.Organization, Intents: []string(row.Intents)},
			OrganizationName: row.Name,
			ExpiresAt:        expires,
		}
		return nil
	})
	return out, err
}

func (r *SetupLinks) Session(ctx context.Context, bearer []byte) (orgadmin.SetupGrant, error) {
	var row struct {
		ID           identity.SetupLinkID    `db:"id"`
		Environment  identity.EnvironmentID  `db:"environment_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Intents      pq.StringArray          `db:"intents"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT l.id,l.environment_id,l.organization_id,l.intents
		FROM org_setup_sessions s JOIN org_setup_links l ON l.id=s.link_id AND l.environment_id=s.environment_id
		JOIN organizations o ON o.id=l.organization_id AND o.environment_id=l.environment_id AND o.active
		WHERE s.token_hash=$1 AND s.expires_at > now() AND l.revoked_at IS NULL AND l.expires_at > now()`, bearer)
	if errors.Is(err, sql.ErrNoRows) {
		return orgadmin.SetupGrant{}, unauthorized()
	}
	if err != nil {
		return orgadmin.SetupGrant{}, failure(err)
	}
	return orgadmin.SetupGrant{Link: row.ID, Environment: row.Environment, Organization: row.Organization, Intents: []string(row.Intents)}, nil
}
