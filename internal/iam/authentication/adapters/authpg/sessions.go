package authpg

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// currentRoot is the root session the token stands for: its own session,
// or the parent of a token-exchange child ($1 environment, $2 session).
const currentRoot = `COALESCE((SELECT parent_session_id FROM sessions WHERE environment_id=$1 AND id=$2), $2::uuid)`

// liveRoot matches the user's root sessions that can still be used ($1
// environment, $3 user).
const liveRoot = `s.environment_id=$1 AND s.user_id=$3 AND s.parent_session_id IS NULL AND s.revoked_at IS NULL AND s.expires_at>now()`

// liveRootCount is liveRoot for the count query, which has no session
// argument (the user is $2).
const liveRootCount = `s.environment_id=$1 AND s.user_id=$2 AND s.parent_session_id IS NULL AND s.revoked_at IS NULL AND s.expires_at>now()`

type sessionRow struct {
	ID              identity.SessionID      `db:"id"`
	Current         bool                    `db:"current"`
	Organization    identity.OrganizationID `db:"organization_id"`
	OrganizationRef string                  `db:"organization_name"`
	Application     identity.ApplicationID  `db:"application_id"`
	ApplicationRef  string                  `db:"application_name"`
	Client          *identity.ClientID      `db:"oauth_client_id"`
	Created         time.Time               `db:"created_at"`
	Authenticated   time.Time               `db:"authenticated_at"`
	Expires         time.Time               `db:"expires_at"`
	AMR             pq.StringArray          `db:"amr"`
	IP              *string                 `db:"ip"`
	UserAgent       *string                 `db:"user_agent"`
	Impersonated    bool                    `db:"impersonated"`
}

func (r *Repository) ListSessions(ctx context.Context, t authentication.Token, page query.Pagination) (query.Paginated[authentication.UserSession], error) {
	empty := query.Paginated[authentication.UserSession]{}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM sessions s WHERE `+liveRootCount, t.EnvironmentID, t.Subject); err != nil {
		return empty, failure(err)
	}
	var rows []sessionRow
	err := r.db.SelectContext(ctx, &rows, `SELECT s.id, s.id=`+currentRoot+` AS current, s.organization_id, o.name AS organization_name,
		s.application_id, a.name AS application_name, s.oauth_client_id, s.created_at, s.authenticated_at, s.expires_at, s.amr,
		host(s.ip_address) AS ip, s.user_agent, (s.actor_id IS NOT NULL OR s.actor_account_id IS NOT NULL) AS impersonated
		FROM sessions s
		JOIN organizations o ON o.id=s.organization_id AND o.environment_id=s.environment_id
		JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id
		WHERE `+liveRoot+` ORDER BY s.created_at DESC, s.id DESC LIMIT $4 OFFSET $5`, t.EnvironmentID, t.SessionID, t.Subject, page.Limit, page.Offset)
	if err != nil {
		return empty, failure(err)
	}
	out := make([]authentication.UserSession, 0, len(rows))
	for _, row := range rows {
		out = append(out, authentication.UserSession{
			ID: row.ID, Current: row.Current,
			Organization:    authentication.SessionOrganization{ID: row.Organization, Name: row.OrganizationRef},
			Application:     authentication.SessionApplication{ID: row.Application, Name: row.ApplicationRef},
			OAuthClient:     row.Client,
			CreatedAt:       row.Created,
			AuthenticatedAt: row.Authenticated,
			ExpiresAt:       row.Expires,
			AMR:             []string(row.AMR),
			IPAddress:       row.IP,
			UserAgent:       row.UserAgent,
			Impersonated:    row.Impersonated,
		})
	}
	return query.NewPaginated(out, total, page), nil
}

// revokeAs runs fn in a transaction whose session.revoked events name the
// user as actor (session_event reads iamkit.session_actor).
func (r *Repository) revokeAs(ctx context.Context, t authentication.Token, fn func(tx *sqlx.Tx) error) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('iamkit.session_actor', $1, true)`, t.Subject.String()); err != nil {
			return failure(err)
		}
		return fn(tx)
	})
}

func (r *Repository) RevokeUserSession(ctx context.Context, t authentication.Token, session identity.SessionID) error {
	return r.revokeAs(ctx, t, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sessions s SET revoked_at=now() WHERE s.id=$2 AND `+liveRoot, t.EnvironmentID, session, t.Subject)
		if err != nil {
			return failure(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return failure(err)
		}
		if n == 0 {
			return errx.NotFound("resource not found")
		}
		return failure(eventpg.Audit(ctx, tx, t.EnvironmentID, t.Subject.String(), "session.revoke_own", session.String()))
	})
}

func (r *Repository) RevokeOtherUserSessions(ctx context.Context, t authentication.Token) (int, error) {
	var count int
	err := r.revokeAs(ctx, t, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE sessions s SET revoked_at=now() WHERE s.id<>`+currentRoot+` AND `+liveRoot, t.EnvironmentID, t.SessionID, t.Subject)
		if err != nil {
			return failure(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return failure(err)
		}
		count = int(n)
		if count == 0 {
			return nil // nothing ended: no audit row, no event
		}
		return failure(eventpg.AuditWith(ctx, tx, t.EnvironmentID, t.Subject.String(), "session.revoke_others", t.Subject.String(), map[string]any{"count": count}))
	})
	return count, err
}
