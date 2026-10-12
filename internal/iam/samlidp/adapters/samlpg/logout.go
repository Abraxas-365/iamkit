package samlpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

var _ samlidp.LogoutRepository = (*Repository)(nil)

// logoutLease is how long a claimed notification stays out of other
// dispatchers' reach (longer than one send).
const logoutLease = 2 * time.Minute

// RememberSession records that the provider received an assertion for the
// session (idempotent).
func (r *Repository) RememberSession(ctx context.Context, s samlidp.IdPSession) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO saml_idp_sessions(session_id,service_provider_id,environment_id,name_id) VALUES($1,$2,$3,$4) ON CONFLICT (session_id, service_provider_id) DO NOTHING`,
		s.Session, s.ServiceProvider, s.Environment, s.NameID)
	return failure(err)
}

// EndSession revokes the session when it was asserted to the provider for
// nameID. The transaction names the provider as origin (the
// queue_saml_logout_notification trigger skips it; every other
// application that received an assertion for the session is told), the
// user as actor and saml_logout as the reason of session.revoked.
func (r *Repository) EndSession(ctx context.Context, m samlidp.Mutation, provider identity.ServiceProviderID, session identity.SessionID, nameID string) (bool, error) {
	ended := false
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var user identity.UserID
		err := tx.GetContext(ctx, &user, `SELECT s.user_id FROM sessions s JOIN saml_idp_sessions l ON l.session_id = s.id
			WHERE s.id=$1 AND s.environment_id=$2 AND l.service_provider_id=$3 AND l.environment_id=$2 AND l.name_id=$4
			AND s.revoked_at IS NULL AND s.expires_at > now() FOR UPDATE OF s`, session, m.Environment, provider, nameID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return failure(err)
		}
		for _, setting := range [][2]string{{"iamkit.saml_logout_origin", provider.String()}, {"iamkit.session_reason", "saml_logout"}, {"iamkit.session_actor", user.String()}} {
			if _, err := tx.ExecContext(ctx, `SELECT set_config($1, $2, true)`, setting[0], setting[1]); err != nil {
				return failure(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = now() WHERE id=$1 AND environment_id=$2 AND revoked_at IS NULL`, session, m.Environment); err != nil {
			return failure(err)
		}
		ended = true
		return audit2(ctx, tx, m, user, session)
	})
	return ended, err
}

func audit2(ctx context.Context, tx *sqlx.Tx, m samlidp.Mutation, user identity.UserID, session identity.SessionID) error {
	return failure(eventpg.AuditWith(ctx, tx, m.Environment, user.String(), m.Action, m.Target, map[string]any{"session_id": session.String(), "user_id": user.String()}))
}

type notificationRow struct {
	row
	Notification int64              `db:"notification_id"`
	Session      identity.SessionID `db:"notification_session_id"`
	NameID       string             `db:"notification_name_id"`
	Attempts     int                `db:"notification_attempts"`
}

// ClaimLogouts leases due notifications with their provider: SKIP LOCKED
// keeps concurrent dispatchers on disjoint rows.
func (r *Repository) ClaimLogouts(ctx context.Context, limit int) ([]samlidp.LogoutNotification, error) {
	rows := []notificationRow{}
	err := r.db.SelectContext(ctx, &rows, `WITH due AS (
		SELECT id FROM saml_logout_notifications
		WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED),
	claimed AS (
		UPDATE saml_logout_notifications n SET attempts = n.attempts + 1, next_attempt_at = now() + make_interval(secs => $2)
		FROM due WHERE n.id = due.id
		RETURNING n.id, n.service_provider_id, n.environment_id, n.session_id, n.name_id, n.attempts)
	SELECT `+columns+`, c.id AS notification_id, c.session_id AS notification_session_id, c.name_id AS notification_name_id, c.attempts AS notification_attempts
	FROM claimed c JOIN saml_service_providers sp ON sp.id = c.service_provider_id AND sp.environment_id = c.environment_id
	JOIN applications a ON a.id = sp.application_id JOIN resources res ON res.id = sp.resource_id
	ORDER BY c.id`, limit, logoutLease.Seconds())
	if err != nil {
		return nil, failure(err)
	}
	out := make([]samlidp.LogoutNotification, 0, len(rows))
	for _, n := range rows {
		sp, err := n.provider()
		if err != nil {
			return nil, err
		}
		out = append(out, samlidp.LogoutNotification{ID: n.Notification, Environment: sp.Environment, ServiceProvider: sp, Session: n.Session, NameID: n.NameID, Attempts: n.Attempts})
	}
	return out, nil
}

func (r *Repository) LogoutDelivered(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE saml_logout_notifications SET delivered_at = now(), last_error = '' WHERE id = $1`, id)
	return failure(err)
}

func (r *Repository) LogoutRetry(ctx context.Context, id int64, next time.Time, problem string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE saml_logout_notifications SET next_attempt_at = $2, last_error = $3 WHERE id = $1`, id, next, problem)
	return failure(err)
}

// LogoutFailed gives up on the notification and records
// saml.logout_failed (actor system).
func (r *Repository) LogoutFailed(ctx context.Context, n samlidp.LogoutNotification, problem string) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE saml_logout_notifications SET failed_at = now(), last_error = $2 WHERE id = $1`, n.ID, problem); err != nil {
			return failure(err)
		}
		return failure(eventpg.System(ctx, tx, n.Environment, samlidp.ActionLogoutFailed, n.ServiceProvider.ID.String()))
	})
}

// PruneLogouts deletes finished notifications and the links of ended
// sessions older than before.
func (r *Repository) PruneLogouts(ctx context.Context, before time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM saml_logout_notifications WHERE COALESCE(delivered_at, failed_at) < $1`, before); err != nil {
		return failure(err)
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM saml_idp_sessions l WHERE l.created_at < $1
		AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = l.session_id AND s.revoked_at IS NULL AND s.expires_at > now())`, before)
	return failure(err)
}
