package oauthpg

import (
	"context"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

var _ oauth.LogoutRepository = (*Repository)(nil)

type logoutRow struct {
	ID          int64                  `db:"id"`
	Environment identity.EnvironmentID `db:"environment_id"`
	Client      identity.ClientID      `db:"client_id"`
	Session     identity.SessionID     `db:"session_id"`
	Subject     identity.UserID        `db:"subject"`
	Attempts    int                    `db:"attempts"`
	URI         string                 `db:"uri"`
}

// ClaimLogouts leases due rows by moving next_attempt_at past the lease;
// SKIP LOCKED keeps concurrent dispatchers on disjoint rows.
func (r *Repository) ClaimLogouts(ctx context.Context, limit int, lease time.Duration) ([]oauth.LogoutNotification, error) {
	rows := []logoutRow{}
	err := r.db.SelectContext(ctx, &rows, `WITH due AS (
		SELECT id FROM logout_notifications
		WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
	UPDATE logout_notifications n SET attempts = n.attempts + 1, next_attempt_at = now() + make_interval(secs => $2)
	FROM due WHERE n.id = due.id
	RETURNING n.id, n.environment_id, n.client_id, n.session_id, n.subject, n.attempts,
		COALESCE((SELECT c.backchannel_logout_uri FROM oauth_clients c WHERE c.id = n.client_id AND c.environment_id = n.environment_id AND c.active), '') AS uri`,
		limit, lease.Seconds())
	if err != nil {
		return nil, failure(err)
	}
	out := make([]oauth.LogoutNotification, 0, len(rows))
	for _, row := range rows {
		out = append(out, oauth.LogoutNotification(row))
	}
	return out, nil
}
func (r *Repository) LogoutDelivered(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE logout_notifications SET delivered_at = now(), last_error = '' WHERE id = $1`, id)
	telemetry.Logout(ctx, telemetry.LogoutDelivered)
	return failure(err)
}
func (r *Repository) LogoutRetry(ctx context.Context, id int64, wait time.Duration, reason string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE logout_notifications SET next_attempt_at = now() + make_interval(secs => $2), last_error = $3 WHERE id = $1`, id, wait.Seconds(), reason)
	telemetry.Logout(ctx, telemetry.LogoutRetried)
	return failure(err)
}
func (r *Repository) LogoutFailed(ctx context.Context, m oauth.Mutation, id int64, reason string) error {
	telemetry.Logout(ctx, telemetry.LogoutFailed)
	return r.audited(ctx, m, `UPDATE logout_notifications SET failed_at = now(), last_error = $2 WHERE id = $1`, id, reason)
}
func (r *Repository) RetryLogout(ctx context.Context, m oauth.Mutation, id int64) error {
	err := r.audited(ctx, m, `UPDATE logout_notifications SET failed_at = NULL, attempts = 0, next_attempt_at = now() WHERE environment_id = $1 AND id = $2 AND failed_at IS NOT NULL`, m.Environment, id)
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeNotFound {
		return errx.NotFound("failed logout delivery not found")
	}
	return err
}

func (r *Repository) PruneLogouts(ctx context.Context, age time.Duration) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM logout_notifications WHERE (delivered_at IS NOT NULL OR failed_at IS NOT NULL) AND created_at < now() - make_interval(secs => $1)`, age.Seconds())
	return failure(err)
}

// LogoutLag measures from the oldest due notification's next_attempt_at.
func (r *Repository) LogoutLag(ctx context.Context) (time.Duration, error) {
	var seconds float64
	err := r.db.GetContext(ctx, &seconds, `SELECT COALESCE(EXTRACT(EPOCH FROM now() - min(next_attempt_at)), 0)::float8
		FROM logout_notifications WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()`)
	if err != nil {
		return 0, failure(err)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

const logoutStatus = `CASE WHEN n.delivered_at IS NOT NULL THEN 'delivered' WHEN n.failed_at IS NOT NULL THEN 'failed' ELSE 'pending' END`

func (r *Repository) LogoutDeliveries(ctx context.Context, environment identity.EnvironmentID, filter oauth.LogoutFilter, page query.Pagination) (query.Paginated[oauth.LogoutDelivery], error) {
	base := `FROM logout_notifications n
		LEFT JOIN oauth_clients c ON c.id = n.client_id AND c.environment_id = n.environment_id
		LEFT JOIN applications a ON a.id = c.application_id AND a.environment_id = c.environment_id
		LEFT JOIN users u ON u.id = n.subject AND u.environment_id = n.environment_id
		WHERE n.environment_id = $1`
	args := []any{environment}
	if filter.Status != "" {
		args = append(args, filter.Status)
		base += fmt.Sprintf(" AND %s = $%d", logoutStatus, len(args))
	}
	if !filter.Client.IsZero() {
		args = append(args, filter.Client)
		base += fmt.Sprintf(" AND n.client_id = $%d", len(args))
	}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		base += fmt.Sprintf(" AND (u.email ILIKE $%d OR a.name ILIKE $%d)", len(args), len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[oauth.LogoutDelivery]{}, failure(err)
	}
	out := []oauth.LogoutDelivery{}
	sel := fmt.Sprintf(`SELECT n.id, n.environment_id, n.client_id, COALESCE(a.name, '') AS application_name, n.session_id, n.subject,
		COALESCE(u.email, '') AS user_email, %s AS status, n.attempts, n.last_error, n.created_at,
		CASE WHEN n.delivered_at IS NULL AND n.failed_at IS NULL THEN n.next_attempt_at END AS next_attempt_at,
		n.delivered_at, n.failed_at %s ORDER BY n.id DESC LIMIT %d OFFSET %d`, logoutStatus, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[oauth.LogoutDelivery]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}
