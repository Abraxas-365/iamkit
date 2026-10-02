package mgmtpg

import (
	"context"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

func (r *Repository) Sessions(ctx context.Context, environment identity.EnvironmentID, filter management.SessionFilter, page query.Pagination) (query.Paginated[management.Session], error) {
	base := `FROM sessions WHERE environment_id=$1`
	args := []any{environment}
	if !filter.User.IsZero() {
		base += ` AND user_id=$2`
		args = append(args, filter.User)
	}
	// Sessions are all UUIDs — no useful ILIKE columns, skip search.
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[management.Session]{}, failure(err)
	}
	out := []management.Session{}
	sel := fmt.Sprintf(`SELECT s.id,s.user_id,s.organization_id,s.application_id,s.resource_id,s.expires_at,s.revoked_at,
		COALESCE(u.name,'') AS user_name, COALESCE(u.email,'') AS user_email, COALESCE(o.name,'') AS organization_name,
		COALESCE(a.name,'') AS application_name, COALESCE(r.name,'') AS resource_name
		FROM (SELECT * %s ORDER BY id DESC LIMIT %d OFFSET %d) s
		LEFT JOIN users u ON u.id=s.user_id AND u.environment_id=s.environment_id
		LEFT JOIN organizations o ON o.id=s.organization_id AND o.environment_id=s.environment_id
		LEFT JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id
		LEFT JOIN resources r ON r.id=s.resource_id AND r.environment_id=s.environment_id
		ORDER BY s.id DESC`, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[management.Session]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}

// targetLabel names the entity an audit event is about: the last UUID of its
// target (a bare ID or the request path), looked up among the environment's
// named entities. Empty when nothing matches, e.g. after a hard delete.
const targetLabel = `COALESCE(
	(SELECT COALESCE(NULLIF(name,''),email) FROM users WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM organizations WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM applications WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT a.name FROM oauth_clients c JOIN applications a ON a.id=c.application_id WHERE c.id=t.id AND c.environment_id=e.environment_id),
	(SELECT name FROM resources WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM roles WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM groups WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM federation_connections WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM service_accounts WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM provisioning_connections WHERE id=t.id AND environment_id=e.environment_id),
	(SELECT name FROM provisioning_credentials WHERE id=t.id AND environment_id=e.environment_id),
	'')`

func (r *Repository) Audit(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[management.AuditEvent], error) {
	base := `FROM audit_events WHERE environment_id=$1`
	args := []any{environment}
	n := 1
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND action ILIKE $%d", n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[management.AuditEvent]{}, failure(err)
	}
	out := []management.AuditEvent{}
	sel := fmt.Sprintf(`SELECT e.id,e.actor_id,e.action,e.target_id,e.created_at,e.actor_kind,e.organization_id,
		COALESCE((SELECT email FROM operators WHERE id=e.actor_id),(SELECT email FROM users WHERE id=e.actor_id AND environment_id=e.environment_id),(SELECT name FROM service_accounts WHERE id=e.actor_id AND environment_id=e.environment_id),'') AS actor_label,
		%s AS target_label
		FROM (SELECT * %s ORDER BY id DESC LIMIT %d OFFSET %d) e
		LEFT JOIN LATERAL (SELECT substring(e.target_id FROM '.*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')::uuid AS id) t ON true
		ORDER BY e.id DESC`, targetLabel, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[management.AuditEvent]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}
func (r *Repository) RevokeSession(ctx context.Context, environment identity.EnvironmentID, id identity.SessionID, actor, action, target string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND id=$2`, environment, id)
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
	if err = eventpg.Audit(ctx, tx, environment, actor, action, target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

var _ management.ActivityRepository = (*Repository)(nil)
