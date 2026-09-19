package mgmtpg

import (
	"context"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

func (r *Repository) Sessions(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[management.Session], error) {
	base := `FROM sessions WHERE environment_id=$1`
	args := []any{environment}
	// Sessions are all UUIDs — no useful ILIKE columns, skip search.
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[management.Session]{}, failure(err)
	}
	out := []management.Session{}
	sel := fmt.Sprintf("SELECT id,user_id,organization_id,application_id,resource_id,expires_at,revoked_at %s ORDER BY id DESC LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &out, sel, args...); err != nil {
		return query.Paginated[management.Session]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}
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
	sel := fmt.Sprintf("SELECT id,actor_id,action,target_id,created_at %s ORDER BY id DESC LIMIT %d OFFSET %d", base, page.Limit, page.Offset)
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
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, environment, actor, action, target)
	if err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

var _ management.ActivityRepository = (*Repository)(nil)
