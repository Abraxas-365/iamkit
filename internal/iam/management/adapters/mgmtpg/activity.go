package mgmtpg

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func (r *Repository) Sessions(ctx context.Context, environment identity.EnvironmentID) ([]management.Session, error) {
	out := []management.Session{}
	err := r.db.SelectContext(ctx, &out, `SELECT id,user_id,organization_id,application_id,resource_id,expires_at,revoked_at FROM sessions WHERE environment_id=$1 ORDER BY id LIMIT 1000`, environment)
	return out, failure(err)
}
func (r *Repository) Audit(ctx context.Context, environment identity.EnvironmentID) ([]management.AuditEvent, error) {
	out := []management.AuditEvent{}
	err := r.db.SelectContext(ctx, &out, `SELECT id,actor_id,action,target_id,created_at FROM audit_events WHERE environment_id=$1 ORDER BY id DESC LIMIT 1000`, environment)
	return out, failure(err)
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
