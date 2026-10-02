package userpg

import (
	"context"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

var _ user.AccessTokenRepository = (*Repository)(nil)

const accessTokenColumns = `id,user_id,organization_id,application_id,resource_id,name,expires_at,last_used_at,revoked_at,created_at`

func (r *Repository) CreateAccessToken(ctx context.Context, m user.Mutation, token user.AccessToken, secretHash []byte) (user.AccessToken, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return user.AccessToken{}, failure(err, "create access token")
	}
	defer tx.Rollback()
	var check struct {
		Kind   string `db:"kind"`
		Member bool   `db:"member"`
		Linked bool   `db:"linked"`
	}
	err = tx.GetContext(ctx, &check, `SELECT u.kind,
		EXISTS(SELECT 1 FROM memberships m WHERE m.environment_id=u.environment_id AND m.organization_id=$3 AND m.user_id=u.id AND m.active) AS member,
		EXISTS(SELECT 1 FROM application_resources ar WHERE ar.environment_id=u.environment_id AND ar.application_id=$4 AND ar.resource_id=$5) AS linked
		FROM users u WHERE u.environment_id=$1 AND u.id=$2 FOR UPDATE`, m.Environment, token.User, token.Organization, token.Application, token.Resource)
	if err != nil {
		return user.AccessToken{}, failure(err, "create access token")
	}
	switch {
	case check.Kind != string(user.KindMachine):
		return user.AccessToken{}, errx.Business("personal access tokens are only for machine users")
	case !check.Member:
		return user.AccessToken{}, errx.Validation("organization_id must be an organization the user belongs to")
	case !check.Linked:
		return user.AccessToken{}, errx.Validation("resource_id must be a resource of the application")
	}
	var out user.AccessToken
	err = tx.GetContext(ctx, &out, `INSERT INTO user_access_tokens(id,environment_id,user_id,organization_id,application_id,resource_id,name,secret_hash,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+accessTokenColumns,
		token.ID, m.Environment, token.User, token.Organization, token.Application, token.Resource, token.Name, secretHash, token.ExpiresAt)
	if err != nil {
		return user.AccessToken{}, failure(err, "create access token")
	}
	if err = audit(ctx, tx, m); err != nil {
		return user.AccessToken{}, failure(err, "audit access token")
	}
	return out, failure(tx.Commit(), "commit access token")
}

// RevokeAccessToken marks the token revoked and ends the sessions
// exchanged from it; revoking twice is a no-op that still answers 204.
func (r *Repository) RevokeAccessToken(ctx context.Context, m user.Mutation, id identity.UserID, token identity.AccessTokenID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "revoke access token")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE user_access_tokens SET revoked_at=coalesce(revoked_at,now()) WHERE environment_id=$1 AND user_id=$2 AND id=$3`, m.Environment, id, token)
	if err != nil {
		return failure(err, "revoke access token")
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err, "revoke access token")
		}
		return errx.NotFound("access token not found")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND access_token_id=$2 AND revoked_at IS NULL`, m.Environment, token); err != nil {
		return failure(err, "revoke access token sessions")
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit access token")
	}
	return failure(tx.Commit(), "commit access token")
}

func (r *Repository) AccessTokens(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, page query.Pagination) (query.Paginated[user.AccessToken], error) {
	var exists bool
	if err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM users WHERE environment_id=$1 AND id=$2)`, environment, id); err != nil {
		return query.Paginated[user.AccessToken]{}, failure(err, "list access tokens")
	}
	if !exists {
		return query.Paginated[user.AccessToken]{}, errx.NotFound("user not found")
	}
	base := `FROM user_access_tokens t WHERE t.environment_id=$1 AND t.user_id=$2`
	args := []any{environment, id}
	if like := query.EscapeLike(page.Search); like != "" {
		base += ` AND t.name ILIKE $3`
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[user.AccessToken]{}, failure(err, "list access tokens")
	}
	rows := []user.AccessToken{}
	columns := `t.id,t.user_id,t.organization_id,t.application_id,t.resource_id,t.name,t.expires_at,t.last_used_at,t.revoked_at,t.created_at,
		(SELECT o.name FROM organizations o WHERE o.id=t.organization_id) AS organization_name,
		(SELECT a.name FROM applications a WHERE a.id=t.application_id) AS application_name,
		(SELECT s.name FROM resources s WHERE s.id=t.resource_id) AS resource_name`
	if err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT %s %s ORDER BY t.created_at DESC, t.id LIMIT %d OFFSET %d", columns, base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[user.AccessToken]{}, failure(err, "list access tokens")
	}
	return query.NewPaginated(rows, total, page), nil
}
