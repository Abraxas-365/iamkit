package userpg

import (
	"context"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

var _ user.KeyRepository = (*Repository)(nil)

const keyColumns = `id,user_id,public_jwk,expires_at,last_used_at,created_at`

func (r *Repository) AddKey(ctx context.Context, m user.Mutation, key user.Key) (user.Key, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return user.Key{}, failure(err, "add key")
	}
	defer tx.Rollback()
	var check struct {
		Kind string `db:"kind"`
		Keys int    `db:"keys"`
	}
	// Locking the user serializes concurrent adds against MaxKeys.
	err = tx.GetContext(ctx, &check, `SELECT u.kind,
		(SELECT count(*) FROM user_keys k WHERE k.environment_id=u.environment_id AND k.user_id=u.id) AS keys
		FROM users u WHERE u.environment_id=$1 AND u.id=$2 FOR UPDATE`, m.Environment, key.User)
	if err != nil {
		return user.Key{}, failure(err, "add key")
	}
	switch {
	case check.Kind != string(user.KindMachine):
		return user.Key{}, errx.Business("keys are only for machine users")
	case check.Keys >= user.MaxKeys:
		return user.Key{}, user.ErrTooManyKeys()
	}
	var out user.Key
	err = tx.GetContext(ctx, &out, `INSERT INTO user_keys(id,environment_id,user_id,public_jwk,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING `+keyColumns,
		key.ID, m.Environment, key.User, string(key.PublicKey), key.ExpiresAt)
	if err != nil {
		return user.Key{}, failure(err, "add key")
	}
	if err = audit(ctx, tx, m); err != nil {
		return user.Key{}, failure(err, "audit key")
	}
	return out, failure(tx.Commit(), "commit key")
}

// RemoveKey deletes the key after ending the sessions opened with it.
func (r *Repository) RemoveKey(ctx context.Context, m user.Mutation, id identity.UserID, key identity.UserKeyID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "remove key")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND user_id=$2 AND user_key_id=$3 AND revoked_at IS NULL`, m.Environment, id, key); err != nil {
		return failure(err, "remove key sessions")
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM user_keys WHERE environment_id=$1 AND user_id=$2 AND id=$3`, m.Environment, id, key)
	if err != nil {
		return failure(err, "remove key")
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err, "remove key")
		}
		return errx.NotFound("key not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit key")
	}
	return failure(tx.Commit(), "commit key")
}

func (r *Repository) Keys(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, page query.Pagination) (query.Paginated[user.Key], error) {
	var exists bool
	if err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM users WHERE environment_id=$1 AND id=$2)`, environment, id); err != nil {
		return query.Paginated[user.Key]{}, failure(err, "list keys")
	}
	if !exists {
		return query.Paginated[user.Key]{}, errx.NotFound("user not found")
	}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM user_keys WHERE environment_id=$1 AND user_id=$2`, environment, id); err != nil {
		return query.Paginated[user.Key]{}, failure(err, "list keys")
	}
	rows := []user.Key{}
	if err := r.db.SelectContext(ctx, &rows, fmt.Sprintf(`SELECT %s FROM user_keys WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at DESC, id LIMIT %d OFFSET %d`, keyColumns, page.Limit, page.Offset), environment, id); err != nil {
		return query.Paginated[user.Key]{}, failure(err, "list keys")
	}
	return query.NewPaginated(rows, total, page), nil
}
