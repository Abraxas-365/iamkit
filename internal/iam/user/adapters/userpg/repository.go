package userpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }
func failure(err error, message string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("resource not found")
	}
	var pg *pq.Error
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23503") {
		return errx.Wrap(err, message, errx.TypeConflict)
	}
	return errx.Wrap(err, message, errx.TypeInternal)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, input user.Create, hash string) (identity.UserID, error) {
	id := identity.NewUserID()
	_, err := r.db.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,otp_enabled) VALUES($1,$2,$3,$4,$5,$6)`, id, environment, input.Email, input.Name, hash, input.OTPEnabled)
	return id, failure(err, "user already exists")
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[user.User], error) {
	base := `FROM users WHERE environment_id=$1`
	args := []any{environment}
	n := 1
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (name ILIKE $%d OR email ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[user.User]{}, failure(err, "list users")
	}
	rows := []user.User{}
	err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT id,email,name,active %s ORDER BY name LIMIT %d OFFSET %d", base, page.Limit, page.Offset), args...)
	if err != nil {
		return query.Paginated[user.User]{}, failure(err, "list users")
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (user.User, error) {
	var row user.User
	err := r.db.GetContext(ctx, &row, `SELECT id,email,name,active,email_verified,otp_enabled,metadata FROM users WHERE environment_id=$1 AND id=$2`, environment, id)
	return row, failure(err, "find user")
}
func (r *Repository) Update(ctx context.Context, m user.Mutation, id identity.UserID, input user.Update) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "update user")
	}
	defer tx.Rollback()
	var metadata any
	if len(input.Metadata) > 0 {
		metadata = string(input.Metadata)
	}
	res, err := tx.ExecContext(ctx, `UPDATE users SET name=coalesce($3,name),active=coalesce($4,active),metadata=coalesce($5::jsonb,metadata),otp_enabled=coalesce($6,otp_enabled) WHERE environment_id=$1 AND id=$2`, m.Environment, id, input.Name, input.Active, metadata, input.OTPEnabled)
	if err != nil {
		return failure(err, "conflicting or out-of-bound resource")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err, "update user")
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err, "audit user update")
	}
	return failure(tx.Commit(), "commit user update")
}
func (r *Repository) Suspend(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET active=false WHERE id=$1 AND environment_id=$2`, id, environment)
	return failure(err, "suspend user")
}

var _ user.Repository = (*Repository)(nil)
