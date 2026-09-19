package apppg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/application"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "application persistence failed", errx.TypeInternal)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, id identity.ApplicationID, input application.Create) error {
	if input.Redirects == nil {
		input.Redirects = []string{}
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO applications(id,environment_id,name,redirect_uris) VALUES($1,$2,$3,$4)`, id, environment, input.Name, pq.Array(input.Redirects))
	return failure(err)
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ApplicationID) (application.Application, error) {
	var result application.Application
	err := r.db.GetContext(ctx, &result, `SELECT id,name,redirect_uris,active FROM applications WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return application.Application{}, errx.NotFound("resource not found")
	}
	return result, failure(err)
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[application.Application], error) {
	base := `FROM applications WHERE environment_id=$1`
	args := []any{environment}
	n := 1
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND name ILIKE $%d", n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[application.Application]{}, failure(err)
	}
	rows := []application.Application{}
	if err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT id,name,redirect_uris,active %s ORDER BY name LIMIT %d OFFSET %d", base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[application.Application]{}, failure(err)
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) Update(ctx context.Context, m application.Mutation, id identity.ApplicationID, input application.Update) error {
	var redirects any
	if input.Redirects != nil {
		redirects = pq.Array(*input.Redirects)
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE applications SET name=coalesce($3,name),active=coalesce($4,active),redirect_uris=coalesce($5,redirect_uris) WHERE environment_id=$1 AND id=$2`, m.Environment, id, input.Name, input.Active, redirects)
	if err != nil {
		var pg *pq.Error
		if errors.As(err, &pg) && pg.Code.Class() == "23" {
			return errx.Conflict("conflicting application")
		}
		return failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

var _ application.Repository = (*Repository)(nil)
