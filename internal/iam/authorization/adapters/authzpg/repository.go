package authzpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "authorization persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("conflicting or out-of-bound resource")
	}
	return failure(err)
}
func array(v []string) any {
	if v == nil {
		v = []string{}
	}
	return pq.Array(v)
}

type resourceRow struct {
	ID          string         `db:"id"`
	Name        string         `db:"name"`
	Audience    string         `db:"audience"`
	Permissions pq.StringArray `db:"permissions"`
}

func (r resourceRow) domain() authorization.Resource {
	return authorization.Resource{ID: r.ID, Name: r.Name, Audience: r.Audience, Permissions: []string(r.Permissions)}
}
func (r *Repository) Create(ctx context.Context, environment string, input authorization.Resource) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO resources(id,environment_id,name,audience,permissions) VALUES($1,$2,$3,$4,$5)`, input.ID, environment, input.Name, input.Audience, array(input.Permissions))
	return conflict(err)
}
func (r *Repository) List(ctx context.Context, environment string) ([]authorization.Resource, error) {
	var rows []resourceRow
	if err := r.db.SelectContext(ctx, &rows, `SELECT id,name,audience,permissions FROM resources WHERE environment_id=$1 ORDER BY id`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]authorization.Resource, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.domain())
	}
	return out, nil
}
func (r *Repository) Find(ctx context.Context, environment, id string) (authorization.Resource, error) {
	var row resourceRow
	err := r.db.GetContext(ctx, &row, `SELECT id,name,audience,permissions FROM resources WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.Resource{}, errx.NotFound("resource not found")
	}
	return row.domain(), failure(err)
}
func (r *Repository) LinkApplication(ctx context.Context, environment, application, resource string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO application_resources(environment_id,application_id,resource_id) VALUES($1,$2,$3)`, environment, application, resource)
	return conflict(err)
}
func (r *Repository) UpdateCatalog(ctx context.Context, m authorization.Mutation, id string, input authorization.Catalog) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE resources SET name=$3,permissions=$4 WHERE environment_id=$1 AND id=$2`, m.Environment, id, input.Name, array(input.Permissions))
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
	for _, query := range []string{
		`UPDATE grants SET permissions=ARRAY(SELECT unnest(permissions) INTERSECT SELECT unnest($3::text[])) WHERE environment_id=$1 AND resource_id=$2`,
		`UPDATE roles SET permissions=ARRAY(SELECT unnest(permissions) INTERSECT SELECT unnest($3::text[])) WHERE environment_id=$1 AND resource_id=$2`,
		`UPDATE service_accounts SET permissions=ARRAY(SELECT unnest(permissions) INTERSECT SELECT unnest($3::text[])) WHERE environment_id=$1 AND resource_id=$2`,
	} {
		if _, err = tx.ExecContext(ctx, query, m.Environment, id, array(input.Permissions)); err != nil {
			return failure(err)
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

var _ authorization.ResourceRepository = (*Repository)(nil)
