package authzpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
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

// resourceRow mirrors authorization.Resource but scans the Postgres text[]
// permissions column into pq.StringArray — sqlx cannot scan a driver.Value
// directly into a plain []string.
type resourceRow struct {
	ID          identity.ResourceID `db:"id"`
	Name        string              `db:"name"`
	Prefix      string              `db:"prefix"`
	Audience    string              `db:"audience"`
	Permissions pq.StringArray      `db:"permissions"`
}

func (row resourceRow) toDomain() authorization.Resource {
	return authorization.Resource{ID: row.ID, Name: row.Name, Prefix: row.Prefix, Audience: row.Audience, Permissions: []string(row.Permissions)}
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, input authorization.Resource) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO resources(id,environment_id,name,prefix,audience,permissions) VALUES($1,$2,$3,$4,$5,$6)`, input.ID, environment, input.Name, input.Prefix, input.Audience, array(input.Permissions))
	return conflict(err)
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[authorization.Resource], error) {
	base := `FROM resources WHERE environment_id=$1`
	args := []any{environment}
	n := 1
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (name ILIKE $%d OR prefix ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	dbRows := []resourceRow{}
	if err := r.db.SelectContext(ctx, &dbRows, fmt.Sprintf("SELECT id,name,prefix,audience,permissions %s ORDER BY name LIMIT %d OFFSET %d", base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	rows := make([]authorization.Resource, len(dbRows))
	for i, row := range dbRows {
		rows[i] = row.toDomain()
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ResourceID) (authorization.Resource, error) {
	var row resourceRow
	err := r.db.GetContext(ctx, &row, `SELECT id,name,prefix,audience,permissions FROM resources WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.Resource{}, errx.NotFound("resource not found")
	}
	return row.toDomain(), failure(err)
}
func (r *Repository) LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO application_resources(environment_id,application_id,resource_id) VALUES($1,$2,$3)`, environment, application, resource)
	return conflict(err)
}
func (r *Repository) UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM application_resources WHERE environment_id=$1 AND application_id=$2 AND resource_id=$3`, environment, application, resource)
	if err != nil {
		return failure(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errx.NotFound("application-resource link not found")
	}
	return nil
}
func (r *Repository) ListByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, page query.Pagination) (query.Paginated[authorization.Resource], error) {
	base := `FROM resources r JOIN application_resources ar ON ar.resource_id=r.id AND ar.environment_id=r.environment_id WHERE ar.environment_id=$1 AND ar.application_id=$2`
	args := []any{environment, application}
	n := 2
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (r.name ILIKE $%d OR r.prefix ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	dbRows := []resourceRow{}
	if err := r.db.SelectContext(ctx, &dbRows, fmt.Sprintf("SELECT r.id, r.name, r.prefix, r.audience, r.permissions %s ORDER BY r.name LIMIT %d OFFSET %d", base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	rows := make([]authorization.Resource, len(dbRows))
	for i, row := range dbRows {
		rows[i] = row.toDomain()
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) UpdateCatalog(ctx context.Context, m authorization.Mutation, id identity.ResourceID, input authorization.Catalog) error {
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
