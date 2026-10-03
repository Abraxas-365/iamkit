package authzpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
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

// resourceConflict names the taken field of a resource insert: prefix and
// audience are unique per environment.
func resourceConflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		switch pg.Constraint {
		case "resources_environment_id_prefix_key":
			return errx.Conflict("prefix is already used by another resource of this environment")
		case "resources_environment_id_audience_key":
			return errx.Conflict("audience is already used by another resource of this environment")
		}
	}
	return conflict(err)
}

// assignment maps the violations of a role assignment insert: a unique
// violation means the role is already held, a foreign-key violation that the
// subject is outside the organization. Both stay 409 Conflict.
func assignment(duplicate, outside string) func(error) error {
	return func(err error) error {
		var pg *pq.Error
		if errors.As(err, &pg) {
			switch pg.Code {
			case "23505":
				return errx.Conflict(duplicate)
			case "23503":
				return errx.Conflict(outside)
			}
		}
		return conflict(err)
	}
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
	ID                identity.ResourceID      `db:"id"`
	Name              string                   `db:"name"`
	Prefix            string                   `db:"prefix"`
	Audience          string                   `db:"audience"`
	Permissions       pq.StringArray           `db:"permissions"`
	OwnerOrganization *identity.OrganizationID `db:"owner_organization_id"`
	RequireGrant      bool                     `db:"require_grant"`
}

// resourceColumns are the columns resourceRow scans, for table alias r.
const resourceColumns = `r.id, r.name, r.prefix, r.audience, r.permissions, r.owner_organization_id, r.require_grant`

func (row resourceRow) toDomain() authorization.Resource {
	return authorization.Resource{ID: row.ID, Name: row.Name, Prefix: row.Prefix, Audience: row.Audience, Permissions: []string(row.Permissions),
		OwnerOrganization: row.OwnerOrganization, RequireGrant: row.RequireGrant}
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, input authorization.Resource) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO resources(id,environment_id,name,prefix,audience,permissions,owner_organization_id,require_grant) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, input.ID, environment, input.Name, input.Prefix, input.Audience, array(input.Permissions), input.OwnerOrganization, input.RequireGrant); err != nil {
			return resourceConflict(err)
		}
		data := map[string]any{"prefix": input.Prefix}
		if input.OwnerOrganization != nil {
			data["organization_id"] = input.OwnerOrganization.String()
		}
		return eventpg.Record(ctx, tx, environment, event.ResourceCreated, event.Subject{Kind: "resource", ID: input.ID.String()}, data)
	})
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[authorization.Resource], error) {
	base := `FROM resources r WHERE r.environment_id=$1`
	args := []any{environment}
	n := 1
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
	if err := r.db.SelectContext(ctx, &dbRows, fmt.Sprintf("SELECT %s %s ORDER BY r.name LIMIT %d OFFSET %d", resourceColumns, base, page.Limit, page.Offset), args...); err != nil {
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
	err := r.db.GetContext(ctx, &row, `SELECT `+resourceColumns+` FROM resources r WHERE r.environment_id=$1 AND r.id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.Resource{}, errx.NotFound("resource not found")
	}
	return row.toDomain(), failure(err)
}
func (r *Repository) LinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO application_resources(environment_id,application_id,resource_id) VALUES($1,$2,$3)`, environment, application, resource); err != nil {
			return conflict(err)
		}
		return linkEvent(ctx, tx, environment, event.ApplicationLinked, application, resource)
	})
}
func (r *Repository) UnlinkApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM application_resources WHERE environment_id=$1 AND application_id=$2 AND resource_id=$3`, environment, application, resource)
		if err != nil {
			// Still referenced (OAuth clients, SAML service providers, …).
			return conflict(err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return errx.NotFound("application-resource link not found")
		}
		return linkEvent(ctx, tx, environment, event.ApplicationUnlinked, application, resource)
	})
}

func linkEvent(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, typ string, application identity.ApplicationID, resource identity.ResourceID) error {
	return eventpg.Record(ctx, tx, environment, typ, event.Subject{Kind: "application", ID: application.String()},
		map[string]any{"resource_id": resource.String()})
}
func (r *Repository) ListByApplication(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, page query.Pagination) (query.Paginated[authorization.Resource], error) {
	base := `FROM resources r JOIN application_resources ar ON ar.resource_id=r.id AND ar.environment_id=r.environment_id WHERE ar.environment_id=$1 AND ar.application_id=$2`
	var exists bool
	if err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1 AND environment_id=$2)`, application, environment); err != nil {
		return query.Paginated[authorization.Resource]{}, failure(err)
	}
	if !exists {
		return query.Paginated[authorization.Resource]{}, errx.NotFound("application not found")
	}
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
	if err := r.db.SelectContext(ctx, &dbRows, fmt.Sprintf("SELECT %s %s ORDER BY r.name LIMIT %d OFFSET %d", resourceColumns, base, page.Limit, page.Offset), args...); err != nil {
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
	if err = audit(ctx, tx, m); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

var _ authorization.ResourceRepository = (*Repository)(nil)
