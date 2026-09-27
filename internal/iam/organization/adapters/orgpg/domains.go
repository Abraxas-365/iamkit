package orgpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/lib/pq"
)

var _ organization.DomainRepository = (*Repository)(nil)

const selectDomain = `SELECT id,organization_id,domain,verification_token,verified_at,verified_by,verification_method,created_at
	FROM organization_domains WHERE environment_id=$1 AND organization_id=$2`

func (r *Repository) CreateDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.DomainID, name, token string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO organization_domains(id,environment_id,organization_id,domain,verification_token) VALUES($1,$2,$3,$4,$5)`, id, b.Environment, b.Organization, name, token)
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		return errx.Conflict("domain is already claimed by an organization in this environment")
	}
	if err != nil {
		return conflict(err)
	}
	m.Target += "/" + id.String() + "?domain=" + name
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) ListDomains(ctx context.Context, b organization.Boundary, page query.Pagination) (query.Paginated[organization.Domain], error) {
	where := ""
	args := []any{b.Environment, b.Organization}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		where = fmt.Sprintf(" AND domain ILIKE $%d", len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM organization_domains WHERE environment_id=$1 AND organization_id=$2`+where, args...); err != nil {
		return query.Paginated[organization.Domain]{}, failure(err)
	}
	out := []organization.Domain{}
	if err := r.db.SelectContext(ctx, &out, fmt.Sprintf("%s%s ORDER BY domain LIMIT %d OFFSET %d", selectDomain, where, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[organization.Domain]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *Repository) FindDomain(ctx context.Context, b organization.Boundary, id identity.DomainID) (organization.Domain, error) {
	var d organization.Domain
	err := r.db.GetContext(ctx, &d, selectDomain+` AND id=$3`, b.Environment, b.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return d, errx.NotFound("domain not found")
	}
	return d, failure(err)
}

// VerifyDomain is idempotent: a concurrent verification keeps the first
// method and actor.
func (r *Repository) VerifyDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.DomainID, method string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE organization_domains SET verified_at=now(),verified_by=$4,verification_method=$5
		WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND verified_at IS NULL`, id, b.Environment, b.Organization, m.Actor, method)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return failure(err)
	}
	m.Target += "?method=" + method
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) DeleteDomain(ctx context.Context, b organization.Boundary, m organization.Mutation, id identity.DomainID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	// Removing an organization's last verified domain while it enforces SSO
	// would silently turn enforcement off (R7).
	var last bool
	err = tx.GetContext(ctx, &last, `SELECT EXISTS(SELECT 1 FROM organization_domains d WHERE d.id=$1 AND d.environment_id=$2 AND d.organization_id=$3 AND d.verified_at IS NOT NULL)
		AND NOT EXISTS(SELECT 1 FROM organization_domains d WHERE d.id<>$1 AND d.environment_id=$2 AND d.organization_id=$3 AND d.verified_at IS NOT NULL)
		AND EXISTS(SELECT 1 FROM federation_connections c WHERE c.environment_id=$2 AND c.organization_id=$3 AND c.active AND c.enforcement='enforced')`, id, b.Environment, b.Organization)
	if err != nil {
		return failure(err)
	}
	if last {
		return errx.Business("cannot delete the last verified domain while the organization enforces SSO")
	}
	var name string
	err = tx.GetContext(ctx, &name, `DELETE FROM organization_domains WHERE id=$1 AND environment_id=$2 AND organization_id=$3 RETURNING domain`, id, b.Environment, b.Organization)
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("domain not found")
	}
	if err != nil {
		return failure(err)
	}
	m.Target += "?domain=" + name
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}
