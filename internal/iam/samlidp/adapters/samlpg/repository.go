// Package samlpg stores SAML service providers and parked requests.
package samlpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ samlidp.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "SAML persistence failed", errx.TypeInternal)
}

func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) {
		switch {
		case pg.Code == "23505":
			return errx.Conflict("a service provider with this entity_id exists")
		case pg.Code == "23503":
			return errx.Conflict("the resource is not linked to the application")
		}
	}
	return failure(err)
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("service provider not found")
	}
	return failure(err)
}

const columns = `sp.id, sp.environment_id, sp.name, sp.application_id, a.name AS application_name, sp.resource_id, res.name AS resource_name, sp.entity_id, sp.acs_urls, sp.name_id_format, sp.attributes, sp.created_at`

const from = ` FROM saml_service_providers sp JOIN applications a ON a.id=sp.application_id JOIN resources res ON res.id=sp.resource_id`

type row struct {
	ID              identity.ServiceProviderID `db:"id"`
	Environment     identity.EnvironmentID     `db:"environment_id"`
	Name            string                     `db:"name"`
	Application     identity.ApplicationID     `db:"application_id"`
	ApplicationName string                     `db:"application_name"`
	Resource        identity.ResourceID        `db:"resource_id"`
	ResourceName    string                     `db:"resource_name"`
	EntityID        string                     `db:"entity_id"`
	ACS             pq.StringArray             `db:"acs_urls"`
	NameIDFormat    string                     `db:"name_id_format"`
	Attributes      []byte                     `db:"attributes"`
	CreatedAt       time.Time                  `db:"created_at"`
}

func (r row) provider() (samlidp.ServiceProvider, error) {
	attributes := map[string]string{}
	if err := json.Unmarshal(r.Attributes, &attributes); err != nil {
		return samlidp.ServiceProvider{}, failure(err)
	}
	return samlidp.ServiceProvider{ID: r.ID, Environment: r.Environment, Name: r.Name, Application: r.Application, ApplicationName: r.ApplicationName, Resource: r.Resource, ResourceName: r.ResourceName, EntityID: r.EntityID, ACSURLs: []string(r.ACS), NameIDFormat: r.NameIDFormat, Attributes: attributes, CreatedAt: r.CreatedAt}, nil
}

func audit(ctx context.Context, tx *sqlx.Tx, m samlidp.Mutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	return failure(err)
}

// change runs one statement that must touch a row, and its audit event.
func (r *Repository) change(ctx context.Context, m samlidp.Mutation, statement string, args ...any) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return conflict(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return notFound(sql.ErrNoRows)
	}
	if err := audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) Create(ctx context.Context, m samlidp.Mutation, sp samlidp.ServiceProvider) error {
	attributes, err := json.Marshal(sp.Attributes)
	if err != nil {
		return failure(err)
	}
	return r.change(ctx, m, `INSERT INTO saml_service_providers(id,environment_id,application_id,resource_id,name,entity_id,acs_urls,name_id_format,attributes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		sp.ID, m.Environment, sp.Application, sp.Resource, sp.Name, sp.EntityID, pq.StringArray(sp.ACSURLs), sp.NameIDFormat, attributes)
}

func (r *Repository) Update(ctx context.Context, m samlidp.Mutation, id identity.ServiceProviderID, input samlidp.Update) error {
	var acs any
	if input.ACSURLs != nil {
		acs = pq.StringArray(*input.ACSURLs)
	}
	var attributes any
	if input.Attributes != nil {
		raw, err := json.Marshal(*input.Attributes)
		if err != nil {
			return failure(err)
		}
		attributes = raw
	}
	return r.change(ctx, m, `UPDATE saml_service_providers SET name=COALESCE($3,name), acs_urls=COALESCE($4,acs_urls), name_id_format=COALESCE($5,name_id_format), attributes=COALESCE($6::jsonb,attributes) WHERE environment_id=$1 AND id=$2`,
		m.Environment, id, input.Name, acs, input.NameIDFormat, attributes)
}

// Delete removes the provider (audit events keep its ID) and, by cascade,
// its parked requests; the application/resource link can then be removed.
func (r *Repository) Delete(ctx context.Context, m samlidp.Mutation, id identity.ServiceProviderID) error {
	return r.change(ctx, m, `DELETE FROM saml_service_providers WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}

func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ServiceProviderID) (samlidp.ServiceProvider, error) {
	var out row
	if err := r.db.GetContext(ctx, &out, `SELECT `+columns+from+` WHERE sp.environment_id=$1 AND sp.id=$2`, environment, id); err != nil {
		return samlidp.ServiceProvider{}, notFound(err)
	}
	return out.provider()
}

func (r *Repository) FindEntity(ctx context.Context, environment identity.EnvironmentID, entity string) (samlidp.ServiceProvider, error) {
	var out row
	err := r.db.GetContext(ctx, &out, `SELECT `+columns+from+` WHERE sp.environment_id=$1 AND sp.entity_id=$2`, environment, entity)
	if errors.Is(err, sql.ErrNoRows) {
		return samlidp.ServiceProvider{}, errx.Validation("unknown service provider")
	}
	if err != nil {
		return samlidp.ServiceProvider{}, failure(err)
	}
	return out.provider()
}

func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, filter samlidp.Filter, page query.Pagination) (query.Paginated[samlidp.ServiceProvider], error) {
	base := from + ` WHERE sp.environment_id=$1`
	args := []any{environment}
	if !filter.Application.IsZero() {
		args = append(args, filter.Application)
		base += fmt.Sprintf(" AND sp.application_id=$%d", len(args))
	}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		base += fmt.Sprintf(" AND (sp.name ILIKE $%d OR sp.entity_id ILIKE $%d)", len(args), len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*)"+base, args...); err != nil {
		return query.Paginated[samlidp.ServiceProvider]{}, failure(err)
	}
	rows := []row{}
	if err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT %s%s ORDER BY sp.name, sp.id LIMIT %d OFFSET %d", columns, base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[samlidp.ServiceProvider]{}, failure(err)
	}
	out := make([]samlidp.ServiceProvider, 0, len(rows))
	for _, r := range rows {
		sp, err := r.provider()
		if err != nil {
			return query.Paginated[samlidp.ServiceProvider]{}, err
		}
		out = append(out, sp)
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *Repository) EnvironmentExists(ctx context.Context, environment identity.EnvironmentID) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM environments WHERE id=$1)`, environment)
	return ok, failure(err)
}

func (r *Repository) SaveRequest(ctx context.Context, ticket, binding []byte, environment identity.EnvironmentID, request samlidp.Request) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO saml_sso_requests(ticket_hash,binding_hash,environment_id,service_provider_id,request_id,acs_url,relay_state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(secs => $8))`,
		ticket, binding, environment, request.ServiceProvider, request.ID, request.ACSURL, request.RelayState, samlidp.RequestTTL.Seconds())
	if err != nil {
		return failure(err)
	}
	_, err = r.db.ExecContext(ctx, `DELETE FROM saml_sso_requests WHERE expires_at < now() - interval '1 hour'`)
	return failure(err)
}

func (r *Repository) PendingRequest(ctx context.Context, ticket []byte) (samlidp.Pending, error) {
	var out struct {
		Binding     []byte                     `db:"binding_hash"`
		Environment identity.EnvironmentID     `db:"environment_id"`
		Provider    identity.ServiceProviderID `db:"service_provider_id"`
		RequestID   string                     `db:"request_id"`
		ACS         string                     `db:"acs_url"`
		RelayState  string                     `db:"relay_state"`
	}
	err := r.db.GetContext(ctx, &out, `SELECT binding_hash,environment_id,service_provider_id,request_id,acs_url,relay_state FROM saml_sso_requests WHERE ticket_hash=$1 AND expires_at>now() AND consumed_at IS NULL`, ticket)
	if errors.Is(err, sql.ErrNoRows) {
		return samlidp.Pending{}, errx.Unauthorized("invalid authorization ticket or browser binding")
	}
	if err != nil {
		return samlidp.Pending{}, failure(err)
	}
	return samlidp.Pending{Request: samlidp.Request{ID: out.RequestID, ServiceProvider: out.Provider, ACSURL: out.ACS, RelayState: out.RelayState}, Environment: out.Environment, Binding: out.Binding}, nil
}

func (r *Repository) ConsumeRequest(ctx context.Context, m samlidp.Mutation, ticket []byte) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE saml_sso_requests SET consumed_at=now() WHERE ticket_hash=$1 AND consumed_at IS NULL AND expires_at>now()`, ticket)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return errx.Unauthorized("invalid authorization ticket or browser binding")
	}
	if err := audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit())
}

func (r *Repository) Subject(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (samlidp.Subject, error) {
	var out samlidp.Subject
	err := r.db.QueryRowxContext(ctx, `SELECT email, name FROM users WHERE environment_id=$1 AND id=$2 AND active`, environment, user).Scan(&out.Email, &out.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return samlidp.Subject{}, errx.Unauthorized("invalid session context")
	}
	return out, failure(err)
}
