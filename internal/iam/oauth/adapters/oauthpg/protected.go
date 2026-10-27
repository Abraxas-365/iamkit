package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// ProtectedResources stores protected resources and their policies.
type ProtectedResources struct{ db *sqlx.DB }

func NewProtectedResources(db *sqlx.DB) *ProtectedResources { return &ProtectedResources{db: db} }

var _ oauth.ProtectedResourceRepository = (*ProtectedResources)(nil)

const protectedColumns = `id,environment_id,application_id,resource_id,uri,name,default_scopes,idle_ttl_seconds,max_ttl_seconds,active,created_at`

type protectedResourceRow struct {
	ID          identity.ProtectedResourceID `db:"id"`
	Environment identity.EnvironmentID       `db:"environment_id"`
	Application identity.ApplicationID       `db:"application_id"`
	Resource    identity.ResourceID          `db:"resource_id"`
	URI         string                       `db:"uri"`
	Name        string                       `db:"name"`
	Scopes      pq.StringArray               `db:"default_scopes"`
	Idle        int64                        `db:"idle_ttl_seconds"`
	Max         int64                        `db:"max_ttl_seconds"`
	Active      bool                         `db:"active"`
	CreatedAt   time.Time                    `db:"created_at"`
}

func (r protectedResourceRow) domain() oauth.ProtectedResource {
	scopes := []string(r.Scopes)
	if scopes == nil {
		scopes = []string{}
	}
	return oauth.ProtectedResource{ID: r.ID, Environment: r.Environment, Application: r.Application, Resource: r.Resource, URI: r.URI, Name: r.Name, DefaultScopes: scopes, IdleTTLSeconds: r.Idle, MaxTTLSeconds: r.Max, Active: r.Active, CreatedAt: r.CreatedAt}
}

// protectedConflict maps the table's constraints to their meaning.
func protectedConflict(err error) error {
	var pg *pq.Error
	if !errors.As(err, &pg) {
		return failure(err)
	}
	switch pg.Constraint {
	case "protected_resources_uri_key":
		return errx.Conflict("a protected resource with this URI already exists")
	case "protected_resources_resource_key":
		return errx.Conflict("the resource already has a protected resource")
	}
	if pg.Code.Class() == "23" {
		return errx.Conflict("invalid application/resource binding")
	}
	return failure(err)
}

func (r *ProtectedResources) ProtectedResourceSource(ctx context.Context, environment identity.EnvironmentID, application identity.ApplicationID, resource identity.ResourceID) (oauth.ProtectedResourceSource, error) {
	var row struct {
		Audience    string         `db:"audience"`
		Permissions pq.StringArray `db:"permissions"`
		System      bool           `db:"system"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT r.audience,r.permissions,r.prefix='iam' AS system FROM resources r JOIN application_resources ar ON ar.resource_id=r.id AND ar.environment_id=r.environment_id WHERE r.environment_id=$1 AND ar.application_id=$2 AND r.id=$3`, environment, application, resource)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.ProtectedResourceSource{}, errx.NotFound("resource not linked to the application")
	}
	return oauth.ProtectedResourceSource{Audience: row.Audience, Permissions: []string(row.Permissions), System: row.System}, failure(err)
}

func (r *ProtectedResources) CreateProtectedResource(ctx context.Context, m oauth.Mutation, id identity.ProtectedResourceID, uri string, input oauth.ProtectedResourceCreate) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO protected_resources(id,environment_id,application_id,resource_id,uri,name,default_scopes,idle_ttl_seconds,max_ttl_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			id, m.Environment, input.Application, input.Resource, uri, input.Name, pq.StringArray(input.DefaultScopes), input.IdleTTLSeconds, input.MaxTTLSeconds); err != nil {
			return protectedConflict(err)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"uri": uri, "resource_id": input.Resource.String()})
	})
}

func (r *ProtectedResources) SaveProtectedResource(ctx context.Context, m oauth.Mutation, p oauth.ProtectedResource) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE protected_resources SET name=$3,default_scopes=$4,idle_ttl_seconds=$5,max_ttl_seconds=$6,active=$7 WHERE id=$1 AND environment_id=$2`,
			p.ID, m.Environment, p.Name, pq.StringArray(p.DefaultScopes), p.IdleTTLSeconds, p.MaxTTLSeconds, p.Active)
		if err != nil {
			return protectedConflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errx.NotFound("protected resource not found")
		}
		if !p.Active {
			if err = endProtectedGrants(ctx, tx, m.Environment, p.ID); err != nil {
				return err
			}
		}
		return eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target)
	})
}

// endProtectedGrants revokes the OAuth sessions of the resource behind a
// protected resource being deactivated or deleted: its grants end at once
// (refresh is invalid_grant, introspection inactive) instead of failing on
// scopes the client no longer has.
func endProtectedGrants(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, id identity.ProtectedResourceID) error {
	_, err := tx.ExecContext(ctx, `UPDATE sessions s SET revoked_at=now() FROM protected_resources p
		WHERE p.id=$2 AND p.environment_id=$1 AND s.environment_id=$1 AND s.resource_id=p.resource_id AND s.oauth_client_id IS NOT NULL AND s.revoked_at IS NULL`, environment, id)
	return failure(err)
}

func (r *ProtectedResources) DeleteProtectedResource(ctx context.Context, m oauth.Mutation, id identity.ProtectedResourceID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if err := endProtectedGrants(ctx, tx, m.Environment, id); err != nil {
			return err
		}
		var uri string
		err := tx.GetContext(ctx, &uri, `DELETE FROM protected_resources WHERE id=$1 AND environment_id=$2 RETURNING uri`, id, m.Environment)
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("protected resource not found")
		}
		if err != nil {
			return failure(err)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"uri": uri})
	})
}

func (r *ProtectedResources) ListProtectedResources(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[oauth.ProtectedResource], error) {
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM protected_resources WHERE environment_id=$1`, environment); err != nil {
		return query.Paginated[oauth.ProtectedResource]{}, failure(err)
	}
	rows := []protectedResourceRow{}
	if err := r.db.SelectContext(ctx, &rows, `SELECT `+protectedColumns+` FROM protected_resources WHERE environment_id=$1 ORDER BY name, id LIMIT $2 OFFSET $3`, environment, page.Limit, page.Offset); err != nil {
		return query.Paginated[oauth.ProtectedResource]{}, failure(err)
	}
	out := make([]oauth.ProtectedResource, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.domain())
	}
	return query.NewPaginated(out, total, page), nil
}

func (r *ProtectedResources) FindProtectedResource(ctx context.Context, environment identity.EnvironmentID, id identity.ProtectedResourceID) (oauth.ProtectedResource, error) {
	var row protectedResourceRow
	err := r.db.GetContext(ctx, &row, `SELECT `+protectedColumns+` FROM protected_resources WHERE id=$1 AND environment_id=$2`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return oauth.ProtectedResource{}, errx.NotFound("protected resource not found")
	}
	return row.domain(), failure(err)
}

// ProtectedResourceImpact counts the sessions endProtectedGrants would end
// that are still live.
func (r *ProtectedResources) ProtectedResourceImpact(ctx context.Context, environment identity.EnvironmentID, id identity.ProtectedResourceID) (oauth.ProtectedResourceImpact, error) {
	var out struct {
		Found    bool `db:"found"`
		Sessions int  `db:"sessions"`
	}
	err := r.db.GetContext(ctx, &out, `SELECT EXISTS(SELECT 1 FROM protected_resources WHERE id=$2 AND environment_id=$1) AS found,
		(SELECT count(*) FROM sessions s JOIN protected_resources p ON p.id=$2 AND p.environment_id=$1
		WHERE s.environment_id=$1 AND s.resource_id=p.resource_id AND s.oauth_client_id IS NOT NULL AND s.revoked_at IS NULL AND s.expires_at>now()) AS sessions`, environment, id)
	if err != nil {
		return oauth.ProtectedResourceImpact{}, failure(err)
	}
	if !out.Found {
		return oauth.ProtectedResourceImpact{}, errx.NotFound("protected resource not found")
	}
	return oauth.ProtectedResourceImpact{ActiveSessions: out.Sessions}, nil
}

func (r *ProtectedResources) ProtectedResourcePolicy(ctx context.Context, environment identity.EnvironmentID) (*oauth.ProtectedResourcePolicy, error) {
	var p oauth.ProtectedResourcePolicy
	err := r.db.QueryRowContext(ctx, `SELECT max_idle_ttl_seconds,max_lifetime_ttl_seconds FROM protected_resource_policies WHERE environment_id=$1`, environment).Scan(&p.MaxIdleTTLSeconds, &p.MaxLifetimeTTLSeconds)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, failure(err)
	}
	return &p, nil
}

func (r *ProtectedResources) SetProtectedResourcePolicy(ctx context.Context, m oauth.Mutation, p oauth.ProtectedResourcePolicy) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO protected_resource_policies(environment_id,max_idle_ttl_seconds,max_lifetime_ttl_seconds) VALUES($1,$2,$3)
			ON CONFLICT (environment_id) DO UPDATE SET max_idle_ttl_seconds=EXCLUDED.max_idle_ttl_seconds,max_lifetime_ttl_seconds=EXCLUDED.max_lifetime_ttl_seconds,updated_at=now()`,
			m.Environment, p.MaxIdleTTLSeconds, p.MaxLifetimeTTLSeconds); err != nil {
			return failure(err)
		}
		// Servers above a lowered ceiling are trimmed to it.
		if _, err := tx.ExecContext(ctx, `UPDATE protected_resources SET max_ttl_seconds=LEAST(max_ttl_seconds,$2),idle_ttl_seconds=LEAST(idle_ttl_seconds,$3,$2) WHERE environment_id=$1 AND (max_ttl_seconds>$2 OR idle_ttl_seconds>$3)`,
			m.Environment, p.MaxLifetimeTTLSeconds, p.MaxIdleTTLSeconds); err != nil {
			return failure(err)
		}
		return eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"max_idle_ttl_seconds": p.MaxIdleTTLSeconds, "max_lifetime_ttl_seconds": p.MaxLifetimeTTLSeconds})
	})
}
