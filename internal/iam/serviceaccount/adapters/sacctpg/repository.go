package sacctpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
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
	return errx.Wrap(err, "service account persistence failed", errx.TypeInternal)
}
func (r *Repository) Catalog(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID) ([]string, error) {
	var out pq.StringArray
	err := r.db.GetContext(ctx, &out, `SELECT permissions FROM resources WHERE id=$1 AND environment_id=$2`, resource, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("resource not found")
	}
	return []string(out), failure(err)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, input serviceaccount.Input, out serviceaccount.Credential, hash []byte) error {
	if input.Permissions == nil {
		input.Permissions = []string{}
	}
	auth := input.ClientAuth
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO service_accounts(id,environment_id,application_id,resource_id,name,permissions,secret_hash,expires_at,token_endpoint_auth_method,token_endpoint_auth_signing_alg,jwks,jwks_uri) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, out.ID, environment, input.Application, input.Resource, input.Name, pq.Array(input.Permissions), hash, out.Expires, auth.Method, auth.SigningAlg, auth.StoredJWKS(), auth.JWKSURI)
		var pg *pq.Error
		if errors.As(err, &pg) && pg.Code.Class() == "23" {
			return errx.Conflict("service account requires application/resource binding")
		}
		if err != nil {
			return failure(err)
		}
		return eventpg.Record(ctx, tx, environment, event.ServiceAccountCreated, event.Subject{Kind: "service_account", ID: out.ID.String()},
			map[string]any{"application_id": input.Application.String(), "resource_id": input.Resource.String()})
	})
}
func (r *Repository) Revoke(ctx context.Context, environment identity.EnvironmentID, id identity.AccountID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE service_accounts SET revoked_at=now() WHERE id=$1 AND environment_id=$2 AND revoked_at IS NULL`, id, environment)
		if err != nil {
			return failure(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Already revoked stays a no-op; an id of another environment is 404.
			var exists bool
			if err = tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM service_accounts WHERE id=$1 AND environment_id=$2)`, id, environment); err != nil {
				return failure(err)
			}
			if !exists {
				return errx.NotFound("service account not found")
			}
			return nil
		}
		return eventpg.Record(ctx, tx, environment, event.ServiceAccountRevoked, event.Subject{Kind: "service_account", ID: id.String()}, nil)
	})
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[serviceaccount.Account], error) {
	base := `FROM service_accounts sa JOIN applications a ON a.id=sa.application_id JOIN resources res ON res.id=sa.resource_id WHERE sa.environment_id=$1`
	args := []any{environment}
	n := 1
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND sa.name ILIKE $%d", n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[serviceaccount.Account]{}, failure(err)
	}
	dbRows := []accountRow{}
	sel := fmt.Sprintf("SELECT %s %s ORDER BY sa.name LIMIT %d OFFSET %d", accountColumns, base, page.Limit, page.Offset)
	if err := r.db.SelectContext(ctx, &dbRows, sel, args...); err != nil {
		return query.Paginated[serviceaccount.Account]{}, failure(err)
	}
	rows := make([]serviceaccount.Account, len(dbRows))
	for i, row := range dbRows {
		rows[i] = row.account()
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.AccountID) (serviceaccount.Account, error) {
	var row accountRow
	err := r.db.GetContext(ctx, &row, `SELECT `+accountColumns+` FROM service_accounts sa JOIN applications a ON a.id=sa.application_id JOIN resources res ON res.id=sa.resource_id WHERE sa.environment_id=$1 AND sa.id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return serviceaccount.Account{}, errx.NotFound("resource not found")
	}
	if err != nil {
		return serviceaccount.Account{}, failure(err)
	}
	return row.account(), nil
}

// SetAuthentication changes a live account's token endpoint authentication
// and audits it in the same transaction.
func (r *Repository) SetAuthentication(ctx context.Context, m serviceaccount.Mutation, id identity.AccountID, auth identity.ClientAuth) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE service_accounts SET token_endpoint_auth_method=$3, token_endpoint_auth_signing_alg=$4, jwks=$5, jwks_uri=$6 WHERE environment_id=$1 AND id=$2 AND revoked_at IS NULL`, m.Environment, id, auth.Method, auth.SigningAlg, auth.StoredJWKS(), auth.JWKSURI)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err)
		}
		return errx.NotFound("resource not found")
	}
	if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

// SetImpersonation changes whether a live account may impersonate and
// audits it in the same transaction; forbidding it ends the sessions the
// account opened.
func (r *Repository) SetImpersonation(ctx context.Context, m serviceaccount.Mutation, id identity.AccountID, allowed bool) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE service_accounts SET can_impersonate=$3 WHERE environment_id=$1 AND id=$2 AND revoked_at IS NULL`, m.Environment, id, allowed)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err)
		}
		return errx.NotFound("resource not found")
	}
	if !allowed {
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND actor_account_id=$2 AND revoked_at IS NULL`, m.Environment, id); err != nil {
			return failure(err)
		}
	}
	if err = eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}

const accountColumns = "sa.id, sa.name, sa.application_id, a.name AS application_name, sa.resource_id, res.name AS resource_name, sa.permissions, sa.expires_at, sa.revoked_at, sa.can_impersonate, sa.token_endpoint_auth_method, sa.token_endpoint_auth_signing_alg, sa.jwks, sa.jwks_uri"

type accountRow struct {
	ID              identity.AccountID     `db:"id"`
	Name            string                 `db:"name"`
	Application     identity.ApplicationID `db:"application_id"`
	ApplicationName string                 `db:"application_name"`
	Resource        identity.ResourceID    `db:"resource_id"`
	ResourceName    string                 `db:"resource_name"`
	Permissions     pq.StringArray         `db:"permissions"`
	Expires         time.Time              `db:"expires_at"`
	Revoked         *time.Time             `db:"revoked_at"`
	CanImpersonate  bool                   `db:"can_impersonate"`
	Method          string                 `db:"token_endpoint_auth_method"`
	SigningAlg      string                 `db:"token_endpoint_auth_signing_alg"`
	JWKS            *[]byte                `db:"jwks"`
	JWKSURI         string                 `db:"jwks_uri"`
}

func (row accountRow) account() serviceaccount.Account {
	auth := identity.ClientAuth{Method: row.Method, SigningAlg: row.SigningAlg, JWKSURI: row.JWKSURI}
	if row.JWKS != nil {
		auth.JWKS = *row.JWKS
	}
	return serviceaccount.Account{ID: row.ID, Name: row.Name, Application: row.Application, ApplicationName: row.ApplicationName, Resource: row.Resource, ResourceName: row.ResourceName, Permissions: []string(row.Permissions), Expires: row.Expires, Revoked: row.Revoked, CanImpersonate: row.CanImpersonate, ClientAuth: auth}
}

var _ serviceaccount.Repository = (*Repository)(nil)
