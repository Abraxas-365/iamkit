package provpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "provisioning persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("identity exists or is outside provisioning boundary; explicit linking required")
	}
	return failure(err)
}

const selectUser = `SELECT u.id,u.email,coalesce(m.display_name,u.name) AS name,(u.active AND m.active) AS active,i.external_id,coalesce(m.manager_id::text,'') AS manager_id FROM provisioned_identities i JOIN users u ON u.id=i.user_id AND u.environment_id=i.environment_id JOIN memberships m ON m.user_id=u.id AND m.environment_id=u.environment_id AND m.organization_id=$3 WHERE i.connection_id=$1 AND i.environment_id=$2`

func (r *Repository) Authenticate(ctx context.Context, hash []byte) (provisioning.Principal, error) {
	var row struct {
		ID           identity.CredentialID   `db:"id"`
		Environment  identity.EnvironmentID  `db:"environment_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Connection   identity.ConnectionID   `db:"connection_id"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT k.id,k.environment_id,k.organization_id,k.connection_id FROM provisioning_credentials k JOIN organizations o ON o.id=k.organization_id AND o.environment_id=k.environment_id WHERE k.secret_hash=$1 AND k.revoked_at IS NULL AND k.expires_at>now() AND o.active`, hash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return provisioning.Principal{}, failure(err)
		}
		return provisioning.Principal{}, errx.Unauthorized("invalid credential")
	}
	return provisioning.Principal{ID: row.ID, Environment: row.Environment, Organization: row.Organization, Connection: row.Connection}, nil
}
func find(ctx context.Context, q sqlx.QueryerContext, p provisioning.Principal, id identity.UserID) (provisioning.User, error) {
	var row provisioning.User
	err := sqlx.GetContext(ctx, q, &row, selectUser+` AND u.id=$4`, p.Connection, p.Environment, p.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return provisioning.User{}, errx.NotFound("user not found")
	}
	return row, failure(err)
}
func (r *Repository) Find(ctx context.Context, p provisioning.Principal, id identity.UserID) (provisioning.User, error) {
	return find(ctx, r.db, p, id)
}
func (r *Repository) List(ctx context.Context, p provisioning.Principal, f provisioning.Filter) ([]provisioning.User, int, error) {
	var rows []provisioning.User
	err := r.db.SelectContext(ctx, &rows, selectUser+` AND ($4='' OR ($4='userName' AND u.email=lower($5)) OR ($4='externalId' AND i.external_id=$5)) ORDER BY u.id LIMIT $6 OFFSET $7`, p.Connection, p.Environment, p.Organization, f.Field, f.Value, f.Count, f.Start-1)
	if err != nil {
		return nil, 0, failure(err)
	}
	var total int
	err = r.db.GetContext(ctx, &total, `SELECT count(*) FROM provisioned_identities i JOIN users u ON u.id=i.user_id AND u.environment_id=i.environment_id WHERE i.connection_id=$1 AND i.environment_id=$2 AND ($3='' OR ($3='userName' AND u.email=lower($4)) OR ($3='externalId' AND i.external_id=$4))`, p.Connection, p.Environment, f.Field, f.Value)
	if err != nil {
		return nil, 0, failure(err)
	}
	return rows, total, nil
}
func (r *Repository) Create(ctx context.Context, p provisioning.Principal, u provisioning.User) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users(id,environment_id,email,name,password_hash) VALUES($1,$2,$3,$4,'')`, []any{u.ID, p.Environment, u.Email, u.Name}},
		{`INSERT INTO memberships(environment_id,organization_id,user_id,active) VALUES($1,$2,$3,$4)`, []any{p.Environment, p.Organization, u.ID, u.Active}},
		{`INSERT INTO provisioned_identities(connection_id,environment_id,user_id,external_id) VALUES($1,$2,$3,$4)`, []any{p.Connection, p.Environment, u.ID, u.External}},
	} {
		if _, err = tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return conflict(err)
		}
	}
	if u.Manager != "" {
		if err = setManager(ctx, tx, p, u.ID, u.Manager); err != nil {
			return err
		}
	}
	return failure(tx.Commit())
}
func (r *Repository) Update(ctx context.Context, p provisioning.Principal, id identity.UserID, input provisioning.Update) (provisioning.User, error) {
	var out provisioning.User
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	if _, err = find(ctx, tx, p, id); err != nil {
		return out, err
	}
	if input.Manager != nil {
		if err = setManager(ctx, tx, p, id, *input.Manager); err != nil {
			return out, err
		}
	}
	if input.Active != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE memberships SET active=$4 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, id, *input.Active); err != nil {
			return out, failure(err)
		}
	}
	if input.Name != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE memberships SET display_name=$4 WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, id, *input.Name); err != nil {
			return out, failure(err)
		}
	}
	out, err = find(ctx, tx, p, id)
	if err != nil {
		return out, err
	}
	return out, failure(tx.Commit())
}
func setManager(ctx context.Context, tx *sqlx.Tx, p provisioning.Principal, user identity.UserID, manager string) error {
	if _, err := tx.ExecContext(ctx, `SELECT id FROM organizations WHERE id=$1 AND environment_id=$2 FOR UPDATE`, p.Organization, p.Environment); err != nil {
		return failure(err)
	}
	if manager != "" {
		var known bool
		if err := tx.GetContext(ctx, &known, `SELECT EXISTS(SELECT 1 FROM provisioned_identities WHERE connection_id=$1 AND environment_id=$2 AND user_id=$3)`, p.Connection, p.Environment, manager); err != nil {
			return failure(err)
		}
		if !known {
			return errx.Validation("manager must belong to this provisioning connection")
		}
		var cycle bool
		if err := tx.GetContext(ctx, &cycle, `WITH RECURSIVE chain AS(SELECT user_id,manager_id FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3 UNION SELECT m.user_id,m.manager_id FROM memberships m JOIN chain c ON m.user_id=c.manager_id WHERE m.environment_id=$1 AND m.organization_id=$2)SELECT EXISTS(SELECT 1 FROM chain WHERE user_id=$4)`, p.Environment, p.Organization, manager, user); err != nil {
			return failure(err)
		}
		if cycle {
			return errx.Validation("manager hierarchy cycle")
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE memberships SET manager_id=nullif($4,'')::uuid WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, p.Environment, p.Organization, user, manager)
	return failure(err)
}

var _ provisioning.Repository = (*Repository)(nil)
