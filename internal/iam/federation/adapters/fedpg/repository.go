package fedpg

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "federation persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("conflicting or out-of-bound federation connection")
	}
	return failure(err)
}
func (r *Repository) Create(ctx context.Context, c federation.Connection) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO federation_connections(id,environment_id,name,issuer,client_id,secret_env) VALUES($1,$2,$3,$4,$5,$6)`, c.ID, c.Environment, c.Name, c.Issuer, c.Client, c.SecretEnv)
	return conflict(err)
}
func (r *Repository) Find(ctx context.Context, environment, id string) (federation.Connection, error) {
	var row struct {
		ID          string `db:"id"`
		Environment string `db:"environment_id"`
		Issuer      string `db:"issuer"`
		Client      string `db:"client_id"`
		Secret      string `db:"secret_env"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT id,environment_id,issuer,client_id,secret_env FROM federation_connections WHERE id=$1 AND environment_id=$2 AND active`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.Connection{}, errx.NotFound("resource not found")
	}
	return federation.Connection{ID: row.ID, Environment: row.Environment, Issuer: row.Issuer, Client: row.Client, SecretEnv: row.Secret}, failure(err)
}
func (r *Repository) SaveState(ctx context.Context, hash []byte, s federation.State) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO federation_states(secret_hash,connection_id,environment_id,organization_id,application_id,resource_id,binding_hash,nonce,verifier,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '5 minutes')`, hash, s.Connection, s.Boundary.EnvironmentID, s.Boundary.OrganizationID, s.Boundary.ApplicationID, s.Boundary.ResourceID, s.Binding, s.Nonce, s.Verifier)
	return conflict(err)
}
func (r *Repository) ConsumeState(ctx context.Context, hash, binding []byte) (federation.State, error) {
	var out federation.State
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	var row struct {
		Connection   string `db:"connection_id"`
		Environment  string `db:"environment_id"`
		Organization string `db:"organization_id"`
		Application  string `db:"application_id"`
		Resource     string `db:"resource_id"`
		Binding      []byte `db:"binding_hash"`
		Nonce        string `db:"nonce"`
		Verifier     string `db:"verifier"`
	}
	err = tx.GetContext(ctx, &row, `SELECT connection_id,environment_id,organization_id,application_id,resource_id,binding_hash,nonce,verifier FROM federation_states WHERE secret_hash=$1 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, failure(err)
	}
	if errors.Is(err, sql.ErrNoRows) || subtle.ConstantTimeCompare(row.Binding, binding) != 1 {
		return out, errx.Unauthorized("invalid federation state or browser binding")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE federation_states SET consumed_at=now() WHERE secret_hash=$1`, hash); err != nil {
		return out, failure(err)
	}
	out = federation.State{Connection: row.Connection, Boundary: authentication.Context{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource}, Binding: row.Binding, Nonce: row.Nonce, Verifier: row.Verifier}
	return out, failure(tx.Commit())
}
func (r *Repository) LinkedUser(ctx context.Context, environment, connection, subject string) (authentication.Transaction, string, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, "", failure(err)
	}
	var user string
	err = tx.GetContext(ctx, &user, `SELECT u.id FROM external_identities x JOIN users u ON u.id=x.user_id AND u.environment_id=x.environment_id WHERE x.connection_id=$1 AND x.environment_id=$2 AND x.subject=$3 AND u.active FOR UPDATE OF u`, connection, environment, subject)
	if err != nil {
		tx.Rollback()
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, "", failure(err)
		}
		return nil, "", errx.Unauthorized("external identity is not linked")
	}
	return authpg.Wrap(tx), user, nil
}
func (r *Repository) mutate(ctx context.Context, m federation.Mutation, query string, args ...any) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return conflict(err)
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
func (r *Repository) Link(ctx context.Context, m federation.Mutation, connection, user, subject string) error {
	return r.mutate(ctx, m, `INSERT INTO external_identities(connection_id,environment_id,user_id,subject) VALUES($1,$2,$3,$4)`, connection, m.Environment, user, subject)
}
func (r *Repository) Disable(ctx context.Context, m federation.Mutation, id string) error {
	return r.mutate(ctx, m, `UPDATE federation_connections SET active=false WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}

var _ federation.Repository = (*Repository)(nil)
