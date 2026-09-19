package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "OAuth persistence failed", errx.TypeInternal)
}
func lookup(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return errx.Unauthorized("invalid OAuth credential")
	}
	return failure(err)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("invalid application/resource binding")
	}
	return failure(err)
}
func (r *Repository) Environment(ctx context.Context, id identity.ClientID) (identity.EnvironmentID, error) {
	var environment identity.EnvironmentID
	err := r.db.GetContext(ctx, &environment, `SELECT environment_id FROM oauth_clients WHERE id=$1 AND active`, id)
	return environment, lookup(err)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID, input oauth.Registration, hash []byte) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public,secret_hash) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, environment, input.Application, input.Resource, pq.Array(input.Redirects), input.Public, hash)
	return conflict(err)
}
func (r *Repository) Disable(ctx context.Context, m oauth.Mutation, id identity.ClientID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE oauth_clients SET active=false WHERE environment_id=$1 AND id=$2`, m.Environment, id)
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
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	if err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID) ([]oauth.ClientView, error) {
	var rows []struct {
		ID              identity.ClientID      `db:"id"`
		Application     identity.ApplicationID `db:"application_id"`
		ApplicationName string                 `db:"application_name"`
		Resource        identity.ResourceID    `db:"resource_id"`
		ResourceName    string                 `db:"resource_name"`
		Redirects       pq.StringArray         `db:"redirect_uris"`
		Public          bool                   `db:"public"`
		Active          bool                   `db:"active"`
	}
	if err := r.db.SelectContext(ctx, &rows, `SELECT oc.id, oc.application_id, a.name AS application_name, oc.resource_id, res.name AS resource_name, oc.redirect_uris, oc.public, oc.active FROM oauth_clients oc JOIN applications a ON a.id=oc.application_id JOIN resources res ON res.id=oc.resource_id WHERE oc.environment_id=$1 ORDER BY oc.id`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]oauth.ClientView, 0, len(rows))
	for _, row := range rows {
		out = append(out, oauth.ClientView{ID: row.ID, Application: row.Application, ApplicationName: row.ApplicationName, Resource: row.Resource, ResourceName: row.ResourceName, Redirects: []string(row.Redirects), Public: row.Public, Active: row.Active})
	}
	return out, nil
}
func (r *Repository) SaveTicket(ctx context.Context, hash, binding []byte, client *oauth.Client, form string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_authorizations(secret_hash,environment_id,client_id,binding_hash,request_form,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '5 minutes')`, hash, client.Environment, client.ID, binding, form)
	return failure(err)
}

type authorization struct{ tx *sqlx.Tx }

func (r *Repository) Begin(ctx context.Context) (oauth.Authorization, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return &authorization{tx}, nil
}
func (t *authorization) Ticket(ctx context.Context, hash []byte) (oauth.Ticket, error) {
	var row oauth.Ticket
	err := t.tx.GetContext(ctx, &row, `SELECT client_id,binding_hash,request_form,requested_at FROM oauth_authorizations WHERE secret_hash=$1 AND expires_at>now() AND consumed_at IS NULL FOR UPDATE`, hash)
	return row, lookup(err)
}
func (t *authorization) SessionTimes(ctx context.Context, id identity.SessionID) (time.Time, time.Time, error) {
	var row struct {
		Expires       time.Time `db:"expires_at"`
		Authenticated time.Time `db:"authenticated_at"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT expires_at,authenticated_at FROM sessions WHERE id=$1 AND revoked_at IS NULL`, id)
	return row.Expires, row.Authenticated, lookup(err)
}
func (t *authorization) Consume(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE oauth_authorizations SET consumed_at=now() WHERE secret_hash=$1`, hash)
	return failure(err)
}
func (t *authorization) Commit() error   { return failure(t.tx.Commit()) }
func (t *authorization) Rollback() error { return failure(t.tx.Rollback()) }
func (r *Repository) Access(ctx context.Context, client *oauth.Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error) {
	var live bool
	err := r.db.GetContext(ctx, &live, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND organization_id=$4 AND application_id=$5 AND resource_id=$6 AND revoked_at IS NULL AND expires_at>now())`, session, client.Environment, subject, organization, client.Application, client.Resource)
	if err != nil {
		return authentication.Access{}, failure(err)
	}
	if !live {
		return authentication.Access{}, errx.Unauthorized("session revoked")
	}
	return authpg.Resolve(ctx, r.db, authentication.Context{EnvironmentID: client.Environment, OrganizationID: organization, ApplicationID: client.Application, ResourceID: client.Resource}, subject)
}

var _ oauth.Repository = (*Repository)(nil)
