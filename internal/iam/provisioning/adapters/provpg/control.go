package provpg

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
)

func (r *Repository) IssueCredential(ctx context.Context, environment string, input provisioning.CredentialInput, out provisioning.Credential, hash []byte, create bool) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if create {
		_, err = tx.ExecContext(ctx, `INSERT INTO provisioning_connections(id,environment_id,organization_id,name) VALUES($1,$2,$3,$4)`, out.Connection, environment, input.Organization, input.Name)
		if err != nil {
			return conflict(err)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO provisioning_credentials(id,environment_id,organization_id,name,secret_hash,expires_at,connection_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, out.ID, environment, input.Organization, input.Name, hash, out.Expires, out.Connection)
	if err != nil {
		return conflict(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) controlMutation(ctx context.Context, m provisioning.Mutation, query string, args ...any) error {
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
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	if err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) RevokeCredential(ctx context.Context, m provisioning.Mutation, id string) error {
	return r.controlMutation(ctx, m, `UPDATE provisioning_credentials SET revoked_at=now() WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}
func (r *Repository) Link(ctx context.Context, m provisioning.Mutation, input provisioning.Link) error {
	return r.controlMutation(ctx, m, `INSERT INTO provisioned_identities(connection_id,environment_id,user_id,external_id) SELECT p.id,p.environment_id,m.user_id,$4 FROM provisioning_connections p JOIN memberships m ON m.environment_id=p.environment_id AND m.organization_id=p.organization_id WHERE p.environment_id=$1 AND p.id=$2 AND m.user_id=$3`, m.Environment, input.Connection, input.User, input.External)
}

var _ provisioning.ControlRepository = (*Repository)(nil)
