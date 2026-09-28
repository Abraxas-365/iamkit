package provpg

import (
	"context"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// IssueCredential creates the credential (and its connection when create) and
// audits it, including any change to the connection's adoption policy.
func (r *Repository) IssueCredential(ctx context.Context, m provisioning.Mutation, input provisioning.CredentialInput, out provisioning.Credential, hash []byte, create bool) error {
	environment := m.Environment
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if create {
		_, err = tx.ExecContext(ctx, `INSERT INTO provisioning_connections(id,environment_id,organization_id,name,adopt_existing_members,adopt_scope) VALUES($1,$2,$3,$4,coalesce($5,false),coalesce($6,'any'))`, out.Connection, environment, input.Organization, input.Name, input.AdoptExistingMembers, input.AdoptScope)
		if err != nil {
			return conflict(err)
		}
	} else if input.AdoptExistingMembers != nil || input.AdoptScope != nil {
		_, err = tx.ExecContext(ctx, `UPDATE provisioning_connections SET adopt_existing_members=coalesce($4,adopt_existing_members),adopt_scope=coalesce($5,adopt_scope) WHERE id=$1 AND environment_id=$2 AND organization_id=$3`, out.Connection, environment, input.Organization, input.AdoptExistingMembers, input.AdoptScope)
		if err != nil {
			return failure(err)
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO provisioning_credentials(id,environment_id,organization_id,name,secret_hash,expires_at,connection_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, out.ID, environment, input.Organization, input.Name, hash, out.Expires, out.Connection)
	if err != nil {
		return conflict(err)
	}
	target := m.Target + "/" + out.ID.String()
	if input.AdoptExistingMembers != nil || input.AdoptScope != nil {
		target += "?connection=" + out.Connection.String()
	}
	if input.AdoptExistingMembers != nil {
		target += fmt.Sprintf("&adopt_existing_members=%t", *input.AdoptExistingMembers)
	}
	if input.AdoptScope != nil {
		target += "&adopt_scope=" + *input.AdoptScope
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, environment, m.Actor, m.Action, target); err != nil {
		return failure(err)
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
func (r *Repository) RevokeCredential(ctx context.Context, m provisioning.Mutation, id identity.CredentialID) error {
	return r.controlMutation(ctx, m, `UPDATE provisioning_credentials SET revoked_at=now() WHERE environment_id=$1 AND id=$2`, m.Environment, id)
}

// Link attaches an existing member to a connection under a directory anchor.
// It also re-anchors an identity deprovisioned by SCIM DELETE or one anchored
// internally by IAMKit (e.g. an email-valued externalId re-keyed by migration
// 002). A live directory anchor or an anchor used by another user conflicts.
func (r *Repository) Link(ctx context.Context, m provisioning.Mutation, input provisioning.Link) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var member bool
	if err = tx.GetContext(ctx, &member, `SELECT EXISTS(SELECT 1 FROM provisioning_connections p JOIN memberships m ON m.environment_id=p.environment_id AND m.organization_id=p.organization_id WHERE p.environment_id=$1 AND p.id=$2 AND m.user_id=$3)`, m.Environment, input.Connection, input.User); err != nil {
		return failure(err)
	}
	if !member {
		return errx.NotFound("resource not found")
	}
	res, err := tx.ExecContext(ctx, `UPDATE provisioned_identities SET external_id=$4,external_id_source='client',deprovisioned_at=NULL,updated_at=now(),version=version+1 WHERE environment_id=$1 AND connection_id=$2 AND user_id=$3 AND (deprovisioned_at IS NOT NULL OR external_id_source='derived')`, m.Environment, input.Connection, input.User, input.External)
	if err != nil {
		return conflict(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO provisioned_identities(connection_id,environment_id,user_id,external_id,origin) VALUES($2,$1,$3,$4,'linked')`, m.Environment, input.Connection, input.User, input.External); err != nil {
			return conflict(err)
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) Credentials(ctx context.Context, environment identity.EnvironmentID) ([]provisioning.CredentialView, error) {
	var rows []struct {
		ID           identity.CredentialID   `db:"id"`
		Name         string                  `db:"name"`
		Organization identity.OrganizationID `db:"organization_id"`
		OrgName      string                  `db:"organization_name"`
		Connection   identity.ConnectionID   `db:"connection_id"`
		ConnName     string                  `db:"connection_name"`
		Expires      time.Time               `db:"expires_at"`
		Revoked      *time.Time              `db:"revoked_at"`
		Adopt        bool                    `db:"adopt_existing_members"`
		AdoptScope   string                  `db:"adopt_scope"`
	}
	if err := r.db.SelectContext(ctx, &rows, `SELECT k.id,k.name,k.organization_id,o.name AS organization_name,k.connection_id,c.name AS connection_name,k.expires_at,k.revoked_at,c.adopt_existing_members,c.adopt_scope FROM provisioning_credentials k JOIN provisioning_connections c ON c.id=k.connection_id AND c.environment_id=k.environment_id JOIN organizations o ON o.id=k.organization_id AND o.environment_id=k.environment_id WHERE k.environment_id=$1 ORDER BY k.id`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]provisioning.CredentialView, 0, len(rows))
	for _, row := range rows {
		out = append(out, provisioning.CredentialView{ID: row.ID, Name: row.Name, Organization: row.Organization, OrganizationName: row.OrgName, Connection: row.Connection, ConnectionName: row.ConnName, Expires: row.Expires, Revoked: row.Revoked, Adopt: row.Adopt, AdoptScope: row.AdoptScope})
	}
	return out, nil
}

var _ provisioning.ControlRepository = (*Repository)(nil)
