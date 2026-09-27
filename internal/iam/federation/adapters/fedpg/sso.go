package fedpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// EnvironmentConnections lists active connections not owned by an
// organization. Their users must already be linked: environment
// connections never provision.
func (r *Repository) EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]federation.ConnectionSummary, error) {
	out := []federation.ConnectionSummary{}
	err := r.db.SelectContext(ctx, &out, `SELECT id,name FROM federation_connections WHERE environment_id=$1 AND organization_id IS NULL AND active ORDER BY name, id`, environment)
	return out, failure(err)
}

func (r *Repository) HasVerifiedDomain(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM organization_domains WHERE environment_id=$1 AND organization_id=$2 AND verified_at IS NOT NULL)`, environment, organization)
	return ok, failure(err)
}

func (r *Repository) OperatorGroup(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, group identity.GroupID) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND connection_id IS NULL)`, group, environment, organization)
	return ok, failure(err)
}

// Discover picks the organization that verified the domain and its active
// SSO connection, preferring the enforced one, then the oldest. Inactive
// organizations do not route to SSO.
func (r *Repository) Discover(ctx context.Context, environment identity.EnvironmentID, domain string) (federation.Discovery, error) {
	var row struct {
		Organization identity.OrganizationID `db:"organization_id"`
		Connection   identity.ConnectionID   `db:"id"`
		Enforcement  string                  `db:"enforcement"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT c.organization_id, c.id, c.enforcement
		FROM organization_domains d
		JOIN organizations o ON o.id=d.organization_id AND o.environment_id=d.environment_id AND o.active
		JOIN federation_connections c ON c.organization_id=d.organization_id AND c.environment_id=d.environment_id AND c.active
		WHERE d.environment_id=$1 AND d.domain=$2 AND d.verified_at IS NOT NULL
		ORDER BY (c.enforcement='enforced') DESC, c.created_at, c.id LIMIT 1`, environment, domain)
	if errors.Is(err, sql.ErrNoRows) {
		return federation.Discovery{}, nil
	}
	if err != nil {
		return federation.Discovery{}, failure(err)
	}
	return federation.Discovery{Method: federation.MethodSSO, Organization: &row.Organization, Connection: &row.Connection, Required: row.Enforcement == federation.EnforcementEnforced}, nil
}

// Provision links a first-time provider identity. It adopts the active user
// with the email, or creates a passwordless user with a verified email;
// ensures a membership and, when configured, membership of the JIT group;
// and records an audit event whose actor is the user. Nothing happens unless
// the email's domain is verified by the organization, checked in the same
// transaction.
func (r *Repository) Provision(ctx context.Context, p federation.Provisioning) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var verified bool
	if err = tx.GetContext(ctx, &verified, `SELECT EXISTS(SELECT 1 FROM organization_domains WHERE environment_id=$1 AND organization_id=$2 AND domain=$3 AND verified_at IS NOT NULL)`, p.Environment, p.Organization, p.Domain); err != nil {
		return failure(err)
	}
	if !verified {
		return errx.Unauthorized("provider email domain is not verified for this organization")
	}
	var existing struct {
		ID     identity.UserID `db:"id"`
		Active bool            `db:"active"`
	}
	err = tx.GetContext(ctx, &existing, `SELECT id, active FROM users WHERE environment_id=$1 AND email=$2 FOR UPDATE`, p.Environment, p.Email)
	user := existing.ID
	switch {
	case errors.Is(err, sql.ErrNoRows):
		user = p.User
		if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,email_verified) VALUES($1,$2,$3,$4,'',true)`, user, p.Environment, p.Email, p.Name); err != nil {
			return conflict(err)
		}
	case err != nil:
		return failure(err)
	case !existing.Active:
		// A deactivated account stays deactivated; SSO must not revive it.
		return errx.Unauthorized("user is inactive")
	}
	// A subject already linked to another user of this connection, or a user
	// already linked to another subject, is a conflict for an operator.
	if _, err = tx.ExecContext(ctx, `INSERT INTO external_identities(connection_id,environment_id,user_id,subject,origin) VALUES($1,$2,$3,$4,'jit')`, p.Connection, p.Environment, user, p.Subject); err != nil {
		return conflict(err)
	}
	// An existing membership is left as is: SSO must not undo an operator's
	// or directory's deactivation (the session then fails with 403).
	if _, err = tx.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3) ON CONFLICT (organization_id,user_id) DO NOTHING`, p.Environment, p.Organization, user); err != nil {
		return failure(err)
	}
	if !p.Group.IsZero() {
		if _, err = tx.ExecContext(ctx, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
			SELECT id,environment_id,organization_id,$4 FROM groups WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND connection_id IS NULL
			ON CONFLICT DO NOTHING`, p.Group, p.Environment, p.Organization, user); err != nil {
			return failure(err)
		}
	}
	if err = audit(ctx, tx, federation.Mutation{Environment: p.Environment, Actor: user.String(), Action: "federation.jit", Target: "/federation-connections/" + p.Connection.String() + "/identities?user=" + user.String()}); err != nil {
		return err
	}
	return failure(tx.Commit())
}
