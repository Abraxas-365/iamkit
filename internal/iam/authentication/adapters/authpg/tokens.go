package authpg

import (
	"context"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

func (r *Repository) Current(ctx context.Context, t authentication.Token, environment identity.EnvironmentID) ([]string, error) {
	var current pq.StringArray
	var err error
	if t.Purpose == "application" {
		err = r.db.GetContext(ctx, &current, `SELECT g.permissions FROM sessions s JOIN users u ON u.id=s.user_id AND u.environment_id=s.environment_id JOIN memberships m ON m.environment_id=s.environment_id AND m.organization_id=s.organization_id AND m.user_id=s.user_id JOIN effective_grants g ON g.environment_id=s.environment_id AND g.organization_id=s.organization_id AND g.user_id=s.user_id AND g.resource_id=s.resource_id JOIN resources r ON r.id=s.resource_id AND r.environment_id=s.environment_id JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id WHERE s.id=$1 AND s.environment_id=$2 AND s.user_id=$3 AND s.organization_id=$4 AND s.application_id=$5 AND s.resource_id=$6 AND r.environment_id=$7 AND s.revoked_at IS NULL AND s.expires_at>now() AND m.active AND u.active AND a.active AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=m.organization_id AND o.environment_id=m.environment_id AND o.active)`, t.SessionID, t.EnvironmentID, t.Subject, t.OrganizationID, t.ApplicationID, t.ResourceID, environment)
	} else {
		err = r.db.GetContext(ctx, &current, `SELECT s.permissions FROM service_accounts s JOIN resources r ON r.id=s.resource_id AND r.environment_id=s.environment_id JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id WHERE s.id=$1 AND s.environment_id=$2 AND s.application_id=$3 AND s.resource_id=$4 AND r.environment_id=$5 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.active`, t.Subject, t.EnvironmentID, t.ApplicationID, t.ResourceID, environment)
	}
	return []string(current), credentialError(err)
}
func (r *Repository) ActorActive(ctx context.Context, t authentication.Token) (bool, error) {
	var active bool
	err := r.db.GetContext(ctx, &active, `SELECT EXISTS(SELECT 1 FROM sessions s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id JOIN workspace_members m ON m.workspace_id=p.workspace_id AND m.operator_id=s.actor_id WHERE s.id=$1 AND s.actor_id=$2 AND m.active AND m.role='owner')`, t.SessionID, t.ActorID)
	return active, failure(err)
}
func (r *Repository) OAuthActive(ctx context.Context, t authentication.Token, clientID identity.ClientID) (bool, error) {
	var live bool
	err := r.db.GetContext(ctx, &live, `SELECT EXISTS(SELECT 1 FROM oauth_clients c WHERE c.id=$1 AND c.environment_id=$2 AND c.active)`, clientID, t.EnvironmentID)
	return live, failure(err)
}
func (r *Repository) Machine(ctx context.Context, hash []byte) (authentication.Token, string, error) {
	var row struct {
		ID          identity.UserID        `db:"id"`
		Environment identity.EnvironmentID `db:"environment_id"`
		Application identity.ApplicationID `db:"application_id"`
		Resource    identity.ResourceID    `db:"resource_id"`
		Audience    string                 `db:"audience"`
		Permissions pq.StringArray         `db:"permissions"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT s.id,s.environment_id,s.application_id,s.resource_id,r.audience,s.permissions FROM service_accounts s JOIN resources r ON r.id=s.resource_id AND r.environment_id=s.environment_id JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id WHERE s.secret_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.active`, hash)
	if err != nil {
		return authentication.Token{}, "", errx.Unauthorized("invalid credentials or access token")
	}
	return authentication.Token{Access: identity.Access{EnvironmentID: row.Environment, ApplicationID: row.Application, ResourceID: row.Resource, Permissions: []string(row.Permissions)}, Subject: row.ID, Purpose: "machine"}, row.Audience, nil
}
func (r *Repository) Revoke(ctx context.Context, environment identity.EnvironmentID, id identity.SessionID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND environment_id=$2`, id, environment)
	return failure(err)
}
func (r *Repository) Profile(ctx context.Context, t authentication.Token) (authentication.Profile, error) {
	out := authentication.Profile{}
	err := r.db.GetContext(ctx, &out, `SELECT u.id,u.email,u.name,u.email_verified,u.environment_id,$2::uuid AS organization_id,$3::uuid AS actor_id FROM users u WHERE u.id=$1`, t.Subject, t.OrganizationID, t.ActorID)
	return out, failure(err)
}
func (r *Repository) Organizations(ctx context.Context, t authentication.Token) ([]authentication.Organization, error) {
	out := []authentication.Organization{}
	err := r.db.SelectContext(ctx, &out, `SELECT o.id,o.name,m.org_unit_id,m.manager_id FROM organizations o JOIN memberships m ON m.organization_id=o.id AND m.environment_id=o.environment_id WHERE m.user_id=$1 AND m.environment_id=$2 AND m.active AND o.active ORDER BY o.id`, t.Subject, t.EnvironmentID)
	return out, failure(err)
}
func (r *Repository) UpdateProfile(ctx context.Context, t authentication.Token, organizationID identity.OrganizationID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET organization_id=$3 WHERE user_id=$1 AND environment_id=$2 AND revoked_at IS NULL AND expires_at>now()`, t.Subject, t.EnvironmentID, organizationID)
	return failure(err)
}
func (r *Repository) AddMember(ctx context.Context, t authentication.Token, organizationID identity.OrganizationID) error {
	res, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id)
SELECT $1,$2,$3 WHERE EXISTS(
  SELECT 1 FROM effective_grants eg
  JOIN resources res ON res.id=eg.resource_id AND res.environment_id=eg.environment_id AND res.prefix='iam'
  WHERE eg.environment_id=$1 AND eg.organization_id=$2 AND eg.user_id=$4
  AND 'iam:members:write' = ANY(eg.permissions)
)`, t.EnvironmentID, organizationID, t.Subject, t.Subject)
	if err != nil {
		var pg *pq.Error
		if errors.As(err, &pg) && pg.Code.Class() == "23" {
			return errx.Conflict("membership exists or user is outside environment")
		}
		return failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if n == 0 {
		return errx.Forbidden("insufficient permissions")
	}
	return nil
}

var _ authentication.TokenRepository = (*Repository)(nil)
