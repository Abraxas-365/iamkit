package fedpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// EnvironmentConnections lists active connections not owned by an
// organization. Their users must already be linked: environment
// connections never provision.
func (r *Repository) EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]federation.ConnectionSummary, error) {
	out := []federation.ConnectionSummary{}
	err := r.db.SelectContext(ctx, &out, `SELECT id,name,provider FROM federation_connections WHERE environment_id=$1 AND organization_id IS NULL AND active ORDER BY name, id`, environment)
	return out, failure(err)
}

func (r *Repository) ActiveOrganization(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND environment_id=$2 AND active)`, organization, environment)
	return ok, failure(err)
}

func (r *Repository) HasUser(ctx context.Context, environment identity.EnvironmentID, email string) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM users WHERE environment_id=$1 AND email=$2)`, environment, email)
	return ok, failure(err)
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
		Provider     string                  `db:"provider"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT c.organization_id, c.id, c.enforcement, c.provider
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
	return federation.Discovery{Method: federation.MethodSSO, Organization: &row.Organization, Connection: &row.Connection, Required: row.Enforcement == federation.EnforcementEnforced, Provider: row.Provider}, nil
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
	user, origin := existing.ID, "jit"
	switch {
	case errors.Is(err, sql.ErrNoRows) && !p.Create:
		return errx.Unauthorized("external identity is not linked")
	case errors.Is(err, sql.ErrNoRows):
		user = p.User
		if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,email_verified,avatar_url,home_organization_id) VALUES($1,$2,$3,$4,'',true,$5,$6)`, user, p.Environment, p.Email, p.Name, p.AvatarURL, p.Organization); err != nil {
			return conflict(err)
		}
		if err = eventpg.UserCreated(ctx, tx, p.Environment, user.String(), user, identity.OrganizationID{}, "federation"); err != nil {
			return err
		}
	case err != nil:
		return failure(err)
	case !existing.Active:
		// A deactivated account stays deactivated; SSO must not revive it.
		return errx.Unauthorized("user is inactive")
	case !p.Create:
		// Linking by email without JIT: only an account that is already a
		// member of the organization, which this login never changes.
		var member bool
		if err = tx.GetContext(ctx, &member, `SELECT EXISTS(SELECT 1 FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3)`, p.Environment, p.Organization, user); err != nil {
			return failure(err)
		}
		if !member {
			return errx.Unauthorized("external identity is not linked")
		}
		origin = "email"
	}
	// A subject already linked to another user of this connection, or a user
	// already linked to another subject, is a conflict for an operator.
	if _, err = tx.ExecContext(ctx, `INSERT INTO external_identities(connection_id,environment_id,user_id,subject,origin) VALUES($1,$2,$3,$4,$5)`, p.Connection, p.Environment, user, p.Subject, origin); err != nil {
		return conflict(err)
	}
	if err = fillAvatar(ctx, tx, p.Environment, user, p.AvatarURL); err != nil {
		return err
	}
	if !p.Create {
		if err = audit(ctx, tx, federation.Mutation{Environment: p.Environment, Actor: user.String(), Action: "federation.email", Target: "/federation-connections/" + p.Connection.String() + "/identities?user=" + user.String()}); err != nil {
			return err
		}
		return failure(tx.Commit())
	}
	// An existing membership is left as is: SSO must not undo an operator's
	// or directory's deactivation (the session then fails with 403).
	res, err := tx.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3) ON CONFLICT (organization_id,user_id) DO NOTHING`, p.Environment, p.Organization, user)
	if err != nil {
		return failure(err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if err = eventpg.Membership(ctx, tx, p.Environment, user.String(), event.MembershipCreated, p.Organization, user); err != nil {
			return err
		}
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

// Join links a first-time identity of an environment connection: to the
// active user with the (provider-verified) email when j.Link, or to a new
// passwordless user with a verified email in the sign-up organization (and
// group) when j.Signup. An existing account is never linked without j.Link,
// and a deactivated one never revived. The audit actor is the user.
func (r *Repository) Join(ctx context.Context, j federation.Joining) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var existing struct {
		ID     identity.UserID `db:"id"`
		Active bool            `db:"active"`
	}
	err = tx.GetContext(ctx, &existing, `SELECT id, active FROM users WHERE environment_id=$1 AND email=$2 FOR UPDATE`, j.Environment, j.Email)
	user, origin := existing.ID, "email"
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !j.Signup {
			return errx.Unauthorized("external identity is not linked")
		}
		var open bool
		if err = tx.GetContext(ctx, &open, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND environment_id=$2 AND active FOR SHARE)`, j.Organization, j.Environment); err != nil {
			return failure(err)
		}
		if !open {
			return errx.Unauthorized("sign-up is not available")
		}
		user, origin = j.User, "signup"
		if _, err = tx.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,email_verified,avatar_url,home_organization_id) VALUES($1,$2,$3,$4,'',true,$5,$6)`, user, j.Environment, j.Email, j.Name, j.AvatarURL, j.Organization); err != nil {
			return conflict(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3)`, j.Environment, j.Organization, user); err != nil {
			return failure(err)
		}
		if err = eventpg.UserCreated(ctx, tx, j.Environment, user.String(), user, j.Organization, "federation"); err != nil {
			return err
		}
		if !j.Group.IsZero() {
			if _, err = tx.ExecContext(ctx, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
				SELECT id,environment_id,organization_id,$4 FROM groups WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND connection_id IS NULL
				ON CONFLICT DO NOTHING`, j.Group, j.Environment, j.Organization, user); err != nil {
				return failure(err)
			}
		}
	case err != nil:
		return failure(err)
	case !existing.Active:
		return errx.Unauthorized("user is inactive")
	case !j.Link:
		return federation.ErrAccountExists()
	}
	// A user already linked to another subject of this connection is a
	// conflict for an operator, not a second link.
	if _, err = tx.ExecContext(ctx, `INSERT INTO external_identities(connection_id,environment_id,user_id,subject,origin) VALUES($1,$2,$3,$4,$5)`, j.Connection, j.Environment, user, j.Subject, origin); err != nil {
		return conflict(err)
	}
	if err = fillAvatar(ctx, tx, j.Environment, user, j.AvatarURL); err != nil {
		return err
	}
	if err = audit(ctx, tx, federation.Mutation{Environment: j.Environment, Actor: user.String(), Action: "federation." + origin, Target: "/federation-connections/" + j.Connection.String() + "/identities?user=" + user.String()}); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// fillAvatar gives a just-linked account the provider's picture when it
// has none.
func fillAvatar(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, user identity.UserID, avatar string) error {
	if avatar == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET avatar_url=$3 WHERE environment_id=$1 AND id=$2 AND avatar_url=''`, environment, user, avatar)
	return failure(err)
}

// Refresh updates the active user linked to p.Subject: its name (and
// avatar) when the
// provider sent one, and its email when p.Email is set, differs, the
// account is passwordless (the provider is how it signs in), no SCIM
// directory manages it, no other account has the email and, for an
// organization connection, the organization verified its domain. The email
// stays verified. A change is audited with the user as actor.
func (r *Repository) Refresh(ctx context.Context, p federation.Profile) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var u struct {
		ID       identity.UserID `db:"id"`
		Name     string          `db:"name"`
		Email    string          `db:"email"`
		Avatar   string          `db:"avatar_url"`
		Password string          `db:"password_hash"`
		Managed  bool            `db:"managed"`
	}
	err = tx.GetContext(ctx, &u, `SELECT u.id, u.name, u.email, u.avatar_url, u.password_hash,
		EXISTS(SELECT 1 FROM provisioned_identities i WHERE i.user_id=u.id AND i.environment_id=u.environment_id AND i.deprovisioned_at IS NULL) AS managed
		FROM external_identities x JOIN users u ON u.id=x.user_id AND u.environment_id=x.environment_id
		WHERE x.connection_id=$1 AND x.environment_id=$2 AND x.subject=$3 AND u.active FOR UPDATE OF u`, p.Connection, p.Environment, p.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return failure(err)
	}
	name, email, avatar := u.Name, u.Email, u.Avatar
	if p.Name != "" {
		name = p.Name
	}
	if p.AvatarURL != "" {
		avatar = p.AvatarURL
	}
	if p.Email != "" && p.Email != u.Email && u.Password == "" && !u.Managed {
		ok := true
		if !p.Organization.IsZero() {
			if err = tx.GetContext(ctx, &ok, `SELECT EXISTS(SELECT 1 FROM organization_domains WHERE environment_id=$1 AND organization_id=$2 AND domain=$3 AND verified_at IS NOT NULL)`, p.Environment, p.Organization, identity.EmailDomain(p.Email)); err != nil {
				return failure(err)
			}
		}
		if ok {
			if err = tx.GetContext(ctx, &ok, `SELECT NOT EXISTS(SELECT 1 FROM users WHERE environment_id=$1 AND email=$2)`, p.Environment, p.Email); err != nil {
				return failure(err)
			}
		}
		if ok {
			email = p.Email
		}
	}
	if name == u.Name && email == u.Email && avatar == u.Avatar {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET name=$3, email=$4, email_verified=CASE WHEN email=$4 THEN email_verified ELSE true END, avatar_url=$5 WHERE id=$1 AND environment_id=$2`, u.ID, p.Environment, name, email, avatar); err != nil {
		return conflict(err)
	}
	if err = audit(ctx, tx, federation.Mutation{Environment: p.Environment, Actor: u.ID.String(), Action: "federation.profile_updated", Target: "/users/" + u.ID.String()}); err != nil {
		return err
	}
	return failure(tx.Commit())
}
