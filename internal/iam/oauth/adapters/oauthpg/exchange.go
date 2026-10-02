package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

// exchangeRoot is the live, not impersonated root session of a subject
// token (locked for the exchange).
type exchangeRoot struct {
	Resource      identity.ResourceID `db:"resource_id"`
	Parent        *identity.SessionID `db:"parent_session_id"`
	Expires       time.Time           `db:"expires_at"`
	AMR           pq.StringArray      `db:"amr"`
	Authenticated time.Time           `db:"authenticated_at"`
}

func (r *Repository) ExchangeSession(ctx context.Context, client *oauth.Client, subject authentication.Token, audience string, id identity.SessionID) (oauth.ExchangeSession, error) {
	var out oauth.ExchangeSession
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	var target identity.ResourceID
	err = tx.GetContext(ctx, &target, `SELECT r.id FROM resources r JOIN application_resources ar ON ar.resource_id=r.id AND ar.environment_id=r.environment_id WHERE r.environment_id=$1 AND ar.application_id=$2 AND r.audience=$3`, client.Environment, client.Application, audience)
	if errors.Is(err, sql.ErrNoRows) {
		return out, oauth.ExchangeError(oauth.ExchangeInvalidTarget, "audience is not a resource of the application")
	}
	if err != nil {
		return out, failure(err)
	}
	// The subject token's session: a root session, or a child one (then
	// the exchange starts from its parent).
	var root exchangeRoot
	rootID := subject.SessionID
	err = tx.GetContext(ctx, &root, `SELECT resource_id,parent_session_id,expires_at,amr,authenticated_at FROM sessions WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND organization_id=$4 AND application_id=$5 AND revoked_at IS NULL AND expires_at>now() AND actor_id IS NULL AND actor_account_id IS NULL FOR UPDATE`, rootID, client.Environment, subject.Subject, subject.OrganizationID, client.Application)
	if err == nil && root.Parent != nil {
		rootID = *root.Parent
		err = tx.GetContext(ctx, &root, `SELECT resource_id,parent_session_id,expires_at,amr,authenticated_at FROM sessions WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>now() AND parent_session_id IS NULL FOR UPDATE`, rootID, client.Environment, subject.Subject)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return out, oauth.ExchangeError(oauth.ExchangeInvalidRequest, "subject_token session ended")
	}
	if err != nil {
		return out, failure(err)
	}
	b := authentication.Context{EnvironmentID: client.Environment, OrganizationID: subject.OrganizationID, ApplicationID: client.Application, ResourceID: target}
	access, err := authpg.Resolve(ctx, tx, b, subject.Subject)
	if err != nil {
		return out, oauth.ExchangeError(oauth.ExchangeInvalidTarget, "the user has no access to the target resource")
	}
	session := rootID
	if root.Resource != target {
		err = tx.GetContext(ctx, &session, `SELECT id FROM sessions WHERE parent_session_id=$1 AND resource_id=$2 AND revoked_at IS NULL`, rootID, target)
		if errors.Is(err, sql.ErrNoRows) {
			session = id
			_, err = tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,amr,authenticated_at,parent_session_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, client.Environment, subject.OrganizationID, subject.Subject, client.Application, target, root.Expires, root.AMR, root.Authenticated, rootID)
			if err == nil {
				err = eventpg.AuditWith(ctx, tx, client.Environment, client.ID.String(), "oauth.token_exchanged", id.String(),
					map[string]any{"user_id": subject.Subject.String(), "oauth_client_id": client.ID.String(), "resource_id": target.String(), "parent_session_id": rootID.String()})
			}
		}
		if err != nil {
			return out, failure(err)
		}
	}
	out = oauth.ExchangeSession{Environment: client.Environment, User: subject.Subject, Session: session, Organization: subject.OrganizationID, Application: client.Application, Resource: target, Audience: access.Audience, Permissions: access.Permissions, AMR: []string(root.AMR), Authenticated: root.Authenticated}
	return out, failure(tx.Commit())
}

func (r *Repository) ImpersonationSession(ctx context.Context, input oauth.Impersonation, id identity.SessionID, expires time.Time) (oauth.ExchangeSession, error) {
	var out oauth.ExchangeSession
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return out, failure(err)
	}
	defer tx.Rollback()
	var account struct {
		Environment identity.EnvironmentID `db:"environment_id"`
		Application identity.ApplicationID `db:"application_id"`
		Resource    identity.ResourceID    `db:"resource_id"`
		Audience    string                 `db:"audience"`
		Allowed     bool                   `db:"can_impersonate"`
	}
	err = tx.GetContext(ctx, &account, `SELECT s.environment_id,s.application_id,s.resource_id,r.audience,s.can_impersonate FROM service_accounts s JOIN resources r ON r.id=s.resource_id AND r.environment_id=s.environment_id JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.active`, input.Account)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, failure(err)
	}
	if err != nil || !account.Allowed {
		return out, oauth.ExchangeError(oauth.ExchangeUnauthorizedClient, "the service account may not impersonate")
	}
	if input.Audience != "" && input.Audience != account.Audience {
		return out, oauth.ExchangeError(oauth.ExchangeInvalidTarget, "audience must be the service account's resource")
	}
	var active bool
	err = tx.GetContext(ctx, &active, `SELECT active FROM users WHERE id=$1 AND environment_id=$2 FOR UPDATE`, input.User, account.Environment)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !active) {
		return out, oauth.ExchangeError(oauth.ExchangeInvalidRequest, "active user not found")
	}
	if err != nil {
		return out, failure(err)
	}
	b := authentication.Context{EnvironmentID: account.Environment, OrganizationID: input.Organization, ApplicationID: account.Application, ResourceID: account.Resource}
	access, err := authpg.Resolve(ctx, tx, b, input.User)
	if err != nil {
		return out, oauth.ExchangeError(oauth.ExchangeInvalidRequest, "the user has no access to the service account's resource in that organization")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,actor_account_id,impersonation_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, account.Environment, input.Organization, input.User, account.Application, account.Resource, expires, input.Account, input.Reason); err != nil {
		return out, failure(err)
	}
	if err = eventpg.AuditWith(ctx, tx, account.Environment, input.Account.String(), "oauth.impersonated", id.String(),
		map[string]any{"user_id": input.User.String(), "service_account_id": input.Account.String(), "organization_id": input.Organization.String()}); err != nil {
		return out, failure(err)
	}
	out = oauth.ExchangeSession{Environment: account.Environment, User: input.User, ActorAccount: input.Account, Session: id, Organization: input.Organization, Application: account.Application, Resource: account.Resource, Audience: access.Audience, Permissions: access.Permissions}
	return out, failure(tx.Commit())
}

var _ oauth.ExchangeRepository = (*Repository)(nil)
