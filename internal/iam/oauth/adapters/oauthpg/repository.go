package oauthpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }

type clientRow struct {
	ID          identity.ClientID      `db:"id"`
	Environment identity.EnvironmentID `db:"environment_id"`
	Application identity.ApplicationID `db:"application_id"`
	Resource    identity.ResourceID    `db:"resource_id"`
	Audience    string                 `db:"audience"`
	Redirects   pq.StringArray         `db:"redirect_uris"`
	Public      bool                   `db:"public"`
	Secret      []byte                 `db:"secret_hash"`
	HostedLogin bool                   `db:"hosted_login"`
	PostLogout  pq.StringArray         `db:"post_logout_redirect_uris"`
	TokenFormat string                 `db:"access_token_format"`
	Grants      pq.StringArray         `db:"grant_types"`
	Initiate    string                 `db:"initiate_login_uri"`
	Source      string                 `db:"source"`
	ExternalID  sql.NullString         `db:"external_id"`
	Name        string                 `db:"client_name"`
	Admission   string                 `db:"admission"`
	Expires     *time.Time             `db:"admission_expires_at"`
	AnyPort     bool                   `db:"loopback_any_port"`
	authRow
	protectedRow
}

// protectedRow is the client's protected resource, if any (LEFT JOIN).
type protectedRow struct {
	Permissions    pq.StringArray                `db:"permissions"`
	ProtectedID    *identity.ProtectedResourceID `db:"protected_id"`
	ProtectedURI   sql.NullString                `db:"protected_uri"`
	ProtectedScope pq.StringArray                `db:"protected_default_scopes"`
	ProtectedIdle  sql.NullInt64                 `db:"protected_idle"`
	ProtectedMax   sql.NullInt64                 `db:"protected_max"`
	PolicyIdle     sql.NullInt64                 `db:"policy_idle"`
	PolicyLifetime sql.NullInt64                 `db:"policy_lifetime"`
}

func (p protectedRow) target() *oauth.ProtectedTarget {
	if p.ProtectedID == nil {
		return nil
	}
	var policy *oauth.ProtectedResourcePolicy
	if p.PolicyIdle.Valid {
		policy = &oauth.ProtectedResourcePolicy{MaxIdleTTLSeconds: p.PolicyIdle.Int64, MaxLifetimeTTLSeconds: p.PolicyLifetime.Int64}
	}
	return oauth.NewProtectedTarget(oauth.ProtectedResource{ID: *p.ProtectedID, URI: p.ProtectedURI.String, DefaultScopes: []string(p.ProtectedScope), IdleTTLSeconds: p.ProtectedIdle.Int64, MaxTTLSeconds: p.ProtectedMax.Int64}, []string(p.Permissions), policy)
}

func (r *Repository) FindActive(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	var row clientRow
	// An external client exists only through its protected resource: it is
	// found while that resource is active.
	err := r.db.GetContext(ctx, &row, `SELECT c.id,c.environment_id,c.application_id,c.resource_id,c.redirect_uris,c.public,c.secret_hash,c.hosted_login,c.post_logout_redirect_uris,c.token_endpoint_auth_method,c.token_endpoint_auth_signing_alg,c.jwks,c.jwks_uri,c.access_token_format,c.grant_types,c.initiate_login_uri,c.source,c.external_id,c.client_name,c.admission,c.admission_expires_at,c.loopback_any_port,r.audience,r.permissions,pr.id AS protected_id,pr.uri AS protected_uri,pr.default_scopes AS protected_default_scopes,pr.idle_ttl_seconds AS protected_idle,pr.max_ttl_seconds AS protected_max,pp.max_idle_ttl_seconds AS policy_idle,pp.max_lifetime_ttl_seconds AS policy_lifetime FROM oauth_clients c JOIN applications a ON a.id=c.application_id AND a.environment_id=c.environment_id JOIN resources r ON r.id=c.resource_id AND r.environment_id=c.environment_id LEFT JOIN protected_resources pr ON pr.resource_id=c.resource_id AND pr.environment_id=c.environment_id AND pr.application_id=c.application_id AND pr.active AND (c.protected_resource_id IS NULL OR pr.id=c.protected_resource_id) LEFT JOIN protected_resource_policies pp ON pp.environment_id=c.environment_id WHERE c.id=$1 AND c.environment_id=$2 AND c.active AND a.active AND (c.protected_resource_id IS NULL OR pr.id IS NOT NULL)`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("OAuth client not found")
	}
	if err != nil {
		return nil, errx.Wrap(err, "load OAuth client", errx.TypeInternal)
	}
	return &oauth.Client{ID: row.ID, Environment: row.Environment, Application: row.Application, Resource: row.Resource, Audience: row.Audience, Redirects: []string(row.Redirects), Public: row.Public, Secret: row.Secret, HostedLogin: row.HostedLogin, PostLogoutRedirects: []string(row.PostLogout), Auth: row.auth(), AccessTokenFormat: row.TokenFormat, GrantTypes: []string(row.Grants), InitiateLoginURI: row.Initiate, Protected: row.target(),
		Source: row.Source, ExternalID: row.ExternalID.String, Name: row.Name, Admission: row.Admission, AdmissionExpiresAt: row.Expires, LoopbackAnyPort: row.AnyPort}, nil
}

func (r *Repository) FindAccount(ctx context.Context, id identity.AccountID) (*oauth.Account, error) {
	var row struct {
		ID          identity.AccountID     `db:"id"`
		Environment identity.EnvironmentID `db:"environment_id"`
		Secret      []byte                 `db:"secret_hash"`
		authRow
	}
	err := r.db.GetContext(ctx, &row, `SELECT s.id,s.environment_id,s.secret_hash,s.token_endpoint_auth_method,s.token_endpoint_auth_signing_alg,s.jwks,s.jwks_uri FROM service_accounts s JOIN applications a ON a.id=s.application_id AND a.environment_id=s.environment_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND a.active`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("service account not found")
	}
	if err != nil {
		return nil, errx.Wrap(err, "load service account", errx.TypeInternal)
	}
	return &oauth.Account{ID: row.ID, Environment: row.Environment, Secret: row.Secret, Auth: row.auth()}, nil
}

var _ oauth.ClientRepository = (*Repository)(nil)
var _ oauth.AccountRepository = (*Repository)(nil)
