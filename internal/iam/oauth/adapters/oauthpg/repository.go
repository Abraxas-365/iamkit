package oauthpg

import (
	"context"
	"database/sql"
	"errors"

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
	authRow
}

func (r *Repository) FindActive(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	var row clientRow
	err := r.db.GetContext(ctx, &row, `SELECT c.id,c.environment_id,c.application_id,c.resource_id,c.redirect_uris,c.public,c.secret_hash,c.hosted_login,c.post_logout_redirect_uris,c.token_endpoint_auth_method,c.token_endpoint_auth_signing_alg,c.jwks,c.jwks_uri,c.access_token_format,c.grant_types,r.audience FROM oauth_clients c JOIN applications a ON a.id=c.application_id AND a.environment_id=c.environment_id JOIN resources r ON r.id=c.resource_id AND r.environment_id=c.environment_id WHERE c.id=$1 AND c.environment_id=$2 AND c.active AND a.active`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("OAuth client not found")
	}
	if err != nil {
		return nil, errx.Wrap(err, "load OAuth client", errx.TypeInternal)
	}
	return &oauth.Client{ID: row.ID, Environment: row.Environment, Application: row.Application, Resource: row.Resource, Audience: row.Audience, Redirects: []string(row.Redirects), Public: row.Public, Secret: row.Secret, HostedLogin: row.HostedLogin, PostLogoutRedirects: []string(row.PostLogout), Auth: row.auth(), AccessTokenFormat: row.TokenFormat, GrantTypes: []string(row.Grants)}, nil
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
