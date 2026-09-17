package oauthpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }

type clientRow struct {
	ID          string         `db:"id"`
	Environment string         `db:"environment_id"`
	Application string         `db:"application_id"`
	Resource    string         `db:"resource_id"`
	Audience    string         `db:"audience"`
	Redirects   pq.StringArray `db:"redirect_uris"`
	Public      bool           `db:"public"`
	Secret      []byte         `db:"secret_hash"`
}

func (r *Repository) FindActive(ctx context.Context, environment, id string) (*oauth.Client, error) {
	var row clientRow
	err := r.db.GetContext(ctx, &row, `SELECT c.id,c.environment_id,c.application_id,c.resource_id,c.redirect_uris,c.public,c.secret_hash,r.audience FROM oauth_clients c JOIN applications a ON a.id=c.application_id AND a.environment_id=c.environment_id JOIN resources r ON r.id=c.resource_id AND r.environment_id=c.environment_id WHERE c.id=$1 AND c.environment_id=$2 AND c.active AND a.active`, id, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errx.NotFound("OAuth client not found")
	}
	if err != nil {
		return nil, errx.Wrap(err, "load OAuth client", errx.TypeInternal)
	}
	return &oauth.Client{ID: row.ID, Environment: row.Environment, Application: row.Application, Resource: row.Resource, Audience: row.Audience, Redirects: []string(row.Redirects), Public: row.Public, Secret: row.Secret}, nil
}

var _ oauth.ClientRepository = (*Repository)(nil)
