// Package hostedpg persists hosted login state and branding in PostgreSQL.
package hostedpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ hosted.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "hosted login persistence failed", errx.TypeInternal)
}

func (r *Repository) Settings(ctx context.Context, environment identity.EnvironmentID) (hosted.Settings, error) {
	out := hosted.Settings{Environment: environment}
	err := r.db.GetContext(ctx, &out, `SELECT environment_id,display_name,logo_url,accent_color,updated_at FROM login_settings WHERE environment_id=$1`, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return hosted.Settings{Environment: environment}, nil
	}
	return out, failure(err)
}

func (r *Repository) SaveSettings(ctx context.Context, m hosted.Mutation, input hosted.Settings) (hosted.Settings, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	defer tx.Rollback()
	var out hosted.Settings
	err = tx.GetContext(ctx, &out, `INSERT INTO login_settings(environment_id,display_name,logo_url,accent_color) VALUES($1,$2,$3,$4)
		ON CONFLICT (environment_id) DO UPDATE SET display_name=EXCLUDED.display_name, logo_url=EXCLUDED.logo_url, accent_color=EXCLUDED.accent_color, updated_at=now()
		RETURNING environment_id,display_name,logo_url,accent_color,updated_at`, m.Environment, input.DisplayName, input.LogoURL, input.AccentColor)
	if err != nil {
		return hosted.Settings{}, failure(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return hosted.Settings{}, failure(err)
	}
	return out, failure(tx.Commit())
}

func (r *Repository) SaveLogin(ctx context.Context, hash []byte, environment identity.EnvironmentID, v authentication.Verified, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO hosted_logins(ticket_hash,environment_id,user_id,email,method,organization_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (ticket_hash) DO UPDATE SET environment_id=EXCLUDED.environment_id, user_id=EXCLUDED.user_id, email=EXCLUDED.email, method=EXCLUDED.method, organization_id=EXCLUDED.organization_id, expires_at=EXCLUDED.expires_at`,
		hash, environment, v.User, v.Email, v.Method, v.Organization, expires)
	return failure(err)
}

func (r *Repository) Login(ctx context.Context, hash []byte, environment identity.EnvironmentID) (authentication.Verified, error) {
	var row struct {
		User         identity.UserID         `db:"user_id"`
		Email        string                  `db:"email"`
		Method       string                  `db:"method"`
		Organization identity.OrganizationID `db:"organization_id"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT user_id,email,method,organization_id FROM hosted_logins WHERE ticket_hash=$1 AND environment_id=$2 AND expires_at>now()`, hash, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.Verified{}, errx.Unauthorized("sign in again")
	}
	if err != nil {
		return authentication.Verified{}, failure(err)
	}
	return authentication.Verified{User: row.User, Email: row.Email, Method: row.Method, Organization: row.Organization}, nil
}

// DeleteLogin removes the login, and every expired one with it.
func (r *Repository) DeleteLogin(ctx context.Context, hash []byte) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM hosted_logins WHERE ticket_hash=$1 OR expires_at<now()`, hash)
	return failure(err)
}
