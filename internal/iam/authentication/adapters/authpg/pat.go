package authpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

// AccessToken resolves a personal access token. Every check a session
// token gets from its session row is made here on each use: the token,
// the machine user, the membership, the organization and the application
// must be live, and the permissions come from effective_grants now.
func (r *Repository) AccessToken(ctx context.Context, hash []byte) (authentication.PersonalAccessToken, error) {
	var row struct {
		ID           identity.AccessTokenID  `db:"id"`
		Environment  identity.EnvironmentID  `db:"environment_id"`
		User         identity.UserID         `db:"user_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Application  identity.ApplicationID  `db:"application_id"`
		Resource     identity.ResourceID     `db:"resource_id"`
		Expires      time.Time               `db:"expires_at"`
		Audience     string                  `db:"audience"`
		Permissions  pq.StringArray          `db:"permissions"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT t.id,t.environment_id,t.user_id,t.organization_id,t.application_id,t.resource_id,t.expires_at,r.audience,g.permissions
		FROM user_access_tokens t
		JOIN users u ON u.id=t.user_id AND u.environment_id=t.environment_id
		JOIN memberships m ON m.environment_id=t.environment_id AND m.organization_id=t.organization_id AND m.user_id=t.user_id
		JOIN organizations o ON o.id=t.organization_id AND o.environment_id=t.environment_id
		JOIN applications a ON a.id=t.application_id AND a.environment_id=t.environment_id
		JOIN resources r ON r.id=t.resource_id AND r.environment_id=t.environment_id
		JOIN effective_grants g ON g.environment_id=t.environment_id AND g.organization_id=t.organization_id AND g.user_id=t.user_id AND g.resource_id=t.resource_id
		WHERE t.secret_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now()
		  AND u.kind='machine' AND u.active AND m.active AND o.active AND a.active`, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PersonalAccessToken{}, errx.Unauthorized("invalid credentials or access token")
	}
	if err != nil {
		return authentication.PersonalAccessToken{}, failure(err)
	}
	// A use counts as the machine user signing in; written at most once a
	// minute per token so busy clients do not rewrite the row per request.
	if _, err = r.db.ExecContext(ctx, `WITH used AS (
			UPDATE user_access_tokens SET last_used_at=now() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute') RETURNING user_id, environment_id)
		UPDATE users u SET last_signed_in_at=now() FROM used WHERE u.id=used.user_id AND u.environment_id=used.environment_id`, row.ID); err != nil {
		return authentication.PersonalAccessToken{}, failure(err)
	}
	return authentication.PersonalAccessToken{
		ID: row.ID,
		Token: authentication.Token{
			Access:  identity.Access{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource, Permissions: []string(row.Permissions)},
			Subject: row.User, Purpose: authentication.PurposeAccessToken, ID: row.ID.String(),
			Audience: []string{row.Audience}, ExpiresAt: row.Expires.Unix(),
		},
		Audience: row.Audience,
		Expires:  row.Expires,
	}, nil
}

// AccessTokenSession reuses the token's live session when it lasts past
// after, else opens session; the session ends with the token (revocation
// in userpg, deletion by cascade).
func (r *Repository) AccessTokenSession(ctx context.Context, t authentication.PersonalAccessToken, session identity.SessionID, after, expires time.Time) (identity.SessionID, error) {
	var existing identity.SessionID
	err := r.db.GetContext(ctx, &existing, `SELECT id FROM sessions WHERE environment_id=$1 AND access_token_id=$2 AND revoked_at IS NULL AND expires_at>$3 ORDER BY expires_at DESC LIMIT 1`, t.Token.EnvironmentID, t.ID, after)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return identity.SessionID{}, failure(err)
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,access_token_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		session, t.Token.EnvironmentID, t.Token.OrganizationID, t.Token.Subject, t.Token.ApplicationID, t.Token.ResourceID, expires, t.ID)
	return session, failure(err)
}
