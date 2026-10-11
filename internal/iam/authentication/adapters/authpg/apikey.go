package authpg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

// neverAfter is how far ahead an expiry counts as "never".
const neverAfter = 50 * 365 * 24 * time.Hour

// APIKey resolves an API key (user, organization or machine user) by its
// hash. Every check a session token gets from its session row is made here
// on each use: the key must be unrevoked and unexpired, the environment's
// policy must allow its kind, the organization must be live, user keys need
// an active person with an active membership, machine keys an active machine
// user with an active membership and an active application linked to the
// resource; and the permissions are api_key_permissions now (the key's list
// ∩ the resource's allowlist ∩ the owner's reach). A key with no effective
// permission is no key.
func (r *Repository) APIKey(ctx context.Context, hash []byte) (authentication.ResolvedAPIKey, error) {
	var row struct {
		ID           identity.APIKeyID       `db:"id"`
		Environment  identity.EnvironmentID  `db:"environment_id"`
		OwnerKind    string                  `db:"owner_kind"`
		User         identity.UserID         `db:"user_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Application  identity.ApplicationID  `db:"application_id"`
		Resource     identity.ResourceID     `db:"resource_id"`
		Name         string                  `db:"name"`
		Expires      time.Time               `db:"expires_at"`
		Audience     string                  `db:"audience"`
		Permissions  pq.StringArray          `db:"permissions"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT k.id,k.environment_id,k.owner_kind,k.user_id,k.organization_id,k.application_id,k.resource_id,k.name,k.expires_at,r.audience,
			api_key_permissions(k.owner_kind,k.permissions,k.environment_id,k.organization_id,k.user_id,k.resource_id) AS permissions
		FROM api_keys k
		JOIN organizations o ON o.id=k.organization_id AND o.environment_id=k.environment_id AND o.active
		JOIN resources r ON r.id=k.resource_id AND r.environment_id=k.environment_id
		LEFT JOIN api_key_policies pol ON pol.environment_id=k.environment_id
		LEFT JOIN users u ON u.id=k.user_id AND u.environment_id=k.environment_id
		LEFT JOIN memberships m ON m.environment_id=k.environment_id AND m.organization_id=k.organization_id AND m.user_id=k.user_id
		LEFT JOIN applications a ON a.id=k.application_id AND a.environment_id=k.environment_id
		WHERE k.secret_hash=$1 AND k.revoked_at IS NULL AND k.expires_at>now()
		  AND CASE k.owner_kind
		    WHEN 'user' THEN coalesce(pol.user_keys,false) AND u.kind='human' AND u.active AND m.active
		    WHEN 'organization' THEN coalesce(pol.organization_keys,false)
		    ELSE u.kind='machine' AND u.active AND m.active AND a.active
		      AND EXISTS (SELECT 1 FROM application_resources ar WHERE ar.environment_id=k.environment_id AND ar.application_id=k.application_id AND ar.resource_id=k.resource_id)
		  END`, hash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && len(row.Permissions) == 0) {
		return authentication.ResolvedAPIKey{}, errx.Unauthorized("invalid credentials or API key")
	}
	if err != nil {
		return authentication.ResolvedAPIKey{}, failure(err)
	}
	// A use is recorded at most once per config.APIKeyUsedInterval so busy
	// clients do not rewrite the row per request; a machine key's use also
	// counts as the machine user signing in.
	if _, err = r.db.ExecContext(ctx, `WITH used AS (
			UPDATE api_keys SET last_used_at=now() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at<now()-make_interval(secs => $2)) RETURNING user_id, environment_id, owner_kind)
		UPDATE users u SET last_signed_in_at=now() FROM used WHERE used.owner_kind='machine' AND u.id=used.user_id AND u.environment_id=used.environment_id`,
		row.ID, config.APIKeyUsedInterval.Seconds()); err != nil {
		return authentication.ResolvedAPIKey{}, failure(err)
	}
	// owner.id is the user of user and machine keys; an organization key's
	// organization is owner.organization_id (SDKs document id as empty).
	owner := authentication.APIKeyOwner{Type: row.OwnerKind, Organization: row.Organization}
	if row.OwnerKind != "organization" {
		owner.ID = row.User.String()
	}
	var exp int64
	if row.Expires.Before(time.Now().Add(neverAfter)) {
		exp = row.Expires.Unix()
	}
	permissions := []string(row.Permissions)
	return authentication.ResolvedAPIKey{
		ID: row.ID,
		Token: authentication.Token{
			Access:  identity.Access{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource, Permissions: permissions},
			Subject: row.User, Purpose: authentication.PurposeAPIKey, ID: row.ID.String(),
			Audience: []string{row.Audience}, ExpiresAt: exp,
			APIKey: &authentication.APIKeyClaims{ID: row.ID, Name: row.Name, Owner: owner, Resource: row.Resource, Permissions: permissions, ExpiresAt: exp},
		},
		Owner:    row.OwnerKind,
		Audience: row.Audience,
		Expires:  row.Expires,
	}, nil
}

// APIKeySession reuses the machine key's live session when it lasts past
// after, else opens session; the session ends with the key (revocation in
// apikeypg, deletion by cascade).
func (r *Repository) APIKeySession(ctx context.Context, k authentication.ResolvedAPIKey, session identity.SessionID, after, expires time.Time) (identity.SessionID, error) {
	var existing identity.SessionID
	err := r.db.GetContext(ctx, &existing, `SELECT id FROM sessions WHERE environment_id=$1 AND api_key_id=$2 AND revoked_at IS NULL AND expires_at>$3 ORDER BY expires_at DESC LIMIT 1`, k.Token.EnvironmentID, k.ID, after)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return identity.SessionID{}, failure(err)
	}
	clientIP, clientAgent := identity.ClientInfoFrom(ctx).Args()
	_, err = r.db.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,api_key_id,ip_address,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		session, k.Token.EnvironmentID, k.Token.OrganizationID, k.Token.Subject, k.Token.ApplicationID, k.Token.ResourceID, expires, k.ID, clientIP, clientAgent)
	return session, failure(err)
}
