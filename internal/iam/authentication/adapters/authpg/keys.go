package authpg

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/lib/pq"
)

// MachineKey resolves a live machine user key.
func (r *Repository) MachineKey(ctx context.Context, key identity.UserKeyID) (authentication.MachineKey, error) {
	var row struct {
		ID          identity.UserKeyID     `db:"id"`
		Environment identity.EnvironmentID `db:"environment_id"`
		User        identity.UserID        `db:"user_id"`
		PublicKey   []byte                 `db:"public_jwk"`
		Expires     time.Time              `db:"expires_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT k.id,k.environment_id,k.user_id,k.public_jwk,k.expires_at
		FROM user_keys k JOIN users u ON u.id=k.user_id AND u.environment_id=k.environment_id
		WHERE k.id=$1 AND k.expires_at>now() AND u.kind='machine' AND u.active`, key)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.MachineKey{}, errx.Unauthorized("invalid assertion")
	}
	if err != nil {
		return authentication.MachineKey{}, failure(err)
	}
	return authentication.MachineKey{ID: row.ID, Environment: row.Environment, User: row.User, PublicKey: json.RawMessage(row.PublicKey), Expires: row.Expires}, nil
}

// assertionReplayKey is the client_assertion_jtis key of a machine user
// key's assertion; the prefix keeps it apart from OAuth clients' jtis.
func assertionReplayKey(key identity.UserKeyID, jti string) []byte {
	sum := sha256.Sum256([]byte("user_key:" + key.String() + "\x00" + jti))
	return sum[:]
}

// KeySession checks the grant and returns the key's session in its
// boundary, all in one transaction: the jti is spent (shared replay table
// with private_key_jwt), the key must still exist, the machine user must
// have access to the resource in the organization, and the session is
// the key's live one there or a new one (amr swk).
func (r *Repository) KeySession(ctx context.Context, g authentication.KeyGrant, session identity.SessionID, after, expires time.Time) (authentication.KeySession, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return authentication.KeySession{}, failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM client_assertion_jtis WHERE expires_at<now()`); err != nil {
		return authentication.KeySession{}, failure(err)
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO client_assertion_jtis(hash,expires_at) VALUES($1,$2) ON CONFLICT (hash) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE client_assertion_jtis.expires_at<=now()`,
		assertionReplayKey(g.Key.ID, g.Assertion.JTI), g.Assertion.Expires)
	if err != nil {
		return authentication.KeySession{}, failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return authentication.KeySession{}, failure(err)
		}
		return authentication.KeySession{}, errx.Unauthorized("assertion already used")
	}
	// Removing the key revokes its sessions; holding the row keeps a
	// removal from racing past a session opened here.
	var live bool
	if err = tx.GetContext(ctx, &live, `SELECT EXISTS(SELECT 1 FROM user_keys WHERE id=$1 AND environment_id=$2 AND user_id=$3 AND expires_at>now() FOR SHARE)`, g.Key.ID, g.Key.Environment, g.Key.User); err != nil {
		return authentication.KeySession{}, failure(err)
	}
	if !live {
		return authentication.KeySession{}, errx.Unauthorized("invalid assertion")
	}
	access, err := Resolve(ctx, tx, g.Boundary, g.Key.User)
	if err != nil {
		return authentication.KeySession{}, err
	}
	out := authentication.KeySession{Audience: access.Audience, Permissions: access.Permissions}
	var existing struct {
		ID            identity.SessionID `db:"id"`
		Authenticated time.Time          `db:"authenticated_at"`
	}
	b := g.Boundary
	err = tx.GetContext(ctx, &existing, `SELECT id,authenticated_at FROM sessions WHERE environment_id=$1 AND user_key_id=$2 AND organization_id=$3 AND application_id=$4 AND resource_id=$5 AND user_id=$6
		AND revoked_at IS NULL AND expires_at>$7 ORDER BY expires_at DESC LIMIT 1`, b.EnvironmentID, g.Key.ID, b.OrganizationID, b.ApplicationID, b.ResourceID, g.Key.User, after)
	switch {
	case err == nil:
		out.Session, out.Authenticated = existing.ID, existing.Authenticated
	case errors.Is(err, sql.ErrNoRows):
		now := time.Now().UTC().Truncate(time.Second)
		if _, err = tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,amr,authenticated_at,user_key_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			session, b.EnvironmentID, b.OrganizationID, g.Key.User, b.ApplicationID, b.ResourceID, expires, pq.StringArray{authentication.AMRKey}, now, g.Key.ID); err != nil {
			return authentication.KeySession{}, failure(err)
		}
		out.Session, out.Authenticated = session, now
	default:
		return authentication.KeySession{}, failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE user_keys SET last_used_at=now() WHERE id=$1`, g.Key.ID); err != nil {
		return authentication.KeySession{}, failure(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET last_signed_in_at=now() WHERE environment_id=$1 AND id=$2`, g.Key.Environment, g.Key.User); err != nil {
		return authentication.KeySession{}, failure(err)
	}
	return out, failure(tx.Commit())
}
