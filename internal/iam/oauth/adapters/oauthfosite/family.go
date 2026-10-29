package oauthfosite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

func (s *Store) revokeFamily(ctx context.Context, id string) error {
	ctx, err := s.BeginTX(ctx)
	if err != nil {
		return err
	}
	defer s.Rollback(ctx)
	if err = s.lock(ctx, id); err != nil {
		return err
	}
	if _, err = s.executor(ctx).ExecContext(ctx, `UPDATE oauth_requests SET active=false WHERE environment_id=$1 AND request_id=$2`, s.Environment, id); err != nil {
		return wrap(err, "revoke OAuth family")
	}
	if revoking(ctx) {
		if err = s.endRevokedGrant(ctx, id); err != nil {
			return err
		}
	}
	return s.Commit(ctx)
}

// revocationKey marks an RFC 7009 revocation request's context (Revoking).
type revocationKey struct{}

// Revoking marks ctx as an RFC 7009 revocation (/oauth/revoke): revoking a
// resource grant's token there also ends its session (D34). Refresh
// rotation and code replay revoke families without it.
func Revoking(ctx context.Context) context.Context {
	return context.WithValue(ctx, revocationKey{}, true)
}

func revoking(ctx context.Context) bool {
	on, _ := ctx.Value(revocationKey{}).(bool)
	return on
}

// endRevokedGrant ends, in the revocation's transaction, the session of a
// revoked resource grant (RFC 8707 flow) when the session is bound to the
// grant's client and a protected resource: the grant's other tokens, and
// tokens exchanged from it (end_child_sessions), stop with it. A plain
// OpenID Connect grant (no resource) keeps its session, as before.
func (s *Store) endRevokedGrant(ctx context.Context, family string) error {
	var row struct {
		Client   string         `db:"client_id"`
		Session  sql.NullString `db:"sid"`
		Resource sql.NullString `db:"resource"`
	}
	err := sqlx.GetContext(ctx, s.executor(ctx), &row, `SELECT client_id, data->'Session'->'access_claims'->'Extra'->>'sid' AS sid, data->'Session'->>'resource' AS resource
		FROM oauth_requests WHERE environment_id=$1 AND request_id=$2 ORDER BY kind LIMIT 1`, s.Environment, family)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return wrap(err, "read revoked OAuth grant")
	}
	if row.Resource.String == "" || row.Session.String == "" {
		return nil
	}
	session, err := identity.ParseSessionID(row.Session.String)
	if err != nil {
		return nil
	}
	if _, err = s.executor(ctx).ExecContext(ctx, `SELECT set_config('iamkit.session_reason', 'token_revoked', true)`); err != nil {
		return wrap(err, "end revoked OAuth grant")
	}
	_, err = s.executor(ctx).ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND environment_id=$2 AND oauth_client_id=$3 AND protected_resource_id IS NOT NULL AND revoked_at IS NULL`, session, s.Environment, row.Client)
	return wrap(err, "end revoked OAuth grant")
}

// WithTokenLock serializes the entire lookup/validation/rotation across replicas.
// Fosite's transaction starts later, so a separate session advisory lock covers
// the read-before-rotation gap. The token endpoint validates client authentication
// through Fosite before any replay revocation can occur.
func (s *Store) WithTokenLock(ctx context.Context, raw, kind, client string, run func() error) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return run()
	}
	signature := parts[len(parts)-1]
	var family string
	err := s.DB.GetContext(ctx, &family, `SELECT request_id FROM oauth_requests WHERE environment_id=$1 AND kind=$2 AND signature_hash=$3 AND client_id=$4`, s.Environment, kind, SignatureHash(signature), client)
	if errors.Is(err, sql.ErrNoRows) {
		return run()
	}
	if err != nil {
		return wrap(err, "resolve OAuth token family")
	}
	conn, err := s.DB.Connx(ctx)
	if err != nil {
		return wrap(err, "acquire OAuth family connection")
	}
	defer conn.Close()
	key := s.Environment.String() + ":endpoint:" + family
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, key); err != nil {
		return wrap(err, "serialize OAuth token request")
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key)
	return run()
}

var _ fosite.Storage = (*Store)(nil)
