package oauthfosite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

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
	return s.Commit(ctx)
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
