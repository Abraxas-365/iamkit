// Package mfapg persists second factors, recovery codes and pending
// multi-factor logins in PostgreSQL.
package mfapg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ mfa.Repository = (*Repository)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "mfa persistence failed", errx.TypeInternal)
}

const factorColumns = `id,kind,confirmed_at,last_used_at,created_at,secret_sealed,last_step,failed_attempts,locked_until`

func (r *Repository) Begin(ctx context.Context) (mfa.Transaction, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return &Transaction{tx}, nil
}

func (r *Repository) Summary(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Summary, error) {
	var exists bool
	if err := r.db.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND environment_id=$2)`, user, environment); err != nil {
		return mfa.Summary{}, failure(err)
	}
	if !exists {
		return mfa.Summary{}, errx.NotFound("user not found")
	}
	out := mfa.Summary{Factors: []mfa.Factor{}}
	if err := r.db.SelectContext(ctx, &out.Factors, `SELECT `+factorColumns+` FROM user_factors WHERE environment_id=$1 AND user_id=$2 ORDER BY created_at`, environment, user); err != nil {
		return mfa.Summary{}, failure(err)
	}
	err := r.db.GetContext(ctx, &out.RecoveryCodes, `SELECT count(*) FROM recovery_codes WHERE environment_id=$1 AND user_id=$2 AND used_at IS NULL`, environment, user)
	return out, failure(err)
}

func (r *Repository) Policy(ctx context.Context, b authentication.Context, user identity.UserID) (mfa.Policy, error) {
	var out mfa.Policy
	err := r.db.GetContext(ctx, &out, `SELECT
		EXISTS(SELECT 1 FROM user_factors f WHERE f.environment_id=$1 AND f.user_id=$3 AND f.confirmed_at IS NOT NULL) AS enrolled,
		o.mfa_required, o.mfa_for_federated
		FROM organizations o WHERE o.id=$2 AND o.environment_id=$1`, b.EnvironmentID, b.OrganizationID, user)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Policy{}, errx.Unauthorized("invalid credentials or access token")
	}
	return out, failure(err)
}

// Account names the user after the environment's hosted login branding, or
// the environment.
func (r *Repository) Account(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Account, error) {
	var out mfa.Account
	err := r.db.GetContext(ctx, &out, `SELECT u.email, coalesce(nullif(s.display_name,''), e.name) AS issuer
		FROM users u JOIN environments e ON e.id=u.environment_id
		LEFT JOIN login_settings s ON s.environment_id=u.environment_id
		WHERE u.id=$1 AND u.environment_id=$2 AND u.active`, user, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Account{}, errx.NotFound("user not found")
	}
	return out, failure(err)
}

func (r *Repository) SaveUnconfirmed(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, factor identity.FactorID, sealed string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var active bool
	err = tx.GetContext(ctx, &active, `SELECT confirmed_at IS NOT NULL FROM user_factors WHERE environment_id=$1 AND user_id=$2 AND kind='totp' FOR UPDATE`, environment, user)
	switch {
	case err == nil && active:
		return errx.Conflict("an authenticator is already enrolled; remove it first")
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_factors WHERE environment_id=$1 AND user_id=$2 AND kind='totp' AND confirmed_at IS NULL`, environment, user); err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_factors(id,environment_id,user_id,kind,secret_sealed) VALUES($1,$2,$3,'totp',$4)`, factor, environment, user, sealed); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return errx.Conflict("an authenticator enrollment is already in progress")
		}
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return errx.NotFound("user not found")
		}
		return failure(err)
	}
	return failure(tx.Commit())
}

// SavePending stores a pending login and sweeps expired ones.
func (r *Repository) SavePending(ctx context.Context, hash []byte, p mfa.Pending) error {
	_, err := r.db.ExecContext(ctx, `WITH sweep AS (DELETE FROM mfa_logins WHERE expires_at<now())
		INSERT INTO mfa_logins(token_hash,environment_id,organization_id,application_id,resource_id,user_id,amr,enroll,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		hash, p.Boundary.EnvironmentID, p.Boundary.OrganizationID, p.Boundary.ApplicationID, p.Boundary.ResourceID, p.User, pq.StringArray(p.AMR), p.Enroll, p.Expires)
	return failure(err)
}

type Transaction struct{ tx *sqlx.Tx }

var _ mfa.Transaction = (*Transaction)(nil)

func (t *Transaction) Factor(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (mfa.Factor, bool, error) {
	var f mfa.Factor
	err := t.tx.GetContext(ctx, &f, `SELECT `+factorColumns+` FROM user_factors WHERE environment_id=$1 AND user_id=$2 AND kind='totp' FOR UPDATE`, environment, user)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Factor{}, false, nil
	}
	return f, err == nil, failure(err)
}

func (t *Transaction) UseStep(ctx context.Context, factor identity.FactorID, step int64) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET last_step=$2, last_used_at=now() WHERE id=$1`, factor, step)
	return failure(err)
}

func (t *Transaction) Confirm(ctx context.Context, factor identity.FactorID, step int64) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET confirmed_at=now(), last_step=$2, last_used_at=now() WHERE id=$1`, factor, step)
	return failure(err)
}

func (t *Transaction) SetFailures(ctx context.Context, factor identity.FactorID, failures int, lockedUntil *time.Time) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE user_factors SET failed_attempts=$2, locked_until=$3 WHERE id=$1`, factor, failures, lockedUntil)
	return failure(err)
}

func (t *Transaction) UseRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, hash []byte) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at=now() WHERE environment_id=$1 AND user_id=$2 AND code_hash=$3 AND used_at IS NULL`, environment, user, hash)
	if err != nil {
		return false, failure(err)
	}
	n, err := res.RowsAffected()
	return n == 1, failure(err)
}

func (t *Transaction) ReplaceRecovery(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, hashes [][]byte) error {
	if _, err := t.tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE environment_id=$1 AND user_id=$2`, environment, user); err != nil {
		return failure(err)
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO recovery_codes(environment_id,user_id,code_hash) SELECT $1,$2,unnest($3::bytea[])`, environment, user, pq.ByteaArray(hashes))
	return failure(err)
}

func (t *Transaction) DeleteFactors(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `DELETE FROM user_factors WHERE environment_id=$1 AND user_id=$2`, environment, user)
	if err != nil {
		return false, failure(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, failure(err)
	}
	codes, err := t.tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE environment_id=$1 AND user_id=$2`, environment, user)
	if err != nil {
		return false, failure(err)
	}
	m, err := codes.RowsAffected()
	return n+m > 0, failure(err)
}

func (t *Transaction) Pending(ctx context.Context, hash []byte) (mfa.Pending, error) {
	var row struct {
		Environment  identity.EnvironmentID  `db:"environment_id"`
		Organization identity.OrganizationID `db:"organization_id"`
		Application  identity.ApplicationID  `db:"application_id"`
		Resource     identity.ResourceID     `db:"resource_id"`
		User         identity.UserID         `db:"user_id"`
		AMR          pq.StringArray          `db:"amr"`
		Enroll       bool                    `db:"enroll"`
		Attempts     int                     `db:"attempts"`
		Expires      time.Time               `db:"expires_at"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT environment_id,organization_id,application_id,resource_id,user_id,amr,enroll,attempts,expires_at FROM mfa_logins WHERE token_hash=$1 AND expires_at>now() FOR UPDATE`, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return mfa.Pending{}, errx.Unauthorized("sign in again")
	}
	if err != nil {
		return mfa.Pending{}, failure(err)
	}
	return mfa.Pending{Boundary: authentication.Context{EnvironmentID: row.Environment, OrganizationID: row.Organization, ApplicationID: row.Application, ResourceID: row.Resource}, User: row.User, AMR: []string(row.AMR), Enroll: row.Enroll, Attempts: row.Attempts, Expires: row.Expires}, nil
}

func (t *Transaction) FailPending(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE mfa_logins SET attempts=attempts+1 WHERE token_hash=$1`, hash)
	return failure(err)
}

func (t *Transaction) DeletePending(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM mfa_logins WHERE token_hash=$1`, hash)
	return failure(err)
}

func (t *Transaction) Audit(ctx context.Context, m mfa.Mutation) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	return failure(err)
}

func (t *Transaction) Commit() error { return failure(t.tx.Commit()) }
func (t *Transaction) Rollback() error {
	err := t.tx.Rollback()
	if errors.Is(err, sql.ErrTxDone) {
		return nil
	}
	return failure(err)
}
