package authpg

import (
	"context"
	"database/sql"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

type Transaction struct{ tx *sqlx.Tx }

func Wrap(tx *sqlx.Tx) *Transaction { return &Transaction{tx} }
func (r *Repository) Begin(ctx context.Context) (authentication.Transaction, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return Wrap(tx), nil
}
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "authentication persistence failed", errx.TypeInternal)
}
func credentialError(err error) error {
	if err == sql.ErrNoRows {
		return errx.Unauthorized("invalid credentials or access")
	}
	return failure(err)
}
func (t *Transaction) Commit() error   { return failure(t.tx.Commit()) }
func (t *Transaction) Rollback() error { return t.tx.Rollback() }
func (t *Transaction) PasswordUser(ctx context.Context, b authentication.Context, email string) (string, string, error) {
	var row struct {
		ID   string `db:"id"`
		Hash string `db:"password_hash"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT id,password_hash FROM users WHERE environment_id=$1 AND email=$2 AND active FOR UPDATE`, b.EnvironmentID, email)
	return row.ID, row.Hash, credentialError(err)
}
func Resolve(ctx context.Context, q sqlx.QueryerContext, b authentication.Context, user string) (authentication.Access, error) {
	var row struct {
		Audience    string         `db:"audience"`
		Permissions pq.StringArray `db:"permissions"`
	}
	err := sqlx.GetContext(ctx, q, &row, `SELECT r.audience,g.permissions FROM memberships m JOIN users u ON u.id=m.user_id AND u.environment_id=m.environment_id JOIN organizations o ON o.id=m.organization_id AND o.environment_id=m.environment_id JOIN effective_grants g ON g.environment_id=m.environment_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id JOIN resources r ON r.id=g.resource_id AND r.environment_id=g.environment_id JOIN application_resources ar ON ar.environment_id=r.environment_id AND ar.resource_id=r.id JOIN applications a ON a.id=ar.application_id AND a.environment_id=ar.environment_id WHERE m.environment_id=$1 AND m.organization_id=$2 AND m.user_id=$3 AND m.active AND u.active AND o.active AND r.id=$4 AND a.id=$5 AND a.active`, b.EnvironmentID, b.OrganizationID, user, b.ResourceID, b.ApplicationID)
	if err != nil {
		return authentication.Access{}, credentialError(err)
	}
	return authentication.Access{Audience: row.Audience, Permissions: []string(row.Permissions)}, nil
}
func (t *Transaction) Resolve(ctx context.Context, b authentication.Context, user string) (authentication.Access, error) {
	return Resolve(ctx, t.tx, b, user)
}
func (t *Transaction) CreateSession(ctx context.Context, b authentication.Context, user, id string, expires time.Time) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, b.EnvironmentID, b.OrganizationID, user, b.ApplicationID, b.ResourceID, expires)
	return failure(err)
}
func (t *Transaction) SaveRefresh(ctx context.Context, hash []byte, session, environment string, expires time.Time) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO refresh_tokens(secret_hash,session_id,environment_id,expires_at) VALUES($1,$2,$3,$4)`, hash, session, environment, expires)
	return failure(err)
}
func (t *Transaction) Refresh(ctx context.Context, b authentication.Context, hash []byte) (authentication.Session, error) {
	var row struct {
		ID      string       `db:"session_id"`
		User    string       `db:"user_id"`
		Expires time.Time    `db:"expires_at"`
		Used    sql.NullTime `db:"used_at"`
		Revoked sql.NullTime `db:"revoked_at"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT s.id AS session_id,s.user_id,s.expires_at,t.used_at,s.revoked_at FROM refresh_tokens t JOIN sessions s ON s.id=t.session_id AND s.environment_id=t.environment_id WHERE t.secret_hash=$1 AND s.environment_id=$2 AND s.organization_id=$3 AND s.application_id=$4 AND s.resource_id=$5 AND t.expires_at>now() FOR UPDATE OF s,t`, hash, b.EnvironmentID, b.OrganizationID, b.ApplicationID, b.ResourceID)
	return authentication.Session{ID: row.ID, User: row.User, Expires: row.Expires, Used: row.Used.Valid, Revoked: row.Revoked.Valid}, credentialError(err)
}
func (t *Transaction) RevokeSession(ctx context.Context, id string) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1`, id)
	return failure(err)
}
func (t *Transaction) UseRefresh(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE refresh_tokens SET used_at=now() WHERE secret_hash=$1`, hash)
	return failure(err)
}
func (t *Transaction) EligibleChallengeUser(ctx context.Context, environment, email, purpose string) (string, error) {
	var user string
	err := t.tx.GetContext(ctx, &user, `SELECT id FROM users WHERE environment_id=$1 AND email=$2 AND active AND ($3!='login' OR otp_enabled) AND ($3!='password_reset' OR password_hash!='') FOR UPDATE`, environment, email, purpose)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return user, failure(err)
}
func (t *Transaction) RecentChallenges(ctx context.Context, environment, user string) (int, error) {
	var count int
	err := t.tx.GetContext(ctx, &count, `SELECT count(*) FROM identity_challenges WHERE environment_id=$1 AND user_id=$2 AND created_at>now()-interval '10 minutes'`, environment, user)
	return count, failure(err)
}
func (t *Transaction) CreateChallenge(ctx context.Context, id, environment, user, purpose string, hash []byte) error {
	if _, err := t.tx.ExecContext(ctx, `UPDATE identity_challenges SET consumed_at=now() WHERE environment_id=$1 AND user_id=$2 AND purpose=$3 AND consumed_at IS NULL`, environment, user, purpose); err != nil {
		return failure(err)
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO identity_challenges(id,environment_id,user_id,purpose,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '5 minutes')`, id, environment, user, purpose, hash)
	return failure(err)
}
func (t *Transaction) Challenge(ctx context.Context, environment, id, purpose string) (authentication.Challenge, error) {
	var out authentication.Challenge
	var user string
	if err := t.tx.GetContext(ctx, &user, `SELECT user_id FROM identity_challenges WHERE id=$1 AND environment_id=$2`, id, environment); err != nil {
		return out, credentialError(err)
	}
	var active bool
	if err := t.tx.GetContext(ctx, &active, `SELECT (active AND ($3!='login' OR otp_enabled) AND ($3!='password_reset' OR password_hash!='')) FROM users WHERE id=$1 AND environment_id=$2 FOR UPDATE`, user, environment, purpose); err != nil {
		return out, credentialError(err)
	}
	if !active {
		return out, errx.Unauthorized("invalid challenge")
	}
	var row struct {
		User     string `db:"user_id"`
		Hash     []byte `db:"secret_hash"`
		Attempts int    `db:"attempts"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT user_id,secret_hash,attempts FROM identity_challenges WHERE id=$1 AND environment_id=$2 AND purpose=$3 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, id, environment, purpose)
	return authentication.Challenge{User: row.User, Hash: row.Hash, Attempts: row.Attempts}, credentialError(err)
}
func (t *Transaction) FailChallenge(ctx context.Context, id string) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE identity_challenges SET attempts=attempts+1 WHERE id=$1`, id)
	return failure(err)
}
func (t *Transaction) CompleteChallenge(ctx context.Context, environment, user, id, purpose, hash string) error {
	if purpose == "password_reset" {
		if _, err := t.tx.ExecContext(ctx, `UPDATE users SET password_hash=$3,email_verified=true WHERE id=$1 AND environment_id=$2`, user, environment, hash); err != nil {
			return failure(err)
		}
	} else {
		if _, err := t.tx.ExecContext(ctx, `UPDATE users SET email_verified=true WHERE id=$1 AND environment_id=$2`, user, environment); err != nil {
			return failure(err)
		}
	}
	_, err := t.tx.ExecContext(ctx, `UPDATE identity_challenges SET consumed_at=now() WHERE id=$1`, id)
	return failure(err)
}

var _ authentication.Repository = (*Repository)(nil)
var _ authentication.Transaction = (*Transaction)(nil)
