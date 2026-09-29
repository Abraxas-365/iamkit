package authpg

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// SignupTransaction implements authentication.SignupTransaction.
type SignupTransaction struct{ tx *sqlx.Tx }

func (r *Repository) BeginSignup(ctx context.Context) (authentication.SignupTransaction, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return &SignupTransaction{tx}, nil
}

var (
	_ authentication.SignupRepository  = (*Repository)(nil)
	_ authentication.SignupTransaction = (*SignupTransaction)(nil)
)

func (t *SignupTransaction) Commit() error   { return failure(t.tx.Commit()) }
func (t *SignupTransaction) Rollback() error { return t.tx.Rollback() }

func (t *SignupTransaction) AccountExists(ctx context.Context, environment identity.EnvironmentID, email string) (bool, error) {
	var exists bool
	err := t.tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM users WHERE environment_id=$1 AND email=$2)`, environment, email)
	return exists, failure(err)
}

func (t *SignupTransaction) RecentSignups(ctx context.Context, environment identity.EnvironmentID, email string) (int, error) {
	var count int
	err := t.tx.GetContext(ctx, &count, `SELECT count(*) FROM signups WHERE environment_id=$1 AND email=$2 AND created_at>now()-interval '10 minutes'`, environment, email)
	return count, failure(err)
}

func (t *SignupTransaction) CreateSignup(ctx context.Context, p authentication.PendingSignup) error {
	if _, err := t.tx.ExecContext(ctx, `UPDATE signups SET consumed_at=now() WHERE environment_id=$1 AND email=$2 AND consumed_at IS NULL`, p.Environment, p.Email); err != nil {
		return failure(err)
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO signups(id,environment_id,email,name,password_hash,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		p.ID, p.Environment, p.Email, p.Name, p.PasswordHash, p.Hash, p.Expires)
	return failure(err)
}

func (t *SignupTransaction) PendingSignup(ctx context.Context, environment identity.EnvironmentID, signup identity.ChallengeID) (authentication.PendingSignup, error) {
	var row struct {
		ID           identity.ChallengeID   `db:"id"`
		Environment  identity.EnvironmentID `db:"environment_id"`
		Email        string                 `db:"email"`
		Name         string                 `db:"name"`
		PasswordHash string                 `db:"password_hash"`
		Hash         []byte                 `db:"secret_hash"`
		Attempts     int                    `db:"attempts"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT id,environment_id,email,name,password_hash,secret_hash,attempts FROM signups
		WHERE id=$1 AND environment_id=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, signup, environment)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.PendingSignup{}, errx.Unauthorized("invalid challenge")
	}
	if err != nil {
		return authentication.PendingSignup{}, failure(err)
	}
	return authentication.PendingSignup{ID: row.ID, Environment: row.Environment, Email: row.Email, Name: row.Name,
		PasswordHash: row.PasswordHash, Hash: row.Hash, Attempts: row.Attempts}, nil
}

func (t *SignupTransaction) FailSignup(ctx context.Context, signup identity.ChallengeID) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE signups SET attempts=attempts+1 WHERE id=$1`, signup)
	return failure(err)
}

func (t *SignupTransaction) Join(ctx context.Context, j authentication.Joining) error {
	var open bool
	if err := t.tx.GetContext(ctx, &open, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1 AND environment_id=$2 AND active FOR SHARE)`, j.Organization, j.Environment); err != nil {
		return failure(err)
	}
	if !open {
		return authentication.ErrSignupDisabled()
	}
	// A passwordless account signs in with email codes (otp_enabled).
	_, err := t.tx.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,email_verified,otp_enabled) VALUES($1,$2,$3,$4,$5,true,$5='')`,
		j.User, j.Environment, j.Email, j.Name, j.PasswordHash)
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		return authentication.ErrAccountExists()
	}
	if err != nil {
		return failure(err)
	}
	if _, err = t.tx.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3)`, j.Environment, j.Organization, j.User); err != nil {
		return failure(err)
	}
	if !j.Group.IsZero() {
		if _, err = t.tx.ExecContext(ctx, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
			SELECT id,environment_id,organization_id,$4 FROM groups WHERE id=$1 AND environment_id=$2 AND organization_id=$3 AND connection_id IS NULL
			ON CONFLICT DO NOTHING`, j.Group, j.Environment, j.Organization, j.User); err != nil {
			return failure(err)
		}
	}
	if _, err = t.tx.ExecContext(ctx, `UPDATE signups SET consumed_at=now() WHERE id=$1`, j.Signup); err != nil {
		return failure(err)
	}
	return audit(ctx, t.tx, authentication.Mutation{Environment: j.Environment, Actor: j.User.String(), Action: authentication.ActionSignup, Target: "/users/" + j.User.String()})
}

func (t *SignupTransaction) SSORequired(ctx context.Context, environment identity.EnvironmentID, email string) (bool, error) {
	return Wrap(t.tx).SSORequired(ctx, authentication.Context{EnvironmentID: environment}, email)
}

func (t *SignupTransaction) SignupMethods(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (authentication.Methods, error) {
	var out authentication.Methods
	err := t.tx.GetContext(ctx, &out, `SELECT allow_password,allow_email_code,allow_social FROM organizations WHERE environment_id=$1 AND id=$2 AND active`, environment, organization)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.Methods{}, nil
	}
	return out, failure(err)
}
