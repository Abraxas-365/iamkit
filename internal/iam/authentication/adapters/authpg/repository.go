package authpg

import (
	"context"
	"database/sql"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
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

// credentialError maps "no row" to the same message every credential failure
// uses, so responses never reveal whether an account or grant exists.
func credentialError(err error) error {
	if err == sql.ErrNoRows {
		return errx.Unauthorized("invalid credentials or access token")
	}
	return failure(err)
}
func (t *Transaction) Commit() error   { return failure(t.tx.Commit()) }
func (t *Transaction) Rollback() error { return t.tx.Rollback() }
func (t *Transaction) PasswordUser(ctx context.Context, b authentication.Context, email string) (authentication.PasswordAccount, error) {
	var row authentication.PasswordAccount
	err := t.tx.GetContext(ctx, &row, `SELECT id,password_hash,failed_logins,locked_until,password_changed_at FROM users WHERE environment_id=$1 AND email=$2 AND active FOR UPDATE`, b.EnvironmentID, email)
	return row, credentialError(err)
}
func (t *Transaction) SetLoginFailures(ctx context.Context, user identity.UserID, failures int, lockedUntil *time.Time) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE users SET failed_logins=$2,locked_until=$3 WHERE id=$1`, user, failures, lockedUntil)
	return failure(err)
}
func (t *Transaction) SetPassword(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, hash string) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE users SET password_hash=$3,password_changed_at=now(),failed_logins=0,locked_until=NULL WHERE id=$1 AND environment_id=$2`, user, environment, hash)
	return failure(err)
}
func (t *Transaction) Audit(ctx context.Context, m authentication.Mutation) error {
	return audit(ctx, t.tx, m)
}
func (t *Transaction) SSORequired(ctx context.Context, b authentication.Context, email string) (bool, error) {
	var required bool
	// A zero organization (hosted login, organization not chosen yet) checks
	// every organization that enforces SSO for the email's domain.
	err := t.tx.GetContext(ctx, &required, `SELECT EXISTS(
		SELECT 1 FROM federation_connections c
		JOIN organization_domains d ON d.organization_id=c.organization_id AND d.environment_id=c.environment_id
		WHERE c.environment_id=$1 AND ($2::uuid IS NULL OR c.organization_id=$2) AND c.active AND c.enforcement='enforced'
		  AND d.domain=$3 AND d.verified_at IS NOT NULL
		  AND NOT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id AND u.environment_id=m.environment_id
		                 WHERE m.environment_id=$1 AND m.organization_id=c.organization_id AND u.email=$4 AND m.sso_bypass))`,
		b.EnvironmentID, b.OrganizationID, identity.EmailDomain(email), email)
	return required, failure(err)
}
func (t *Transaction) OrganizationMethods(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (authentication.Methods, error) {
	var out authentication.Methods
	err := t.tx.GetContext(ctx, &out, `SELECT allow_password,allow_email_code,allow_social FROM organizations WHERE environment_id=$1 AND id=$2`, environment, organization)
	return out, credentialError(err)
}
func (t *Transaction) AccessibleOrganizations(ctx context.Context, target authentication.Target, user identity.UserID) ([]authentication.Organization, error) {
	out := []authentication.Organization{}
	err := t.tx.SelectContext(ctx, &out, `SELECT o.id,o.name,m.org_unit_id,m.manager_id,o.allow_password,o.allow_email_code,o.allow_social FROM memberships m
		JOIN users u ON u.id=m.user_id AND u.environment_id=m.environment_id
		JOIN organizations o ON o.id=m.organization_id AND o.environment_id=m.environment_id
		JOIN applications a ON a.id=$3 AND a.environment_id=m.environment_id
		JOIN application_resources ar ON ar.environment_id=m.environment_id AND ar.application_id=a.id AND ar.resource_id=$4
		WHERE m.environment_id=$1 AND m.user_id=$2 AND m.active AND u.active AND o.active AND a.active
		  AND EXISTS(SELECT 1 FROM effective_grants g WHERE g.environment_id=m.environment_id AND g.organization_id=m.organization_id AND g.user_id=m.user_id AND g.resource_id=$4)
		ORDER BY o.name, o.id`, target.Environment, user, target.Application, target.Resource)
	return out, failure(err)
}
func Resolve(ctx context.Context, q sqlx.QueryerContext, b authentication.Context, user identity.UserID) (authentication.Access, error) {
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
func (t *Transaction) Resolve(ctx context.Context, b authentication.Context, user identity.UserID) (authentication.Access, error) {
	return Resolve(ctx, t.tx, b, user)
}
func (t *Transaction) CreateSession(ctx context.Context, b authentication.Context, user identity.UserID, id identity.SessionID, authenticated, expires time.Time, amr []string) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO sessions(id,environment_id,organization_id,user_id,application_id,resource_id,expires_at,amr,authenticated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, b.EnvironmentID, b.OrganizationID, user, b.ApplicationID, b.ResourceID, expires, pq.StringArray(amr), authenticated)
	return failure(err)
}
func (t *Transaction) SaveRefresh(ctx context.Context, hash []byte, user identity.UserID, session identity.SessionID, expires time.Time) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO refresh_tokens(secret_hash,session_id,environment_id,expires_at) VALUES($1,$2,(SELECT environment_id FROM sessions WHERE id=$2),$3)`, hash, session, expires)
	return failure(err)
}
func (t *Transaction) Refresh(ctx context.Context, b authentication.Context, hash []byte) (authentication.Session, error) {
	var row struct {
		ID      identity.SessionID `db:"session_id"`
		User    identity.UserID    `db:"user_id"`
		Expires time.Time          `db:"expires_at"`
		Used    sql.NullTime       `db:"used_at"`
		Revoked sql.NullTime       `db:"revoked_at"`
		AMR     pq.StringArray     `db:"amr"`
		Auth    time.Time          `db:"authenticated_at"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT s.id AS session_id,s.user_id,s.expires_at,t.used_at,s.revoked_at,s.amr,s.authenticated_at FROM refresh_tokens t JOIN sessions s ON s.id=t.session_id AND s.environment_id=t.environment_id WHERE t.secret_hash=$1 AND s.environment_id=$2 AND s.organization_id=$3 AND s.application_id=$4 AND s.resource_id=$5 AND t.expires_at>now() FOR UPDATE OF s,t`, hash, b.EnvironmentID, b.OrganizationID, b.ApplicationID, b.ResourceID)
	return authentication.Session{ID: row.ID, User: row.User, Expires: row.Expires, Used: row.Used.Valid, Revoked: row.Revoked.Valid, AMR: []string(row.AMR), Authenticated: row.Auth}, credentialError(err)
}
func (t *Transaction) RevokeSession(ctx context.Context, id identity.SessionID) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1`, id)
	return failure(err)
}
func (t *Transaction) UseRefresh(ctx context.Context, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE refresh_tokens SET used_at=now() WHERE secret_hash=$1`, hash)
	return failure(err)
}
func (t *Transaction) EligibleChallengeUser(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.UserID, error) {
	var user identity.UserID
	err := t.tx.GetContext(ctx, &user, `SELECT id FROM users WHERE environment_id=$1 AND email=$2 AND active AND ($3!='login' OR otp_enabled) AND ($3!='password_reset' OR password_hash!='') FOR UPDATE`, environment, email, purpose)
	if err == sql.ErrNoRows {
		return identity.UserID{}, nil
	}
	return user, failure(err)
}
func (t *Transaction) RecentChallenges(ctx context.Context, user identity.UserID, purpose string) (int, error) {
	var count int
	err := t.tx.GetContext(ctx, &count, `SELECT count(*) FROM identity_challenges WHERE user_id=$1 AND purpose=$2 AND created_at>now()-interval '10 minutes'`, user, purpose)
	return count, failure(err)
}
func (t *Transaction) CreateChallenge(ctx context.Context, id identity.ChallengeID, user identity.UserID, purpose string, environment identity.EnvironmentID, hash []byte) error {
	if _, err := t.tx.ExecContext(ctx, `UPDATE identity_challenges SET consumed_at=now() WHERE environment_id=$1 AND user_id=$2 AND purpose=$3 AND consumed_at IS NULL`, environment, user, purpose); err != nil {
		return failure(err)
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO identity_challenges(id,environment_id,user_id,purpose,secret_hash,expires_at) VALUES($1,$2,$3,$4,$5,now()+make_interval(secs => $6))`, id, environment, user, purpose, hash, config.ChallengeTTL.Seconds())
	return failure(err)
}
func (t *Transaction) Challenge(ctx context.Context, id identity.ChallengeID, _ identity.UserID, purpose string) (authentication.Challenge, error) {
	var out authentication.Challenge
	var user identity.UserID
	if err := t.tx.GetContext(ctx, &user, `SELECT user_id FROM identity_challenges WHERE id=$1`, id); err != nil {
		return out, credentialError(err)
	}
	var account struct {
		Active bool   `db:"eligible"`
		Email  string `db:"email"`
	}
	if err := t.tx.GetContext(ctx, &account, `SELECT (active AND ($2!='login' OR otp_enabled) AND ($2!='password_reset' OR password_hash!='')) AS eligible, email FROM users WHERE id=$1 FOR UPDATE`, user, purpose); err != nil {
		return out, credentialError(err)
	}
	if !account.Active {
		return out, errx.Unauthorized("invalid challenge")
	}
	var row struct {
		User        identity.UserID        `db:"user_id"`
		Environment identity.EnvironmentID `db:"environment_id"`
		Hash        []byte                 `db:"secret_hash"`
		Attempts    int                    `db:"attempts"`
	}
	err := t.tx.GetContext(ctx, &row, `SELECT user_id,environment_id,secret_hash,attempts FROM identity_challenges WHERE id=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, id, purpose)
	return authentication.Challenge{User: row.User, Environment: row.Environment, Email: account.Email, Hash: row.Hash, Attempts: row.Attempts}, credentialError(err)
}
func (t *Transaction) FailChallenge(ctx context.Context, id identity.ChallengeID) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE identity_challenges SET attempts=attempts+1 WHERE id=$1`, id)
	return failure(err)
}
func (t *Transaction) CompleteChallenge(ctx context.Context, id identity.ChallengeID, user identity.UserID, purpose string, environment identity.EnvironmentID, hash string) error {
	if purpose == "password_reset" {
		// A reset proves the mailbox: it also lifts a lockout and restarts
		// the password's age.
		if _, err := t.tx.ExecContext(ctx, `UPDATE users SET password_hash=$3,email_verified=true,password_changed_at=now(),failed_logins=0,locked_until=NULL WHERE id=$1 AND environment_id=$2`, user, environment, hash); err != nil {
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
