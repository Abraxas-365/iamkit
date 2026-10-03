package userpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db: db} }
func failure(err error, message string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errx.NotFound("resource not found")
	}
	var pg *pq.Error
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "23503") {
		return errx.Wrap(err, message, errx.TypeConflict)
	}
	return errx.Wrap(err, message, errx.TypeInternal)
}

// usernameTaken reports a duplicate username in the environment.
func usernameTaken(err error) bool {
	var pg *pq.Error
	return errors.As(err, &pg) && pg.Code == "23505" && pg.Constraint == "users_environment_username"
}

// emailTaken reports a duplicate email in the environment.
func emailTaken(err error) bool {
	var pg *pq.Error
	return errors.As(err, &pg) && pg.Code == "23505" && pg.Constraint == "users_environment_id_email_key"
}

// phoneUnverifiable reports phone_verified without a number.
func phoneUnverifiable(err error) bool {
	var pg *pq.Error
	return errors.As(err, &pg) && pg.Code == "23514" && pg.Constraint == "users_phone_verified"
}

// Create inserts the user and, with a home organization, the membership
// in it, in one transaction.
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, input user.Create, hash string) (identity.UserID, error) {
	id := identity.NewUserID()
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return id, failure(err, "create user")
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,otp_enabled,avatar_url,username,home_organization_id,kind) VALUES($1,$2,nullif($3,''),$4,$5,$6,$7,nullif($8,''),$9,$10)`, id, environment, input.Email, input.Name, hash, input.OTPEnabled, input.AvatarURL, input.Username, input.HomeOrganization, kind(input.Kind))
	if usernameTaken(err) {
		return id, errx.Conflict("username is taken")
	}
	if emailTaken(err) {
		return id, errx.Conflict("email is taken")
	}
	if homeMissing(err) {
		return id, errx.Validation("home_organization_id must be an organization of the environment")
	}
	if err != nil {
		return id, failure(err, "user already exists")
	}
	if !input.HomeOrganization.IsZero() {
		if _, err = tx.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3)`, environment, input.HomeOrganization, id); err != nil {
			return id, failure(err, "create membership")
		}
	}
	if err = eventpg.UserCreated(ctx, tx, environment, event.ActorFrom(ctx), id, input.HomeOrganization, "api"); err != nil {
		return id, err
	}
	return id, failure(tx.Commit(), "commit user")
}

// homeMissing reports a home organization outside the environment.
func homeMissing(err error) bool {
	var pg *pq.Error
	return errors.As(err, &pg) && pg.Code == "23503" && pg.Constraint == "users_home_organization"
}

// kind stores "" as human.
func kind(k user.Kind) string {
	if k == "" {
		return string(user.KindHuman)
	}
	return string(k)
}

// stateSQL derives user.State for the users row u (see user.State).
const stateSQL = `CASE
	WHEN NOT u.active THEN 'suspended'
	WHEN u.locked_until > now() THEN 'locked'
	WHEN u.last_signed_in_at IS NULL THEN 'initial'
	WHEN NOT EXISTS (SELECT 1 FROM memberships m JOIN organizations o ON o.id=m.organization_id AND o.environment_id=m.environment_id
		WHERE m.environment_id=u.environment_id AND m.user_id=u.id AND m.active AND o.active) THEN 'inactive'
	ELSE 'active' END`

func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, filter user.Filter, page query.Pagination) (query.Paginated[user.User], error) {
	base := `FROM users u WHERE u.environment_id=$1`
	args := []any{environment}
	n := 1
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (u.name ILIKE $%d OR u.email ILIKE $%d OR u.username ILIKE $%d)", n, n, n)
		args = append(args, like)
	}
	if filter.State != "" {
		n++
		base += fmt.Sprintf(" AND (%s)=$%d", stateSQL, n)
		args = append(args, string(filter.State))
	}
	if !filter.HomeOrganization.IsZero() {
		n++
		base += fmt.Sprintf(" AND u.home_organization_id=$%d", n)
		args = append(args, filter.HomeOrganization)
	}
	if filter.Kind != "" {
		n++
		base += fmt.Sprintf(" AND u.kind=$%d", n)
		args = append(args, string(filter.Kind))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[user.User]{}, failure(err, "list users")
	}
	rows := []user.User{}
	err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT u.id,u.kind,coalesce(u.email,'') AS email,u.name,coalesce(u.username,'') AS username,u.home_organization_id,u.avatar_url,u.active,%s AS state,u.last_signed_in_at %s ORDER BY u.name, u.id LIMIT %d OFFSET %d", stateSQL, base, page.Limit, page.Offset), args...)
	if err != nil {
		return query.Paginated[user.User]{}, failure(err, "list users")
	}
	return query.NewPaginated(rows, total, page), nil
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (user.User, error) {
	var row user.User
	err := r.db.GetContext(ctx, &row, `SELECT u.id,u.kind,coalesce(u.email,'') AS email,u.name,coalesce(u.username,'') AS username,u.home_organization_id,u.avatar_url,u.active,u.email_verified,u.otp_enabled,u.phone,u.phone_verified,u.metadata,u.profile,u.failed_logins,CASE WHEN u.locked_until>now() THEN u.locked_until END AS locked_until,`+stateSQL+` AS state,u.last_signed_in_at,u.terms_accepted_at,u.password_change_required FROM users u WHERE u.environment_id=$1 AND u.id=$2`, environment, id)
	return row, failure(err, "find user")
}

// SetActive suspends or reactivates the user, audited.
func (r *Repository) SetActive(ctx context.Context, m user.Mutation, id identity.UserID, active bool) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "update user")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET active=$3 WHERE environment_id=$1 AND id=$2`, m.Environment, id, active)
	if err != nil {
		return failure(err, "update user")
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err, "update user")
		}
		return errx.NotFound("resource not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit user state")
	}
	return failure(tx.Commit(), "commit user state")
}

// Unlock clears the wrong-password count and lockout, audited.
func (r *Repository) Unlock(ctx context.Context, m user.Mutation, id identity.UserID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "unlock user")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins=0,locked_until=NULL WHERE environment_id=$1 AND id=$2`, m.Environment, id)
	if err != nil {
		return failure(err, "unlock user")
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err, "unlock user")
		}
		return errx.NotFound("resource not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit user unlock")
	}
	return failure(tx.Commit(), "commit user unlock")
}

// RevokeSessions ends the user's live sessions (their children with them,
// by trigger) and audits how many.
func (r *Repository) RevokeSessions(ctx context.Context, m user.Mutation, id identity.UserID) (int, error) {
	var count int
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var exists bool
		if err := tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM users WHERE environment_id=$1 AND id=$2)`, m.Environment, id); err != nil {
			return failure(err, "revoke sessions")
		}
		if !exists {
			return errx.NotFound("resource not found")
		}
		res, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at=now() WHERE environment_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, m.Environment, id)
		if err != nil {
			return failure(err, "revoke sessions")
		}
		n, err := res.RowsAffected()
		if err != nil {
			return failure(err, "revoke sessions")
		}
		count = int(n)
		return failure(eventpg.AuditWith(ctx, tx, m.Environment, m.Actor, m.Action, m.Target, map[string]any{"count": count}), "audit revoked sessions")
	})
	return count, err
}

// RequirePasswordChange flags a user who has a password.
func (r *Repository) RequirePasswordChange(ctx context.Context, m user.Mutation, id identity.UserID) error {
	return eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		var hasPassword bool
		err := tx.GetContext(ctx, &hasPassword, `SELECT password_hash<>'' FROM users WHERE environment_id=$1 AND id=$2 FOR UPDATE`, m.Environment, id)
		if errors.Is(err, sql.ErrNoRows) {
			return errx.NotFound("resource not found")
		}
		if err != nil {
			return failure(err, "require password change")
		}
		if !hasPassword {
			return errx.Business("the user has no password to change")
		}
		if _, err = tx.ExecContext(ctx, `UPDATE users SET password_change_required=true WHERE environment_id=$1 AND id=$2`, m.Environment, id); err != nil {
			return failure(err, "require password change")
		}
		return audit(ctx, tx, m)
	})
}
func (r *Repository) Update(ctx context.Context, m user.Mutation, id identity.UserID, input user.Update) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "update user")
	}
	defer tx.Rollback()
	var metadata any
	if len(input.Metadata) > 0 {
		metadata = string(input.Metadata)
	}
	// $10 true = change the home organization to $11 (NULL clears it); a new
	// home must be one of the user's memberships.
	var home any
	if input.HomeOrganization != nil && !input.HomeOrganization.IsZero() {
		home = *input.HomeOrganization
	}
	res, err := tx.ExecContext(ctx, `UPDATE users SET name=coalesce($3,name),active=coalesce($4,active),metadata=coalesce($5::jsonb,metadata),otp_enabled=coalesce($6,otp_enabled),
		phone_verified=CASE WHEN $12::boolean IS NOT NULL THEN $12::boolean WHEN $7::text IS NULL OR $7::text=phone THEN phone_verified ELSE false END,phone=coalesce($7::text,phone),
		avatar_url=coalesce($8::text,avatar_url),
		username=CASE WHEN $9::text IS NULL THEN username ELSE nullif($9::text,'') END,
		home_organization_id=CASE WHEN $10::boolean THEN $11::uuid ELSE home_organization_id END
		WHERE environment_id=$1 AND id=$2`, m.Environment, id, input.Name, input.Active, metadata, input.OTPEnabled, input.Phone, input.AvatarURL, input.Username,
		input.HomeOrganization != nil, home, input.PhoneVerified)
	if usernameTaken(err) {
		return errx.Conflict("username is taken")
	}
	if phoneUnverifiable(err) {
		return errx.Validation("phone_verified requires a phone number")
	}
	if homeMissing(err) {
		return errx.Validation("home_organization_id must be an organization of the environment")
	}
	if err != nil {
		return failure(err, "conflicting or out-of-bound resource")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err, "update user")
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if home != nil {
		var member bool
		if err = tx.GetContext(ctx, &member, `SELECT EXISTS(SELECT 1 FROM memberships WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3)`, m.Environment, home, id); err != nil {
			return failure(err, "update user")
		}
		if !member {
			return errx.Validation("home_organization_id must be an organization the user belongs to")
		}
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit user update")
	}
	if input.PhoneVerified != nil {
		m := m
		m.Action, m.Target = user.ActionPhoneVerifiedSet, fmt.Sprintf("%s?phone_verified=%t", id, *input.PhoneVerified)
		if err = audit(ctx, tx, m); err != nil {
			return failure(err, "audit user update")
		}
	}
	return failure(tx.Commit(), "commit user update")
}

// Delete permanently erases a user and every row that references it —
// sessions, refresh tokens, grants, role assignments, position assignments,
// memberships, external identities, identity challenges, provisioned
// identities, and invitations accepted by or addressed to the user. This is irreversible; callers that only want to disable sign-in
// should use SetActive instead.
func (r *Repository) Delete(ctx context.Context, m user.Mutation, id identity.UserID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "delete user")
	}
	defer tx.Rollback()
	statements := []string{
		`DELETE FROM refresh_tokens WHERE environment_id=$1 AND session_id IN (SELECT id FROM sessions WHERE environment_id=$1 AND user_id=$2)`,
		`DELETE FROM sessions WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM grants WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM role_assignments WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM position_assignments WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM group_members WHERE environment_id=$1 AND user_id=$2`,
		`UPDATE memberships SET manager_id=NULL WHERE environment_id=$1 AND manager_id=$2`,
		`DELETE FROM memberships WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM external_identities WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM identity_challenges WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM provisioned_identities WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM invitations WHERE environment_id=$1 AND (accepted_user_id=$2 OR email=(SELECT email FROM users WHERE environment_id=$1 AND id=$2))`,
		`DELETE FROM mfa_logins WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM recovery_codes WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM user_factors WHERE environment_id=$1 AND user_id=$2`,
		`DELETE FROM user_mfa_state WHERE environment_id=$1 AND user_id=$2`,
	}
	for _, stmt := range statements {
		if _, err = tx.ExecContext(ctx, stmt, m.Environment, id); err != nil {
			return failure(err, "delete user")
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE environment_id=$1 AND id=$2`, m.Environment, id)
	if err != nil {
		return failure(err, "delete user")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return failure(err, "delete user")
	}
	if n == 0 {
		return errx.NotFound("resource not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return failure(err, "audit user deletion")
	}
	return failure(tx.Commit(), "commit user deletion")
}

var _ user.Repository = (*Repository)(nil)
