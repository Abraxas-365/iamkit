// Package invpg stores invitations in PostgreSQL.
package invpg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }

var _ invitation.Repository = (*Repository)(nil)
var _ invitation.Transaction = (*Transaction)(nil)

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "invitation persistence failed", errx.TypeInternal)
}

func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code == "23505" {
		switch pg.Constraint {
		case "invitations_pending":
			return errx.Conflict("a pending invitation already exists for this email")
		case "users_environment_id_email_key":
			return errx.Conflict("an account with this email was created meanwhile; accept again")
		}
		return errx.Conflict("conflicting invitation")
	}
	return failure(err)
}

const columns = `i.id,i.organization_id,i.email,i.role_ids,i.group_ids,i.inviter,i.expires_at,i.accepted_at,i.accepted_user_id,i.revoked_at,i.created_at`

// row maps the uuid[] columns, which identity IDs cannot scan directly.
type row struct {
	invitation.Invitation
	RoleIDs  pq.StringArray `db:"role_ids"`
	GroupIDs pq.StringArray `db:"group_ids"`
}

func (r row) invitation() (invitation.Invitation, error) {
	out := r.Invitation
	out.Roles = make([]identity.RoleID, 0, len(r.RoleIDs))
	for _, raw := range r.RoleIDs {
		id, err := identity.ParseRoleID(raw)
		if err != nil {
			return out, failure(err)
		}
		out.Roles = append(out.Roles, id)
	}
	out.Groups = make([]identity.GroupID, 0, len(r.GroupIDs))
	for _, raw := range r.GroupIDs {
		id, err := identity.ParseGroupID(raw)
		if err != nil {
			return out, failure(err)
		}
		out.Groups = append(out.Groups, id)
	}
	return out, nil
}

func ids[T interface{ String() string }](in []T) pq.StringArray {
	out := make(pq.StringArray, len(in))
	for i, id := range in {
		out[i] = id.String()
	}
	return out
}

func audit(ctx context.Context, tx *sqlx.Tx, m invitation.Mutation) error {
	return failure(eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target))
}

func (r *Repository) Begin(ctx context.Context) (invitation.Transaction, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err)
	}
	return &Transaction{tx}, nil
}

var statusFilter = map[string]string{
	invitation.StatusPending:  ` AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>now()`,
	invitation.StatusExpired:  ` AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at<=now()`,
	invitation.StatusAccepted: ` AND i.accepted_at IS NOT NULL`,
	invitation.StatusRevoked:  ` AND i.revoked_at IS NOT NULL`,
}

func (r *Repository) List(ctx context.Context, b invitation.Boundary, filter invitation.Filter, page query.Pagination) (query.Paginated[invitation.Invitation], error) {
	where := ` WHERE i.environment_id=$1 AND i.organization_id=$2` + statusFilter[filter.Status]
	args := []any{b.Environment, b.Organization}
	if like := query.EscapeLike(page.Search); like != "" {
		args = append(args, like)
		where += fmt.Sprintf(" AND i.email ILIKE $%d", len(args))
	}
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM invitations i`+where, args...); err != nil {
		return query.Paginated[invitation.Invitation]{}, failure(err)
	}
	var rows []row
	if err := r.db.SelectContext(ctx, &rows, fmt.Sprintf("SELECT %s FROM invitations i%s ORDER BY i.created_at DESC, i.id LIMIT %d OFFSET %d", columns, where, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[invitation.Invitation]{}, failure(err)
	}
	out := make([]invitation.Invitation, 0, len(rows))
	for _, row := range rows {
		inv, err := row.invitation()
		if err != nil {
			return query.Paginated[invitation.Invitation]{}, err
		}
		out = append(out, inv)
	}
	return query.NewPaginated(out, total, page), nil
}

func find(ctx context.Context, q sqlx.QueryerContext, b invitation.Boundary, id identity.InvitationID, lock string) (invitation.Invitation, error) {
	var r row
	err := sqlx.GetContext(ctx, q, &r, `SELECT `+columns+` FROM invitations i WHERE i.environment_id=$1 AND i.organization_id=$2 AND i.id=$3`+lock, b.Environment, b.Organization, id)
	if errors.Is(err, sql.ErrNoRows) {
		return invitation.Invitation{}, errx.NotFound("invitation not found")
	}
	if err != nil {
		return invitation.Invitation{}, failure(err)
	}
	return r.invitation()
}

func (r *Repository) Find(ctx context.Context, b invitation.Boundary, id identity.InvitationID) (invitation.Invitation, error) {
	return find(ctx, r.db, b, id, "")
}

// target loads the invitation by token hash with its organization, the
// invitee's account and whether SSO is enforced for the email (same rule as
// password login, including the membership's break-glass bypass).
func target(ctx context.Context, q sqlx.QueryerContext, hash []byte, lock bool) (invitation.Target, error) {
	var r struct {
		row
		Environment identity.EnvironmentID `db:"environment_id"`
		OrgName     string                 `db:"org_name"`
		OrgActive   bool                   `db:"org_active"`
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE OF i"
	}
	err := sqlx.GetContext(ctx, q, &r, `SELECT `+columns+`,i.environment_id,o.name AS org_name,o.active AS org_active
		FROM invitations i JOIN organizations o ON o.id=i.organization_id AND o.environment_id=i.environment_id
		WHERE i.token_hash=$1`+suffix, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return invitation.Target{}, invitation.ErrInvalid
	}
	if err != nil {
		return invitation.Target{}, failure(err)
	}
	inv, err := r.row.invitation()
	if err != nil {
		return invitation.Target{}, err
	}
	t := invitation.Target{Invitation: inv, Environment: r.Environment, OrgName: r.OrgName, OrgActive: r.OrgActive}
	var account struct {
		ID          identity.UserID `db:"id"`
		Active      bool            `db:"active"`
		HasPassword bool            `db:"has_password"`
	}
	suffix = ""
	if lock {
		suffix = " FOR UPDATE"
	}
	err = sqlx.GetContext(ctx, q, &account, `SELECT id,active,password_hash<>'' AS has_password FROM users WHERE environment_id=$1 AND email=$2`+suffix, t.Environment, inv.Email)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return t, failure(err)
	default:
		t.Account = invitation.Account{ID: account.ID, Active: account.Active, HasPassword: account.HasPassword}
	}
	err = sqlx.GetContext(ctx, q, &t.SSORequired, `SELECT EXISTS(
		SELECT 1 FROM federation_connections c
		JOIN organization_domains d ON d.organization_id=c.organization_id AND d.environment_id=c.environment_id
		WHERE c.environment_id=$1 AND c.organization_id=$2 AND c.active AND c.enforcement='enforced'
		  AND d.domain=$3 AND d.verified_at IS NOT NULL
		  AND NOT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id AND u.environment_id=m.environment_id
		                 WHERE m.environment_id=$1 AND m.organization_id=$2 AND u.email=$4 AND m.sso_bypass))`,
		t.Environment, inv.Organization, identity.EmailDomain(inv.Email), inv.Email)
	return t, failure(err)
}

func (r *Repository) Target(ctx context.Context, hash []byte) (invitation.Target, error) {
	return target(ctx, r.db, hash, false)
}

func (r *Repository) InviterName(ctx context.Context, actor string) (string, error) {
	var name string
	// Operators act on the management API, users (JWT subjects) on /api/v1.
	err := r.db.GetContext(ctx, &name, `SELECT email FROM operators WHERE id::text=$1 UNION ALL SELECT name FROM users WHERE id::text=$1 LIMIT 1`, actor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return name, failure(err)
}

type Transaction struct{ tx *sqlx.Tx }

func (t *Transaction) Commit() error   { return failure(t.tx.Commit()) }
func (t *Transaction) Rollback() error { return t.tx.Rollback() }

func (t *Transaction) Organization(ctx context.Context, b invitation.Boundary) (invitation.Organization, error) {
	var o invitation.Organization
	err := t.tx.GetContext(ctx, &o, `SELECT name,active FROM organizations WHERE environment_id=$1 AND id=$2`, b.Environment, b.Organization)
	if errors.Is(err, sql.ErrNoRows) {
		return o, errx.NotFound("organization not found")
	}
	return o, failure(err)
}

func (t *Transaction) ActiveMember(ctx context.Context, b invitation.Boundary, email string) (bool, error) {
	var member bool
	err := t.tx.GetContext(ctx, &member, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id AND u.environment_id=m.environment_id
		WHERE m.environment_id=$1 AND m.organization_id=$2 AND u.email=$3 AND m.active)`, b.Environment, b.Organization, email)
	return member, failure(err)
}

func (t *Transaction) References(ctx context.Context, b invitation.Boundary, roles []identity.RoleID, groups []identity.GroupID) (invitation.References, error) {
	var out struct {
		Roles  int `db:"roles"`
		Groups int `db:"groups"`
	}
	err := t.tx.GetContext(ctx, &out, `SELECT
		(SELECT count(*) FROM roles WHERE environment_id=$1 AND id::text=ANY($3)) AS roles,
		(SELECT count(*) FROM groups WHERE environment_id=$1 AND organization_id=$2 AND connection_id IS NULL AND id::text=ANY($4)) AS groups`,
		b.Environment, b.Organization, ids(roles), ids(groups))
	return invitation.References{Roles: out.Roles, Groups: out.Groups}, failure(err)
}

func (t *Transaction) ExpirePending(ctx context.Context, b invitation.Boundary, email string) error {
	_, err := t.tx.ExecContext(ctx, `UPDATE invitations SET revoked_at=expires_at
		WHERE environment_id=$1 AND organization_id=$2 AND email=$3 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at<=now()`,
		b.Environment, b.Organization, email)
	return failure(err)
}

func (t *Transaction) Create(ctx context.Context, b invitation.Boundary, m invitation.Mutation, inv invitation.Invitation, hash []byte) error {
	_, err := t.tx.ExecContext(ctx, `INSERT INTO invitations(id,environment_id,organization_id,email,role_ids,group_ids,inviter,token_hash,expires_at)
		VALUES($1,$2,$3,$4,$5::uuid[],$6::uuid[],$7,$8,$9)`,
		inv.ID, b.Environment, b.Organization, inv.Email, ids(inv.Roles), ids(inv.Groups), inv.Inviter, hash, inv.ExpiresAt)
	if err != nil {
		return conflict(err)
	}
	m.Action = "invitation.create"
	m.Target = "/organizations/" + b.Organization.String() + "/invitations/" + inv.ID.String()
	return audit(ctx, t.tx, m)
}

func (t *Transaction) Lock(ctx context.Context, b invitation.Boundary, id identity.InvitationID) (invitation.Invitation, error) {
	return find(ctx, t.tx, b, id, " FOR UPDATE")
}

func (t *Transaction) Reissue(ctx context.Context, b invitation.Boundary, m invitation.Mutation, id identity.InvitationID, hash []byte, expires time.Time) error {
	if _, err := t.tx.ExecContext(ctx, `UPDATE invitations SET token_hash=$4,expires_at=$5 WHERE environment_id=$1 AND organization_id=$2 AND id=$3`,
		b.Environment, b.Organization, id, hash, expires); err != nil {
		return failure(err)
	}
	m.Action = "invitation.resend"
	m.Target = "/organizations/" + b.Organization.String() + "/invitations/" + id.String()
	return audit(ctx, t.tx, m)
}

func (t *Transaction) Revoke(ctx context.Context, b invitation.Boundary, m invitation.Mutation, id identity.InvitationID) error {
	if _, err := t.tx.ExecContext(ctx, `UPDATE invitations SET revoked_at=now() WHERE environment_id=$1 AND organization_id=$2 AND id=$3`,
		b.Environment, b.Organization, id); err != nil {
		return failure(err)
	}
	m.Action = "invitation.revoke"
	m.Target = "/organizations/" + b.Organization.String() + "/invitations/" + id.String()
	return audit(ctx, t.tx, m)
}

func (t *Transaction) LockTarget(ctx context.Context, hash []byte) (invitation.Target, error) {
	return target(ctx, t.tx, hash, true)
}

// Join applies an accepted invitation. Roles and groups deleted since the
// invitation was created are skipped; directory groups never get members.
func (t *Transaction) Join(ctx context.Context, j invitation.Joining) error {
	inv := j.Invitation
	var err error
	if j.NewUser {
		_, err = t.tx.ExecContext(ctx, `INSERT INTO users(id,environment_id,email,name,password_hash,email_verified,home_organization_id) VALUES($1,$2,$3,$4,$5,true,$6)`,
			j.User, j.Environment, inv.Email, j.Name, j.PasswordHash, inv.Organization)
	} else {
		_, err = t.tx.ExecContext(ctx, `UPDATE users SET email_verified=true WHERE environment_id=$1 AND id=$2`, j.Environment, j.User)
	}
	if err != nil {
		return conflict(err)
	}
	steps := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3)
			ON CONFLICT (organization_id,user_id) DO UPDATE SET active=true`, []any{j.Environment, inv.Organization, j.User}},
		{`INSERT INTO role_assignments(environment_id,organization_id,user_id,resource_id,role_id)
			SELECT environment_id,$2,$3,resource_id,id FROM roles WHERE environment_id=$1 AND id::text=ANY($4)
			ON CONFLICT DO NOTHING`, []any{j.Environment, inv.Organization, j.User, ids(inv.Roles)}},
		{`INSERT INTO group_members(group_id,environment_id,organization_id,user_id)
			SELECT id,environment_id,organization_id,$3 FROM groups
			WHERE environment_id=$1 AND organization_id=$2 AND connection_id IS NULL AND id::text=ANY($4)
			ON CONFLICT DO NOTHING`, []any{j.Environment, inv.Organization, j.User, ids(inv.Groups)}},
		{`UPDATE invitations SET accepted_at=now(),accepted_user_id=$2 WHERE id=$1`, []any{inv.ID, j.User}},
	}
	for _, step := range steps {
		if _, err = t.tx.ExecContext(ctx, step.query, step.args...); err != nil {
			return failure(err)
		}
	}
	if j.NewUser {
		err = eventpg.UserCreated(ctx, t.tx, j.Environment, j.User.String(), j.User, inv.Organization, "invitation")
	} else {
		err = eventpg.Membership(ctx, t.tx, j.Environment, j.User.String(), event.MembershipCreated, inv.Organization, j.User)
	}
	if err != nil {
		return err
	}
	return audit(ctx, t.tx, invitation.Mutation{Environment: j.Environment, Actor: j.User.String(), Action: "invitation.accept",
		Target: "/organizations/" + inv.Organization.String() + "/invitations/" + inv.ID.String() + "?user=" + j.User.String()})
}
