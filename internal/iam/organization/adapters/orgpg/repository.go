package orgpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Repository struct{ db *sqlx.DB }

func New(db *sqlx.DB) *Repository { return &Repository{db} }
func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "organization persistence failed", errx.TypeInternal)
}
func conflict(err error) error {
	var pg *pq.Error
	if errors.As(err, &pg) && pg.Code.Class() == "23" {
		return errx.Conflict("conflicting or out-of-bound organization")
	}
	return failure(err)
}
func (r *Repository) Create(ctx context.Context, environment identity.EnvironmentID, id identity.OrganizationID, name string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO organizations(id,environment_id,name) VALUES($1,$2,$3)`, id, environment, name)
	return failure(err)
}
func (r *Repository) List(ctx context.Context, environment identity.EnvironmentID, filter organization.Filter, page query.Pagination) (query.Paginated[organization.Summary], error) {
	base := `FROM organizations WHERE environment_id=$1`
	args := []any{environment}
	n := 1
	if !filter.User.IsZero() {
		n++
		base += fmt.Sprintf(" AND id IN (SELECT organization_id FROM memberships WHERE environment_id=$1 AND user_id=$%d)", n)
		args = append(args, filter.User)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND name ILIKE $%d", n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[organization.Summary]{}, failure(err)
	}
	out := []organization.Summary{}
	if err := r.db.SelectContext(ctx, &out, fmt.Sprintf("SELECT id,name,active %s ORDER BY name LIMIT %d OFFSET %d", base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[organization.Summary]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}
func (r *Repository) Find(ctx context.Context, environment identity.EnvironmentID, id identity.OrganizationID) (organization.Organization, error) {
	var row struct {
		ID              identity.OrganizationID `db:"id"`
		Name            string                  `db:"name"`
		Active          bool                    `db:"active"`
		Metadata        []byte                  `db:"metadata"`
		MFARequired     bool                    `db:"mfa_required"`
		MFAForFederated bool                    `db:"mfa_for_federated"`
		AllowPassword   bool                    `db:"allow_password"`
		AllowEmailCode  bool                    `db:"allow_email_code"`
		AllowSocial     bool                    `db:"allow_social"`
		AllowPasskey    bool                    `db:"allow_passkey"`
		AllowedFactors  pq.StringArray          `db:"allowed_factors"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT id,name,active,metadata,mfa_required,mfa_for_federated,allow_password,allow_email_code,allow_social,allow_passkey,allowed_factors FROM organizations WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return organization.Organization{}, errx.NotFound("resource not found")
	}
	return organization.Organization{ID: row.ID, Name: row.Name, Active: row.Active, Metadata: json.RawMessage(row.Metadata), MFARequired: row.MFARequired, MFAForFederated: row.MFAForFederated,
		AllowPassword: row.AllowPassword, AllowEmailCode: row.AllowEmailCode, AllowSocial: row.AllowSocial, AllowPasskey: row.AllowPasskey, AllowedFactors: []string(row.AllowedFactors)}, failure(err)
}
func (r *Repository) UpdateMember(ctx context.Context, m organization.Mutation, org identity.OrganizationID, user identity.UserID, input organization.MemberUpdate) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE memberships SET sso_bypass=coalesce($4,sso_bypass) WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, m.Environment, org, user, input.SSOBypass)
	if err != nil {
		return failure(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if count == 0 {
		return errx.NotFound("resource not found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) Update(ctx context.Context, m organization.Mutation, id identity.OrganizationID, input organization.Update) error {
	var metadata any
	if len(input.Metadata) > 0 {
		metadata = string(input.Metadata)
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	var factors any
	if input.AllowedFactors != nil {
		factors = pq.Array(input.AllowedFactors)
	}
	result, err := tx.ExecContext(ctx, `UPDATE organizations SET name=coalesce($3,name),active=coalesce($4,active),metadata=coalesce($5::jsonb,metadata),mfa_required=coalesce($6,mfa_required),mfa_for_federated=coalesce($7,mfa_for_federated),
		allow_password=coalesce($8,allow_password),allow_email_code=coalesce($9,allow_email_code),allow_social=coalesce($10,allow_social),allowed_factors=coalesce($11::text[],allowed_factors),
		allow_passkey=coalesce($12,allow_passkey) WHERE environment_id=$1 AND id=$2`,
		m.Environment, id, input.Name, input.Active, metadata, input.MFARequired, input.MFAForFederated, input.AllowPassword, input.AllowEmailCode, input.AllowSocial, factors, input.AllowPasskey)
	if err != nil {
		return conflict(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return failure(err)
	}
	if count == 0 {
		return errx.NotFound("resource not found")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) AddMember(ctx context.Context, environment identity.EnvironmentID, input organization.Membership) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3)`, environment, input.Organization, input.User)
	return conflict(err)
}

// RemoveMember deactivates the membership and drops the user from the
// organization's groups; re-adding the member does not restore them.
func (r *Repository) RemoveMember(ctx context.Context, environment identity.EnvironmentID, org identity.OrganizationID, user identity.UserID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE memberships SET active=false WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, environment, org, user); err != nil {
		return failure(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM group_members WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, environment, org, user); err != nil {
		return failure(err)
	}
	return failure(tx.Commit())
}
func (r *Repository) Members(ctx context.Context, environment identity.EnvironmentID, org identity.OrganizationID, filter organization.MemberFilter, page query.Pagination) (query.Paginated[organization.MemberView], error) {
	base := `FROM memberships m JOIN users u ON u.id=m.user_id LEFT JOIN users mgr ON mgr.id=m.manager_id WHERE m.environment_id=$1 AND m.organization_id=$2`
	args := []any{environment, org}
	n := 2
	if !filter.ManagerID.IsZero() {
		n++
		base += fmt.Sprintf(" AND m.manager_id=$%d", n)
		args = append(args, filter.ManagerID)
	}
	if filter.Active != nil {
		n++
		base += fmt.Sprintf(" AND m.active=$%d", n)
		args = append(args, *filter.Active)
	}
	if like := query.EscapeLike(page.Search); like != "" {
		n++
		base += fmt.Sprintf(" AND (u.name ILIKE $%d OR u.email ILIKE $%d)", n, n)
		args = append(args, like)
	}
	var total int
	if err := r.db.GetContext(ctx, &total, "SELECT count(*) "+base, args...); err != nil {
		return query.Paginated[organization.MemberView]{}, failure(err)
	}
	out := []organization.MemberView{}
	if err := r.db.SelectContext(ctx, &out, fmt.Sprintf("SELECT m.user_id, u.name AS user_name, u.email AS user_email, m.active, m.manager_id, mgr.name AS manager_name, m.sso_bypass %s ORDER BY u.name LIMIT %d OFFSET %d", base, page.Limit, page.Offset), args...); err != nil {
		return query.Paginated[organization.MemberView]{}, failure(err)
	}
	return query.NewPaginated(out, total, page), nil
}

var _ organization.Repository = (*Repository)(nil)
