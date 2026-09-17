package orgpg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
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
func (r *Repository) Create(ctx context.Context, environment, id, name string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO organizations(id,environment_id,name) VALUES($1,$2,$3)`, id, environment, name)
	return failure(err)
}
func (r *Repository) List(ctx context.Context, environment string) ([]organization.Summary, error) {
	var rows []struct {
		ID   string `db:"id"`
		Name string `db:"name"`
	}
	if err := r.db.SelectContext(ctx, &rows, `SELECT id,name FROM organizations WHERE environment_id=$1 ORDER BY id LIMIT 100`, environment); err != nil {
		return nil, failure(err)
	}
	out := make([]organization.Summary, 0, len(rows))
	for _, row := range rows {
		out = append(out, organization.Summary{ID: row.ID, Name: row.Name})
	}
	return out, nil
}
func (r *Repository) Find(ctx context.Context, environment, id string) (organization.Organization, error) {
	var row struct {
		ID       string `db:"id"`
		Name     string `db:"name"`
		Active   bool   `db:"active"`
		Metadata []byte `db:"metadata"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT id,name,active,metadata FROM organizations WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return organization.Organization{}, errx.NotFound("resource not found")
	}
	return organization.Organization{ID: row.ID, Name: row.Name, Active: row.Active, Metadata: json.RawMessage(row.Metadata)}, failure(err)
}
func (r *Repository) Update(ctx context.Context, m organization.Mutation, id string, input organization.Update) error {
	var metadata any
	if len(input.Metadata) > 0 {
		metadata = string(input.Metadata)
	}
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE organizations SET name=coalesce($3,name),active=coalesce($4,active),metadata=coalesce($5::jsonb,metadata) WHERE environment_id=$1 AND id=$2`, m.Environment, id, input.Name, input.Active, metadata)
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
func (r *Repository) AddMember(ctx context.Context, environment string, input organization.Membership) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO memberships(environment_id,organization_id,user_id,role) VALUES($1,$2,$3,$4)`, environment, input.Organization, input.User, input.Role)
	return conflict(err)
}
func (r *Repository) RemoveMember(ctx context.Context, environment, org, user string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE memberships SET active=false WHERE environment_id=$1 AND organization_id=$2 AND user_id=$3`, environment, org, user)
	return failure(err)
}

var _ organization.Repository = (*Repository)(nil)
