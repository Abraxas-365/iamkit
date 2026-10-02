package userpg

import (
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// audit records m in the transaction.
func audit(ctx context.Context, tx *sqlx.Tx, m user.Mutation) error {
	return failure(eventpg.Audit(ctx, tx, m.Environment, m.Actor, m.Action, m.Target), "audit user change")
}

// EditMetadata locks the user's row, applies edit and stores the result.
func (r *Repository) EditMetadata(ctx context.Context, m user.Mutation, id identity.UserID, edit func(json.RawMessage) (json.RawMessage, error)) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "edit metadata")
	}
	defer tx.Rollback()
	var current []byte
	if err = tx.GetContext(ctx, &current, `SELECT metadata FROM users WHERE environment_id=$1 AND id=$2 FOR UPDATE`, m.Environment, id); err != nil {
		return failure(err, "edit metadata")
	}
	next, err := edit(current)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET metadata=$3::jsonb WHERE environment_id=$1 AND id=$2`, m.Environment, id, string(next)); err != nil {
		return failure(err, "edit metadata")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit(), "commit metadata")
}

// EditProfile locks the user's row, applies edit with the current schema
// and stores the result.
func (r *Repository) EditProfile(ctx context.Context, m user.Mutation, id identity.UserID, edit func(json.RawMessage, user.Schema) (json.RawMessage, error)) (json.RawMessage, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, failure(err, "edit profile")
	}
	defer tx.Rollback()
	var current []byte
	if err = tx.GetContext(ctx, &current, `SELECT profile FROM users WHERE environment_id=$1 AND id=$2 FOR UPDATE`, m.Environment, id); err != nil {
		return nil, failure(err, "edit profile")
	}
	schema, err := schemaOf(ctx, tx, m.Environment)
	if err != nil {
		return nil, err
	}
	next, err := edit(current, schema)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET profile=$3::jsonb WHERE environment_id=$1 AND id=$2`, m.Environment, id, string(next)); err != nil {
		return nil, failure(err, "edit profile")
	}
	if err = audit(ctx, tx, m); err != nil {
		return nil, err
	}
	return next, failure(tx.Commit(), "commit profile")
}

func (r *Repository) Profile(ctx context.Context, environment identity.EnvironmentID, id identity.UserID) (json.RawMessage, error) {
	var profile []byte
	err := r.db.GetContext(ctx, &profile, `SELECT profile FROM users WHERE environment_id=$1 AND id=$2`, environment, id)
	return profile, failure(err, "read profile")
}

func schemaOf(ctx context.Context, q sqlx.QueryerContext, environment identity.EnvironmentID) (user.Schema, error) {
	var rows []user.Schema
	if err := sqlx.SelectContext(ctx, q, &rows, `SELECT schema,version,updated_at FROM user_schemas WHERE environment_id=$1`, environment); err != nil {
		return user.Schema{}, failure(err, "read user schema")
	}
	if len(rows) == 0 {
		return user.Schema{}, nil
	}
	return rows[0], nil
}

func (r *Repository) Schema(ctx context.Context, environment identity.EnvironmentID) (user.Schema, error) {
	return schemaOf(ctx, r.db, environment)
}

func (r *Repository) SaveSchema(ctx context.Context, m user.Mutation, schema json.RawMessage) (user.Schema, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return user.Schema{}, failure(err, "save user schema")
	}
	defer tx.Rollback()
	var out user.Schema
	err = tx.GetContext(ctx, &out, `INSERT INTO user_schemas(environment_id,schema) VALUES($1,$2::jsonb)
		ON CONFLICT (environment_id) DO UPDATE SET schema=excluded.schema,version=user_schemas.version+1,updated_at=now()
		RETURNING schema,version,updated_at`, m.Environment, string(schema))
	if err != nil {
		return user.Schema{}, failure(err, "save user schema")
	}
	if err = audit(ctx, tx, m); err != nil {
		return user.Schema{}, err
	}
	return out, failure(tx.Commit(), "commit user schema")
}

func (r *Repository) DeleteSchema(ctx context.Context, m user.Mutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err, "delete user schema")
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM user_schemas WHERE environment_id=$1`, m.Environment)
	if err != nil {
		return failure(err, "delete user schema")
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("no user schema is saved")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return failure(tx.Commit(), "commit user schema")
}

func (r *Repository) Profiles(ctx context.Context, environment identity.EnvironmentID) ([]user.ProfileRow, error) {
	rows := []user.ProfileRow{}
	err := r.db.SelectContext(ctx, &rows, `SELECT id,profile FROM users WHERE environment_id=$1 AND profile<>'{}'::jsonb`, environment)
	return rows, failure(err, "read profiles")
}
