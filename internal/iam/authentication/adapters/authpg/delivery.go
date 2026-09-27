package authpg

import (
	"context"
	"database/sql"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// DeliveryConfigRepository implements authentication.DeliveryConfigRepository.
type DeliveryConfigRepository struct{ db *sqlx.DB }

func NewDeliveryConfigRepository(db *sqlx.DB) *DeliveryConfigRepository {
	return &DeliveryConfigRepository{db}
}

func (r *DeliveryConfigRepository) GetDeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID) (authentication.DeliveryConfig, string, error) {
	var row struct {
		EnvironmentID identity.EnvironmentID `db:"environment_id"`
		WebhookURL    string                 `db:"webhook_url"`
		WebhookToken  string                 `db:"webhook_token"`
		InvitationURL string                 `db:"invitation_url"`
		CreatedAt     time.Time              `db:"created_at"`
		UpdatedAt     time.Time              `db:"updated_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT environment_id, webhook_url, webhook_token, invitation_url, created_at, updated_at FROM delivery_configs WHERE environment_id = $1`, environmentID)
	if err == sql.ErrNoRows {
		return authentication.DeliveryConfig{}, "", errx.NotFound("delivery config not found")
	}
	if err != nil {
		return authentication.DeliveryConfig{}, "", errx.Wrap(err, "read delivery config", errx.TypeInternal)
	}
	cfg := authentication.DeliveryConfig{
		EnvironmentID: row.EnvironmentID,
		WebhookURL:    row.WebhookURL,
		HasToken:      row.WebhookToken != "",
		InvitationURL: row.InvitationURL,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
	return cfg, row.WebhookToken, nil
}

func (r *DeliveryConfigRepository) SetDeliveryConfig(ctx context.Context, m authentication.Mutation, input authentication.DeliveryConfigInput) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "save delivery config", errx.TypeInternal)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO delivery_configs (environment_id, webhook_url, webhook_token, invitation_url, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (environment_id) DO UPDATE SET webhook_url = $2, webhook_token = $3, invitation_url = $4, updated_at = now()`,
		m.Environment, input.WebhookURL, input.WebhookToken, input.InvitationURL)
	if err != nil {
		return errx.Wrap(err, "save delivery config", errx.TypeInternal)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "save delivery config")
}

func (r *DeliveryConfigRepository) DeleteDeliveryConfig(ctx context.Context, m authentication.Mutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "delete delivery config", errx.TypeInternal)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM delivery_configs WHERE environment_id = $1`, m.Environment)
	if err != nil {
		return errx.Wrap(err, "delete delivery config", errx.TypeInternal)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("delivery config not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "delete delivery config")
}

func audit(ctx context.Context, tx sqlx.ExecerContext, m authentication.Mutation) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, m.Environment, m.Actor, m.Action, m.Target)
	if err != nil {
		return errx.Wrap(err, "audit delivery", errx.TypeInternal)
	}
	return nil
}

func commit(tx *sqlx.Tx, message string) error {
	if err := tx.Commit(); err != nil {
		return errx.Wrap(err, message, errx.TypeInternal)
	}
	return nil
}

var _ authentication.DeliveryConfigRepository = (*DeliveryConfigRepository)(nil)

// RecordAttempt keeps the latest attempt; a failure also replaces the
// latest-failure columns, which later successes leave in place. Attempts for
// an unknown environment are ignored.
func (r *DeliveryConfigRepository) RecordAttempt(ctx context.Context, environmentID identity.EnvironmentID, a authentication.Attempt) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO delivery_activity AS d (environment_id, source, purpose, delivered, status, reason, latency_ms, attempted_at,
			failure_source, failure_purpose, failure_status, failure_reason, failed_at)
		SELECT e.id, $2, $3, $4, $5, $6, $7, $8,
			CASE WHEN $4 THEN NULL ELSE $2 END, CASE WHEN $4 THEN NULL ELSE $3 END,
			CASE WHEN $4 THEN NULL ELSE $5::int END, CASE WHEN $4 THEN NULL ELSE $6 END,
			CASE WHEN $4 THEN NULL ELSE $8::timestamptz END
		FROM environments e WHERE e.id = $1
		ON CONFLICT (environment_id) DO UPDATE SET
			source = EXCLUDED.source, purpose = EXCLUDED.purpose, delivered = EXCLUDED.delivered,
			status = EXCLUDED.status, reason = EXCLUDED.reason, latency_ms = EXCLUDED.latency_ms,
			attempted_at = EXCLUDED.attempted_at,
			failure_source  = CASE WHEN EXCLUDED.delivered THEN d.failure_source  ELSE EXCLUDED.failure_source END,
			failure_purpose = CASE WHEN EXCLUDED.delivered THEN d.failure_purpose ELSE EXCLUDED.failure_purpose END,
			failure_status  = CASE WHEN EXCLUDED.delivered THEN d.failure_status  ELSE EXCLUDED.failure_status END,
			failure_reason  = CASE WHEN EXCLUDED.delivered THEN d.failure_reason  ELSE EXCLUDED.failure_reason END,
			failed_at       = CASE WHEN EXCLUDED.delivered THEN d.failed_at       ELSE EXCLUDED.failed_at END`,
		environmentID, a.Source, a.Purpose, a.Delivered, a.Status, a.Reason, a.LatencyMS, a.At)
	if err != nil {
		return errx.Wrap(err, "record delivery attempt", errx.TypeInternal)
	}
	return nil
}

// Activity returns the latest attempt and the latest failure, if any.
func (r *DeliveryConfigRepository) Activity(ctx context.Context, environmentID identity.EnvironmentID) (authentication.Activity, error) {
	var row struct {
		Source         string         `db:"source"`
		Purpose        string         `db:"purpose"`
		Delivered      bool           `db:"delivered"`
		Status         sql.NullInt32  `db:"status"`
		Reason         string         `db:"reason"`
		LatencyMS      int            `db:"latency_ms"`
		AttemptedAt    time.Time      `db:"attempted_at"`
		FailureSource  sql.NullString `db:"failure_source"`
		FailurePurpose sql.NullString `db:"failure_purpose"`
		FailureStatus  sql.NullInt32  `db:"failure_status"`
		FailureReason  sql.NullString `db:"failure_reason"`
		FailedAt       sql.NullTime   `db:"failed_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT source, purpose, delivered, status, reason, latency_ms, attempted_at,
		failure_source, failure_purpose, failure_status, failure_reason, failed_at
		FROM delivery_activity WHERE environment_id = $1`, environmentID)
	if err == sql.ErrNoRows {
		return authentication.Activity{}, nil
	}
	if err != nil {
		return authentication.Activity{}, errx.Wrap(err, "read delivery activity", errx.TypeInternal)
	}
	out := authentication.Activity{Last: &authentication.Attempt{
		Source: row.Source, Purpose: row.Purpose, Delivered: row.Delivered, Status: nullInt(row.Status),
		Reason: row.Reason, LatencyMS: row.LatencyMS, At: row.AttemptedAt,
	}}
	if row.FailedAt.Valid {
		out.LastFailure = &authentication.Attempt{
			Source: row.FailureSource.String, Purpose: row.FailurePurpose.String, Status: nullInt(row.FailureStatus),
			Reason: row.FailureReason.String, At: row.FailedAt.Time,
		}
	}
	return out, nil
}

func nullInt(v sql.NullInt32) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int32)
	return &n
}

func (r *DeliveryConfigRepository) Audit(ctx context.Context, m authentication.Mutation) error {
	return audit(ctx, r.db, m)
}
