package authpg

import (
	"context"
	"database/sql"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// SMSRepository implements authentication.SMSRepository.
type SMSRepository struct{ db *sqlx.DB }

func NewSMSRepository(db *sqlx.DB) *SMSRepository { return &SMSRepository{db} }

var _ authentication.SMSRepository = (*SMSRepository)(nil)

func (r *SMSRepository) GetSMSConfig(ctx context.Context, environment identity.EnvironmentID) (authentication.SMSConfig, string, error) {
	var row struct {
		authentication.SMSConfig
		Sealed string `db:"secret_sealed"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT environment_id, provider, account_sid, from_number, messaging_service_sid, webhook_url,
		secret_sealed, created_at, updated_at FROM sms_configs WHERE environment_id=$1`, environment)
	if err == sql.ErrNoRows {
		return authentication.SMSConfig{}, "", errx.NotFound("SMS configuration not found")
	}
	if err != nil {
		return authentication.SMSConfig{}, "", errx.Wrap(err, "read SMS configuration", errx.TypeInternal)
	}
	row.SMSConfig.HasSecret = row.Sealed != ""
	return row.SMSConfig, row.Sealed, nil
}

// SetSMSConfig writes the whole row: switching provider clears the other
// provider's settings.
func (r *SMSRepository) SetSMSConfig(ctx context.Context, m authentication.Mutation, input authentication.SMSConfigInput, sealed string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "save SMS configuration", errx.TypeInternal)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sms_configs (environment_id, provider, account_sid, from_number, messaging_service_sid, webhook_url, secret_sealed)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (environment_id) DO UPDATE SET provider=$2, account_sid=$3, from_number=$4, messaging_service_sid=$5,
			webhook_url=$6, secret_sealed=$7, updated_at=now()`,
		m.Environment, input.Provider, input.AccountSID, input.FromNumber, input.MessagingServiceSID, input.WebhookURL, sealed)
	if err != nil {
		return errx.Wrap(err, "save SMS configuration", errx.TypeInternal)
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "save SMS configuration")
}

func (r *SMSRepository) DeleteSMSConfig(ctx context.Context, m authentication.Mutation) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "delete SMS configuration", errx.TypeInternal)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM sms_configs WHERE environment_id=$1`, m.Environment)
	if err != nil {
		return errx.Wrap(err, "delete SMS configuration", errx.TypeInternal)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errx.NotFound("SMS configuration not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "delete SMS configuration")
}

func (r *SMSRepository) RecordSMSAttempt(ctx context.Context, environment identity.EnvironmentID, a authentication.Attempt) error {
	return recordAttempt(ctx, r.db, environment, "sms", a)
}

func (r *SMSRepository) SMSActivity(ctx context.Context, environment identity.EnvironmentID) (authentication.Activity, error) {
	return activity(ctx, r.db, environment, "sms")
}

func (r *SMSRepository) Audit(ctx context.Context, m authentication.Mutation) error {
	return audit(ctx, r.db, m)
}
