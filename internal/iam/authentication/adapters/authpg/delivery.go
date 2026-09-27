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

func (r *DeliveryConfigRepository) SetDeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID, input authentication.DeliveryConfigInput) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO delivery_configs (environment_id, webhook_url, webhook_token, invitation_url, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (environment_id) DO UPDATE SET webhook_url = $2, webhook_token = $3, invitation_url = $4, updated_at = now()`,
		environmentID, input.WebhookURL, input.WebhookToken, input.InvitationURL)
	if err != nil {
		return errx.Wrap(err, "save delivery config", errx.TypeInternal)
	}
	return nil
}

func (r *DeliveryConfigRepository) DeleteDeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM delivery_configs WHERE environment_id = $1`, environmentID)
	if err != nil {
		return errx.Wrap(err, "delete delivery config", errx.TypeInternal)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errx.NotFound("delivery config not found")
	}
	return nil
}

var _ authentication.DeliveryConfigRepository = (*DeliveryConfigRepository)(nil)
