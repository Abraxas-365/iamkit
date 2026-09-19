package authpg

import (
	"context"
	"database/sql"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/jmoiron/sqlx"
)

// DeliveryConfigRepository implements authentication.DeliveryConfigRepository.
type DeliveryConfigRepository struct{ db *sqlx.DB }

func NewDeliveryConfigRepository(db *sqlx.DB) *DeliveryConfigRepository {
	return &DeliveryConfigRepository{db}
}

func (r *DeliveryConfigRepository) GetDeliveryConfig(ctx context.Context, environmentID string) (authentication.DeliveryConfig, string, error) {
	var row struct {
		EnvironmentID string    `db:"environment_id"`
		WebhookURL    string    `db:"webhook_url"`
		WebhookToken  string    `db:"webhook_token"`
		CreatedAt     time.Time `db:"created_at"`
		UpdatedAt     time.Time `db:"updated_at"`
	}
	err := r.db.GetContext(ctx, &row, `SELECT environment_id, webhook_url, webhook_token, created_at, updated_at FROM delivery_configs WHERE environment_id = $1`, environmentID)
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
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
	return cfg, row.WebhookToken, nil
}

func (r *DeliveryConfigRepository) SetDeliveryConfig(ctx context.Context, environmentID, webhookURL, webhookToken string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO delivery_configs (environment_id, webhook_url, webhook_token, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (environment_id) DO UPDATE SET webhook_url = $2, webhook_token = $3, updated_at = now()`,
		environmentID, webhookURL, webhookToken)
	if err != nil {
		return errx.Wrap(err, "save delivery config", errx.TypeInternal)
	}
	return nil
}

func (r *DeliveryConfigRepository) DeleteDeliveryConfig(ctx context.Context, environmentID string) error {
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
