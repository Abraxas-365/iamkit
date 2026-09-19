package authsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// DeliveryFactory creates a Delivery adapter from a URL and token.
// Injected by the module layer (e.g. authmail.WebhookDelivery).
type DeliveryFactory func(url, token string) authentication.Delivery

// DeliveryService manages per-environment webhook delivery configuration
// and sends challenge codes using the environment's config (or falls back
// to the global Delivery adapter).
type DeliveryService struct {
	repo    authentication.DeliveryConfigRepository
	global  authentication.Delivery  // fallback when no per-env config exists
	factory DeliveryFactory          // creates Delivery from per-env config
}

func NewDeliveryService(repo authentication.DeliveryConfigRepository, global authentication.Delivery, factory DeliveryFactory) *DeliveryService {
	return &DeliveryService{repo: repo, global: global, factory: factory}
}

// SetDeliveryConfig creates or replaces the per-environment delivery webhook.
func (s *DeliveryService) SetDeliveryConfig(ctx context.Context, environmentID string, input authentication.DeliveryConfigInput) error {
	if !identity.ValidID(environmentID) {
		return errx.Validation("environment_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repo.SetDeliveryConfig(ctx, environmentID, input.WebhookURL, input.WebhookToken)
}

// DeleteDeliveryConfig removes the per-environment config; the environment
// falls back to the global EMAIL_WEBHOOK_URL.
func (s *DeliveryService) DeleteDeliveryConfig(ctx context.Context, environmentID string) error {
	if !identity.ValidID(environmentID) {
		return errx.Validation("environment_id must be a valid UUID")
	}
	return s.repo.DeleteDeliveryConfig(ctx, environmentID)
}

// DeliveryConfig returns the per-environment delivery configuration.
func (s *DeliveryService) DeliveryConfig(ctx context.Context, environmentID string) (authentication.DeliveryConfig, error) {
	if !identity.ValidID(environmentID) {
		return authentication.DeliveryConfig{}, errx.Validation("environment_id must be a valid UUID")
	}
	cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	return cfg, err
}

// Send delivers a challenge code using the per-environment webhook config
// if available, otherwise falls back to the global delivery adapter.
func (s *DeliveryService) Send(ctx context.Context, environmentID, email, purpose, code string) error {
	// Try per-environment config first.
	cfg, token, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	if err == nil && s.factory != nil {
		d := s.factory(cfg.WebhookURL, token)
		return d.Send(ctx, email, purpose, code)
	}
	// Fall back to global.
	if s.global != nil {
		return s.global.Send(ctx, email, purpose, code)
	}
	return errx.External("email delivery is not configured")
}
