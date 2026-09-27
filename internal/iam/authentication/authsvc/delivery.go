package authsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type DeliveryFactory func(url, token string) authentication.Delivery

type DeliveryService struct {
	repo    authentication.DeliveryConfigRepository
	global  authentication.Delivery
	factory DeliveryFactory
}

func NewDeliveryService(repo authentication.DeliveryConfigRepository, global authentication.Delivery, factory DeliveryFactory) *DeliveryService {
	return &DeliveryService{repo: repo, global: global, factory: factory}
}

func (s *DeliveryService) SetDeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID, input authentication.DeliveryConfigInput) error {
	if environmentID.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repo.SetDeliveryConfig(ctx, environmentID, input)
}

func (s *DeliveryService) DeleteDeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID) error {
	if environmentID.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	return s.repo.DeleteDeliveryConfig(ctx, environmentID)
}

func (s *DeliveryService) DeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID) (authentication.DeliveryConfig, error) {
	if environmentID.IsZero() {
		return authentication.DeliveryConfig{}, errx.Validation("environment_id must be a valid UUID")
	}
	cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	return cfg, err
}

// InvitationURL returns the environment's invitation page, or "" when it
// has none (the global webhook has no invitation page).
func (s *DeliveryService) InvitationURL(ctx context.Context, environmentID identity.EnvironmentID) (string, error) {
	cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeNotFound {
		return "", nil
	}
	return cfg.InvitationURL, err
}

// Send delivers through the environment's webhook, falling back to the
// global one.
func (s *DeliveryService) Send(ctx context.Context, environmentID identity.EnvironmentID, m authentication.Message) error {
	cfg, token, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	if err == nil && s.factory != nil {
		return s.factory(cfg.WebhookURL, token).Send(ctx, m)
	}
	if s.global != nil {
		return s.global.Send(ctx, m)
	}
	return errx.External("email delivery is not configured")
}
