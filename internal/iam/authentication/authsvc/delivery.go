package authsvc

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type DeliveryFactory func(url, token string) authentication.Delivery

type DeliveryService struct {
	repo    authentication.DeliveryConfigRepository
	global  authentication.Delivery
	factory DeliveryFactory
	issuer  string
	now     func() time.Time
}

var _ authentication.DeliveryConfigCommands = (*DeliveryService)(nil)
var _ authentication.DeliveryConfigQueries = (*DeliveryService)(nil)

// NewDeliveryService builds the delivery service; issuer is IAMKit's public
// URL, used to offer the hosted invitation page.
func NewDeliveryService(repo authentication.DeliveryConfigRepository, global authentication.Delivery, factory DeliveryFactory, issuer string) *DeliveryService {
	return &DeliveryService{repo: repo, global: global, factory: factory, issuer: strings.TrimRight(issuer, "/"), now: time.Now}
}

// Audited delivery actions; the target is the environment's delivery path
// (or, for tests, the source used), never the URL or token.
const (
	ActionDeliveryUpdate = "delivery.update"
	ActionDeliveryDelete = "delivery.delete"
	ActionDeliveryTest   = "delivery.test"
)

func (s *DeliveryService) SetDeliveryConfig(ctx context.Context, m authentication.Mutation, input authentication.DeliveryConfigInput) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	m.Action, m.Target = ActionDeliveryUpdate, "/environments/"+m.Environment.String()+"/delivery"
	return s.repo.SetDeliveryConfig(ctx, m, input)
}

func (s *DeliveryService) DeleteDeliveryConfig(ctx context.Context, m authentication.Mutation) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	m.Action, m.Target = ActionDeliveryDelete, "/environments/"+m.Environment.String()+"/delivery"
	return s.repo.DeleteDeliveryConfig(ctx, m)
}

func (s *DeliveryService) DeliveryConfig(ctx context.Context, environmentID identity.EnvironmentID) (authentication.DeliveryConfig, error) {
	if environmentID.IsZero() {
		return authentication.DeliveryConfig{}, errx.Validation("environment_id must be a valid UUID")
	}
	cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	return cfg, err
}

// DeliveryStatus reports which webhook serves the environment and its
// recent delivery activity.
func (s *DeliveryService) DeliveryStatus(ctx context.Context, environmentID identity.EnvironmentID) (authentication.DeliveryStatus, error) {
	if environmentID.IsZero() {
		return authentication.DeliveryStatus{}, errx.Validation("environment_id must be a valid UUID")
	}
	source := authentication.SourceEnvironment
	if _, _, err := s.repo.GetDeliveryConfig(ctx, environmentID); err != nil {
		if !notFound(err) {
			return authentication.DeliveryStatus{}, err
		}
		source = authentication.SourceNone
		if s.global != nil {
			source = authentication.SourceGlobal
		}
	}
	activity, err := s.repo.Activity(ctx, environmentID)
	if err != nil {
		return authentication.DeliveryStatus{}, err
	}
	out := authentication.DeliveryStatus{Source: source, GlobalConfigured: s.global != nil, Activity: activity}
	if s.issuer != "" {
		out.HostedInvitationURL = s.issuer + "/hosted/invite"
	}
	return out, nil
}

// InvitationURL returns the environment's invitation page, or "" when it
// has none (the global webhook has no invitation page).
func (s *DeliveryService) InvitationURL(ctx context.Context, environmentID identity.EnvironmentID) (string, error) {
	cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	if notFound(err) {
		return "", nil
	}
	return cfg.InvitationURL, err
}

// Send delivers through the environment's webhook, falling back to the
// global one, and records the outcome for the console.
func (s *DeliveryService) Send(ctx context.Context, environmentID identity.EnvironmentID, m authentication.Message) error {
	_, err := s.deliver(ctx, environmentID, m)
	return err
}

// TestDelivery sends a code-less test message through the effective webhook.
// A failed delivery is a result, not an error: the attempt says why.
func (s *DeliveryService) TestDelivery(ctx context.Context, m authentication.Mutation, input authentication.TestInput) (authentication.Attempt, error) {
	if m.Environment.IsZero() {
		return authentication.Attempt{}, errx.Validation("environment_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return authentication.Attempt{}, err
	}
	email, _ := identity.Email(input.Email)
	attempt, _ := s.deliver(ctx, m.Environment, authentication.Message{Email: email, Purpose: authentication.PurposeTest})
	m.Action, m.Target = ActionDeliveryTest, attempt.Source
	if err := s.repo.Audit(ctx, m); err != nil {
		return authentication.Attempt{}, err
	}
	return attempt, nil
}

// deliver picks the environment webhook, else the global one (also when the
// configuration lookup fails), sends, and records the attempt.
func (s *DeliveryService) deliver(ctx context.Context, environmentID identity.EnvironmentID, m authentication.Message) (authentication.Attempt, error) {
	start := s.now()
	source, sender := authentication.SourceNone, authentication.Delivery(nil)
	cfg, token, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	switch {
	case err == nil && s.factory != nil:
		source, sender = authentication.SourceEnvironment, s.factory(cfg.WebhookURL, token)
	case s.global != nil:
		source, sender = authentication.SourceGlobal, s.global
	}
	err = authentication.ErrDeliveryNotConfigured()
	if sender != nil {
		err = sender.Send(ctx, m)
	}
	attempt := authentication.Attempt{Source: source, Purpose: m.Purpose, Delivered: err == nil, LatencyMS: int(s.now().Sub(start).Milliseconds()), At: start.UTC()}
	if err != nil {
		attempt.Status, attempt.Reason = authentication.Describe(err)
	}
	// Best effort: recording must never fail a delivery.
	if recordErr := s.repo.RecordAttempt(context.WithoutCancel(ctx), environmentID, attempt); recordErr != nil {
		slog.WarnContext(ctx, "record delivery attempt failed", "environment", environmentID, "err", recordErr)
	}
	return attempt, err
}

func notFound(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeNotFound
}
