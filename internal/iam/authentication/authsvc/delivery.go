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

// DeliveryFactory builds the delivery of a stored configuration; it opens
// the sealed secret, so it can fail (DELIVERY_CREDENTIAL).
type DeliveryFactory func(cfg authentication.DeliveryConfig, secret authentication.DeliverySecret) (authentication.Delivery, error)

type DeliveryService struct {
	repo    authentication.DeliveryConfigRepository
	global  authentication.Delivery
	factory DeliveryFactory
	cipher  authentication.Cipher
	issuer  string
	now     func() time.Time
	// globalProvider names the global delivery's provider for status.
	globalProvider string
}

var _ authentication.DeliveryConfigCommands = (*DeliveryService)(nil)
var _ authentication.DeliveryConfigQueries = (*DeliveryService)(nil)

// NewDeliveryService builds the delivery service; cipher seals provider
// secrets (nil refuses to store them); issuer is IAMKit's public URL, used
// to offer the hosted invitation page.
func NewDeliveryService(repo authentication.DeliveryConfigRepository, global authentication.Delivery, factory DeliveryFactory, cipher authentication.Cipher, issuer string) *DeliveryService {
	return &DeliveryService{repo: repo, global: global, factory: factory, cipher: cipher, issuer: strings.TrimRight(issuer, "/"), now: time.Now, globalProvider: authentication.ProviderWebhook}
}

// SetGlobalProvider names the provider of the global delivery (webhook by
// default) for DeliveryStatus.
func (s *DeliveryService) SetGlobalProvider(provider string) { s.globalProvider = provider }

// Audited delivery actions; the target is the environment's delivery path
// (or, for tests, the source used), never the URL or secret.
const (
	ActionDeliveryUpdate = "delivery.update"
	ActionDeliveryDelete = "delivery.delete"
	ActionDeliveryTest   = "delivery.test"
)

// SetDeliveryConfig validates and stores the configuration. A provider
// secret (SMTP password, Resend API key) is sealed; left blank while keeping
// the same provider, the stored one is kept.
func (s *DeliveryService) SetDeliveryConfig(ctx context.Context, m authentication.Mutation, input authentication.DeliveryConfigInput) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return err
	}
	sealed := ""
	if input.Provider != authentication.ProviderWebhook {
		var err error
		if sealed, err = s.secret(ctx, m.Environment, input); err != nil {
			return err
		}
	}
	m.Action, m.Target = ActionDeliveryUpdate, "/environments/"+m.Environment.String()+"/delivery"
	return s.repo.SetDeliveryConfig(ctx, m, input, sealed)
}

// secret returns the sealed provider secret to store: the new one, the
// stored one (same provider, blank input), or "" when the provider needs
// none (SMTP without authentication).
func (s *DeliveryService) secret(ctx context.Context, environment identity.EnvironmentID, input authentication.DeliveryConfigInput) (string, error) {
	if plain := input.Secret(); plain != "" {
		if s.cipher == nil {
			return "", errx.Business("storing secrets requires IAMKIT_ENCRYPTION_KEY to be configured")
		}
		return s.cipher.Seal([]byte(plain))
	}
	stored, secret, err := s.repo.GetDeliveryConfig(ctx, environment)
	if err != nil && !notFound(err) {
		return "", err
	}
	kept := ""
	if err == nil && stored.Provider == input.Provider {
		kept = secret.Sealed
	}
	switch {
	case input.Provider == authentication.ProviderResend && kept == "":
		return "", errx.Validation("api_key is required")
	case input.Provider == authentication.ProviderSMTP && input.SMTPUsername != "" && kept == "":
		return "", errx.Validation("smtp_password is required")
	case input.Provider == authentication.ProviderSMTP && input.SMTPUsername == "":
		return "", nil // no authentication: nothing to keep
	}
	return kept, nil
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

// DeliveryStatus reports which configuration serves the environment, its
// provider, and its recent delivery activity.
func (s *DeliveryService) DeliveryStatus(ctx context.Context, environmentID identity.EnvironmentID) (authentication.DeliveryStatus, error) {
	if environmentID.IsZero() {
		return authentication.DeliveryStatus{}, errx.Validation("environment_id must be a valid UUID")
	}
	source, provider := authentication.SourceEnvironment, ""
	if cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID); err == nil {
		provider = cfg.Provider
	} else {
		if !notFound(err) {
			return authentication.DeliveryStatus{}, err
		}
		source = authentication.SourceNone
		if s.global != nil {
			source, provider = authentication.SourceGlobal, s.globalProvider
		}
	}
	activity, err := s.repo.Activity(ctx, environmentID)
	if err != nil {
		return authentication.DeliveryStatus{}, err
	}
	out := authentication.DeliveryStatus{Source: source, Provider: provider, GlobalConfigured: s.global != nil, Activity: activity}
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

// deliver picks the environment's delivery, else the global one (also when
// the configuration lookup fails), sends, and records the attempt. A stored
// configuration that cannot be built (undecryptable secret) fails the
// attempt rather than falling back.
func (s *DeliveryService) deliver(ctx context.Context, environmentID identity.EnvironmentID, m authentication.Message) (authentication.Attempt, error) {
	start := s.now()
	m.Environment = environmentID
	source, sender := authentication.SourceNone, authentication.Delivery(nil)
	var buildErr error
	cfg, secret, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	switch {
	case err == nil && s.factory != nil:
		source = authentication.SourceEnvironment
		sender, buildErr = s.factory(cfg, secret)
	case s.global != nil:
		source, sender = authentication.SourceGlobal, s.global
	}
	err = authentication.ErrDeliveryNotConfigured()
	switch {
	case buildErr != nil:
		err = buildErr
	case sender != nil:
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
