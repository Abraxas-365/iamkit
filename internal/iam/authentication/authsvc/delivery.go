package authsvc

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// DeliveryFactory builds the delivery of a stored configuration; it opens
// the sealed secret, so it can fail (DELIVERY_CREDENTIAL).
type DeliveryFactory func(cfg authentication.DeliveryConfig, secret authentication.DeliverySecret) (authentication.Delivery, error)

type DeliveryService struct {
	repo     authentication.DeliveryConfigRepository
	global   authentication.Delivery
	factory  DeliveryFactory
	cipher   authentication.Cipher
	renderer authentication.Renderer
	// templates stores customized email wording (nil: defaults only).
	templates authentication.TemplateRepository
	issuer    string
	now       func() time.Time
	// globalProvider names the global delivery's provider for status.
	globalProvider string
	// usage meters sends (nil: none).
	usage authentication.Usage
}

// SetUsage enforces emails_per_day on Send and counts delivered emails.
func (s *DeliveryService) SetUsage(u authentication.Usage) { s.usage = u }

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

// SetRenderer sets the renderer of previews; without one, Preview fails.
func (s *DeliveryService) SetRenderer(r authentication.Renderer) { s.renderer = r }

// Audited delivery actions; the target is the environment's delivery path
// (or, for tests, the source used), never the URL or secret.
const (
	ActionDeliveryUpdate = "delivery.update"
	ActionDeliveryDelete = "delivery.delete"
	ActionDeliveryTest   = "delivery.test"
)

// SetDeliveryConfig validates and stores the configuration. A provider
// secret (SMTP password, Resend API key, webhook token) is sealed; left blank
// while keeping the same provider, a stored SMTP password or API key is kept.
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
	} else if s.cipher != nil {
		// The webhook token is sealed like the other providers' secrets;
		// without a configured key it is kept in plaintext, as before.
		switch token, err := s.cipher.Seal([]byte(input.WebhookToken)); {
		case err == nil:
			sealed, input.WebhookToken = token, ""
		case !keyRequired(err):
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
			e := errx.Business("storing secrets requires IAMKIT_ENCRYPTION_KEY to be configured")
			e.Code = "ENCRYPTION_KEY_REQUIRED" // = cryptox.CodeKeyRequired, as the sealer reports it
			return "", e
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
	case input.Provider == authentication.ProviderSMTP && input.SMTPUsername == "":
		return "", nil // no authentication: nothing to keep
	case input.Provider == authentication.ProviderSMTP && kept != "" && !sameServer(stored, input):
		// A kept password only ever goes to the server it was entered for:
		// otherwise anyone who may edit the configuration could point it at
		// their own host and receive the stored credential.
		return "", errx.Validation("smtp_password is required when changing smtp_host, smtp_port, smtp_tls or smtp_username")
	case input.Provider == authentication.ProviderSMTP && kept == "":
		return "", errx.Validation("smtp_password is required")
	}
	return kept, nil
}

// sameServer reports whether an SMTP input targets the stored server and
// account (input is normalized).
func sameServer(stored authentication.DeliveryConfig, input authentication.DeliveryConfigInput) bool {
	return stored.SMTPHost == input.SMTPHost && stored.SMTPPort == input.SMTPPort &&
		stored.SMTPTLS == input.SMTPTLS && stored.SMTPUsername == input.SMTPUsername
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

// InvitationURL returns the environment's invitation page. Without one,
// emails IAMKit renders itself (SMTP, Resend) link to the hosted page, so
// the link in the email and the one returned to the inviter agree; the
// webhook gets none, as before.
func (s *DeliveryService) InvitationURL(ctx context.Context, environmentID identity.EnvironmentID) (string, error) {
	provider := ""
	cfg, _, err := s.repo.GetDeliveryConfig(ctx, environmentID)
	switch {
	case err == nil:
		if cfg.InvitationURL != "" {
			return cfg.InvitationURL, nil
		}
		provider = cfg.Provider
	case !notFound(err):
		return "", err
	case s.global != nil:
		provider = s.globalProvider
	}
	if s.issuer != "" && (provider == authentication.ProviderSMTP || provider == authentication.ProviderResend) {
		return s.issuer + "/hosted/invite", nil
	}
	return "", nil
}

// Sample values of previews.
const (
	sampleCode         = "123456"
	sampleOrganization = "Acme"
	sampleInviter      = "Jane Doe"
	sampleEmail        = "jane@example.com"
)

// Preview renders a sample email of input.Purpose for the environment;
// nothing is sent, recorded or audited.
func (s *DeliveryService) Preview(ctx context.Context, environmentID identity.EnvironmentID, input authentication.PreviewInput) (authentication.Preview, error) {
	if environmentID.IsZero() {
		return authentication.Preview{}, errx.Validation("environment_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return authentication.Preview{}, err
	}
	if s.renderer == nil {
		return authentication.Preview{}, errx.Internal("email preview is not available")
	}
	m := authentication.Message{Email: sampleEmail, Purpose: input.Purpose, Environment: environmentID, Locale: i18n.Match(input.Locale)}
	switch input.Purpose {
	case authentication.PurposeInvitation:
		expires := s.now().Add(config.InvitationTTL)
		m.Organization, m.Inviter, m.ExpiresAt, m.Token = sampleOrganization, sampleInviter, &expires, "sample"
		base := s.issuer + "/hosted/invite"
		if url, err := s.InvitationURL(ctx, environmentID); err == nil && url != "" {
			base = url
		}
		m.Link = authentication.InvitationLink(base, "sample")
	case authentication.PurposeTest:
	default:
		m.Code = sampleCode
	}
	email, err := s.renderer.Render(ctx, m, authentication.Draft{Copy: input.Template, AppName: input.AppName})
	if err != nil {
		return authentication.Preview{}, err
	}
	return authentication.Preview{Subject: email.Subject, HTML: email.HTML, Text: email.Text}, nil
}

// Send delivers through the environment's webhook, falling back to the
// global one, and records the outcome for the console.
func (s *DeliveryService) Send(ctx context.Context, environmentID identity.EnvironmentID, m authentication.Message) error {
	if s.usage != nil {
		if err := s.usage.Admit(ctx, environmentID, usage.LimitEmails); err != nil {
			return err
		}
	}
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
	} else if s.usage != nil {
		s.usage.Count(ctx, environmentID, usage.MetricEmails, 1)
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

// keyRequired reports the cipher's "no IAMKIT_ENCRYPTION_KEY" refusal
// (cryptox.CodeKeyRequired).
func keyRequired(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Code == "ENCRYPTION_KEY_REQUIRED"
}
