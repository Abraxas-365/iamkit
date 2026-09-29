package authsvc

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SMSFactory builds the sender of an environment's SMS configuration from
// its opened secret.
type SMSFactory func(cfg authentication.SMSConfig, secret string) (authentication.SMSDelivery, error)

// SMSService implements the SMS provider use cases and sends second-factor
// texts. There is no deployment-wide SMS provider: every environment
// configures its own.
type SMSService struct {
	repo     authentication.SMSRepository
	factory  SMSFactory
	cipher   authentication.Cipher
	branding authentication.Branding
	locale   string
	now      func() time.Time
}

// NewSMSService: branding (optional) names the app in the text and picks
// its language, else locale.
func NewSMSService(repo authentication.SMSRepository, factory SMSFactory, cipher authentication.Cipher, branding authentication.Branding, locale string) *SMSService {
	return &SMSService{repo: repo, factory: factory, cipher: cipher, branding: branding, locale: locale, now: time.Now}
}

var (
	_ authentication.SMSCommands = (*SMSService)(nil)
	_ authentication.SMSQueries  = (*SMSService)(nil)
)

func smsTarget(environment identity.EnvironmentID) string {
	return "/environments/" + environment.String() + "/sms"
}

func (s *SMSService) SetSMSConfig(ctx context.Context, m authentication.Mutation, input authentication.SMSConfigInput) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return err
	}
	sealed := ""
	if plain := input.Secret(); plain != "" {
		if s.cipher == nil {
			return errx.Business("IAMKIT_ENCRYPTION_KEY is required to store SMS credentials")
		}
		var err error
		if sealed, err = s.cipher.Seal([]byte(plain)); err != nil {
			return err
		}
	} else {
		stored, kept, err := s.repo.GetSMSConfig(ctx, m.Environment)
		switch {
		case err != nil && !notFound(err):
			return err
		case err == nil && stored.Provider == input.Provider:
			sealed = kept
		}
		if sealed == "" {
			if input.Provider == authentication.SMSProviderTwilio {
				return errx.Validation("auth_token is required")
			}
			return errx.Validation("webhook_token is required")
		}
	}
	m.Action, m.Target = authentication.ActionSMSUpdate, smsTarget(m.Environment)
	return s.repo.SetSMSConfig(ctx, m, input, sealed)
}

func (s *SMSService) DeleteSMSConfig(ctx context.Context, m authentication.Mutation) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	m.Action, m.Target = authentication.ActionSMSDelete, smsTarget(m.Environment)
	return s.repo.DeleteSMSConfig(ctx, m)
}

func (s *SMSService) SMSConfig(ctx context.Context, environment identity.EnvironmentID) (authentication.SMSConfig, error) {
	if environment.IsZero() {
		return authentication.SMSConfig{}, errx.Validation("environment_id must be a valid UUID")
	}
	cfg, _, err := s.repo.GetSMSConfig(ctx, environment)
	return cfg, err
}

func (s *SMSService) SMSStatus(ctx context.Context, environment identity.EnvironmentID) (authentication.SMSStatus, error) {
	if environment.IsZero() {
		return authentication.SMSStatus{}, errx.Validation("environment_id must be a valid UUID")
	}
	out := authentication.SMSStatus{}
	cfg, _, err := s.repo.GetSMSConfig(ctx, environment)
	switch {
	case err == nil:
		out.Configured, out.Provider = true, cfg.Provider
	case !notFound(err):
		return out, err
	}
	activity, err := s.repo.SMSActivity(ctx, environment)
	if err != nil {
		return out, err
	}
	out.Activity = activity
	return out, nil
}

// Configured reports whether the environment has an SMS provider.
func (s *SMSService) Configured(ctx context.Context, environment identity.EnvironmentID) (bool, error) {
	_, _, err := s.repo.GetSMSConfig(ctx, environment)
	if notFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (s *SMSService) TestSMS(ctx context.Context, m authentication.Mutation, input authentication.SMSTestInput) (authentication.Attempt, error) {
	if m.Environment.IsZero() {
		return authentication.Attempt{}, errx.Validation("environment_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return authentication.Attempt{}, err
	}
	phone, _ := identity.Phone(input.Phone)
	attempt, _ := s.deliver(ctx, m.Environment, phone, authentication.PurposeTest, "")
	m.Action, m.Target = authentication.ActionSMSTest, attempt.Source
	if err := s.repo.Audit(ctx, m); err != nil {
		return authentication.Attempt{}, err
	}
	return attempt, nil
}

func (s *SMSService) SendSMS(ctx context.Context, environment identity.EnvironmentID, phone, purpose, code string) error {
	if !authentication.ValidSMSPurpose(purpose) || purpose == authentication.PurposeTest {
		return errx.Internal("unknown SMS purpose " + purpose)
	}
	_, err := s.deliver(ctx, environment, phone, purpose, code)
	return err
}

// Body is the text of an SMS: the app name, the code and its purpose, in
// the environment's language.
func (s *SMSService) Body(ctx context.Context, environment identity.EnvironmentID, purpose, code string) string {
	name, locale := "", ""
	if s.branding != nil {
		if b, err := s.branding.Brand(ctx, environment); err == nil {
			name, locale = strings.TrimSpace(b.Name), b.Locale
		}
	}
	if name == "" {
		name = "IAMKit"
	}
	locale = i18n.Resolve(locale, s.locale)
	if purpose == authentication.PurposeTest {
		return i18n.T(locale, "sms.test", name)
	}
	return i18n.T(locale, "sms."+purpose, code, name)
}

// deliver sends through the environment's provider and records the attempt
// (best effort).
func (s *SMSService) deliver(ctx context.Context, environment identity.EnvironmentID, phone, purpose, code string) (authentication.Attempt, error) {
	start := s.now()
	source := authentication.SourceNone
	var sender authentication.SMSDelivery
	cfg, sealed, err := s.repo.GetSMSConfig(ctx, environment)
	switch {
	case err == nil && s.factory != nil:
		source = authentication.SourceEnvironment
		sender, err = s.open(cfg, sealed)
	case err == nil || notFound(err):
		err = authentication.ErrSMSNotConfigured()
	}
	if err == nil {
		err = sender.SendSMS(ctx, authentication.SMS{Phone: phone, Purpose: purpose, Code: code, Body: s.Body(ctx, environment, purpose, code), Environment: environment})
	}
	attempt := authentication.Attempt{Source: source, Purpose: purpose, Delivered: err == nil, LatencyMS: int(s.now().Sub(start).Milliseconds()), At: start.UTC()}
	if err != nil {
		attempt.Status, attempt.Reason = authentication.Describe(err)
	}
	if recordErr := s.repo.RecordSMSAttempt(context.WithoutCancel(ctx), environment, attempt); recordErr != nil {
		slog.WarnContext(ctx, "record SMS attempt failed", "environment", environment, "err", recordErr)
	}
	return attempt, err
}

func (s *SMSService) open(cfg authentication.SMSConfig, sealed string) (authentication.SMSDelivery, error) {
	if s.cipher == nil {
		return nil, authentication.DeliveryFailure(errx.Internal("no cipher to open the SMS secret"), authentication.CodeDeliveryCredential)
	}
	plain, err := s.cipher.Open(sealed)
	if err != nil {
		return nil, authentication.DeliveryFailure(err, authentication.CodeDeliveryCredential)
	}
	return s.factory(cfg, string(plain))
}
