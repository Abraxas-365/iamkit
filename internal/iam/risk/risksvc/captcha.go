package risksvc

import (
	"context"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// maxCaptchaToken bounds a widget answer (Turnstile's are at most 2048
// characters); longer ones are refused without calling the provider.
const maxCaptchaToken = 4096

// testResponse is the dummy answer TestCaptcha sends: every provider
// rejects it as an invalid response, which proves the secret.
const testResponse = "iamkit-captcha-test"

func captchaTarget(environment identity.EnvironmentID) string {
	return environment.String()
}

func (s *Service) SaveCaptcha(ctx context.Context, m risk.Mutation, input risk.CaptchaInput) (risk.CaptchaConfig, error) {
	if m.Environment.IsZero() {
		return risk.CaptchaConfig{}, errx.Validation("environment_id must be a valid UUID")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return risk.CaptchaConfig{}, err
	}
	sealed := ""
	if input.Secret != nil {
		if s.cipher == nil {
			return risk.CaptchaConfig{}, cryptox.KeyRequired()
		}
		var err error
		if sealed, err = s.cipher.Seal([]byte(*input.Secret)); err != nil {
			return risk.CaptchaConfig{}, err
		}
	} else {
		stored, kept, err := s.captchas.Captcha(ctx, m.Environment)
		switch {
		case err != nil && !isNotFound(err):
			return risk.CaptchaConfig{}, err
		case err == nil && stored.Provider == input.Provider:
			// A secret belongs to one provider: switching needs a new one.
			sealed = kept
		}
		if sealed == "" {
			return risk.CaptchaConfig{}, errx.Validation("secret is required")
		}
	}
	config := risk.CaptchaConfig{Environment: m.Environment, Provider: input.Provider, SiteKey: input.SiteKey,
		Hosted: input.Hosted == nil || *input.Hosted, Headless: input.Headless == nil || *input.Headless, Hostnames: input.Hostnames}
	m.Action, m.Target = risk.ActionCaptchaUpdate, captchaTarget(m.Environment)
	if err := s.captchas.SaveCaptcha(ctx, m, config, sealed); err != nil {
		return risk.CaptchaConfig{}, err
	}
	out, _, err := s.captchas.Captcha(ctx, m.Environment)
	return out, err
}

func (s *Service) DeleteCaptcha(ctx context.Context, m risk.Mutation) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	m.Action, m.Target = risk.ActionCaptchaDelete, captchaTarget(m.Environment)
	return s.captchas.DeleteCaptcha(ctx, m)
}

// TestCaptcha sends a dummy answer: the provider rejecting the response
// (not the secret) proves the stored secret is valid.
func (s *Service) TestCaptcha(ctx context.Context, environment identity.EnvironmentID) error {
	if environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	cfg, sealed, err := s.captchas.Captcha(ctx, environment)
	if err != nil {
		return err
	}
	secret, err := s.openSecret(sealed)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, config.CaptchaTimeout)
	defer cancel()
	answer, err := s.verifier.Verify(ctx, cfg.Provider, secret, risk.CaptchaCheck{Environment: environment, Token: testResponse})
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Type == errx.TypeExternal {
			return err
		}
		return errx.External("the CAPTCHA provider did not answer")
	}
	for _, code := range answer.Codes {
		switch code {
		case "invalid-input-secret", "missing-input-secret", "sitekey-secret-mismatch":
			return risk.ErrCaptchaSecretInvalid()
		}
	}
	return nil
}

func (s *Service) GrantPass(ctx context.Context, environment identity.EnvironmentID, ticket []byte) error {
	if len(ticket) == 0 {
		return nil
	}
	return s.captchas.SavePass(ctx, environment, ticket, s.now().Add(config.CaptchaPassTTL), config.CaptchaPassUses)
}

func (s *Service) UsePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte) (bool, error) {
	if len(ticket) == 0 {
		return false, nil
	}
	return s.captchas.UsePass(ctx, environment, ticket, s.now())
}

func (s *Service) Passed(ctx context.Context, environment identity.EnvironmentID, ticket []byte) (bool, error) {
	if len(ticket) == 0 {
		return false, nil
	}
	return s.captchas.Pass(ctx, environment, ticket, s.now())
}

// Captcha is the configuration, without its secret.
func (s *Service) Captcha(ctx context.Context, environment identity.EnvironmentID) (risk.CaptchaConfig, error) {
	if environment.IsZero() {
		return risk.CaptchaConfig{}, errx.Validation("environment_id must be a valid UUID")
	}
	cfg, _, err := s.captchas.Captcha(ctx, environment)
	return cfg, err
}

// active is the environment's configuration when a CAPTCHA applies to
// surface: the captcha feature is on, a configuration exists and requires
// the surface. Only the provider's own outage fails open (CheckCaptcha): a
// failed flag lookup keeps the flag on (a kill switch, like risk_signals)
// and a failed configuration lookup is the error, so a database blip never
// silently turns the CAPTCHA off.
func (s *Service) active(ctx context.Context, environment identity.EnvironmentID, surface string) (risk.CaptchaConfig, string, bool, error) {
	if s.captchas == nil || environment.IsZero() {
		return risk.CaptchaConfig{}, "", false, nil
	}
	if s.features != nil {
		on, err := s.features.Enabled(ctx, environment, config.FeatureCaptcha)
		if err != nil {
			slog.ErrorContext(ctx, "captcha feature lookup failed; keeping it on", "err", err)
			on = true
		}
		if !on {
			return risk.CaptchaConfig{}, "", false, nil
		}
	}
	cfg, sealed, err := s.captchas.Captcha(ctx, environment)
	if isNotFound(err) {
		return risk.CaptchaConfig{}, "", false, nil
	}
	if err != nil {
		slog.ErrorContext(ctx, "captcha configuration lookup failed", "err", err)
		return risk.CaptchaConfig{}, "", false, err
	}
	if !cfg.Required(surface) {
		return risk.CaptchaConfig{}, "", false, nil
	}
	return cfg, sealed, true, nil
}

func (s *Service) PublicCaptcha(ctx context.Context, environment identity.EnvironmentID, surface string) (risk.PublicCaptcha, error) {
	cfg, _, ok, err := s.active(ctx, environment, surface)
	if err != nil || !ok {
		return risk.PublicCaptcha{}, err
	}
	return risk.PublicCaptcha{Enabled: true, Provider: cfg.Provider, SiteKey: cfg.SiteKey, Headless: surface == risk.SurfaceHeadless}, nil
}

// CheckCaptcha verifies the widget's answer. Without a CAPTCHA for the
// surface it returns ""; a missing or rejected answer is always
// ErrCaptchaRequired; a provider that does not answer (transport error,
// timeout) fails open as CaptchaUnavailable.
func (s *Service) CheckCaptcha(ctx context.Context, check risk.CaptchaCheck) (string, error) {
	cfg, sealed, ok, err := s.active(ctx, check.Environment, check.Surface)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	token := strings.TrimSpace(check.Token)
	if token == "" || len(token) > maxCaptchaToken {
		return "", risk.ErrCaptchaRequired(cfg.Provider)
	}
	secret, err := s.openSecret(sealed)
	if err != nil {
		// Not a provider outage: an unreadable secret is a misconfiguration
		// and must not open the gate.
		slog.ErrorContext(ctx, "captcha secret unreadable", "err", err)
		return "", err
	}
	check.Token = token
	if check.Surface == risk.SurfaceHosted && check.Hostname == "" {
		check.Hostname = s.issuerHost
	}
	if check.Surface != risk.SurfaceHosted && check.Hostname == "" && len(cfg.Hostnames) > 0 && s.issuerHost != "" && !slices.Contains(cfg.Hostnames, s.issuerHost) {
		// Headless tokens may also come from the issuer's own host.
		cfg.Hostnames = append(slices.Clone(cfg.Hostnames), s.issuerHost)
	}
	vctx, cancel := context.WithTimeout(ctx, config.CaptchaTimeout)
	defer cancel()
	answer, err := s.verifier.Verify(vctx, cfg.Provider, secret, check)
	if err != nil {
		slog.WarnContext(ctx, "captcha provider did not answer; failing open", "provider", cfg.Provider, "err", err)
		return risk.CaptchaUnavailable, nil
	}
	if !answer.Accepts(cfg, check) {
		return "", risk.ErrCaptchaRequired(cfg.Provider)
	}
	return risk.CaptchaPassed, nil
}

func (s *Service) openSecret(sealed string) (string, error) {
	if s.cipher == nil {
		return "", cryptox.KeyRequired()
	}
	plain, err := s.cipher.Open(sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func isNotFound(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeNotFound
}

// HostOf returns the host name of an issuer URL ("" when unparsable).
func HostOf(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
