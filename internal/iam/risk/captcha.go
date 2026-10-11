// Package risk is bot protection (CAPTCHA) and risk signals for end-user
// sign-ins: an environment's CAPTCHA provider, its risk policy (what each
// detection does), allow/deny restrictions checked before any credential,
// and the log of sign-in attempts the detections read. Everything is off
// until an operator configures it.
package risk

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// CAPTCHA providers.
const (
	ProviderTurnstile = "turnstile"
	ProviderHCaptcha  = "hcaptcha"
)

// Providers lists the CAPTCHA providers, in display order.
var Providers = []string{ProviderTurnstile, ProviderHCaptcha}

// Surfaces: IAMKit's hosted pages or a headless client (custom sign-in UI
// calling /identity/v1).
const (
	SurfaceHosted   = "hosted"
	SurfaceHeadless = "headless"
)

// CAPTCHA actions: what the widget protects (Turnstile checks it; hCaptcha
// ignores it).
const (
	CaptchaLogin  = "login"
	CaptchaSignup = "signup"
	CaptchaDevice = "device"
)

// CAPTCHA outcomes recorded on a sign-in attempt ("" = not required).
const (
	CaptchaPassed      = "passed"
	CaptchaFailed      = "failed"
	CaptchaUnavailable = "unavailable"
)

// MaxCaptchaHostnames caps the extra hostnames of a CAPTCHA configuration.
const MaxCaptchaHostnames = 20

// CaptchaConfig is an environment's CAPTCHA provider. The secret is sealed
// and never returned; HasSecret says one is stored.
type CaptchaConfig struct {
	Environment identity.EnvironmentID `json:"environment_id"`
	Provider    string                 `json:"provider"`
	SiteKey     string                 `json:"site_key"`
	HasSecret   bool                   `json:"has_secret"`
	// Hosted / Headless: where a solved CAPTCHA is required — the hosted
	// pages (identify, signup, device code) and the headless routes
	// (/login, /challenges, /signup, /federation/ldap/login).
	Hosted   bool `json:"hosted"`
	Headless bool `json:"headless"`
	// Hostnames are the hostnames a headless token may have been solved on
	// (the custom sign-in UI's); empty = any. Hosted tokens must come from
	// the issuer's host.
	Hostnames []string  `json:"hostnames"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Required says whether surface needs a solved CAPTCHA.
func (c CaptchaConfig) Required(surface string) bool {
	if c.Provider == "" {
		return false
	}
	if surface == SurfaceHosted {
		return c.Hosted
	}
	return c.Headless
}

// CaptchaInput sets the CAPTCHA configuration (PUT). Secret nil keeps the
// stored one (required when none is stored); Hosted/Headless nil = true.
type CaptchaInput struct {
	Provider  string   `json:"provider"`
	SiteKey   string   `json:"site_key"`
	Secret    *string  `json:"secret,omitempty"`
	Hosted    *bool    `json:"hosted,omitempty"`
	Headless  *bool    `json:"headless,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}

// Validate checks the input; Normalize first.
func (in CaptchaInput) Validate() error {
	if !slices.Contains(Providers, in.Provider) {
		return errx.Validation("provider must be turnstile or hcaptcha")
	}
	if in.SiteKey == "" || len(in.SiteKey) > 200 || strings.ContainsAny(in.SiteKey, " \t\r\n") {
		return errx.Validation("site_key is required (at most 200 characters, no spaces)")
	}
	if in.Secret != nil && (*in.Secret == "" || len(*in.Secret) > 500) {
		return errx.Validation("secret must be 1 to 500 characters")
	}
	if len(in.Hostnames) > MaxCaptchaHostnames {
		return errx.Validation("at most 20 hostnames")
	}
	for _, h := range in.Hostnames {
		if !ValidHostname(h) {
			return errx.Validation("hostnames must be host names without scheme, port or path")
		}
	}
	return nil
}

// Normalize trims the input and lowercases hostnames.
func (in CaptchaInput) Normalize() CaptchaInput {
	in.Provider = strings.TrimSpace(in.Provider)
	in.SiteKey = strings.TrimSpace(in.SiteKey)
	if in.Secret != nil {
		s := strings.TrimSpace(*in.Secret)
		in.Secret = &s
	}
	hosts := make([]string, 0, len(in.Hostnames))
	for _, h := range in.Hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	in.Hostnames = hosts
	return in
}

// ValidHostname reports whether h is a bare host name (what siteverify
// answers as hostname).
func ValidHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "/:@ ?#") {
		return false
	}
	u, err := url.Parse("https://" + h)
	return err == nil && u.Hostname() == h
}

// PublicCaptcha is what a sign-in UI needs to render the widget (public:
// GET /identity/v1/captcha/:environment and the authorize ticket
// description). Enabled is false when no CAPTCHA applies to the surface.
type PublicCaptcha struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	SiteKey  string `json:"site_key,omitempty"`
	Headless bool   `json:"headless,omitempty"`
}

// CaptchaCheck is one CAPTCHA to verify.
type CaptchaCheck struct {
	Environment identity.EnvironmentID
	Surface     string
	// Token is the widget's answer (headless captcha_token, hosted
	// cf-turnstile-response / h-captcha-response).
	Token string
	// Hostname the token must have been solved on: the issuer's host for
	// hosted pages; "" for headless (the configured Hostnames apply).
	Hostname string
	// Action is CaptchaLogin, CaptchaSignup or CaptchaDevice.
	Action   string
	RemoteIP string
}

// Answer is a provider's siteverify answer.
type Answer struct {
	Success  bool
	Hostname string
	Action   string
	// Codes are the provider's error codes (e.g. invalid-input-response).
	Codes []string
	// Testing: the stored secret is one of the provider's published testing
	// secrets, whose answers carry a placeholder hostname; it is not
	// checked (such a secret accepts every token anyway).
	Testing bool
}

// Accepts reports whether the answer passes check under config: success,
// the hostname (hosted: the issuer's; headless: one of config.Hostnames
// when set; not for testing keys) and the action when the provider
// reports one.
func (a Answer) Accepts(config CaptchaConfig, check CaptchaCheck) bool {
	if !a.Success {
		return false
	}
	host := strings.ToLower(a.Hostname)
	switch {
	case a.Testing:
	case check.Hostname != "":
		if host != strings.ToLower(check.Hostname) {
			return false
		}
	case len(config.Hostnames) > 0:
		if !slices.Contains(config.Hostnames, host) {
			return false
		}
	}
	return a.Action == "" || check.Action == "" || a.Action == check.Action
}

// CodeCaptchaRequired is the code of ErrCaptchaRequired.
const CodeCaptchaRequired = "CAPTCHA_REQUIRED"

// ErrCaptchaRequired refuses a request without a valid CAPTCHA answer.
func ErrCaptchaRequired(provider string) error {
	e := errx.Forbidden("complete the CAPTCHA and try again")
	e.Code = CodeCaptchaRequired
	// The provider is public (GET /identity/v1/captcha/:environment shows it).
	e.Details = map[string]any{"provider": provider}
	e.Public = true
	return e
}

// CodeCaptchaSecretInvalid: the provider rejected the stored secret (Test).
const CodeCaptchaSecretInvalid = "CAPTCHA_SECRET_INVALID"

// ErrCaptchaSecretInvalid answers a Test whose secret the provider refused.
func ErrCaptchaSecretInvalid() error {
	e := errx.Business("the CAPTCHA provider rejected the secret key")
	e.Code = CodeCaptchaSecretInvalid
	return e
}

// Mutation names who changes the environment's security settings, for the
// audit row.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Audit actions.
const (
	ActionCaptchaUpdate     = "captcha.update"
	ActionCaptchaDelete     = "captcha.delete"
	ActionPolicyUpdate      = "risk_policy.update"
	ActionPolicyDelete      = "risk_policy.delete"
	ActionRestrictionCreate = "risk_restriction.create"
	ActionRestrictionDelete = "risk_restriction.delete"
)
