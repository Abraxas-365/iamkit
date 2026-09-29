package authentication

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SMS is a text message with a one-time code: a second-factor code (purpose
// "mfa"), the confirmation of a new phone number ("phone_verification") or
// a console test ("test", no code). Body is the rendered text for providers
// that send it as-is (Twilio); a webhook receives every field and may write
// its own text.
type SMS struct {
	Phone   string `json:"phone"`
	Purpose string `json:"purpose"`
	Code    string `json:"code,omitempty"`
	Body    string `json:"body"`

	Environment identity.EnvironmentID `json:"-"`
}

// SMS purposes.
const (
	SMSPurposeMFA   = "mfa"
	SMSPurposePhone = "phone_verification"
)

// SMSPurposes are the messages IAMKit texts.
var SMSPurposes = []string{SMSPurposeMFA, SMSPurposePhone, PurposeTest}

// SMS providers: Twilio's Messages API, or the customer's webhook.
const (
	SMSProviderTwilio  = "twilio"
	SMSProviderWebhook = "webhook"
)

// SMSConfig is an environment's SMS provider. It is separate from email
// delivery: email webhooks never receive text messages. Secrets (the Twilio
// auth token, the webhook signing token) are never returned: HasSecret
// reports them.
type SMSConfig struct {
	EnvironmentID       identity.EnvironmentID `json:"environment_id" db:"environment_id"`
	Provider            string                 `json:"provider" db:"provider"`
	AccountSID          string                 `json:"account_sid,omitempty" db:"account_sid"`
	FromNumber          string                 `json:"from_number,omitempty" db:"from_number"`
	MessagingServiceSID string                 `json:"messaging_service_sid,omitempty" db:"messaging_service_sid"`
	WebhookURL          string                 `json:"webhook_url,omitempty" db:"webhook_url"`
	HasSecret           bool                   `json:"has_secret" db:"-"`
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
}

// SMSConfigInput writes an environment's SMS provider. AuthToken (Twilio)
// and WebhookToken are write-only; left blank on an update that keeps the
// provider, the stored one is kept. Twilio sends from FromNumber or
// through MessagingServiceSID.
type SMSConfigInput struct {
	Provider            string `json:"provider"`
	AccountSID          string `json:"account_sid"`
	AuthToken           string `json:"auth_token"`
	FromNumber          string `json:"from_number"`
	MessagingServiceSID string `json:"messaging_service_sid"`
	WebhookURL          string `json:"webhook_url"`
	WebhookToken        string `json:"webhook_token"`
}

// Secret is the input's provider secret.
func (s SMSConfigInput) Secret() string {
	if s.Provider == SMSProviderTwilio {
		return s.AuthToken
	}
	return s.WebhookToken
}

// Normalize trims every field and lowercases the provider.
func (s SMSConfigInput) Normalize() SMSConfigInput {
	s.Provider = strings.ToLower(strings.TrimSpace(s.Provider))
	s.AccountSID = strings.TrimSpace(s.AccountSID)
	s.AuthToken = strings.TrimSpace(s.AuthToken)
	s.FromNumber = strings.TrimSpace(s.FromNumber)
	s.MessagingServiceSID = strings.TrimSpace(s.MessagingServiceSID)
	s.WebhookURL = strings.TrimSpace(s.WebhookURL)
	s.WebhookToken = strings.TrimSpace(s.WebhookToken)
	return s
}

var (
	twilioAccount = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)
	twilioService = regexp.MustCompile(`^MG[0-9a-fA-F]{32}$`)
)

// Validate checks the (normalized) input's shape; whether a secret is
// required depends on the stored configuration (service).
func (s SMSConfigInput) Validate() error {
	switch s.Provider {
	case SMSProviderTwilio:
		if !twilioAccount.MatchString(s.AccountSID) {
			return errx.Validation("account_sid must be a Twilio account SID (AC followed by 32 hex digits)")
		}
		if s.FromNumber == "" && s.MessagingServiceSID == "" {
			return errx.Validation("from_number or messaging_service_sid is required")
		}
		if s.FromNumber != "" {
			if _, err := identity.Phone(s.FromNumber); err != nil {
				return errx.Validation("from_number must be an E.164 phone number such as +15551234567")
			}
		}
		if s.MessagingServiceSID != "" && !twilioService.MatchString(s.MessagingServiceSID) {
			return errx.Validation("messaging_service_sid must be a Twilio messaging service SID (MG followed by 32 hex digits)")
		}
		if len(s.AuthToken) > 256 || hasControl(s.AuthToken) || strings.ContainsRune(s.AuthToken, ' ') {
			return errx.Validation("auth_token must be at most 256 characters without spaces")
		}
		if s.WebhookURL != "" || s.WebhookToken != "" {
			return errx.Validation("webhook_url is not used by provider twilio")
		}
	case SMSProviderWebhook:
		if !SecureURL(s.WebhookURL) {
			return errx.Validation("webhook_url must use HTTPS (HTTP allowed only on loopback)")
		}
		if len(s.WebhookToken) > 1024 || hasControl(s.WebhookToken) {
			return errx.Validation("webhook_token must be at most 1024 characters on one line")
		}
		if s.AccountSID != "" || s.AuthToken != "" || s.FromNumber != "" || s.MessagingServiceSID != "" {
			return errx.Validation("account_sid is not used by provider webhook")
		}
	default:
		return errx.Validation("provider must be one of twilio, webhook")
	}
	return nil
}

// SMSStatus says whether an environment can send text messages, through
// which provider ("" when none), and its recent activity.
type SMSStatus struct {
	Configured bool   `json:"configured"`
	Provider   string `json:"provider"`
	Activity
}

// SMSTestInput asks for a test message to Phone.
type SMSTestInput struct {
	Phone string `json:"phone"`
}

// Validate checks the recipient number.
func (t SMSTestInput) Validate() error {
	if _, err := identity.Phone(t.Phone); err != nil {
		return err
	}
	return nil
}

// ValidSMSPurpose reports whether purpose is one IAMKit texts.
func ValidSMSPurpose(purpose string) bool { return slices.Contains(SMSPurposes, purpose) }

// Audit actions of SMS settings.
const (
	ActionSMSUpdate = "sms.update"
	ActionSMSDelete = "sms.delete"
	ActionSMSTest   = "sms.test"
)

// SMS failure codes (delivery adapters set them; Describe explains them).
const (
	CodeSMSUnavailable         = "SMS_NOT_CONFIGURED"
	CodeSMSProviderRejected    = "SMS_PROVIDER_REJECTED"
	CodeSMSProviderAuth        = "SMS_PROVIDER_AUTH"
	CodeSMSProviderTimeout     = "SMS_PROVIDER_TIMEOUT"
	CodeSMSProviderUnreachable = "SMS_PROVIDER_UNREACHABLE"
)

// ErrSMSNotConfigured is returned when the environment has no SMS provider.
func ErrSMSNotConfigured() error {
	e := errx.External("SMS delivery is not configured")
	e.Code = CodeSMSUnavailable
	return e
}

// SMSRejected is a non-2xx answer of the SMS provider API (status 0: none
// known).
func SMSRejected(status int) error {
	e := errx.External("SMS provider rejected the request")
	if status != 0 {
		e = e.WithDetail("status", status)
	}
	e.Code = CodeSMSProviderRejected
	return e
}
