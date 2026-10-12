// Package apierror mirrors the public errx response without importing server internals.
package apierror

import "fmt"

type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Type       string `json:"type"`
	HTTPStatus int    `json:"http_status"`
	// Details carries machine-readable context for some client errors, e.g.
	// PASSWORD_POLICY: {"rule": "length", "min_length": 12}.
	Details map[string]any `json:"details,omitempty"`
}

// Password error codes and the rules a PASSWORD_POLICY error reports.
const (
	CodePasswordPolicy         = "PASSWORD_POLICY"
	CodePasswordChangeRequired = "PASSWORD_CHANGE_REQUIRED"

	RuleLength   = "length"
	RuleUpper    = "upper"
	RuleLower    = "lower"
	RuleDigit    = "digit"
	RuleSymbol   = "symbol"
	RuleBreached = "breached"
	RuleReused   = "reused"
)

// Account self-service error codes: ReauthenticationRequired (HTTP 403)
// also answers a switch the target organization's sign-in rules refuse
// (details organization_id and reason sso|mfa|method).
const (
	CodeReauthenticationRequired = "REAUTHENTICATION_REQUIRED"
	CodeInvalidCurrentPassword   = "INVALID_CURRENT_PASSWORD"
	CodeNoPassword               = "NO_PASSWORD"
)

// Sign-in policy error codes (HTTP 403): the environment or organization
// does not allow the method, or the environment does not offer password
// reset.
const (
	CodeMethodNotAllowed      = "METHOD_NOT_ALLOWED"
	CodePasswordResetDisabled = "PASSWORD_RESET_DISABLED"
)

// Self-registration error codes: the environment does not offer sign-up
// (HTTP 403), or the email got an account while the sign-up waited for its
// code (HTTP 409).
const (
	CodeSignupDisabled = "SIGNUP_DISABLED"
	CodeAccountExists  = "ACCOUNT_EXISTS"
)

// Waitlist error codes: a waitlist approval link that is not valid anymore —
// unknown, expired, used or for another email — answers 400 on sign-up; a
// decision on a rejected or completed entry answers 409.
const (
	CodeWaitlistTokenInvalid = "WAITLIST_TOKEN_INVALID"
	CodeWaitlistNotPending   = "WAITLIST_ENTRY_NOT_PENDING"
)

// Bot protection and risk error codes (HTTP 403 unless noted). They appear
// only when the operator configured a CAPTCHA, a risk policy or restrictions:
// CAPTCHA_REQUIRED asks for a (new) captcha_token — Details["provider"] names
// the provider; SIGN_IN_BLOCKED means a restriction or risk rule refused the
// sign-in (do not retry); RISK_CHALLENGE asks for a risk challenge where
// none can be parked; CHALLENGE_UNAVAILABLE means the user has no verified
// email to challenge.
const (
	CodeCaptchaRequired      = "CAPTCHA_REQUIRED"
	CodeSignInBlocked        = "SIGN_IN_BLOCKED"
	CodeRiskChallenge        = "RISK_CHALLENGE"
	CodeChallengeUnavailable = "CHALLENGE_UNAVAILABLE"
)

// IsCaptchaRequired reports whether the sign-in needs a captcha_token.
func (e *Error) IsCaptchaRequired() bool { return e.Code == CodeCaptchaRequired }

// IsSignInBlocked reports whether a restriction or risk rule refused the
// sign-in.
func (e *Error) IsSignInBlocked() bool { return e.Code == CodeSignInBlocked }

// Provider returns the CAPTCHA provider a CAPTCHA_REQUIRED error names
// ("turnstile" or "hcaptcha"), or "".
func (e *Error) Provider() string {
	provider, _ := e.Details["provider"].(string)
	return provider
}

// Rule returns the password policy rule a PASSWORD_POLICY error names, or "".
func (e *Error) Rule() string {
	rule, _ := e.Details["rule"].(string)
	return rule
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s (HTTP %d)", e.Code, e.Message, e.HTTPStatus)
}
