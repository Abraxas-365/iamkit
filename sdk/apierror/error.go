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

// Rule returns the password policy rule a PASSWORD_POLICY error names, or "".
func (e *Error) Rule() string {
	rule, _ := e.Details["rule"].(string)
	return rule
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s (HTTP %d)", e.Code, e.Message, e.HTTPStatus)
}
