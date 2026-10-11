package oauth

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// OIDC Core 3.1.2.1 prompt values, as advertised in discovery.
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

// PromptValues are the prompt values IAMKit accepts (discovery
// prompt_values_supported).
func PromptValues() []string {
	return []string{PromptNone, PromptLogin, PromptConsent, PromptSelectAccount}
}

// Interaction is what an authorize request's prompt and max_age ask of the
// sign-in. IAMKit keeps no browser session between authorize requests, so
// every authorization signs in afresh: login and max_age are met by
// construction in the hosted pages (a custom sign-in UI completing with an
// older token is refused by the authorize endpoint), consent has no screen
// to force, and none can never be satisfied silently.
type Interaction struct {
	None          bool
	Login         bool
	Consent       bool
	SelectAccount bool
	// MaxAge is max_age in seconds; nil when absent.
	MaxAge *int64
}

// Reauthenticate reports whether the user must have signed in during the
// authorization: prompt=login, or max_age=0 (which OIDC Core defines as
// equivalent).
func (i Interaction) Reauthenticate() bool {
	return i.Login || (i.MaxAge != nil && *i.MaxAge == 0)
}

// ParseInteraction reads prompt (space-separated, case-sensitive) and
// max_age from an authorize request form. Unknown prompt values, none
// combined with another value, and a max_age that is not a non-negative
// integer are validation errors.
func ParseInteraction(form url.Values) (Interaction, error) {
	var out Interaction
	for _, value := range strings.Fields(form.Get("prompt")) {
		switch value {
		case PromptNone:
			out.None = true
		case PromptLogin:
			out.Login = true
		case PromptConsent:
			out.Consent = true
		case PromptSelectAccount:
			out.SelectAccount = true
		default:
			return Interaction{}, invalidRequest("prompt must be a space-separated list of none, login, consent and select_account")
		}
	}
	if out.None && (out.Login || out.Consent || out.SelectAccount) {
		return Interaction{}, invalidRequest("prompt=none cannot be combined with other prompt values")
	}
	if raw := form.Get("max_age"); raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || seconds < 0 || raw[0] == '+' {
			return Interaction{}, invalidRequest("max_age must be a non-negative integer number of seconds")
		}
		out.MaxAge = &seconds
	}
	return out, nil
}

// FormInteraction is the Interaction of a stored authorize form (zero when
// none or unreadable: the form was checked when the authorization started).
func FormInteraction(form string) Interaction {
	values, err := url.ParseQuery(form)
	if err != nil {
		return Interaction{}
	}
	out, _ := ParseInteraction(values)
	return out
}

func invalidRequest(message string) error {
	e := errx.Validation(message)
	e.Code = "INVALID_REQUEST"
	return e
}
