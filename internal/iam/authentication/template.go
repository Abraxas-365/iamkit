package authentication

import (
	"regexp"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/i18n"
)

// Email purposes IAMKit renders, besides PurposeTest.
const (
	PurposeLogin             = "login"
	PurposePasswordReset     = "password_reset"
	PurposeEmailVerification = "email_verification"
	PurposeInvitation        = "invitation"
)

// Copy is the wording of one email. The layout around it (logo, code box,
// button, link fallback) is IAMKit's, so wording can never drop the code or
// the link. Body and Footer may span lines; a blank line starts a paragraph.
// Wording may use the purpose's Placeholders, written {{name}}.
type Copy struct {
	Subject string `json:"subject"`
	Heading string `json:"heading"`
	Body    string `json:"body"`
	Action  string `json:"action"` // button label; only emails with a link have one
	Footer  string `json:"footer"`
}

// Overlay returns c with every non-empty field of override replacing it.
func (c Copy) Overlay(override Copy) Copy {
	for _, f := range []struct{ dst, src *string }{
		{&c.Subject, &override.Subject}, {&c.Heading, &override.Heading}, {&c.Body, &override.Body},
		{&c.Action, &override.Action}, {&c.Footer, &override.Footer},
	} {
		if strings.TrimSpace(*f.src) != "" {
			*f.dst = *f.src
		}
	}
	return c
}

// HasAction reports whether emails of purpose carry a button.
func HasAction(purpose string) bool { return purpose == PurposeInvitation }

// DefaultCopy is IAMKit's wording for purpose in locale (English when the
// locale is unknown).
func DefaultCopy(purpose, locale string) Copy {
	key := func(field string) string { return i18n.T(locale, "email."+purpose+"."+field) }
	c := Copy{Subject: key("subject"), Heading: key("heading"), Body: key("body"), Footer: key("footer")}
	if HasAction(purpose) {
		c.Action = key("action")
	}
	return c
}

// Placeholder names. Values come from the message and the brand.
const (
	PlaceholderAppName      = "app_name"     // brand name
	PlaceholderEmail        = "email"        // recipient
	PlaceholderCode         = "code"         // one-time code
	PlaceholderExpiresIn    = "expires_in"   // code lifetime in minutes
	PlaceholderOrganization = "organization" // invited-to organization
	PlaceholderInviter      = "inviter"      // who invited
	PlaceholderExpiresAt    = "expires_at"   // invitation expiry date
)

var placeholders = map[string][]string{
	PurposeLogin:             {PlaceholderAppName, PlaceholderEmail, PlaceholderCode, PlaceholderExpiresIn},
	PurposePasswordReset:     {PlaceholderAppName, PlaceholderEmail, PlaceholderCode, PlaceholderExpiresIn},
	PurposeEmailVerification: {PlaceholderAppName, PlaceholderEmail, PlaceholderCode, PlaceholderExpiresIn},
	PurposeInvitation:        {PlaceholderAppName, PlaceholderEmail, PlaceholderOrganization, PlaceholderInviter, PlaceholderExpiresAt},
	PurposeTest:              {PlaceholderAppName, PlaceholderEmail},
}

// Placeholders lists the placeholders wording of purpose may use.
func Placeholders(purpose string) []string { return placeholders[purpose] }

var placeholder = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_]+)\s*\}\}`)

// Fill replaces each {{name}} in text with values[name]; unknown names are
// left as written. Values are inserted as plain text: escaping is the
// renderer's job, and filled text is never parsed again.
func Fill(text string, values map[string]string) string {
	return placeholder.ReplaceAllStringFunc(text, func(match string) string {
		if v, ok := values[placeholder.FindStringSubmatch(match)[1]]; ok {
			return v
		}
		return match
	})
}
