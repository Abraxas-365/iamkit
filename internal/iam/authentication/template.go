package authentication

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
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

// Wording limits, in characters (as in the email_templates schema).
const (
	maxSubject = 200
	maxHeading = 200
	maxAction  = 60
	maxBody    = 2000
	maxFooter  = 500
)

// Normalize trims the wording and writes line breaks as "\n".
func (c Copy) Normalize() Copy {
	for _, f := range []*string{&c.Subject, &c.Heading, &c.Body, &c.Action, &c.Footer} {
		*f = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(*f, "\r\n", "\n"), "\r", "\n"))
	}
	return c
}

// Empty reports whether c changes nothing (every field keeps the default).
func (c Copy) Empty() bool { return c == Copy{} }

// Validate checks wording for purpose: lengths, one-line subject, heading
// and action, no action where the email has no button, and only the
// purpose's placeholders. Empty fields keep the defaults.
func (c Copy) Validate(purpose string) error {
	for _, f := range []struct {
		name, value string
		max         int
		oneLine     bool
	}{
		{"subject", c.Subject, maxSubject, true},
		{"heading", c.Heading, maxHeading, true},
		{"body", c.Body, maxBody, false},
		{"action", c.Action, maxAction, true},
		{"footer", c.Footer, maxFooter, false},
	} {
		if utf8.RuneCountInString(f.value) > f.max {
			return errx.Validation(f.name + " must be at most " + strconv.Itoa(f.max) + " characters")
		}
		if strings.ContainsFunc(f.value, func(r rune) bool { return unicode.IsControl(r) && (f.oneLine || (r != '\n' && r != '\r' && r != '\t')) }) {
			if f.oneLine {
				return errx.Validation(f.name + " must be one line")
			}
			return errx.Validation(f.name + " must not contain control characters")
		}
		for _, match := range placeholder.FindAllStringSubmatch(f.value, -1) {
			if !slices.Contains(placeholders[purpose], match[1]) {
				return errx.Validation(f.name + " uses unknown placeholder {{" + match[1] + "}}; available: " + strings.Join(placeholders[purpose], ", "))
			}
		}
	}
	if c.Action != "" && !HasAction(purpose) {
		return errx.Validation("action is not used by " + purpose + " emails")
	}
	return nil
}

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

// EmailTemplate is an environment's saved wording for one email in one
// language; empty fields keep IAMKit's defaults.
type EmailTemplate struct {
	Purpose   string    `json:"purpose"`
	Locale    string    `json:"locale"`
	Copy      Copy      `json:"template"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TemplateKey names one email in one language.
type TemplateKey struct {
	Purpose string
	Locale  string
}

// Validate checks the purpose is an email IAMKit renders and the locale an
// available language (exactly, e.g. "es").
func (k TemplateKey) Validate() error {
	if !slices.Contains(PreviewPurposes, k.Purpose) {
		return errx.Validation("purpose must be one of " + strings.Join(PreviewPurposes, ", "))
	}
	if !i18n.Supported(k.Locale) {
		var codes []string
		for _, l := range i18n.Locales() {
			codes = append(codes, l.Code)
		}
		return errx.Validation("locale must be one of " + strings.Join(codes, ", "))
	}
	return nil
}

// TemplateSummary says whether one email in one language is customized.
type TemplateSummary struct {
	Purpose    string     `json:"purpose"`
	Locale     string     `json:"locale"`
	Customized bool       `json:"customized"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
}

// TemplateView is what an editor needs: the saved wording (empty fields =
// default), IAMKit's defaults and the placeholders the wording may use.
type TemplateView struct {
	TemplateSummary
	Template     Copy     `json:"template"`
	Defaults     Copy     `json:"defaults"`
	Placeholders []string `json:"placeholders"`
}
