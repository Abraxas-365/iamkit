package hosted

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// TextPrefix is the catalog prefix of the texts hosted pages show; only
// these keys can be customized (emails keep their own templates).
const TextPrefix = "hosted."

// Text scopes: who a set of custom texts applies to.
const (
	ScopeEnvironment  = "environment"
	ScopeClient       = "client"
	ScopeOrganization = "organization"
)

// Texts are custom wordings of the hosted pages in one language, for the
// environment (Client and Organization nil), one OAuth client, or one
// organization. Pages resolve each key organization ← client ←
// environment ← the catalog in the page language ← English. Messages are
// plain text in the catalog's format: they keep the catalog message's
// placeholders (%s, {count}) and pages escape them.
type Texts struct {
	Environment  identity.EnvironmentID   `json:"environment_id"`
	Client       *identity.ClientID       `json:"client_id,omitempty"`
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	Locale       string                   `json:"locale"`
	Messages     map[string]string        `json:"texts"`
	UpdatedAt    *time.Time               `json:"updated_at,omitempty"`
}

// Scope names who the texts apply to.
func (t Texts) Scope() string {
	switch {
	case t.Organization != nil:
		return ScopeOrganization
	case t.Client != nil:
		return ScopeClient
	}
	return ScopeEnvironment
}

// TextScope is who custom texts apply to: the environment (both zero), a
// client or an organization. Reading a page's wording both may be set
// (the organization's texts over the client's).
type TextScope struct {
	Client       identity.ClientID
	Organization identity.OrganizationID
}

// Target is the scope the texts apply to.
func (t Texts) Target() TextScope {
	var s TextScope
	if t.Client != nil {
		s.Client = *t.Client
	}
	if t.Organization != nil {
		s.Organization = *t.Organization
	}
	return s
}

// TextKey is one customizable text: the catalog message in a language,
// what it fills in and the longest custom message allowed.
type TextKey struct {
	Key          string   `json:"key"`
	Default      string   `json:"default"`
	Placeholders []string `json:"placeholders"`
	MaxLength    int      `json:"max_length"`
}

// TextCatalog lists the customizable texts of locale.
func TextCatalog(locale string) []TextKey {
	keys := i18n.Keys(locale, TextPrefix)
	out := make([]TextKey, 0, len(keys))
	for _, key := range keys {
		message, _ := i18n.Message(locale, key)
		placeholders := i18n.Placeholders(message)
		if placeholders == nil {
			placeholders = []string{}
		}
		out = append(out, TextKey{Key: key, Default: message, Placeholders: placeholders, MaxLength: TextLimit(message)})
	}
	return out
}

// TextLimit is the longest custom message (in characters) for a catalog
// message: three times its length, at least 80 and at most 1000.
func TextLimit(original string) int {
	return min(max(3*utf8.RuneCountInString(original), 80), 1000)
}

// Validate normalizes the locale and each message (trimmed; an empty one
// is dropped, so the key inherits) and checks every key is a text of the
// language, plain text within its length, with the catalog message's
// placeholders.
func (t *Texts) Validate() error {
	locale, err := Language(t.Locale, "locale")
	if err != nil {
		return err
	}
	if locale == "" {
		return errx.Validation("locale is required")
	}
	t.Locale = locale
	if t.Client != nil && t.Organization != nil {
		return errx.Validation("texts apply to a client or an organization, not both")
	}
	known := map[string]bool{}
	for _, key := range i18n.Keys(locale, TextPrefix) {
		known[key] = true
	}
	out := make(map[string]string, len(t.Messages))
	for key, message := range t.Messages {
		if !known[key] {
			return errx.Validation("texts." + key + " is not a customizable text of " + locale)
		}
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		original, _ := i18n.Message(locale, key)
		if n := TextLimit(original); utf8.RuneCountInString(message) > n {
			return errx.Validation("texts." + key + " must be at most " + strconv.Itoa(n) + " characters")
		}
		if !utf8.ValidString(message) || strings.ContainsFunc(message, unicode.IsControl) {
			return errx.Validation("texts." + key + " must be plain text on one line")
		}
		if !i18n.SameArgs(message, original) {
			return errx.Validation("texts." + key + " must keep the placeholders " + strings.Join(i18n.Placeholders(original), " ") + " (write a percent sign as %%)")
		}
		out[key] = message
	}
	t.Messages = out
	return nil
}

// LayTexts merges sets of custom texts in locale, later ones winning per
// key (pass them environment, client, organization). Messages the catalog
// no longer has, or whose placeholders it changed since, are left out.
func LayTexts(locale string, sets ...Texts) i18n.Texts {
	out := i18n.Texts{}
	for _, set := range sets {
		for key, message := range set.Messages {
			if original, ok := i18n.Message(locale, key); ok && strings.HasPrefix(key, TextPrefix) && i18n.SameArgs(message, original) {
				out[key] = message
			}
		}
	}
	return out
}
