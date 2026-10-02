package hosted

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// OrganizationSettings are an organization's overrides of the hosted pages
// and invitation emails. A nil field inherits the client style or the
// environment default (field-level merge, environment ← client ←
// organization); Theme replaces the whole theme when set. Locale is the
// organization's language for hosted pages and invitation emails into it
// (nil inherits; it must be one of the environment's languages, checked by
// the service).
type OrganizationSettings struct {
	Environment  identity.EnvironmentID  `json:"environment_id"`
	Organization identity.OrganizationID `json:"organization_id"`
	DisplayName  *string                 `json:"display_name"`
	LogoURL      *string                 `json:"logo_url"`
	AccentColor  *string                 `json:"accent_color"`
	Theme        *Theme                  `json:"theme"`
	Locale       *string                 `json:"locale"`
	UpdatedAt    *time.Time              `json:"updated_at,omitempty"`
}

// Validate normalizes and checks the fields the organization sets, with
// the rules of Settings.
func (o *OrganizationSettings) Validate() error {
	if o.Locale != nil {
		locale, err := Language(*o.Locale, "locale")
		if err != nil {
			return err
		}
		if locale == "" {
			o.Locale = nil
		} else {
			o.Locale = &locale
		}
	}
	if o.DisplayName != nil {
		name := strings.TrimSpace(*o.DisplayName)
		if utf8.RuneCountInString(name) > maxDisplayName {
			return errx.Validation("display_name must be at most 100 characters")
		}
		o.DisplayName = &name
	}
	if o.LogoURL != nil {
		logo := strings.TrimSpace(*o.LogoURL)
		if err := image(logo, "logo_url"); err != nil {
			return err
		}
		o.LogoURL = &logo
	}
	if o.AccentColor != nil {
		accent := strings.ToLower(strings.TrimSpace(*o.AccentColor))
		if accent != "" && !color.MatchString(accent) {
			return errx.Validation("accent_color must be a #rrggbb color")
		}
		o.AccentColor = &accent
	}
	if o.Theme != nil {
		if err := o.Theme.validate(); err != nil {
			return err
		}
		// As in Settings, accent_color fills an unset theme.light.primary.
		if o.Theme.Light.Primary == "" && o.AccentColor != nil {
			o.Theme.Light.Primary = *o.AccentColor
		}
	}
	return nil
}

// Custom reports whether the organization overrides anything.
func (o OrganizationSettings) Custom() bool {
	return o.DisplayName != nil || o.LogoURL != nil || o.AccentColor != nil || o.Theme != nil || o.Locale != nil
}

// Apply lays the organization's overrides over the branding underneath
// (a client style or the environment default).
func (o OrganizationSettings) Apply(s Settings) Settings {
	if o.Locale != nil {
		locale := *o.Locale
		s.Locale = &locale
	}
	if o.DisplayName != nil {
		s.DisplayName = *o.DisplayName
	}
	if o.LogoURL != nil {
		s.LogoURL = *o.LogoURL
	}
	accent := s.AccentColor
	if o.AccentColor != nil {
		accent = *o.AccentColor
	}
	switch {
	case o.Theme != nil:
		s.Theme = *o.Theme
		if s.Theme.Light.Primary == "" {
			s.Theme.Light.Primary = accent
		}
	case o.AccentColor != nil:
		s.Theme.Light.Primary = accent
	}
	s.AccentColor = s.Theme.Light.Primary
	return s
}
