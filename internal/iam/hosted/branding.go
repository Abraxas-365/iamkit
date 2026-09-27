package hosted

import (
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Settings brand the hosted pages: the environment default (Client nil) or
// the style of one OAuth client. Empty values fall back to IAMKit defaults.
// AccentColor is the light primary color (theme.light.primary), kept for
// clients that only send the original three fields.
type Settings struct {
	Environment identity.EnvironmentID `json:"environment_id"`
	Client      *identity.ClientID     `json:"client_id,omitempty"`
	DisplayName string                 `json:"display_name"`
	LogoURL     string                 `json:"logo_url"`
	AccentColor string                 `json:"accent_color"`
	Theme       Theme                  `json:"theme"`
	UpdatedAt   *time.Time             `json:"updated_at,omitempty"`
}

// Theme is the look of the hosted pages beyond name, logo and accent.
type Theme struct {
	// Mode is light, dark, or adaptive (follows the browser).
	Mode    string `json:"mode"`
	Radius  *int   `json:"radius"`
	Spacing string `json:"spacing"`
	// Align places the form: center, left or right.
	Align string  `json:"align"`
	Light Palette `json:"light"`
	Dark  Palette `json:"dark"`
	// LogoDarkURL replaces the logo in dark mode.
	LogoDarkURL string `json:"logo_dark_url"`
	FaviconURL  string `json:"favicon_url"`
	// LogoPosition shows the logo and name in the card or in the header.
	LogoPosition string `json:"logo_position"`
	Header       Header `json:"header"`
	Footer       Footer `json:"footer"`
}

// Palette colors one scheme; empty colors use the defaults.
type Palette struct {
	Primary    string `json:"primary"`
	Background string `json:"background"`
	Card       string `json:"card"`
	Text       string `json:"text"`
	Header     string `json:"header"`
}

type Header struct {
	Show bool `json:"show"`
}

type Footer struct {
	Text  string `json:"text"`
	Links []Link `json:"links"`
}

type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Theme values.
const (
	ModeLight      = "light"
	ModeDark       = "dark"
	ModeAdaptive   = "adaptive"
	SpacingCompact = "compact"
	SpacingNormal  = "normal"
	SpacingRoomy   = "roomy"
	AlignCenter    = "center"
	AlignLeft      = "left"
	AlignRight     = "right"
	PositionCard   = "card"
	PositionHeader = "header"
	DefaultRadius  = 12
	MaxRadius      = 24
	MaxFooterLinks = 5
	maxURL         = 2048
	maxDisplayName = 100
	maxFooterText  = 200
	maxFooterLabel = 40
)

var color = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// Validate normalizes and checks the branding. Images must be https URLs
// (the pages' content security policy only loads https images); every
// value ends up in the pages' style block, so each is a closed format.
func (s *Settings) Validate() error {
	s.DisplayName = strings.TrimSpace(s.DisplayName)
	s.LogoURL = strings.TrimSpace(s.LogoURL)
	s.AccentColor = strings.ToLower(strings.TrimSpace(s.AccentColor))
	if utf8.RuneCountInString(s.DisplayName) > maxDisplayName {
		return errx.Validation("display_name must be at most 100 characters")
	}
	if err := image(s.LogoURL, "logo_url"); err != nil {
		return err
	}
	if s.AccentColor != "" && !color.MatchString(s.AccentColor) {
		return errx.Validation("accent_color must be a #rrggbb color")
	}
	if err := s.Theme.validate(); err != nil {
		return err
	}
	// accent_color and theme.light.primary are the same color.
	if s.Theme.Light.Primary == "" {
		s.Theme.Light.Primary = s.AccentColor
	}
	s.AccentColor = s.Theme.Light.Primary
	return nil
}

func (t *Theme) validate() error {
	var err error
	if t.Mode, err = choice(t.Mode, "theme.mode", ModeLight, ModeLight, ModeDark, ModeAdaptive); err != nil {
		return err
	}
	if t.Spacing, err = choice(t.Spacing, "theme.spacing", SpacingNormal, SpacingCompact, SpacingNormal, SpacingRoomy); err != nil {
		return err
	}
	if t.Align, err = choice(t.Align, "theme.align", AlignCenter, AlignCenter, AlignLeft, AlignRight); err != nil {
		return err
	}
	if t.LogoPosition, err = choice(t.LogoPosition, "theme.logo_position", PositionCard, PositionCard, PositionHeader); err != nil {
		return err
	}
	if t.LogoPosition == PositionHeader && !t.Header.Show {
		return errx.Validation("theme.logo_position header requires theme.header.show")
	}
	if t.Radius == nil {
		r := DefaultRadius
		t.Radius = &r
	}
	if *t.Radius < 0 || *t.Radius > MaxRadius {
		return errx.Validation("theme.radius must be between 0 and 24")
	}
	if err = t.Light.validate("theme.light"); err != nil {
		return err
	}
	if err = t.Dark.validate("theme.dark"); err != nil {
		return err
	}
	t.LogoDarkURL = strings.TrimSpace(t.LogoDarkURL)
	if err = image(t.LogoDarkURL, "theme.logo_dark_url"); err != nil {
		return err
	}
	t.FaviconURL = strings.TrimSpace(t.FaviconURL)
	if err = image(t.FaviconURL, "theme.favicon_url"); err != nil {
		return err
	}
	return t.Footer.validate()
}

func (p *Palette) validate(field string) error {
	for _, c := range []struct {
		name  string
		value *string
	}{{"primary", &p.Primary}, {"background", &p.Background}, {"card", &p.Card}, {"text", &p.Text}, {"header", &p.Header}} {
		*c.value = strings.ToLower(strings.TrimSpace(*c.value))
		if *c.value != "" && !color.MatchString(*c.value) {
			return errx.Validation(field + "." + c.name + " must be a #rrggbb color")
		}
	}
	return nil
}

func (f *Footer) validate() error {
	f.Text = strings.TrimSpace(f.Text)
	if utf8.RuneCountInString(f.Text) > maxFooterText {
		return errx.Validation("theme.footer.text must be at most 200 characters")
	}
	if len(f.Links) > MaxFooterLinks {
		return errx.Validation("theme.footer.links allows at most 5 links")
	}
	if f.Links == nil {
		f.Links = []Link{}
	}
	for i := range f.Links {
		l := &f.Links[i]
		l.Label, l.URL = strings.TrimSpace(l.Label), strings.TrimSpace(l.URL)
		if l.Label == "" || utf8.RuneCountInString(l.Label) > maxFooterLabel {
			return errx.Validation("theme.footer.links label must be 1 to 40 characters")
		}
		u, err := url.Parse(l.URL)
		if err != nil || len(l.URL) > maxURL || u.User != nil ||
			!(u.Scheme == "https" && u.Host != "" || u.Scheme == "mailto" && u.Opaque != "") {
			return errx.Validation("theme.footer.links url must be an https or mailto URL")
		}
	}
	return nil
}

// choice normalizes an enumerated value; empty takes the default.
func choice(value, field, fallback string, allowed ...string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback, nil
	}
	for _, a := range allowed {
		if value == a {
			return value, nil
		}
	}
	return "", errx.Validation(field + " must be one of " + strings.Join(allowed, ", "))
}

func image(raw, field string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(raw) > maxURL {
		return errx.Validation(field + " must be an https URL")
	}
	return nil
}
