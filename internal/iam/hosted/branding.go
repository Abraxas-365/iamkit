package hosted

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
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
	// Locale is the default language of the hosted pages and emails ("" =
	// the deployment default for emails, the browser's for pages; on a
	// client style "" = the environment's). Omitted on save keeps the
	// stored one, so clients that predate it don't reset it.
	Locale *string `json:"locale,omitempty"`
	// Languages are the languages hosted pages may use (empty = every
	// available one); environment default only. Omitted (null) on save
	// keeps the stored list.
	Languages []string `json:"languages"`
	// Legal links show on the sign-in and sign-up pages (the sign-up
	// page links the terms when the sign-in policy requires accepting
	// them). Omitted (nil) on save keeps the stored ones; reads always
	// carry them. An empty client style's Legal inherits the environment's.
	Legal     *Legal     `json:"legal,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// Legal are the links to an application's policies.
type Legal struct {
	PrivacyURL   string `json:"privacy_url"`
	TermsURL     string `json:"terms_url"`
	HelpURL      string `json:"help_url"`
	SupportEmail string `json:"support_email"`
}

// Empty reports whether nothing is set.
func (l Legal) Empty() bool { return l == Legal{} }

// Over lays these links over base: empty fields keep base's.
func (l Legal) Over(base Legal) Legal {
	pick := func(own, inherited string) string {
		if own != "" {
			return own
		}
		return inherited
	}
	return Legal{PrivacyURL: pick(l.PrivacyURL, base.PrivacyURL), TermsURL: pick(l.TermsURL, base.TermsURL),
		HelpURL: pick(l.HelpURL, base.HelpURL), SupportEmail: pick(l.SupportEmail, base.SupportEmail)}
}

// Validate normalizes and checks the links: https URLs and an email.
func (l *Legal) Validate() error {
	l.PrivacyURL, l.TermsURL, l.HelpURL = strings.TrimSpace(l.PrivacyURL), strings.TrimSpace(l.TermsURL), strings.TrimSpace(l.HelpURL)
	for _, f := range []struct{ name, value string }{{"legal.privacy_url", l.PrivacyURL}, {"legal.terms_url", l.TermsURL}, {"legal.help_url", l.HelpURL}} {
		if err := image(f.value, f.name); err != nil {
			return err
		}
	}
	if l.SupportEmail = strings.TrimSpace(l.SupportEmail); l.SupportEmail != "" {
		email, err := identity.Email(l.SupportEmail)
		if err != nil {
			return errx.Validation("legal.support_email must be a valid address")
		}
		l.SupportEmail = email
	}
	return nil
}

// Font is a typeface of the hosted pages: one of the fonts IAMKit serves
// (Fonts) or, with Family "custom", an https woff2 file (URL).
type Font struct {
	Family string `json:"family"`
	URL    string `json:"url"`
}

// Font families; FontSystem (the default) uses the device's own font.
const (
	FontSystem = "system"
	FontCustom = "custom"
)

// Fonts are the families IAMKit serves itself (no third-party request).
var Fonts = []string{"inter", "roboto", "open-sans", "lora"}

func (f *Font) validate(field string) error {
	family, err := choice(f.Family, field+".family", FontSystem, append([]string{FontSystem, FontCustom}, Fonts...)...)
	if err != nil {
		return err
	}
	f.Family, f.URL = family, strings.TrimSpace(f.URL)
	if family != FontCustom {
		f.URL = ""
		return nil
	}
	// The URL is written into a CSS url(""), like the background image.
	u, err := url.Parse(f.URL)
	if f.URL == "" || err != nil || image(f.URL, field+".url") != nil || !strings.HasSuffix(strings.ToLower(u.Path), ".woff2") ||
		strings.ContainsAny(f.URL, "\"'()\\<>{};` \t\r\n") {
		return errx.Validation(field + ".url must be an https URL of a .woff2 file without quotes, parentheses, backslashes or spaces")
	}
	return nil
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
	// BackgroundImageURL covers the page behind the card; BackgroundOverlay
	// (0-90 %) tints it with the background color so text stays readable.
	BackgroundImageURL string `json:"background_image_url"`
	BackgroundOverlay  int    `json:"background_overlay"`
	// Font is the text typeface; HeadingFont the title's (system = Font).
	Font        Font `json:"font"`
	HeadingFont Font `json:"heading_font"`
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
	MaxOverlay     = 90
	MaxLanguages   = 64
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
	if s.Legal != nil {
		if err := s.Legal.Validate(); err != nil {
			return err
		}
	}
	if s.Locale != nil {
		locale, err := Language(*s.Locale, "locale")
		if err != nil {
			return err
		}
		s.Locale = &locale
	}
	if s.Languages != nil {
		if len(s.Languages) > MaxLanguages {
			return errx.Validation("languages has at most 64 entries")
		}
		languages := make([]string, 0, len(s.Languages))
		for _, raw := range s.Languages {
			code, err := Language(raw, "languages")
			if err != nil {
				return err
			}
			if code != "" && !slices.Contains(languages, code) {
				languages = append(languages, code)
			}
		}
		s.Languages = languages
		if s.Locale != nil && *s.Locale != "" && len(languages) > 0 && !slices.Contains(languages, *s.Locale) {
			return errx.Validation("locale must be one of languages")
		}
	}
	// accent_color and theme.light.primary are the same color.
	if s.Theme.Light.Primary == "" {
		s.Theme.Light.Primary = s.AccentColor
	}
	s.AccentColor = s.Theme.Light.Primary
	return nil
}

// Preferred is the language the configuration asks for: the first
// available, enabled language of uiLocales (the application's request),
// else the configured Locale when enabled, else "" (the browser decides,
// see Negotiate).
func (s Settings) Preferred(uiLocales string) string {
	if code := i18n.MatchIn(s.Languages, uiLocales); code != "" {
		return code
	}
	if s.Locale != nil {
		return i18n.MatchIn(s.Languages, *s.Locale)
	}
	return ""
}

// Negotiate is the page language: preferred when set, else the browser's
// Accept-Language, within the enabled languages (falling back to English,
// else the first enabled one).
func (s Settings) Negotiate(preferred, acceptLanguage string) string {
	return i18n.Negotiate(s.Languages, preferred, acceptLanguage)
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
	// The background image is written into a CSS url(""): on top of being
	// an https URL it must not carry characters that could leave it.
	t.BackgroundImageURL = strings.TrimSpace(t.BackgroundImageURL)
	if err = image(t.BackgroundImageURL, "theme.background_image_url"); err != nil {
		return err
	}
	if strings.ContainsAny(t.BackgroundImageURL, "\"'()\\<>{};` \t\r\n") {
		return errx.Validation("theme.background_image_url must not contain quotes, parentheses, backslashes or spaces")
	}
	if t.BackgroundOverlay < 0 || t.BackgroundOverlay > MaxOverlay {
		return errx.Validation("theme.background_overlay must be between 0 and 90")
	}
	if err = t.Font.validate("theme.font"); err != nil {
		return err
	}
	if err = t.HeadingFont.validate("theme.heading_font"); err != nil {
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

// Language normalizes a language code to its catalog form ("PT_br" →
// "pt-BR"; "" stays ""), refusing unavailable languages for field.
func Language(code, field string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", nil
	}
	out, ok := i18n.Canonical(code)
	if !ok {
		return "", errx.Validation(field + " must be one of " + strings.Join(i18n.Codes(), ", "))
	}
	return out, nil
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
