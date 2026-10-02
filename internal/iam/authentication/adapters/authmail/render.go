package authmail

import (
	"context"
	"embed"
	htmltemplate "html/template"
	"log/slog"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	texttemplate "text/template"
	"unicode"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

//go:embed templates/email.html templates/email.txt
var templateFiles embed.FS

var (
	htmlEmail = htmltemplate.Must(htmltemplate.ParseFS(templateFiles, "templates/email.html"))
	textEmail = texttemplate.Must(texttemplate.New("").ParseFS(templateFiles, "templates/email.txt"))
)

// Brand defaults: the name when an environment has none, and the accent
// hosted pages use.
const (
	DefaultBrandName = "IAMKit"
	DefaultAccent    = "#2563eb"
)

var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// Renderer writes the emails IAMKit sends itself (SMTP, Resend) from a
// Message: brand and language from Branding, wording from Templates over
// IAMKit's defaults, all optional. Locale is the deployment default
// language (EMAIL_LOCALE).
type Renderer struct {
	Branding  authentication.Branding
	Templates authentication.Templates
	Locale    string
}

var _ authentication.Renderer = Renderer{}

// view is what the templates see. Wording fields are already filled and
// split into paragraphs of lines; html/template escapes all of it.
type view struct {
	Lang, Subject, Preheader, Heading, Action string
	Body, Footer                              [][]string
	Code, Token, TokenLabel                   string
	Link                                      string
	LinkFallback                              string
	Brand                                     viewBrand
}

type viewBrand struct{ Name, Logo, Accent, OnAccent string }

// Dir is the email language's writing direction (ltr or rtl).
func (v view) Dir() string { return i18n.Dir(v.Lang) }

// Render never fails for a missing brand or saved wording (it logs and uses
// the defaults): a broken template setting must not stop a sign-in code.
func (r Renderer) Render(ctx context.Context, m authentication.Message, draft authentication.Draft) (authentication.Email, error) {
	if authentication.Placeholders(m.Purpose) == nil {
		return authentication.Email{}, errx.Internal("unknown email purpose " + m.Purpose)
	}
	var brand authentication.Brand
	if r.Branding != nil && !m.Environment.IsZero() {
		b, err := r.Branding.Brand(ctx, m.Environment, m.OrganizationID)
		if err != nil {
			slog.WarnContext(ctx, "email branding unavailable, using defaults", "environment", m.Environment, "err", err)
		} else {
			brand = b
		}
	}
	if draft.AppName != nil {
		brand.Name = *draft.AppName
	}
	locale := i18n.Negotiate(brand.Languages, m.Locale, brand.Locale, r.Locale)
	wording := authentication.DefaultCopy(m.Purpose, locale)
	switch {
	case draft.Copy != nil:
		wording = wording.Overlay(*draft.Copy)
	case r.Templates != nil && !m.Environment.IsZero():
		saved, ok, err := r.Templates.Copy(ctx, m.Environment, m.Purpose, locale)
		if err != nil {
			slog.WarnContext(ctx, "email template unavailable, using defaults", "environment", m.Environment, "purpose", m.Purpose, "locale", locale, "err", err)
		} else if ok {
			wording = wording.Overlay(saved)
		}
	}

	v := view{Lang: locale, Code: m.Code, Brand: brandView(brand)}
	values := placeholderValues(m, v.Brand.Name, locale)
	fill := func(s string) string { return authentication.Fill(s, values) }
	v.Subject = singleLine(fill(wording.Subject))
	v.Heading = singleLine(fill(wording.Heading))
	v.Body = paragraphs(fill(wording.Body))
	v.Footer = paragraphs(fill(wording.Footer))
	if len(v.Body) > 0 {
		v.Preheader = strings.Join(v.Body[0], " ")
	}
	if m.Purpose == authentication.PurposeInvitation {
		if link := webLink(m.Link); link != "" {
			v.Link = link
			v.Action = singleLine(fill(wording.Action))
			v.LinkFallback = i18n.T(locale, "email.common.link_fallback")
		} else {
			v.Token = m.Token
			v.TokenLabel = i18n.T(locale, "email.common.token_label")
		}
	}

	var html, text strings.Builder
	if err := htmlEmail.ExecuteTemplate(&html, "email", v); err != nil {
		return authentication.Email{}, errx.Wrap(err, "render email", errx.TypeInternal)
	}
	if err := textEmail.ExecuteTemplate(&text, "email", v); err != nil {
		return authentication.Email{}, errx.Wrap(err, "render email", errx.TypeInternal)
	}
	return authentication.Email{To: m.Email, Subject: v.Subject, HTML: html.String(), Text: text.String()}, nil
}

func placeholderValues(m authentication.Message, appName, locale string) map[string]string {
	values := map[string]string{
		authentication.PlaceholderAppName: appName,
		authentication.PlaceholderEmail:   m.Email,
	}
	switch m.Purpose {
	case authentication.PurposeInvitation:
		values[authentication.PlaceholderOrganization] = singleLine(m.Organization)
		inviter := singleLine(m.Inviter)
		if inviter == "" {
			inviter = i18n.T(locale, "email.common.someone")
		}
		values[authentication.PlaceholderInviter] = inviter
		if m.ExpiresAt != nil {
			values[authentication.PlaceholderExpiresAt] = i18n.Date(locale, *m.ExpiresAt)
		}
	case authentication.PurposeTest:
	default:
		values[authentication.PlaceholderCode] = m.Code
		values[authentication.PlaceholderExpiresIn] = strconv.Itoa(int(config.ChallengeTTL.Minutes()))
	}
	return values
}

func brandView(b authentication.Brand) viewBrand {
	v := viewBrand{Name: singleLine(b.Name), Accent: strings.ToLower(strings.TrimSpace(b.Accent))}
	if v.Name == "" {
		v.Name = DefaultBrandName
	}
	if u, err := url.Parse(strings.TrimSpace(b.LogoURL)); err == nil && u.Scheme == "https" && u.Host != "" {
		v.Logo = u.String()
	}
	if !hexColor.MatchString(v.Accent) {
		v.Accent = DefaultAccent
	}
	v.OnAccent = readable(v.Accent)
	return v
}

// webLink returns link when it is an absolute http(s) URL, else "".
func webLink(link string) string {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.String()
}

// singleLine turns every run of whitespace or control characters into one
// space, so a value can never break a header or a heading.
func singleLine(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
}

// paragraphs splits text at blank lines into paragraphs of trimmed lines,
// dropping control characters.
func paragraphs(s string) [][]string {
	var out [][]string
	var current []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = singleLine(line)
		if line == "" {
			if current != nil {
				out, current = append(out, current), nil
			}
			continue
		}
		current = append(current, line)
	}
	if current != nil {
		out = append(out, current)
	}
	return out
}

// readable is black or white, whichever contrasts more with a #rrggbb color.
func readable(hex string) string {
	channel := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	if 0.2126*channel(1)+0.7152*channel(3)+0.0722*channel(5) > 0.179 {
		return "#000000"
	}
	return "#ffffff"
}

// Rendered is a Delivery that renders each message and hands it to a
// Mailer from the configured sender (SMTP, Resend).
type Rendered struct {
	Renderer authentication.Renderer
	Mailer   authentication.Mailer
	From     string
	FromName string
	ReplyTo  string
}

var _ authentication.Delivery = Rendered{}

func (d Rendered) Send(ctx context.Context, m authentication.Message) error {
	email, err := d.Renderer.Render(ctx, m, authentication.Draft{})
	if err != nil {
		return err
	}
	email.From, email.FromName, email.ReplyTo = d.From, d.FromName, d.ReplyTo
	return d.Mailer.Deliver(ctx, email)
}
