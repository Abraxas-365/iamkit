package hostedhttp

import (
	"fmt"
	"html/template"
	"math"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
)

// brand is the resolved look of a page: every value is either a default or
// a validated setting (colors are #rrggbb, images https), so Vars is safe to
// place in the page's style block.
type brand struct {
	Name, Logo, LogoDark, Favicon, Accent string
	Header, LogoInHeader                  bool
	FooterText                            string
	Links                                 []hosted.Link
	Vars                                  template.CSS
}

// Default palettes; an empty dark primary follows the light one (the brand
// color), headers follow the card.
var (
	lightDefaults = hosted.Palette{Primary: defaultAccent, Background: "#f5f5f7", Card: "#ffffff", Text: "#1d1d1f"}
	darkDefaults  = hosted.Palette{Background: "#0f1115", Card: "#1a1d23", Text: "#f2f2f3"}
)

type scheme struct {
	palette            hosted.Palette
	errorBg, errorFg   string
	noticeBg, noticeFg string
	colorScheme        string
}

// brandOf resolves settings for a page. force renders a light or dark page
// regardless of the mode (previews); empty uses the configured mode.
func brandOf(s hosted.Settings, force string) brand {
	t := s.Theme
	b := brand{Name: s.DisplayName, Logo: s.LogoURL, Favicon: t.FaviconURL, Header: t.Header.Show,
		LogoInHeader: t.Header.Show && t.LogoPosition == hosted.PositionHeader, FooterText: t.Footer.Text, Links: t.Footer.Links}
	own := t.Light
	if own.Primary == "" {
		own.Primary = s.AccentColor
	}
	light := merge(own, lightDefaults)
	darkBase := darkDefaults
	darkBase.Primary = light.Primary
	dark := merge(t.Dark, darkBase)
	b.Accent = light.Primary

	mode := t.Mode
	if force == hosted.ModeLight || force == hosted.ModeDark {
		mode = force
	}
	lightScheme := scheme{light, "#fdecea", "#8a1c12", "#e8f4ea", "#1c5a2a", "light"}
	darkScheme := scheme{dark, "#3b1715", "#fca5a5", "#0f2e1a", "#86efac", "dark"}
	logoDark := t.LogoDarkURL
	var css strings.Builder
	css.WriteString(":root{" + layoutVars(t) + "}")
	switch mode {
	case hosted.ModeDark:
		b.Accent = dark.Primary
		css.WriteString(":root{" + schemeVars(darkScheme) + "}")
		if logoDark != "" {
			b.Logo = logoDark
		}
	case hosted.ModeAdaptive:
		css.WriteString(":root{" + schemeVars(lightScheme) + "}")
		css.WriteString("@media (prefers-color-scheme: dark){:root{" + schemeVars(darkScheme) + "}}")
		if b.Logo != "" {
			b.LogoDark = logoDark
		}
	default:
		css.WriteString(":root{" + schemeVars(lightScheme) + "}")
	}
	b.Vars = template.CSS(css.String())
	return b
}

func merge(p, defaults hosted.Palette) hosted.Palette {
	pick := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	out := hosted.Palette{Primary: pick(p.Primary, defaults.Primary), Background: pick(p.Background, defaults.Background), Card: pick(p.Card, defaults.Card), Text: pick(p.Text, defaults.Text)}
	out.Header = pick(p.Header, out.Card)
	return out
}

func layoutVars(t hosted.Theme) string {
	radius := hosted.DefaultRadius
	if t.Radius != nil {
		radius = *t.Radius
	}
	pad, gap := "32px", "12px"
	switch t.Spacing {
	case hosted.SpacingCompact:
		pad, gap = "24px", "8px"
	case hosted.SpacingRoomy:
		pad, gap = "40px", "16px"
	}
	align := "center"
	switch t.Align {
	case hosted.AlignLeft:
		align = "flex-start"
	case hosted.AlignRight:
		align = "flex-end"
	}
	return fmt.Sprintf("--radius:%dpx;--field-radius:%dpx;--pad:%s;--gap:%s;--align:%s", radius, radius*2/3, pad, gap, align)
}

func schemeVars(s scheme) string {
	p := s.palette
	return "color-scheme:" + s.colorScheme +
		";--accent:" + p.Primary + ";--on-accent:" + readable(p.Primary) + ";--link:" + p.Primary +
		";--bg:" + p.Background + ";--card:" + p.Card + ";--text:" + p.Text +
		";--header:" + p.Header + ";--on-header:" + readable(p.Header) +
		";--muted:color-mix(in srgb," + p.Text + " 62%," + p.Card + ")" +
		";--border:color-mix(in srgb," + p.Text + " 18%," + p.Card + ")" +
		";--error-bg:" + s.errorBg + ";--error:" + s.errorFg + ";--notice-bg:" + s.noticeBg + ";--notice:" + s.noticeFg
}

// readable is black or white, whichever contrasts more with a #rrggbb color.
func readable(hex string) string {
	if luminance(hex) > 0.179 {
		return "#000000"
	}
	return "#ffffff"
}

// luminance is the WCAG relative luminance of a #rrggbb color.
func luminance(hex string) float64 {
	channel := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	if len(hex) != 7 {
		return 0
	}
	return 0.2126*channel(1) + 0.7152*channel(3) + 0.0722*channel(5)
}
