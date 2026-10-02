package hostedhttp

import (
	"embed"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/gofiber/fiber/v2"
)

// The fonts IAMKit serves itself (hosted.Fonts), so a page with one of them
// makes no third-party request: the latin and latin-ext subsets of each
// variable font (SIL Open Font License, fonts/OFL.txt).
//
//go:embed fonts/*.woff2
var fontFiles embed.FS

// fontPath is where the pages load the embedded fonts from.
const fontPath = "/hosted/fonts/"

// systemFonts is the stack of FontSystem (and the fallback of the others).
const systemFonts = `system-ui,-apple-system,"Segoe UI",Roboto,sans-serif`

// builtinFonts are each embedded family's display name and weight range.
var builtinFonts = map[string]struct{ name, weights string }{
	"inter":     {"Inter", "100 900"},
	"roboto":    {"Roboto", "100 900"},
	"open-sans": {"Open Sans", "300 800"},
	"lora":      {"Lora", "400 700"},
}

// Subsets of the embedded files: the browser downloads only those the page
// text uses.
var fontSubsets = []struct{ suffix, ranges string }{
	{"latin", "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD"},
	{"latin-ext", "U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF"},
}

// font serves an embedded font file. Fonts are fetched in CORS mode, and the
// console previews pages in a sandboxed (opaque origin) frame, so any
// origin may read them; they are public files.
func (h *Handler) font(c *fiber.Ctx) error {
	name := c.Params("file")
	family, _, _ := strings.Cut(name, "-latin")
	if _, ok := builtinFonts[family]; !ok || strings.ContainsAny(name, "/\\") {
		return fiber.ErrNotFound
	}
	data, err := fontFiles.ReadFile("fonts/" + name)
	if err != nil {
		return fiber.ErrNotFound
	}
	c.Set("Content-Type", "font/woff2")
	c.Set("Cache-Control", "public, max-age=604800")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Cross-Origin-Resource-Policy", "cross-origin")
	return c.Send(data)
}

// fontFaces is the CSS of the theme's fonts: @font-face rules and the
// --font / --heading-font variables the layout uses. The second result is
// the page's font-src: "" without fonts to load, 'self' for embedded fonts,
// plus https: for a custom font. Custom URLs are validated https .woff2 URLs
// without quotes, parentheses, backslashes or spaces, so they cannot leave
// url("").
func fontFaces(t hosted.Theme) (string, string) {
	var css strings.Builder
	var sources []string
	stack := func(f hosted.Font, role string) string {
		switch {
		case f.Family == hosted.FontCustom && f.URL != "":
			name := "IAMKit " + role
			css.WriteString(`@font-face{font-family:"` + name + `";src:url("` + f.URL + `") format("woff2");font-weight:100 900;font-display:swap}`)
			if !slices.Contains(sources, "https:") {
				sources = append(sources, "https:")
			}
			return `"` + name + `",` + systemFonts
		case builtinFonts[f.Family].name != "":
			b := builtinFonts[f.Family]
			if !strings.Contains(css.String(), `font-family:"`+b.name+`"`) {
				for _, s := range fontSubsets {
					css.WriteString(`@font-face{font-family:"` + b.name + `";src:url("` + fontPath + f.Family + "-" + s.suffix + `.woff2") format("woff2");font-weight:` + b.weights + `;font-display:swap;unicode-range:` + s.ranges + `}`)
				}
			}
			if !slices.Contains(sources, "'self'") {
				sources = append([]string{"'self'"}, sources...)
			}
			return `"` + b.name + `",` + systemFonts
		}
		return ""
	}
	body := stack(t.Font, "Text")
	heading := stack(t.HeadingFont, "Heading")
	if body == "" {
		body = systemFonts
	}
	css.WriteString(":root{--font:" + body)
	if heading != "" {
		css.WriteString(";--heading-font:" + heading)
	} else {
		css.WriteString(";--heading-font:var(--font)")
	}
	css.WriteString("}")
	return css.String(), strings.Join(sources, " ")
}
