package authorization

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
)

// Limits of a permission description (D40).
const (
	MaxDisplayName = 80
	MaxDescription = 300
)

// PermissionDescription is how people read one permission of a resource's
// catalog: a short name and a sentence, in one language. Locale "" is the
// default text, shown when no text matches the reader's language. The
// permission's name (resources.permissions) stays the identifier and the
// last fallback; descriptions never rename or add permissions.
type PermissionDescription struct {
	Permission  string `json:"permission" db:"permission"`
	Locale      string `json:"locale" db:"locale"`
	DisplayName string `json:"display_name" db:"display_name"`
	Description string `json:"description" db:"description"`
}

// DescribedPermission is a permission as a reader sees it: DisplayName is
// the permission's name itself when nothing describes it, Description may
// be empty. Described reports whether any text matched.
type DescribedPermission struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Described   bool   `json:"described"`
}

// MaxDescriptions is the most descriptions a catalog of n permissions
// holds: one default and one per available language each.
func MaxDescriptions(permissions int) int {
	return permissions * (1 + len(i18n.Codes()))
}

// plain checks text is one line of plain text.
func plain(field, s string, max int) error {
	if !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return errx.Validation(field + " must be plain text on one line")
	}
	if utf8.RuneCountInString(s) > max {
		return errx.Validation(field + " must be at most " + strconv.Itoa(max) + " characters")
	}
	return nil
}

// Clean trims the texts and canonicalizes the locale ("es_MX" is "es-MX"
// only when a catalog has it; "" stays the default), then checks the
// description against the language list and its limits. It does not know
// the catalog; see ValidateDescriptions.
func (d PermissionDescription) Clean() (PermissionDescription, error) {
	d.Permission = strings.TrimSpace(d.Permission)
	d.DisplayName = strings.TrimSpace(d.DisplayName)
	d.Description = strings.TrimSpace(d.Description)
	d.Locale = strings.TrimSpace(d.Locale)
	if d.Permission == "" {
		return d, errx.Validation("permission is required")
	}
	if d.Locale != "" {
		code, ok := i18n.Canonical(d.Locale)
		if !ok {
			return d, errx.Validation("locale " + d.Locale + " is not an available language")
		}
		d.Locale = code
	}
	if err := plain("display_name", d.DisplayName, MaxDisplayName); err != nil {
		return d, err
	}
	if err := plain("description", d.Description, MaxDescription); err != nil {
		return d, err
	}
	if d.DisplayName == "" && d.Description == "" {
		return d, errx.Validation("display_name or description is required for " + d.Permission)
	}
	return d, nil
}

// ValidateDescriptions cleans a full set of descriptions against the
// resource's catalog: every permission must be in it, each
// (permission, locale) appears once, and the set fits MaxDescriptions. The
// result is ordered by permission, then locale.
func ValidateDescriptions(catalog []string, in []PermissionDescription) ([]PermissionDescription, error) {
	if len(in) > MaxDescriptions(len(catalog)) {
		return nil, errx.Validation("too many permission descriptions")
	}
	known := make(map[string]bool, len(catalog))
	for _, p := range catalog {
		known[p] = true
	}
	type key struct{ permission, locale string }
	seen := make(map[key]bool, len(in))
	out := make([]PermissionDescription, 0, len(in))
	for _, d := range in {
		d, err := d.Clean()
		if err != nil {
			return nil, err
		}
		if !known[d.Permission] {
			return nil, errx.Validation(d.Permission + " is not a permission of the resource")
		}
		k := key{d.Permission, d.Locale}
		if seen[k] {
			return nil, errx.Validation("permission " + d.Permission + " is described twice for locale \"" + d.Locale + "\"")
		}
		seen[k] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Permission != out[j].Permission {
			return out[i].Permission < out[j].Permission
		}
		return out[i].Locale < out[j].Locale
	})
	return out, nil
}

// Locales reads an Accept-Language header or an OIDC ui_locales value (or
// one locale) as a preference list, without weights, in the order given.
func Locales(header string) []string {
	var out []string
	for _, tag := range strings.FieldsFunc(header, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		tag, _, _ = strings.Cut(tag, ";")
		if tag = strings.TrimSpace(strings.ReplaceAll(tag, "_", "-")); tag != "" && tag != "*" {
			out = append(out, tag)
		}
	}
	return out
}

// LocaleChain is the locales a reader who prefers locales is served, best
// first: for each preference its exact locale, the catalog language it
// matches (a bare "pt" matches "pt-BR" when that is the only Portuguese)
// and its base language ("es-PE" → "es"); the default "" comes last.
func LocaleChain(locales ...string) []string {
	var chain []string
	add := func(l string) {
		if l != "" && !slices.Contains(chain, strings.ToLower(l)) {
			chain = append(chain, strings.ToLower(l))
		}
	}
	for _, l := range locales {
		for _, tag := range Locales(l) {
			add(tag)
			add(i18n.Match(tag))
			if base, _, ok := strings.Cut(tag, "-"); ok {
				add(base)
			}
		}
	}
	return append(chain, "")
}

// Describe resolves name for a reader who prefers locales among
// descriptions (any set; other permissions are ignored) along the
// LocaleChain. Each field is taken from the first text of the chain that
// has it, so a translation that only names the permission still shows the
// default sentence; with no text the display name is the permission's own
// name (Described false). Locales compare case-insensitively.
func Describe(descriptions []PermissionDescription, name string, locales ...string) DescribedPermission {
	by := make(map[string]PermissionDescription)
	for _, d := range descriptions {
		if d.Permission == name {
			by[strings.ToLower(d.Locale)] = d
		}
	}
	out := DescribedPermission{Name: name, DisplayName: name}
	named := false
	for _, l := range LocaleChain(locales...) {
		d, ok := by[l]
		if !ok {
			continue
		}
		if !named && d.DisplayName != "" {
			out.DisplayName, out.Described, named = d.DisplayName, true, true
		}
		if out.Description == "" && d.Description != "" {
			out.Description, out.Described = d.Description, true
		}
	}
	return out
}

// DescribeAll resolves each of names (in order).
func DescribeAll(descriptions []PermissionDescription, names []string, locales ...string) []DescribedPermission {
	out := make([]DescribedPermission, len(names))
	for i, name := range names {
		out[i] = Describe(descriptions, name, locales...)
	}
	return out
}
