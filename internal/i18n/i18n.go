// Package i18n holds the message catalogs of text IAMKit writes for end
// users (emails today). Catalogs are embedded JSON files, one per language
// (locales/<code>.json): adding a language is adding a file. Every catalog
// must carry the same keys with the same format verbs as English (enforced
// by tests); a missing key falls back to English at runtime.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Default is the language used when nothing else applies, and the fallback
// for missing keys.
const Default = "en"

//go:embed locales/*.json
var files embed.FS

// catalogs maps a language code to its messages.
var catalogs = load()

func load() map[string]map[string]string {
	entries, err := files.ReadDir("locales")
	if err != nil {
		panic("i18n: read catalogs: " + err.Error())
	}
	out := map[string]map[string]string{}
	for _, entry := range entries {
		raw, err := files.ReadFile(path.Join("locales", entry.Name()))
		if err != nil {
			panic("i18n: read " + entry.Name() + ": " + err.Error())
		}
		messages := map[string]string{}
		if err := json.Unmarshal(raw, &messages); err != nil {
			panic("i18n: parse " + entry.Name() + ": " + err.Error())
		}
		out[strings.TrimSuffix(entry.Name(), ".json")] = messages
	}
	if _, ok := out[Default]; !ok {
		panic("i18n: missing " + Default + " catalog")
	}
	return out
}

// Locale is an available language: its code and its name in itself.
type Locale struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Locales lists the available languages, ordered by code.
func Locales() []Locale {
	out := make([]Locale, 0, len(catalogs))
	for code, messages := range catalogs {
		out = append(out, Locale{Code: code, Name: messages["_name"]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Supported reports whether code names an available language exactly.
func Supported(code string) bool {
	_, ok := catalogs[code]
	return ok
}

// Resolve returns the first candidate that matches an available language,
// or Default. Candidates may be language tags ("es-MX", "ES_mx") or
// space/comma separated lists of them (an OIDC ui_locales value, an
// Accept-Language header without weights); the primary subtag is matched.
func Resolve(candidates ...string) string {
	for _, candidate := range candidates {
		if code := Match(candidate); code != "" {
			return code
		}
	}
	return Default
}

// Match returns the first available language in candidate (a tag or a
// list of them, as in Resolve), or "" when none is available.
func Match(candidate string) string {
	for _, tag := range strings.FieldsFunc(candidate, func(r rune) bool { return r == ' ' || r == ',' }) {
		tag, _, _ = strings.Cut(tag, ";") // drop an Accept-Language weight
		tag = strings.ToLower(strings.TrimSpace(tag))
		if Supported(tag) {
			return tag
		}
		if primary, _, found := strings.Cut(strings.ReplaceAll(tag, "_", "-"), "-"); found && Supported(primary) {
			return primary
		}
	}
	return ""
}

// T formats the message key in locale with args, falling back to English
// for an unknown locale or key, and to the key itself when English lacks it.
func T(locale, key string, args ...any) string {
	format, ok := catalogs[locale][key]
	if !ok {
		if format, ok = catalogs[Default][key]; !ok {
			return key
		}
	}
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

// Date formats the calendar date of t (in UTC) as a long date in locale,
// such as "September 27, 2026" or "27 de septiembre de 2026".
func Date(locale string, t time.Time) string {
	t = t.UTC()
	return T(locale, "date.long", t.Day(), T(locale, fmt.Sprintf("date.month.%d", int(t.Month()))), t.Year())
}
