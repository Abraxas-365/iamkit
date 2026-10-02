// Package i18n holds the message catalogs of text IAMKit writes for end
// users (hosted pages, emails, SMS). Catalogs are embedded JSON files, one
// per language (locales/<code>.json, a BCP 47 tag such as "es" or
// "pt-BR"): adding a language is adding a file. Every catalog must carry
// the same keys with the same format verbs and placeholders as English
// (enforced by tests); a missing key falls back to English at runtime.
//
// Messages are fmt formats (%s, %[1]d) or carry named placeholders
// ({name}, see V). Plural messages are families of keys ending in a CLDR
// category (key.one, key.few, key.other …, see N); each catalog lists the
// categories its language uses. Email wording placeholders ({{name}}) are
// filled by the email renderer, not here. The "_name" key is the
// language's name in itself, "_dir" its writing direction (rtl, else
// ltr) and "_status" "beta" for a machine-drafted catalog awaiting a
// native speaker's review.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Default is the language used when nothing else applies, and the fallback
// for missing keys.
const Default = "en"

//go:embed locales/*.json
var files embed.FS

// catalogs maps a language code to its messages; codes maps lowercased
// codes to catalog codes ("pt-br" → "pt-BR").
var catalogs, codes = load()

func load() (map[string]map[string]string, map[string]string) {
	entries, err := files.ReadDir("locales")
	if err != nil {
		panic("i18n: read catalogs: " + err.Error())
	}
	out, lower := map[string]map[string]string{}, map[string]string{}
	for _, entry := range entries {
		raw, err := files.ReadFile(path.Join("locales", entry.Name()))
		if err != nil {
			panic("i18n: read " + entry.Name() + ": " + err.Error())
		}
		messages := map[string]string{}
		if err := json.Unmarshal(raw, &messages); err != nil {
			panic("i18n: parse " + entry.Name() + ": " + err.Error())
		}
		code := strings.TrimSuffix(entry.Name(), ".json")
		out[code], lower[strings.ToLower(code)] = messages, code
	}
	if _, ok := out[Default]; !ok {
		panic("i18n: missing " + Default + " catalog")
	}
	return out, lower
}

// Locale is an available language: its code, its name in itself, its
// writing direction (ltr or rtl) and whether its catalog is a draft that
// awaits a native speaker's review ("_status": "beta").
type Locale struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Dir  string `json:"dir"`
	Beta bool   `json:"beta,omitempty"`
}

// Locales lists the available languages: Default first, then by code.
func Locales() []Locale {
	out := make([]Locale, 0, len(catalogs))
	for _, code := range Codes() {
		messages := catalogs[code]
		out = append(out, Locale{Code: code, Name: messages["_name"], Dir: Dir(code), Beta: messages["_status"] == "beta"})
	}
	return out
}

// Codes lists the available language codes: Default first, then by code.
func Codes() []string {
	out := make([]string, 0, len(catalogs))
	for code := range catalogs {
		out = append(out, code)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i] == Default) != (out[j] == Default) {
			return out[i] == Default
		}
		return out[i] < out[j]
	})
	return out
}

// Stable lists the languages that are not beta (natively reviewed), in
// Codes order.
func Stable() []string {
	out := []string{}
	for _, code := range Codes() {
		if catalogs[code]["_status"] != "beta" {
			out = append(out, code)
		}
	}
	return out
}

// Supported reports whether code names an available language exactly.
func Supported(code string) bool {
	_, ok := catalogs[code]
	return ok
}

// Canonical returns the catalog code for code in any letter case or with
// "_" ("PT_br" → "pt-BR"), or false when no catalog has it.
func Canonical(code string) (string, bool) {
	out, ok := codes[strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "_", "-"))]
	return out, ok
}

// Dir is the writing direction of locale: "rtl" or "ltr".
func Dir(locale string) string {
	if catalogs[locale]["_dir"] == "rtl" {
		return "rtl"
	}
	return "ltr"
}

// aliases send tags with no catalog of their own to the closest one (only
// when that catalog exists).
var aliases = map[string]string{
	"zh": "zh-CN", "zh-hans": "zh-CN", "zh-sg": "zh-CN",
	"zh-hant": "zh-TW", "zh-hk": "zh-TW", "zh-mo": "zh-TW",
	"pt-pt": "pt", "nb": "no", "nn": "no",
}

// Resolve returns the first candidate that matches an available language,
// or Default. Candidates may be language tags ("es-MX", "ES_mx") or
// space/comma separated lists of them (an OIDC ui_locales value, an
// Accept-Language header without weights).
func Resolve(candidates ...string) string {
	return Negotiate(nil, candidates...)
}

// Negotiate is Resolve limited to the enabled languages (nil or empty =
// every available language). When no candidate matches, it answers
// Default if enabled, else the first enabled language.
func Negotiate(enabled []string, candidates ...string) string {
	for _, candidate := range candidates {
		if code := MatchIn(enabled, candidate); code != "" {
			return code
		}
	}
	if allowed(enabled, Default) {
		return Default
	}
	for _, code := range enabled {
		if Supported(code) {
			return code
		}
	}
	return Default
}

// Match returns the first available language in candidate (a tag or a
// list of them, as in Resolve), or "" when none is available.
func Match(candidate string) string { return MatchIn(nil, candidate) }

// MatchIn is Match limited to the enabled languages (nil = all). A tag
// matches a catalog exactly ("pt-BR"), through an alias ("zh-Hant" →
// "zh-TW"), by its primary subtag ("es-MX" → "es"), or, for a bare primary
// subtag, the only catalog of that language ("pt" when only "pt-BR"
// exists).
func MatchIn(enabled []string, candidate string) string {
	for _, tag := range strings.FieldsFunc(candidate, func(r rune) bool { return r == ' ' || r == ',' }) {
		tag, _, _ = strings.Cut(tag, ";") // drop an Accept-Language weight
		if code := matchTag(enabled, tag); code != "" {
			return code
		}
	}
	return ""
}

func matchTag(enabled []string, tag string) string {
	tag = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(tag), "_", "-"))
	if tag == "" {
		return ""
	}
	try := func(lower string) string {
		if code, ok := codes[lower]; ok && allowed(enabled, code) {
			return code
		}
		return ""
	}
	if code := try(tag); code != "" {
		return code
	}
	// zh-Hant-TW: script and region in turn.
	parts := strings.Split(tag, "-")
	for i := len(parts) - 1; i >= 1; i-- {
		prefix := strings.Join(parts[:i+1], "-")
		if alias, ok := aliases[prefix]; ok {
			if code := try(strings.ToLower(alias)); code != "" {
				return code
			}
		}
		if code := try(parts[0] + "-" + parts[i]); code != "" {
			return code
		}
	}
	if alias, ok := aliases[parts[0]]; ok {
		if code := try(strings.ToLower(alias)); code != "" {
			return code
		}
	}
	if code := try(parts[0]); code != "" {
		return code
	}
	// A bare language with only regional catalogs: the only one.
	only := ""
	for lower, code := range codes {
		if strings.HasPrefix(lower, parts[0]+"-") && allowed(enabled, code) {
			if only != "" {
				return ""
			}
			only = code
		}
	}
	return only
}

func allowed(enabled []string, code string) bool {
	if len(enabled) == 0 {
		return Supported(code)
	}
	for _, e := range enabled {
		if e == code {
			return true
		}
	}
	return false
}

// message is the message key in locale, else English, else the key.
func message(locale, key string) (string, bool) {
	if format, ok := catalogs[locale][key]; ok {
		return format, true
	}
	format, ok := catalogs[Default][key]
	return format, ok
}

// Texts are custom messages (key → message in the catalog's format) that
// replace the catalog's in one language: the wording an operator chose
// for the hosted pages. A nil Texts is the catalog alone.
type Texts map[string]string

func (x Texts) message(locale, key string) (string, bool) {
	if format, ok := x[key]; ok {
		return format, true
	}
	return message(locale, key)
}

// T formats the message key in locale with args, falling back to English
// for an unknown locale or key, and to the key itself when English lacks it.
func T(locale, key string, args ...any) string { return Texts(nil).T(locale, key, args...) }

// T is the package T with the custom messages first.
func (x Texts) T(locale, key string, args ...any) string {
	format, ok := x.message(locale, key)
	if !ok {
		return key
	}
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

// Vars are named placeholder values for V and N.
type Vars map[string]any

// V renders the message key in locale with named placeholders: each
// {name} is replaced by vars[name] (fmt's %v); unknown names stay as they
// are. Email placeholders ({{name}}) are left untouched.
func V(locale, key string, vars Vars) string { return Texts(nil).V(locale, key, vars) }

// V is the package V with the custom messages first.
func (x Texts) V(locale, key string, vars Vars) string {
	format, ok := x.message(locale, key)
	if !ok {
		return key
	}
	return fill(format, vars)
}

// N renders the plural message key for count n in locale: the key's CLDR
// category for n (key.one, key.few …), else key.other, with the named
// placeholders of vars plus {count}.
func N(locale, key string, n int, vars Vars) string { return Texts(nil).N(locale, key, n, vars) }

// N is the package N with the custom messages (of locale's categories)
// first.
func (x Texts) N(locale, key string, n int, vars Vars) string {
	if !Supported(locale) {
		locale = Default
	}
	all := Vars{"count": n}
	for k, v := range vars {
		all[k] = v
	}
	for _, k := range []string{key + "." + Plural(locale, n), key + ".other"} {
		if format, ok := x[k]; ok {
			return fill(format, all)
		}
		if format, ok := catalogs[locale][k]; ok {
			return fill(format, all)
		}
	}
	for _, k := range []string{key + "." + Plural(Default, n), key + ".other"} {
		if format, ok := catalogs[Default][k]; ok {
			return fill(format, all)
		}
	}
	return key
}

// Keys lists the message keys under prefix ("hosted.") that locale can
// carry, sorted: the English keys, with each plural family expanded to the
// categories locale uses.
func Keys(locale, prefix string) []string {
	var out []string
	seen := map[string]bool{}
	for key := range catalogs[Default] {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if family, ok := PluralFamily(key); ok {
			if !seen[family] {
				seen[family] = true
				for _, category := range Categories(locale) {
					out = append(out, family+"."+category)
				}
			}
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Message is the catalog message for key in locale: its own, else
// English (for a plural category English lacks, the family's .other);
// false when neither has it.
func Message(locale, key string) (string, bool) {
	if format, ok := message(locale, key); ok {
		return format, true
	}
	if family, ok := PluralFamily(key); ok {
		format, ok := catalogs[Default][family+".other"]
		return format, ok
	}
	return "", false
}

// verbPattern is an fmt verb (%s, %[2]d, %%).
var verbPattern = regexp.MustCompile(`%(\[\d+\])?[a-zA-Z%]`)

// namedPattern is a named placeholder ({name}, not {{email}} ones).
var namedPattern = regexp.MustCompile(`(^|[^{])\{([a-z_0-9]+)\}`)

// Placeholders lists what a message fills in: its fmt verbs, in order,
// then its named placeholders ({name}), sorted.
func Placeholders(format string) []string {
	out := verbPattern.FindAllString(format, -1)
	var names []string
	for _, m := range namedPattern.FindAllStringSubmatch(format, -1) {
		names = append(names, "{"+m[2]+"}")
	}
	sort.Strings(names)
	return append(out, slices.Compact(names)...)
}

// SameArgs reports whether custom can replace the catalog message
// original: the same fmt verbs (in order, or the same set when all are
// indexed) and named placeholders. Where original has verbs, every % in
// custom must belong to one (a percent sign is %%); where it has none, the
// message is shown as written and only named placeholders count.
func SameArgs(custom, original string) bool {
	verbs, want := verbPattern.FindAllString(custom, -1), verbPattern.FindAllString(original, -1)
	if len(want) > 0 {
		percents := 0
		for _, v := range verbs {
			percents += strings.Count(v, "%")
		}
		if percents != strings.Count(custom, "%") {
			return false
		}
		literal := func(v string) bool { return v == "%%" }
		if !sameVerbs(slices.DeleteFunc(verbs, literal), slices.DeleteFunc(want, literal)) {
			return false
		}
	}
	return slices.Equal(namedSet(custom), namedSet(original))
}

func namedSet(format string) []string {
	var out []string
	for _, m := range namedPattern.FindAllStringSubmatch(format, -1) {
		out = append(out, m[2])
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// sameVerbs: the same verbs in order, or, when all are indexed (%[2]s),
// the same set in any order.
func sameVerbs(got, want []string) bool {
	if slices.Equal(got, want) {
		return true
	}
	for _, v := range append(slices.Clone(got), want...) {
		if v[1] != '[' {
			return false
		}
	}
	got, want = slices.Clone(got), slices.Clone(want)
	sort.Strings(got)
	sort.Strings(want)
	return slices.Equal(got, want)
}

// fill replaces {name} placeholders, skipping {{email}} ones.
func fill(format string, vars Vars) string {
	if !strings.Contains(format, "{") {
		return format
	}
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '{' {
			b.WriteByte(c)
			continue
		}
		if i+1 < len(format) && format[i+1] == '{' {
			end := strings.Index(format[i:], "}}")
			if end < 0 {
				b.WriteString(format[i:])
				break
			}
			b.WriteString(format[i : i+end+2])
			i += end + 1
			continue
		}
		end := strings.IndexByte(format[i:], '}')
		name := ""
		if end > 0 {
			name = format[i+1 : i+end]
		}
		value, ok := vars[name]
		if !ok || !placeholderName(name) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprint(&b, value)
		i += end
	}
	return b.String()
}

func placeholderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '_' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// Date formats the calendar date of t (in UTC) as a long date in locale,
// such as "September 27, 2026" or "27 de septiembre de 2026".
func Date(locale string, t time.Time) string {
	t = t.UTC()
	return T(locale, "date.long", t.Day(), T(locale, fmt.Sprintf("date.month.%d", int(t.Month()))), t.Year())
}

// Missing lists the English keys locale's catalog lacks (they fall back to
// English at runtime), sorted. Plural families count as present when the
// catalog has every category its language uses.
func Missing(locale string) []string {
	messages := catalogs[locale]
	var out []string
	seen := map[string]bool{}
	for key := range catalogs[Default] {
		if family, ok := PluralFamily(key); ok {
			if seen[family] {
				continue
			}
			seen[family] = true
			for _, category := range Categories(locale) {
				if _, ok := messages[family+"."+category]; !ok {
					out = append(out, family+"."+category)
				}
			}
			continue
		}
		if _, ok := messages[key]; !ok {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// PluralFamily reports whether key belongs to a plural family in English
// (it ends in a CLDR category and English has the family's .other) and
// returns the family.
func PluralFamily(key string) (string, bool) {
	i := strings.LastIndexByte(key, '.')
	if i < 0 {
		return "", false
	}
	family, category := key[:i], key[i+1:]
	switch category {
	case "zero", "one", "two", "few", "many", "other":
	default:
		return "", false
	}
	_, ok := catalogs[Default][family+".other"]
	return family, ok
}
