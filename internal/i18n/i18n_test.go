package i18n

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var verb = regexp.MustCompile(`%(\[\d+\])?[a-zA-Z%]`)

// placeholder is an email wording placeholder ({{code}}); translations must
// keep the same set.
var placeholder = regexp.MustCompile(`\{\{[a-z_]+\}\}`)

// named is a named placeholder ({name}); translations keep the same set.
var named = regexp.MustCompile(`(^|[^{])\{([a-z_0-9]+)\}`)

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

func names(s string) []string {
	var out []string
	for _, m := range named.FindAllStringSubmatch(s, -1) {
		out = append(out, m[2])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// pluralKey reports whether key is a category of an English plural
// family, and the family.
func pluralKey(key string) (string, bool) {
	i := strings.LastIndexByte(key, '.')
	if i < 0 {
		return "", false
	}
	switch key[i+1:] {
	case "zero", "one", "two", "few", "many", "other":
	default:
		return "", false
	}
	if _, ok := PluralFamily(key[:i] + ".other"); !ok {
		return "", false
	}
	return key[:i], true
}

// english is the English message a catalog key translates: the same key,
// or, for a plural category English lacks (few, many …), the family's
// English .other.
func english(key string) (string, bool) {
	if want, ok := catalogs[Default][key]; ok {
		return want, true
	}
	if family, ok := pluralKey(key); ok {
		want, ok := catalogs[Default][family+".other"]
		return want, ok
	}
	return "", false
}

// Every catalog has exactly the English keys (plural families with exactly
// the categories of its language), and each message uses the same format
// verbs — in the same order, or, when all verbs are indexed (%[2]s), the
// same set in any order — and the same placeholders.
func TestCatalogParity(t *testing.T) {
	for code, messages := range catalogs {
		if messages["_name"] == "" {
			t.Errorf("%s: missing _name", code)
		}
		if dir, ok := messages["_dir"]; ok && dir != "rtl" && dir != "ltr" {
			t.Errorf("%s: _dir %q", code, dir)
		}
		if status, ok := messages["_status"]; ok && status != "beta" {
			t.Errorf("%s: _status %q", code, status)
		}
		if missing := Missing(code); len(missing) > 0 {
			t.Errorf("%s: missing keys %v", code, missing)
		}
		for key, message := range messages {
			if key == "_dir" || key == "_status" {
				continue
			}
			want, ok := english(key)
			if !ok {
				t.Errorf("%s: key %q is not in %s", code, key, Default)
				continue
			}
			family, plural := pluralKey(key)
			if plural && !slices.Contains(Categories(code), key[len(family)+1:]) {
				t.Errorf("%s: %q: the language has no plural category %q", code, key, key[len(family)+1:])
			}
			if got, exp := verb.FindAllString(message, -1), verb.FindAllString(want, -1); !sameVerbs(got, exp) {
				t.Errorf("%s: %q verbs %v, want %v", code, key, got, exp)
			}
			if got, exp := sorted(placeholder.FindAllString(message, -1)), sorted(placeholder.FindAllString(want, -1)); !slices.Equal(got, exp) {
				t.Errorf("%s: %q placeholders %v, want %v", code, key, got, exp)
			}
			// A plural form may leave {count} out ("one attempt").
			got, exp := names(message), names(want)
			if plural {
				got = slices.DeleteFunc(got, func(s string) bool { return s == "count" })
				exp = slices.DeleteFunc(exp, func(s string) bool { return s == "count" })
			}
			if !slices.Equal(got, exp) {
				t.Errorf("%s: %q named placeholders %v, want %v", code, key, got, exp)
			}
		}
	}
}

// TestMissingReport logs each catalog's coverage (go test -v -run
// TestMissingReport ./internal/i18n), a quick view for translators.
func TestMissingReport(t *testing.T) {
	for _, l := range Locales() {
		t.Logf("%-6s %-20s %s %d missing", l.Code, l.Name, l.Dir, len(Missing(l.Code)))
	}
}

func TestLocales(t *testing.T) {
	got := Locales()
	en := slices.IndexFunc(got, func(l Locale) bool { return l.Code == "en" })
	es := slices.IndexFunc(got, func(l Locale) bool { return l.Code == "es" })
	if en < 0 || es < 0 || got[en] != (Locale{Code: "en", Name: "English", Dir: "ltr"}) || got[es].Name != "Español" {
		t.Fatalf("Locales() = %v", got)
	}
	if got[0].Code != Default || !slices.IsSortedFunc(got[1:], func(a, b Locale) int { return strings.Compare(a.Code, b.Code) }) {
		t.Fatal("Locales must list Default first, then order by code")
	}
	if !slices.Equal(Codes(), slices.Collect(func(yield func(string) bool) {
		for _, l := range got {
			if !yield(l.Code) {
				return
			}
		}
	})) {
		t.Fatal("Codes must follow Locales")
	}
	if ar := got[slices.IndexFunc(got, func(l Locale) bool { return l.Code == "ar" })]; ar.Dir != "rtl" || !ar.Beta {
		t.Fatalf("ar = %+v, want rtl beta", ar)
	}
	if !Supported("es") || Supported("ES") || Supported("xx") || Supported("") {
		t.Fatal("Supported must match catalog codes exactly")
	}
	if code, ok := Canonical(" ES "); !ok || code != "es" {
		t.Fatalf("Canonical: %q %v", code, ok)
	}
	if _, ok := Canonical("xx"); ok {
		t.Fatal("Canonical(xx)")
	}
}

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "en"},
		{[]string{""}, "en"},
		{[]string{"es"}, "es"},
		{[]string{"es-MX"}, "es"},
		{[]string{"ES_mx"}, "es"},
		{[]string{"xx-CA xx es"}, "es"},
		{[]string{"xx, es-419;q=0.8"}, "es"},
		{[]string{"xx", "", "es"}, "es"},
		{[]string{"en-GB", "es"}, "en"},
		{[]string{"zz"}, "en"},
	} {
		if got := Resolve(tc.in...); got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if Match("xx yy") != "" || Match("xx es-AR") != "es" {
		t.Error("Match")
	}
}

// Regional catalogs (pt-BR, zh-TW) match exactly, through aliases and,
// for a bare language, when they are its only catalog.
func TestRegional(t *testing.T) {
	saved := catalogs
	savedCodes := codes
	t.Cleanup(func() { catalogs, codes = saved, savedCodes })
	catalogs = map[string]map[string]string{"en": {}, "pt-BR": {}, "zh-CN": {}, "zh-TW": {}}
	codes = map[string]string{"en": "en", "pt-br": "pt-BR", "zh-cn": "zh-CN", "zh-tw": "zh-TW"}
	for in, want := range map[string]string{
		"pt-BR": "pt-BR", "pt_br": "pt-BR", "pt": "pt-BR", "pt-PT": "pt-BR", "es-PT": "",
		"zh": "zh-CN", "zh-Hant": "zh-TW", "zh-Hant-TW": "zh-TW", "zh-HK": "zh-TW", "zh-Hans-SG": "zh-CN", "zh-TW": "zh-TW",
	} {
		if got := Match(in); got != want {
			t.Errorf("Match(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNegotiate(t *testing.T) {
	if got := Negotiate([]string{"es"}, "en-US"); got != "es" {
		t.Errorf("only es enabled: %q", got)
	}
	if got := Negotiate([]string{"en", "es"}, "xx", "es-MX"); got != "es" {
		t.Errorf("second candidate: %q", got)
	}
	if got := Negotiate([]string{"en", "es"}, "xx"); got != "en" {
		t.Errorf("default: %q", got)
	}
	if got := Negotiate(nil, "es"); got != "es" {
		t.Errorf("nil enables all: %q", got)
	}
	if got := MatchIn([]string{"en"}, "es"); got != "" {
		t.Errorf("disabled language matched: %q", got)
	}
}

func TestT(t *testing.T) {
	if got := T("es", "email.login.heading"); got != "Tu código de acceso" {
		t.Errorf("es: %q", got)
	}
	if got := T("xx", "email.login.heading"); got != "Your sign-in code" {
		t.Errorf("unknown locale falls back to English: %q", got)
	}
	if got := T("es", "no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key: %q", got)
	}
	if got := T("es", "date.long", 3, "mayo", 2026); got != "3 de mayo de 2026" {
		t.Errorf("args: %q", got)
	}
}

func TestPlural(t *testing.T) {
	for _, tc := range []struct {
		locale string
		n      int
		want   string
	}{
		{"en", 1, "one"}, {"en", 0, "other"}, {"en", 2, "other"}, {"en", -1, "one"},
		{"fr", 0, "one"}, {"fr", 1, "one"}, {"fr", 2, "other"},
		{"ru", 1, "one"}, {"ru", 21, "one"}, {"ru", 11, "many"}, {"ru", 3, "few"}, {"ru", 13, "many"}, {"ru", 5, "many"},
		{"pl", 1, "one"}, {"pl", 21, "many"}, {"pl", 22, "few"},
		{"cs", 3, "few"}, {"cs", 5, "other"},
		{"ro", 0, "few"}, {"ro", 19, "few"}, {"ro", 20, "other"},
		{"ar", 0, "zero"}, {"ar", 2, "two"}, {"ar", 105, "few"}, {"ar", 111, "many"}, {"ar", 100, "other"},
		{"ja", 1, "other"}, {"zh-TW", 1, "other"}, {"pt-BR", 0, "one"}, {"pt", 0, "other"},
	} {
		if got := Plural(tc.locale, tc.n); got != tc.want {
			t.Errorf("Plural(%s, %d) = %s, want %s", tc.locale, tc.n, got, tc.want)
		}
		if !slices.Contains(Categories(tc.locale), tc.want) {
			t.Errorf("Categories(%s) lacks %s", tc.locale, tc.want)
		}
	}
}

func TestNamed(t *testing.T) {
	if got := fill("Hi {name}, {{app_name}} {missing} {Name} {}", Vars{"name": "Ana"}); got != "Hi Ana, {{app_name}} {missing} {Name} {}" {
		t.Errorf("fill: %q", got)
	}
	if got := N("en", "hosted.notice.attempts_left", 1, nil); got != "1 attempt left." {
		t.Errorf("N one: %q", got)
	}
	if got := N("en", "hosted.notice.attempts_left", 3, nil); got != "3 attempts left." {
		t.Errorf("N other: %q", got)
	}
	if got := N("es", "hosted.notice.attempts_left", 1, nil); got != "Te queda 1 intento." {
		t.Errorf("N es: %q", got)
	}
	if got := N("xx", "no.such", 1, nil); got != "no.such" {
		t.Errorf("N unknown: %q", got)
	}
	if got := V("es", "hosted.error.password_between", Vars{"min": 8, "max": 72}); got != "La contraseña debe tener entre 8 y 72 caracteres." {
		t.Errorf("V: %q", got)
	}
}

func TestTexts(t *testing.T) {
	x := Texts{"hosted.title.sign_in": "Welcome back", "hosted.notice.code_sent": "Code sent to %s!", "hosted.notice.attempts_left.one": "Last try ({count})."}
	if got := x.T("es", "hosted.title.sign_in"); got != "Welcome back" {
		t.Errorf("custom: %q", got)
	}
	if got := x.T("es", "hosted.form.email"); got != T("es", "hosted.form.email") {
		t.Errorf("catalog fallback: %q", got)
	}
	if got := x.T("en", "hosted.notice.code_sent", "a@b.c"); got != "Code sent to a@b.c!" {
		t.Errorf("verbs: %q", got)
	}
	if got := x.N("en", "hosted.notice.attempts_left", 1, nil); got != "Last try (1)." {
		t.Errorf("plural custom: %q", got)
	}
	if got := x.N("en", "hosted.notice.attempts_left", 2, nil); got != "2 attempts left." {
		t.Errorf("plural fallback: %q", got)
	}
	if got := Texts(nil).T("en", "hosted.title.sign_in"); got != T("en", "hosted.title.sign_in") {
		t.Errorf("nil texts: %q", got)
	}
}

func TestKeysAndArgs(t *testing.T) {
	en, ru := Keys("en", "hosted."), Keys("ru", "hosted.")
	if !slices.Contains(en, "hosted.notice.attempts_left.one") || slices.Contains(en, "hosted.notice.attempts_left.few") {
		t.Errorf("en keys: plural categories")
	}
	if len(ru) > 0 && !slices.Contains(ru, "hosted.notice.attempts_left.one") {
		t.Errorf("ru keys")
	}
	if slices.ContainsFunc(en, func(k string) bool { return !strings.HasPrefix(k, "hosted.") }) {
		t.Errorf("prefix")
	}
	if m, ok := Message("es", "hosted.notice.attempts_left.many"); !ok || m == "" {
		t.Errorf("plural category fallback: %q %v", m, ok)
	}
	if _, ok := Message("en", "hosted.nope"); ok {
		t.Errorf("unknown key")
	}
	for _, tc := range []struct {
		custom, original string
		ok               bool
	}{
		{"Code sent to %s", "We sent a code to %s.", true},
		{"Code sent", "We sent a code to %s.", false},
		{"Code sent to %s, 100%", "We sent a code to %s.", false},
		{"Code sent to %s, 100%%", "We sent a code to %s.", true},
		{"%d left", "We sent a code to %s.", false},
		{"Save 100%", "Continue", true},
		{"{count} left", "{count} attempts left.", true},
		{"left", "{count} attempts left.", false},
		{"{other} left", "{count} attempts left.", false},
		{"{{code}} {count}", "{count} attempts left.", true},
	} {
		if got := SameArgs(tc.custom, tc.original); got != tc.ok {
			t.Errorf("SameArgs(%q, %q) = %v", tc.custom, tc.original, got)
		}
	}
	if got := Placeholders("Hi %s, {b} {a} {a}"); !slices.Equal(got, []string{"%s", "{a}", "{b}"}) {
		t.Errorf("Placeholders: %v", got)
	}
}

func TestDate(t *testing.T) {
	at := time.Date(2026, time.September, 27, 23, 30, 0, 0, time.FixedZone("-05", -5*3600)) // 28 Sep UTC
	if got := Date("en", at); got != "September 28, 2026" {
		t.Errorf("en: %q", got)
	}
	if got := Date("es", at); got != "28 de septiembre de 2026" {
		t.Errorf("es: %q", got)
	}
}
