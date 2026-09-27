package i18n

import (
	"regexp"
	"slices"
	"testing"
	"time"
)

var verb = regexp.MustCompile(`%(\[\d+\])?[a-zA-Z%]`)

// placeholder is an email wording placeholder ({{code}}); translations must
// keep the same set.
var placeholder = regexp.MustCompile(`\{\{[a-z_]+\}\}`)

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// Every catalog has exactly the English keys, and each message uses the same
// format verbs: in the same order, or, when all verbs are indexed
// (%[2]s), the same set in any order.
func TestCatalogParity(t *testing.T) {
	english := catalogs[Default]
	for code, messages := range catalogs {
		if messages["_name"] == "" {
			t.Errorf("%s: missing _name", code)
		}
		for key := range english {
			if _, ok := messages[key]; !ok {
				t.Errorf("%s: missing key %q", code, key)
			}
		}
		for key, message := range messages {
			want, ok := english[key]
			if !ok {
				t.Errorf("%s: key %q is not in %s", code, key, Default)
				continue
			}
			if got, exp := verb.FindAllString(message, -1), verb.FindAllString(want, -1); !sameVerbs(got, exp) {
				t.Errorf("%s: %q verbs %v, want %v", code, key, got, exp)
			}
			if got, exp := sorted(placeholder.FindAllString(message, -1)), sorted(placeholder.FindAllString(want, -1)); !slices.Equal(got, exp) {
				t.Errorf("%s: %q placeholders %v, want %v", code, key, got, exp)
			}
		}
	}
}

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
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func TestLocales(t *testing.T) {
	got := Locales()
	if len(got) < 2 || got[0] != (Locale{"en", "English"}) || got[1] != (Locale{"es", "Español"}) {
		t.Fatalf("Locales() = %v", got)
	}
	if !Supported("es") || Supported("ES") || Supported("xx") || Supported("") {
		t.Fatal("Supported must match catalog codes exactly")
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
		{[]string{"fr-CA fr es"}, "es"},
		{[]string{"fr, es-419;q=0.8"}, "es"},
		{[]string{"xx", "", "es"}, "es"},
		{[]string{"en-GB", "es"}, "en"},
		{[]string{"zz"}, "en"},
	} {
		if got := Resolve(tc.in...); got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.in, got, tc.want)
		}
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

func TestDate(t *testing.T) {
	at := time.Date(2026, time.September, 27, 23, 30, 0, 0, time.FixedZone("-05", -5*3600)) // 28 Sep UTC
	if got := Date("en", at); got != "September 28, 2026" {
		t.Errorf("en: %q", got)
	}
	if got := Date("es", at); got != "28 de septiembre de 2026" {
		t.Errorf("es: %q", got)
	}
}
