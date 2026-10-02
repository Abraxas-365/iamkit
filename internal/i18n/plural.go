package i18n

import "strings"

// plural is a CLDR cardinal rule for integers: the categories a language
// uses (always ending in "other") and the category of n.
type plural struct {
	categories []string
	of         func(n int) string
}

var (
	otherOnly = plural{[]string{"other"}, func(int) string { return "other" }}
	oneOther  = plural{[]string{"one", "other"}, func(n int) string {
		if n == 1 {
			return "one"
		}
		return "other"
	}}
	zeroOneOther = plural{[]string{"one", "other"}, func(n int) string {
		if n == 0 || n == 1 {
			return "one"
		}
		return "other"
	}}
	// slavic is Russian and Ukrainian: 1, 21 → one; 2-4, 22-24 → few;
	// 0, 5-20, 25-30 → many.
	slavic = plural{[]string{"one", "few", "many", "other"}, func(n int) string {
		switch {
		case n%10 == 1 && n%100 != 11:
			return "one"
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return "few"
		default:
			return "many"
		}
	}}
	polish = plural{[]string{"one", "few", "many", "other"}, func(n int) string {
		switch {
		case n == 1:
			return "one"
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return "few"
		default:
			return "many"
		}
	}}
	czech = plural{[]string{"one", "few", "other"}, func(n int) string {
		switch {
		case n == 1:
			return "one"
		case n >= 2 && n <= 4:
			return "few"
		default:
			return "other"
		}
	}}
	romanian = plural{[]string{"one", "few", "other"}, func(n int) string {
		switch {
		case n == 1:
			return "one"
		case n == 0 || (n%100 >= 2 && n%100 <= 19):
			return "few"
		default:
			return "other"
		}
	}}
	arabic = plural{[]string{"zero", "one", "two", "few", "many", "other"}, func(n int) string {
		switch {
		case n == 0:
			return "zero"
		case n == 1:
			return "one"
		case n == 2:
			return "two"
		case n%100 >= 3 && n%100 <= 10:
			return "few"
		case n%100 >= 11:
			return "many"
		default:
			return "other"
		}
	}}
)

// plurals maps a catalog code, else its primary language, to its rule.
// Languages not listed use one/other (n == 1).
var plurals = map[string]plural{
	"ja": otherOnly, "zh": otherOnly, "ko": otherOnly, "id": otherOnly,
	"fr": zeroOneOther, "pt-BR": zeroOneOther,
	"ru": slavic, "uk": slavic,
	"pl": polish, "cs": czech, "ro": romanian, "ar": arabic,
}

func rule(locale string) plural {
	if r, ok := plurals[locale]; ok {
		return r
	}
	primary, _, _ := strings.Cut(locale, "-")
	if r, ok := plurals[primary]; ok {
		return r
	}
	return oneOther
}

// Plural is the CLDR cardinal category of the integer n in locale (zero,
// one, two, few, many or other). Negative numbers use their magnitude.
func Plural(locale string, n int) string {
	if n < 0 {
		n = -n
	}
	return rule(locale).of(n)
}

// Categories lists the plural categories locale uses (a plural message
// family needs a key for each).
func Categories(locale string) []string {
	return rule(locale).categories
}
