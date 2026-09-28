package authentication

import (
	"regexp"
	"slices"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/i18n"
)

// Every default wording exists in every language and uses only the
// placeholders its purpose offers, so defaults never render "{{x}}".
func TestDefaultCopyPlaceholders(t *testing.T) {
	used := regexp.MustCompile(`\{\{([a-z_]+)\}\}`)
	for _, locale := range i18n.Locales() {
		for _, purpose := range PreviewPurposes {
			c := DefaultCopy(purpose, locale.Code)
			if c.Subject == "" || c.Heading == "" || c.Body == "" || c.Footer == "" {
				t.Errorf("%s/%s: incomplete default %+v", purpose, locale.Code, c)
			}
			if (c.Action != "") != HasAction(purpose) {
				t.Errorf("%s/%s: action %q", purpose, locale.Code, c.Action)
			}
			for _, field := range []string{c.Subject, c.Heading, c.Body, c.Action, c.Footer} {
				for _, m := range used.FindAllStringSubmatch(field, -1) {
					if !slices.Contains(Placeholders(purpose), m[1]) {
						t.Errorf("%s/%s: placeholder {{%s}} not offered", purpose, locale.Code, m[1])
					}
				}
			}
		}
	}
	if DefaultCopy(PurposeLogin, "xx") != DefaultCopy(PurposeLogin, "en") {
		t.Error("unknown locale must fall back to English")
	}
}

func TestCopyOverlay(t *testing.T) {
	base := Copy{Subject: "s", Heading: "h", Body: "b", Action: "a", Footer: "f"}
	got := base.Overlay(Copy{Subject: "S", Body: "  ", Footer: "F"})
	if got != (Copy{Subject: "S", Heading: "h", Body: "b", Action: "a", Footer: "F"}) {
		t.Fatalf("got %+v", got)
	}
	if base.Overlay(Copy{}) != base {
		t.Fatal("empty override must keep every default")
	}
}

func TestFill(t *testing.T) {
	values := map[string]string{"code": "123", "app_name": "{{code}}"}
	for in, want := range map[string]string{
		"Code {{code}}":         "Code 123",
		"Code {{ code }}":       "Code 123",
		"{{app_name}}":          "{{code}}", // values are never filled again
		"{{unknown}} {{code}}":  "{{unknown}} 123",
		"no placeholders":       "no placeholders",
		"{{code}}{{code}}":      "123123",
		"{code} {{code":         "{code} {{code",
		"<b>{{code}}</b>":       "<b>123</b>", // escaping is the renderer's job
		"{{CODE}} stays as is ": "{{CODE}} stays as is ",
	} {
		if got := Fill(in, values); got != want {
			t.Errorf("Fill(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCopyValidate(t *testing.T) {
	ok := []struct {
		purpose string
		c       Copy
	}{
		{PurposeLogin, Copy{}},
		{PurposeLogin, Copy{Subject: "Your {{ code }} for {{app_name}}", Body: "Hi {{email}},\n\nCode:\t{{code}}\r\n", Footer: "Bye"}},
		{PurposeInvitation, Copy{Action: "Join {{organization}}", Body: "{{inviter}} until {{expires_at}}"}},
	}
	for _, tc := range ok {
		if err := tc.c.Validate(tc.purpose); err != nil {
			t.Fatalf("%s %+v: %v", tc.purpose, tc.c, err)
		}
	}
	long := string(make([]rune, 201))
	bad := []struct {
		purpose string
		c       Copy
	}{
		{PurposeLogin, Copy{Subject: "a\nb"}},
		{PurposeLogin, Copy{Heading: "a\tb"}},
		{PurposeLogin, Copy{Body: "a\x00b"}},
		{PurposeLogin, Copy{Subject: long}},
		{PurposeLogin, Copy{Action: "Go"}},
		{PurposeLogin, Copy{Body: "{{organization}}"}},
		{PurposeTest, Copy{Subject: "{{code}}"}},
		{PurposeInvitation, Copy{Footer: "{{code}}"}},
	}
	for _, tc := range bad {
		if err := tc.c.Validate(tc.purpose); err == nil {
			t.Fatalf("%s %+v accepted", tc.purpose, tc.c)
		}
	}
}
