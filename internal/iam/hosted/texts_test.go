package hosted

import (
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestTextsValidate(t *testing.T) {
	ok := Texts{Locale: "ES", Messages: map[string]string{
		"hosted.title.sign_in":            "  Bienvenido  ",
		"hosted.form.continue":            "   ",
		"hosted.notice.code_sent":         "Código enviado a %s",
		"hosted.notice.attempts_left.one": "Último ({count})",
	}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Locale != "es" || ok.Messages["hosted.title.sign_in"] != "Bienvenido" || len(ok.Messages) != 3 {
		t.Fatalf("normalized %+v", ok)
	}

	client := identity.NewClientID()
	organization := identity.NewOrganizationID()
	for name, tc := range map[string]struct {
		texts Texts
		want  string
	}{
		"no locale":       {Texts{Messages: map[string]string{}}, "locale is required"},
		"unknown locale":  {Texts{Locale: "xx"}, "locale must be one of"},
		"both scopes":     {Texts{Locale: "en", Client: &client, Organization: &organization}, "not both"},
		"email key":       {Texts{Locale: "en", Messages: map[string]string{"email.login.subject": "x"}}, "not a customizable text"},
		"unknown key":     {Texts{Locale: "en", Messages: map[string]string{"hosted.nope": "x"}}, "not a customizable text"},
		"plural category": {Texts{Locale: "en", Messages: map[string]string{"hosted.notice.attempts_left.few": "x"}}, "not a customizable text"},
		"lost verb":       {Texts{Locale: "en", Messages: map[string]string{"hosted.notice.code_sent": "Code sent"}}, "must keep the placeholders %s"},
		"lost name":       {Texts{Locale: "en", Messages: map[string]string{"hosted.notice.attempts_left.other": "few left"}}, "{count}"},
		"stray percent":   {Texts{Locale: "en", Messages: map[string]string{"hosted.notice.code_sent": "100% sent to %s"}}, "placeholders"},
		"two lines":       {Texts{Locale: "en", Messages: map[string]string{"hosted.title.sign_in": "Sign\nin"}}, "plain text on one line"},
		"too long":        {Texts{Locale: "en", Messages: map[string]string{"hosted.title.sign_in": strings.Repeat("a", 81)}}, "at most 80"},
	} {
		err := tc.texts.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestLayTexts(t *testing.T) {
	client := identity.NewClientID()
	organization := identity.NewOrganizationID()
	out := LayTexts("en",
		Texts{Messages: map[string]string{"hosted.title.sign_in": "env", "hosted.form.continue": "env", "hosted.form.email": "env"}},
		Texts{Client: &client, Messages: map[string]string{"hosted.title.sign_in": "client", "hosted.form.continue": "client"}},
		Texts{Organization: &organization, Messages: map[string]string{"hosted.title.sign_in": "org", "hosted.gone": "x", "hosted.notice.code_sent": "stale"}},
	)
	want := map[string]string{"hosted.title.sign_in": "org", "hosted.form.continue": "client", "hosted.form.email": "env"}
	if len(out) != len(want) {
		t.Fatalf("got %v", out)
	}
	for k, v := range want {
		if out[k] != v {
			t.Fatalf("%s = %q, want %q", k, out[k], v)
		}
	}
}

func TestTextCatalog(t *testing.T) {
	items := TextCatalog("en")
	found := false
	for _, item := range items {
		if !strings.HasPrefix(item.Key, TextPrefix) || item.Default == "" || item.MaxLength < 80 {
			t.Fatalf("item %+v", item)
		}
		if item.Key == "hosted.notice.code_sent" {
			found = len(item.Placeholders) == 1 && item.Placeholders[0] == "%s"
		}
	}
	if !found {
		t.Fatal("code_sent placeholders")
	}
}
