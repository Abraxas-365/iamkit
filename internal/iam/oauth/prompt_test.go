package oauth

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParseInteraction(t *testing.T) {
	zero, five := int64(0), int64(300)
	for _, tc := range []struct {
		name  string
		query string
		want  Interaction
		ok    bool
	}{
		{"none given", "", Interaction{}, true},
		{"login", "prompt=login", Interaction{Login: true}, true},
		{"consent", "prompt=consent", Interaction{Consent: true}, true},
		{"several", "prompt=login+consent+select_account", Interaction{Login: true, Consent: true, SelectAccount: true}, true},
		{"none", "prompt=none", Interaction{None: true}, true},
		{"none with login", "prompt=none+login", Interaction{}, false},
		{"none with consent", "prompt=consent+none", Interaction{}, false},
		{"unknown", "prompt=create", Interaction{}, false},
		{"case sensitive", "prompt=Login", Interaction{}, false},
		{"max_age", "max_age=300", Interaction{MaxAge: &five}, true},
		{"max_age zero", "max_age=0", Interaction{MaxAge: &zero}, true},
		{"max_age negative", "max_age=-1", Interaction{}, false},
		{"max_age text", "max_age=abc", Interaction{}, false},
		{"max_age fraction", "max_age=1.5", Interaction{}, false},
		{"max_age signed", "max_age=%2B5", Interaction{}, false},
		{"max_age empty value", "max_age=", Interaction{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form, _ := url.ParseQuery(tc.query)
			got, err := ParseInteraction(form)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestReauthenticate(t *testing.T) {
	for query, want := range map[string]bool{
		"": false, "prompt=login": true, "prompt=consent": false, "max_age=0": true, "max_age=60": false, "prompt=select_account": false,
	} {
		form, _ := url.ParseQuery(query)
		got, _ := ParseInteraction(form)
		if got.Reauthenticate() != want {
			t.Fatalf("%q: Reauthenticate = %v, want %v", query, got.Reauthenticate(), want)
		}
	}
	if FormInteraction("prompt=login%zz").Reauthenticate() {
		t.Fatal("an unreadable stored form asks for nothing")
	}
}

func TestDiscoveryPromptValues(t *testing.T) {
	if got := NewDiscovery("https://iam.example").PromptValuesSupported; !reflect.DeepEqual(got, []string{"none", "login", "consent", "select_account"}) {
		t.Fatalf("prompt_values_supported = %v", got)
	}
}
