package authorization

import (
	"strings"
	"testing"
)

func TestDescribeResolutionOrder(t *testing.T) {
	set := []PermissionDescription{
		{Permission: "docs:read", Locale: "", DisplayName: "Read documents", Description: "See your documents."},
		{Permission: "docs:read", Locale: "es", DisplayName: "Leer documentos", Description: "Ver tus documentos."},
		{Permission: "docs:read", Locale: "es-PE", DisplayName: "Leer documentos (PE)"},
		{Permission: "docs:write", Locale: "es", DisplayName: "Escribir documentos"},
		{Permission: "other:read", Locale: "", DisplayName: "Other"},
	}
	cases := []struct {
		name    string
		perm    string
		locales []string
		want    DescribedPermission
	}{
		{"exact locale; missing sentence falls to the base language", "docs:read", []string{"es-PE"}, DescribedPermission{Name: "docs:read", DisplayName: "Leer documentos (PE)", Description: "Ver tus documentos.", Described: true}},
		{"base language", "docs:read", []string{"es-MX"}, DescribedPermission{Name: "docs:read", DisplayName: "Leer documentos", Description: "Ver tus documentos.", Described: true}},
		{"case and underscore", "docs:read", []string{"ES_mx"}, DescribedPermission{Name: "docs:read", DisplayName: "Leer documentos", Description: "Ver tus documentos.", Described: true}},
		{"default text", "docs:read", []string{"fr"}, DescribedPermission{Name: "docs:read", DisplayName: "Read documents", Description: "See your documents.", Described: true}},
		{"no preference", "docs:read", nil, DescribedPermission{Name: "docs:read", DisplayName: "Read documents", Description: "See your documents.", Described: true}},
		{"accept-language list", "docs:read", []string{"fr-CA, es;q=0.8"}, DescribedPermission{Name: "docs:read", DisplayName: "Leer documentos", Description: "Ver tus documentos.", Described: true}},
		{"translation only, no default: raw sentence empty", "docs:write", []string{"es"}, DescribedPermission{Name: "docs:write", DisplayName: "Escribir documentos", Described: true}},
		{"translation not matching and no default: raw name", "docs:write", []string{"en"}, DescribedPermission{Name: "docs:write", DisplayName: "docs:write"}},
		{"undescribed: raw name", "none:read", []string{"es"}, DescribedPermission{Name: "none:read", DisplayName: "none:read"}},
	}
	for _, c := range cases {
		if got := Describe(set, c.perm, c.locales...); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestDescribeAllKeepsOrder(t *testing.T) {
	got := DescribeAll(nil, []string{"b", "a"}, "es")
	if len(got) != 2 || got[0].Name != "b" || got[1].DisplayName != "a" || got[0].Described {
		t.Fatalf("got %+v", got)
	}
}

func TestValidateDescriptions(t *testing.T) {
	catalog := []string{"docs:read", "docs:write"}
	ok := func(in ...PermissionDescription) []PermissionDescription {
		t.Helper()
		out, err := ValidateDescriptions(catalog, in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return out
	}
	bad := func(name string, in ...PermissionDescription) {
		t.Helper()
		if _, err := ValidateDescriptions(catalog, in); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	out := ok(
		PermissionDescription{Permission: "docs:write", Locale: "PT_br", DisplayName: " Escribir "},
		PermissionDescription{Permission: "docs:read", DisplayName: "Read", Description: "x"},
	)
	if out[0].Permission != "docs:read" || out[1].Locale != "pt-BR" || out[1].DisplayName != "Escribir" {
		t.Errorf("not cleaned and ordered: %+v", out)
	}
	if len(ok()) != 0 {
		t.Error("an empty set clears")
	}
	ok(PermissionDescription{Permission: "docs:read", DisplayName: strings.Repeat("é", MaxDisplayName), Description: strings.Repeat("é", MaxDescription)})

	bad("not in catalog", PermissionDescription{Permission: "nope", DisplayName: "x"})
	bad("display name too long", PermissionDescription{Permission: "docs:read", DisplayName: strings.Repeat("a", MaxDisplayName+1)})
	bad("description too long", PermissionDescription{Permission: "docs:read", Description: strings.Repeat("a", MaxDescription+1)})
	bad("newline", PermissionDescription{Permission: "docs:read", DisplayName: "a\nb"})
	bad("control char", PermissionDescription{Permission: "docs:read", Description: "a\x00b"})
	bad("invalid utf8", PermissionDescription{Permission: "docs:read", DisplayName: "a\xffb"})
	bad("unknown locale", PermissionDescription{Permission: "docs:read", Locale: "xx", DisplayName: "x"})
	bad("empty texts", PermissionDescription{Permission: "docs:read"})
	bad("no permission", PermissionDescription{DisplayName: "x"})
	bad("duplicate", PermissionDescription{Permission: "docs:read", DisplayName: "a"}, PermissionDescription{Permission: "docs:read", DisplayName: "b"})
	// The same permission in another locale is fine.
	ok(PermissionDescription{Permission: "docs:read", DisplayName: "a"}, PermissionDescription{Permission: "docs:read", Locale: "es", DisplayName: "b"})

	many := make([]PermissionDescription, MaxDescriptions(len(catalog))+1)
	bad("more than catalog × (1 + languages)", many...)
}
