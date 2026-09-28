package authsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// memTemplates is an in-memory TemplateRepository that records audits.
type memTemplates struct {
	saved   map[authentication.TemplateKey]authentication.EmailTemplate
	audited []authentication.Mutation
}

func (r *memTemplates) ListTemplates(context.Context, identity.EnvironmentID) ([]authentication.EmailTemplate, error) {
	var out []authentication.EmailTemplate
	for _, t := range r.saved {
		out = append(out, t)
	}
	return out, nil
}
func (r *memTemplates) GetTemplate(_ context.Context, _ identity.EnvironmentID, key authentication.TemplateKey) (authentication.EmailTemplate, error) {
	t, ok := r.saved[key]
	if !ok {
		return t, errx.NotFound("email template not customized")
	}
	return t, nil
}
func (r *memTemplates) SetTemplate(_ context.Context, m authentication.Mutation, key authentication.TemplateKey, input authentication.Copy) error {
	if r.saved == nil {
		r.saved = map[authentication.TemplateKey]authentication.EmailTemplate{}
	}
	r.saved[key] = authentication.EmailTemplate{Purpose: key.Purpose, Locale: key.Locale, Copy: input, UpdatedAt: time.Unix(1700000000, 0)}
	r.audited = append(r.audited, m)
	return nil
}
func (r *memTemplates) DeleteTemplate(_ context.Context, m authentication.Mutation, key authentication.TemplateKey) error {
	delete(r.saved, key)
	r.audited = append(r.audited, m)
	return nil
}

func templateService() (*DeliveryService, *memTemplates) {
	repo := &memTemplates{}
	s := NewDeliveryService(&memDelivery{}, nil, nil, nil, "")
	s.SetTemplates(repo)
	return s, repo
}

func TestSetTemplate(t *testing.T) {
	ctx, m := context.Background(), deliveryMutation()
	s, repo := templateService()
	key := authentication.TemplateKey{Purpose: "login", Locale: "es"}

	if err := s.SetTemplate(ctx, m, key, authentication.Copy{Subject: "  Tu código {{code}} ", Body: "Hola\r\n\r\n{{email}}"}); err != nil {
		t.Fatal(err)
	}
	got := repo.saved[key].Copy
	if got.Subject != "Tu código {{code}}" || got.Body != "Hola\n\n{{email}}" {
		t.Fatalf("not normalized: %+v", got)
	}
	if a := repo.audited[0]; a.Action != ActionTemplateUpdate || !strings.HasSuffix(a.Target, "/delivery/templates/login/es") || a.Actor != "op" {
		t.Fatalf("audit %+v", a)
	}

	// All-empty wording resets.
	if err := s.SetTemplate(ctx, m, key, authentication.Copy{Subject: "  "}); err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.saved[key]; ok || repo.audited[1].Action != ActionTemplateReset {
		t.Fatalf("empty wording kept: %+v", repo.audited)
	}

	for _, tc := range []struct {
		key   authentication.TemplateKey
		input authentication.Copy
		want  string
	}{
		{authentication.TemplateKey{Purpose: "welcome", Locale: "es"}, authentication.Copy{Subject: "x"}, "purpose"},
		{authentication.TemplateKey{Purpose: "login", Locale: "es-MX"}, authentication.Copy{Subject: "x"}, "locale"},
		{authentication.TemplateKey{Purpose: "login", Locale: "fr"}, authentication.Copy{Subject: "x"}, "locale"},
		{key, authentication.Copy{Subject: "{{link}}"}, "unknown placeholder {{link}}"},
		{key, authentication.Copy{Action: "Go"}, "action"},
		{key, authentication.Copy{Body: strings.Repeat("é", 2001)}, "body must be at most 2000"},
	} {
		err := s.SetTemplate(ctx, m, tc.key, tc.input)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%+v %+v: got %v, want %q", tc.key, tc.input, err, tc.want)
		}
	}
	if len(repo.audited) != 2 {
		t.Fatalf("rejected input was stored: %d audits", len(repo.audited))
	}
	if err := s.SetTemplate(ctx, authentication.Mutation{}, key, authentication.Copy{Subject: "x"}); err == nil {
		t.Fatal("accepted a zero environment")
	}
}

func TestResetTemplateIdempotent(t *testing.T) {
	ctx, m := context.Background(), deliveryMutation()
	s, repo := templateService()
	key := authentication.TemplateKey{Purpose: "invitation", Locale: "en"}
	for range 2 {
		if err := s.ResetTemplate(ctx, m, key); err != nil {
			t.Fatal(err)
		}
	}
	if len(repo.audited) != 2 || repo.audited[0].Action != ActionTemplateReset {
		t.Fatalf("audits %+v", repo.audited)
	}
	if err := s.ResetTemplate(ctx, m, authentication.TemplateKey{Purpose: "invitation", Locale: "xx"}); err == nil {
		t.Fatal("reset an unknown locale")
	}
}

func TestListAndGetTemplates(t *testing.T) {
	ctx, m := context.Background(), deliveryMutation()
	s, _ := templateService()
	key := authentication.TemplateKey{Purpose: "invitation", Locale: "es"}
	if err := s.SetTemplate(ctx, m, key, authentication.Copy{Action: "Únete a {{organization}}"}); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListTemplates(ctx, m.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(authentication.PreviewPurposes)*2 {
		t.Fatalf("want every purpose × language, got %d", len(list))
	}
	if list[0].Purpose != authentication.PreviewPurposes[0] || list[0].Locale != "en" {
		t.Fatalf("order %+v", list[0])
	}
	customized := 0
	for _, item := range list {
		if item.Customized {
			customized++
			if item.Purpose != "invitation" || item.Locale != "es" || item.UpdatedAt == nil {
				t.Fatalf("customized %+v", item)
			}
		}
	}
	if customized != 1 {
		t.Fatalf("customized %d", customized)
	}

	view, err := s.Template(ctx, m.Environment, key)
	if err != nil || !view.Customized || view.Template.Action != "Únete a {{organization}}" || view.Defaults.Subject == "" || view.Defaults.Action == "" ||
		len(view.Placeholders) == 0 || view.UpdatedAt == nil {
		t.Fatalf("view %+v, %v", view, err)
	}
	view, err = s.Template(ctx, m.Environment, authentication.TemplateKey{Purpose: "login", Locale: "en"})
	if err != nil || view.Customized || view.Template != (authentication.Copy{}) || view.Defaults.Subject == "" || view.Defaults.Action != "" {
		t.Fatalf("default view %+v, %v", view, err)
	}
}

// The renderer reads saved wording; missing wording is not an error.
func TestSavedCopy(t *testing.T) {
	ctx, m := context.Background(), deliveryMutation()
	s, repo := templateService()
	if _, ok, err := s.Copy(ctx, m.Environment, "login", "en"); ok || err != nil {
		t.Fatalf("none: %v %v", ok, err)
	}
	_ = s.SetTemplate(ctx, m, authentication.TemplateKey{Purpose: "login", Locale: "en"}, authentication.Copy{Subject: "Code {{code}}"})
	if c, ok, err := (SavedCopy{repo}).Copy(ctx, m.Environment, "login", "en"); !ok || err != nil || c.Subject != "Code {{code}}" {
		t.Fatalf("saved: %+v %v %v", c, ok, err)
	}

	bare := NewDeliveryService(&memDelivery{}, nil, nil, nil, "")
	if _, ok, err := bare.Copy(ctx, m.Environment, "login", "en"); ok || err != nil {
		t.Fatalf("without storage: %v %v", ok, err)
	}
	if _, err := bare.ListTemplates(ctx, m.Environment); err == nil {
		t.Fatal("listed without storage")
	}
}
