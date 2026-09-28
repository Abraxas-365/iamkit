package authsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Audited template actions; the target is the template's path.
const (
	ActionTemplateUpdate = "email_template.updated"
	ActionTemplateReset  = "email_template.reset"
)

var (
	_ authentication.TemplateCommands = (*DeliveryService)(nil)
	_ authentication.TemplateQueries  = (*DeliveryService)(nil)
	_ authentication.Templates        = (*DeliveryService)(nil)
)

// SetTemplates sets where email wording is stored; without it every email
// keeps IAMKit's wording and template changes fail.
func (s *DeliveryService) SetTemplates(repo authentication.TemplateRepository) { s.templates = repo }

func (s *DeliveryService) templateRepo() (authentication.TemplateRepository, error) {
	if s.templates == nil {
		return nil, errx.Internal("email templates are not available")
	}
	return s.templates, nil
}

func templateTarget(environment identity.EnvironmentID, key authentication.TemplateKey) string {
	return "/environments/" + environment.String() + "/delivery/templates/" + key.Purpose + "/" + key.Locale
}

func (s *DeliveryService) SetTemplate(ctx context.Context, m authentication.Mutation, key authentication.TemplateKey, input authentication.Copy) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	if err := key.Validate(); err != nil {
		return err
	}
	input = input.Normalize()
	if input.Empty() {
		return s.ResetTemplate(ctx, m, key)
	}
	if err := input.Validate(key.Purpose); err != nil {
		return err
	}
	repo, err := s.templateRepo()
	if err != nil {
		return err
	}
	m.Action, m.Target = ActionTemplateUpdate, templateTarget(m.Environment, key)
	return repo.SetTemplate(ctx, m, key, input)
}

func (s *DeliveryService) ResetTemplate(ctx context.Context, m authentication.Mutation, key authentication.TemplateKey) error {
	if m.Environment.IsZero() {
		return errx.Validation("environment_id must be a valid UUID")
	}
	if err := key.Validate(); err != nil {
		return err
	}
	repo, err := s.templateRepo()
	if err != nil {
		return err
	}
	m.Action, m.Target = ActionTemplateReset, templateTarget(m.Environment, key)
	return repo.DeleteTemplate(ctx, m, key)
}

// ListTemplates lists every purpose in every language, in PreviewPurposes
// then language order.
func (s *DeliveryService) ListTemplates(ctx context.Context, environment identity.EnvironmentID) ([]authentication.TemplateSummary, error) {
	if environment.IsZero() {
		return nil, errx.Validation("environment_id must be a valid UUID")
	}
	repo, err := s.templateRepo()
	if err != nil {
		return nil, err
	}
	saved, err := repo.ListTemplates(ctx, environment)
	if err != nil {
		return nil, err
	}
	updated := map[authentication.TemplateKey]time.Time{}
	for _, t := range saved {
		updated[authentication.TemplateKey{Purpose: t.Purpose, Locale: t.Locale}] = t.UpdatedAt
	}
	var out []authentication.TemplateSummary
	for _, purpose := range authentication.PreviewPurposes {
		for _, l := range i18n.Locales() {
			summary := authentication.TemplateSummary{Purpose: purpose, Locale: l.Code}
			if at, ok := updated[authentication.TemplateKey{Purpose: purpose, Locale: l.Code}]; ok {
				summary.Customized, summary.UpdatedAt = true, &at
			}
			out = append(out, summary)
		}
	}
	return out, nil
}

func (s *DeliveryService) Template(ctx context.Context, environment identity.EnvironmentID, key authentication.TemplateKey) (authentication.TemplateView, error) {
	if environment.IsZero() {
		return authentication.TemplateView{}, errx.Validation("environment_id must be a valid UUID")
	}
	if err := key.Validate(); err != nil {
		return authentication.TemplateView{}, err
	}
	repo, err := s.templateRepo()
	if err != nil {
		return authentication.TemplateView{}, err
	}
	out := authentication.TemplateView{
		TemplateSummary: authentication.TemplateSummary{Purpose: key.Purpose, Locale: key.Locale},
		Defaults:        authentication.DefaultCopy(key.Purpose, key.Locale),
		Placeholders:    authentication.Placeholders(key.Purpose),
	}
	saved, err := repo.GetTemplate(ctx, environment, key)
	switch {
	case err == nil:
		out.Customized, out.UpdatedAt, out.Template = true, &saved.UpdatedAt, saved.Copy
	case !notFound(err):
		return authentication.TemplateView{}, err
	}
	return out, nil
}

// Copy is the saved wording the renderer lays over IAMKit's defaults.
func (s *DeliveryService) Copy(ctx context.Context, environment identity.EnvironmentID, purpose, locale string) (authentication.Copy, bool, error) {
	if s.templates == nil {
		return authentication.Copy{}, false, nil
	}
	return SavedCopy{s.templates}.Copy(ctx, environment, purpose, locale)
}

// SavedCopy reads the renderer's wording straight from storage.
type SavedCopy struct {
	Repo authentication.TemplateRepository
}

var _ authentication.Templates = SavedCopy{}

func (t SavedCopy) Copy(ctx context.Context, environment identity.EnvironmentID, purpose, locale string) (authentication.Copy, bool, error) {
	saved, err := t.Repo.GetTemplate(ctx, environment, authentication.TemplateKey{Purpose: purpose, Locale: locale})
	switch {
	case err == nil:
		return saved.Copy, true, nil
	case notFound(err):
		return authentication.Copy{}, false, nil
	}
	return authentication.Copy{}, false, err
}
