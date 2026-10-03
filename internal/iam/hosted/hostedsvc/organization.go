package hostedsvc

import (
	"context"
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func (s *Service) OrganizationSettings(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (hosted.OrganizationSettings, error) {
	if environment.IsZero() || organization.IsZero() {
		return hosted.OrganizationSettings{}, errx.Validation("environment_id and organization_id are required")
	}
	out, err := s.repository.OrganizationSettings(ctx, environment, organization)
	if notFound(err) {
		if err = s.repository.Owner(ctx, environment, hosted.TextScope{Organization: organization}); err != nil {
			return hosted.OrganizationSettings{}, err
		}
		return hosted.OrganizationSettings{Environment: environment, Organization: organization}, nil
	}
	return out, err
}

func (s *Service) SaveOrganizationSettings(ctx context.Context, m hosted.Mutation, organization identity.OrganizationID, input hosted.OrganizationSettings) (hosted.OrganizationSettings, error) {
	if organization.IsZero() {
		return hosted.OrganizationSettings{}, errx.Validation("organization_id is required")
	}
	if err := input.Validate(); err != nil {
		return hosted.OrganizationSettings{}, err
	}
	if err := s.environmentLanguage(ctx, m.Environment, input.Locale); err != nil {
		return hosted.OrganizationSettings{}, err
	}
	input.Environment, input.Organization = m.Environment, organization
	return s.repository.SaveOrganizationSettings(ctx, m, organization, input)
}

func (s *Service) DeleteOrganizationSettings(ctx context.Context, m hosted.Mutation, organization identity.OrganizationID) error {
	if organization.IsZero() {
		return errx.Validation("organization_id is required")
	}
	return s.repository.DeleteOrganizationSettings(ctx, m, organization)
}

// Branded lays the organization's overrides over the client style (or the
// environment default), its language included; the enabled languages stay
// the environment's — without a list, every language, or only the stable
// ones while the beta_languages feature is off.
func (s *Service) Branded(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, organization identity.OrganizationID) (hosted.Settings, error) {
	out, err := s.branded(ctx, environment, client, organization)
	if err != nil || len(out.Languages) > 0 || s.features == nil {
		return out, err
	}
	beta, err := s.features.Enabled(ctx, environment, config.FeatureBetaLanguages)
	if err != nil {
		return hosted.Settings{}, err
	}
	if !beta {
		out.Languages = i18n.Stable()
		// An explicitly chosen default language stays offered.
		if out.Locale != nil && !slices.Contains(out.Languages, *out.Locale) {
			out.Languages = append(out.Languages, *out.Locale)
		}
	}
	return out, nil
}

func (s *Service) branded(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, organization identity.OrganizationID) (hosted.Settings, error) {
	if environment.IsZero() {
		return hosted.Settings{}, errx.Validation("environment_id is required")
	}
	out, err := s.style(ctx, environment, client)
	if err != nil || organization.IsZero() {
		return out, err
	}
	overrides, err := s.repository.OrganizationSettings(ctx, environment, organization)
	if notFound(err) {
		return out, nil
	}
	if err != nil {
		return hosted.Settings{}, err
	}
	out = overrides.Apply(out)
	return out, filled(&out)
}

func (s *Service) DraftOrganization(ctx context.Context, environment identity.EnvironmentID, input hosted.OrganizationSettings) (hosted.Settings, error) {
	if err := input.Validate(); err != nil {
		return hosted.Settings{}, err
	}
	out, err := s.Settings(ctx, environment)
	if err != nil {
		return hosted.Settings{}, err
	}
	out = input.Apply(out)
	return out, filled(&out)
}

// brandOrganization is the organization a hosted page brands for: the
// authorization's hint, else the organization the parked login chose, else
// the one that verified the typed email's domain.
func (s *Service) brandOrganization(ctx context.Context, r hosted.Request, environment identity.EnvironmentID, hint identity.OrganizationID, email string) (identity.OrganizationID, error) {
	if !hint.IsZero() {
		return hint, nil
	}
	if login, err := s.repository.Login(ctx, s.secrets.Hash(r.Ticket), environment); err == nil && !login.Chosen.IsZero() {
		return login.Chosen, nil
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return identity.OrganizationID{}, nil
	}
	return s.repository.DomainOrganization(ctx, environment, strings.ToLower(strings.TrimSpace(email[at+1:])))
}

func notFound(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeNotFound
}
