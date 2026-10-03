package hostedsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

var (
	_ hosted.TextCommands = (*Service)(nil)
	_ hosted.TextQueries  = (*Service)(nil)
)

// textScope checks a scope names at most one of client and organization.
func textScope(environment identity.EnvironmentID, scope hosted.TextScope) error {
	if environment.IsZero() {
		return errx.Validation("environment_id is required")
	}
	if !scope.Client.IsZero() && !scope.Organization.IsZero() {
		return errx.Validation("texts apply to a client or an organization, not both")
	}
	return nil
}

// textLocale is the catalog code of locale.
func textLocale(locale string) (string, error) {
	out, err := hosted.Language(locale, "locale")
	if err == nil && out == "" {
		err = errx.Validation("locale is required")
	}
	return out, err
}

func (s *Service) Texts(ctx context.Context, environment identity.EnvironmentID, scope hosted.TextScope, locale string) (hosted.Texts, error) {
	if err := textScope(environment, scope); err != nil {
		return hosted.Texts{}, err
	}
	locale, err := textLocale(locale)
	if err != nil {
		return hosted.Texts{}, err
	}
	out, err := s.repository.Texts(ctx, environment, scope, locale)
	if notFound(err) {
		if err = s.repository.Owner(ctx, environment, scope); err != nil {
			return hosted.Texts{}, err
		}
		out = hosted.Texts{Environment: environment, Locale: locale}
		if !scope.Client.IsZero() {
			out.Client = &scope.Client
		}
		if !scope.Organization.IsZero() {
			out.Organization = &scope.Organization
		}
		err = nil
	}
	if out.Messages == nil {
		out.Messages = map[string]string{}
	}
	return out, err
}

func (s *Service) ListTexts(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[hosted.Texts], error) {
	if environment.IsZero() {
		return query.Paginated[hosted.Texts]{}, errx.Validation("environment_id is required")
	}
	return s.repository.ListTexts(ctx, environment, page)
}

// Wording lays the client's and the organization's texts over the
// environment's. A failed read leaves the page in the catalog's words
// rather than failing a sign-in.
func (s *Service) Wording(ctx context.Context, environment identity.EnvironmentID, scope hosted.TextScope, locale string) (i18n.Texts, error) {
	if environment.IsZero() || !i18n.Supported(locale) {
		return nil, nil
	}
	sets, err := s.repository.ScopeTexts(ctx, environment, scope, locale)
	if err != nil {
		return nil, err
	}
	rank := func(t hosted.Texts) int {
		switch t.Scope() {
		case hosted.ScopeOrganization:
			return 2
		case hosted.ScopeClient:
			return 1
		}
		return 0
	}
	ordered := make([]hosted.Texts, 3)
	for _, set := range sets {
		ordered[rank(set)] = set
	}
	out := hosted.LayTexts(locale, ordered...)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s *Service) DraftWording(ctx context.Context, environment identity.EnvironmentID, input hosted.Texts) (i18n.Texts, error) {
	input.Environment = environment
	if err := textScope(environment, input.Target()); err != nil {
		return nil, err
	}
	if err := input.Validate(); err != nil {
		return nil, err
	}
	if input.Scope() == hosted.ScopeEnvironment {
		return hosted.LayTexts(input.Locale, input), nil
	}
	// A client's or organization's draft lies over the saved environment
	// texts (the zero scope reads only those).
	sets, err := s.repository.ScopeTexts(ctx, environment, hosted.TextScope{}, input.Locale)
	if err != nil {
		return nil, err
	}
	return hosted.LayTexts(input.Locale, append(sets, input)...), nil
}

func (s *Service) SaveTexts(ctx context.Context, m hosted.Mutation, input hosted.Texts) (hosted.Texts, error) {
	input.Environment = m.Environment
	if err := textScope(m.Environment, input.Target()); err != nil {
		return hosted.Texts{}, err
	}
	if err := input.Validate(); err != nil {
		return hosted.Texts{}, err
	}
	if len(input.Messages) == 0 {
		return hosted.Texts{}, errx.Validation("texts must customize at least one text (delete them to inherit every text)")
	}
	return s.repository.SaveTexts(ctx, m, input)
}

func (s *Service) DeleteTexts(ctx context.Context, m hosted.Mutation, scope hosted.TextScope, locale string) error {
	if err := textScope(m.Environment, scope); err != nil {
		return err
	}
	locale, err := textLocale(locale)
	if err != nil {
		return err
	}
	return s.repository.DeleteTexts(ctx, m, scope, locale)
}
