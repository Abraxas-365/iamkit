package orgadminsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// API keys of the organization. The scope is the principal's organization:
// organization keys and members' user keys, never machine keys (another
// organization's key or a machine key is not found).

func keyScope(p orgadmin.Principal) apikey.Scope {
	return apikey.OrganizationScope(p.Environment, p.Organization)
}

func (s *Service) keyMutation(p orgadmin.Principal) apikey.Mutation {
	return apikey.Mutation{Scope: keyScope(p), Actor: p.Actor(), Granter: p.User}
}

// requireKeyAdmin admits principals with an account: a setup link has no
// user to answer for the key.
func requireKeyAdmin(p orgadmin.Principal, permission string) error {
	if p.Setup() || p.User.IsZero() {
		return errx.Forbidden("not available through a setup link")
	}
	return p.Require(permission)
}

func (s *Service) CreateAPIKey(ctx context.Context, p orgadmin.Principal, input apikey.NewAPIKey) (apikey.Issued, error) {
	if err := requireKeyAdmin(p, authorization.PermOrgAPIKeysWrite); err != nil {
		return apikey.Issued{}, err
	}
	input.Owner = apikey.Owner{Type: apikey.OwnerOrganization}
	if input.Organization.IsZero() {
		input.Organization = p.Organization
	}
	return s.d.APIKeys.Create(ctx, s.keyMutation(p), input)
}

func (s *Service) RevokeAPIKey(ctx context.Context, p orgadmin.Principal, key identity.APIKeyID) error {
	if err := requireKeyAdmin(p, authorization.PermOrgAPIKeysWrite); err != nil {
		return err
	}
	return s.d.APIKeys.Revoke(ctx, s.keyMutation(p), key)
}

func (s *Service) APIKeys(ctx context.Context, p orgadmin.Principal, filter apikey.Filter, page query.Pagination) (query.Paginated[apikey.APIKey], error) {
	if err := requireKeyAdmin(p, authorization.PermOrgAPIKeysRead); err != nil {
		return query.Paginated[apikey.APIKey]{}, err
	}
	return s.d.APIKeyViews.List(ctx, keyScope(p), filter, page)
}

func (s *Service) APIKey(ctx context.Context, p orgadmin.Principal, key identity.APIKeyID) (apikey.APIKey, error) {
	if err := requireKeyAdmin(p, authorization.PermOrgAPIKeysRead); err != nil {
		return apikey.APIKey{}, err
	}
	return s.d.APIKeyViews.Find(ctx, keyScope(p), key)
}

func (s *Service) APIKeyOptions(ctx context.Context, p orgadmin.Principal) (apikey.Options, error) {
	if err := requireKeyAdmin(p, authorization.PermOrgAPIKeysWrite); err != nil {
		return apikey.Options{}, err
	}
	return s.d.APIKeyViews.Options(ctx, keyScope(p), p.User, identity.ApplicationID{})
}
