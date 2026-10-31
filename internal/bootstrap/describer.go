package bootstrap

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// scopeDescriber adapts the authorization module's DescriptionQueries to
// the one-method ports of the consumers that word permission scopes
// (hosted.PermissionDescriber, oauth.PermissionDescriber; D40). Only the
// permissions a resource describes are returned, so consumers keep the raw
// name for the rest.
type scopeDescriber struct {
	queries authorization.DescriptionQueries
}

func (d scopeDescriber) DescribeScopes(ctx context.Context, environment identity.EnvironmentID, resource identity.ResourceID, scopes []string, locales ...string) (map[string]oauth.ScopeText, error) {
	described, err := d.queries.Describe(ctx, environment, resource, scopes, locales...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]oauth.ScopeText, len(described))
	for _, p := range described {
		if p.Described {
			out[p.Name] = oauth.ScopeText{DisplayName: p.DisplayName, Description: p.Description}
		}
	}
	return out, nil
}

var _ oauth.PermissionDescriber = scopeDescriber{}
