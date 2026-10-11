package orgadminsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Directories (SCIM credentials). Everything is scoped to the principal's
// organization: the credential's organization is forced, and credentials of
// another organization or environment are not found.

func provisioningMutation(p orgadmin.Principal) provisioning.Mutation {
	return provisioning.Mutation{Environment: p.Environment, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

func (s *Service) Directories(ctx context.Context, p orgadmin.Principal, page query.Pagination) (orgadmin.Directories, error) {
	if err := p.Require(authorization.PermOrgRead); err != nil {
		return orgadmin.Directories{}, err
	}
	out, err := s.d.DirectoryViews.OrganizationCredentials(ctx, p.Environment, p.Organization, page)
	if err != nil {
		return orgadmin.Directories{}, err
	}
	return orgadmin.Directories{Items: out.Items, Page: out.Page, SCIMURL: s.scimURL()}, nil
}

func (s *Service) IssueDirectory(ctx context.Context, p orgadmin.Principal, input orgadmin.NewDirectory) (orgadmin.IssuedDirectory, error) {
	if err := p.Require(authorization.PermOrgSSOWrite); err != nil {
		return orgadmin.IssuedDirectory{}, err
	}
	if err := input.Validate(); err != nil {
		return orgadmin.IssuedDirectory{}, err
	}
	if p.Setup() {
		// A setup link's bearer is not an administrator of the account:
		// adopting existing members could sweep in owners (SCIM would then
		// deactivate them) and a credential that never expires outlives the link.
		if input.AdoptExistingMembers != nil && *input.AdoptExistingMembers {
			return orgadmin.IssuedDirectory{}, errx.Validation("adopt_existing_members is not available through a setup link")
		}
		if input.ExpiresIn != nil && *input.ExpiresIn == "never" {
			return orgadmin.IssuedDirectory{}, errx.Validation("expires_in \"never\" is not available through a setup link: use at most 8760h")
		}
	}
	out, err := s.d.Directories.Issue(ctx, provisioningMutation(p), input.Input(p.Organization))
	if err != nil {
		return orgadmin.IssuedDirectory{}, err
	}
	return orgadmin.IssuedDirectory{ID: out.ID, Secret: out.Secret, Expires: out.Expires, Connection: out.Connection, SCIMURL: s.scimURL()}, nil
}

func (s *Service) scimURL() string { return strings.TrimRight(s.d.Issuer, "/") + "/scim/v2" }

func (s *Service) RevokeDirectory(ctx context.Context, p orgadmin.Principal, credential identity.CredentialID) error {
	if err := p.Require(authorization.PermOrgSSOWrite); err != nil {
		return err
	}
	return s.d.Directories.RevokeOrganization(ctx, provisioningMutation(p), p.Organization, credential)
}
