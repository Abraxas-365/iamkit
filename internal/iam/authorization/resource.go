package authorization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Resource struct {
	ID          identity.ResourceID `json:"id"`
	Name        string              `json:"name"`
	Prefix      string              `json:"prefix"`
	Audience    string              `json:"audience"`
	Permissions []string            `json:"permissions"`
	// OwnerOrganization and RequireGrant: see ResourceAccess.
	OwnerOrganization *identity.OrganizationID `json:"owner_organization_id"`
	RequireGrant      bool                     `json:"require_grant"`
	// APIKeyPermissions is the allowlist of user and organization API keys.
	APIKeyPermissions APIKeyPermissions `json:"api_key_permissions"`
}

// Access is the resource's ownership and grant requirement.
func (r Resource) Access() ResourceAccess {
	return ResourceAccess{OwnerOrganization: r.OwnerOrganization, RequireGrant: r.RequireGrant}
}

// Validate checks the structural invariants Resource owns.
func (r Resource) Validate() error {
	if err := r.Access().Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.Name) == "" {
		return errx.Validation("resource name is required")
	}
	if strings.TrimSpace(r.Audience) == "" {
		return errx.Validation("resource audience is required")
	}
	if strings.TrimSpace(r.Prefix) == "" {
		return errx.Validation("resource prefix is required")
	}
	return nil
}

// APIKeyPermissions are the permissions API keys may carry on a resource
// (WorkOS-style allowlist): User for user keys, Organization for
// organization keys. Both are subsets of the resource's permissions; empty
// means no key of that kind for the resource. The IAM resource has none:
// IAMKit's own API is reached with the customer's own credential (service
// account or machine user). Removing a permission from the resource removes
// it from both lists.
type APIKeyPermissions struct {
	User         []string `json:"user"`
	Organization []string `json:"organization"`
}

// Validate checks both lists against the resource's catalog.
func (a APIKeyPermissions) Validate(r Resource) error {
	if r.Prefix == "iam" && (len(a.User) > 0 || len(a.Organization) > 0) {
		return errx.Validation("API keys cannot carry IAM permissions; call IAMKit with a service account or machine user")
	}
	known := make(map[string]bool, len(r.Permissions))
	for _, p := range r.Permissions {
		known[p] = true
	}
	for _, list := range [][]string{a.User, a.Organization} {
		for _, p := range list {
			if !known[p] {
				return errx.Validation("API key permission " + p + " is not a permission of the resource")
			}
		}
	}
	return nil
}

type Catalog struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func (c Catalog) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("catalog name is required")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
