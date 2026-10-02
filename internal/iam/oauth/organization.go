package oauth

import (
	"net/url"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Organization hints: an authorize request names the organization it signs
// in to with the organization_id parameter or, for ZITADEL-compatible
// clients, the scope urn:iamkit:org:id:<id>. The hosted pages then show
// its branding and the login may only enter that organization.
const (
	ParamOrganization       = "organization_id"
	OrganizationScopePrefix = "urn:iamkit:org:id:"
)

// OrganizationHint reads the organization an authorize request form names
// (zero when none). A malformed ID or two different organizations are a
// validation error.
func OrganizationHint(form url.Values) (identity.OrganizationID, error) {
	var out identity.OrganizationID
	take := func(raw string) error {
		id, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return errx.Validation("organization_id must be an organization ID")
		}
		if !out.IsZero() && out != id {
			return errx.Validation("the authorization request names two organizations")
		}
		out = id
		return nil
	}
	if raw := form.Get(ParamOrganization); raw != "" {
		if err := take(raw); err != nil {
			return identity.OrganizationID{}, err
		}
	}
	for _, scope := range strings.Fields(form.Get("scope")) {
		if raw, ok := strings.CutPrefix(scope, OrganizationScopePrefix); ok {
			if err := take(raw); err != nil {
				return identity.OrganizationID{}, err
			}
		}
	}
	return out, nil
}

// FormOrganization is the organization hint of a stored authorize form
// (zero when none or unreadable: the form was checked when the
// authorization started).
func FormOrganization(form string) identity.OrganizationID {
	values, err := url.ParseQuery(form)
	if err != nil {
		return identity.OrganizationID{}
	}
	out, _ := OrganizationHint(values)
	return out
}

// ErrOrganizationHint refuses a login into another organization than the
// one the authorization request named.
func ErrOrganizationHint() error {
	e := errx.Forbidden("this sign-in is limited to another organization")
	e.Code = "ORGANIZATION_HINT"
	return e
}
