package oauthfosite

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/ory/fosite"
)

// scopeStrategy is fosite's wildcard matching plus the organization hint
// scope (urn:iamkit:org:id:<id>), which any client may request; the ID
// itself is checked by oauthsvc.ValidateAuthorization.
func scopeStrategy(haystack []string, needle string) bool {
	if strings.HasPrefix(needle, oauth.OrganizationScopePrefix) {
		return true
	}
	return fosite.WildcardScopeStrategy(haystack, needle)
}
