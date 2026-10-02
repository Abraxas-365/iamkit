package orgadmin

import (
	"net/url"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SystemClient marks the portal's OAuth client (oauth_clients.system).
const SystemClient = "org_admin"

// PortalApplication is the name of the application IAMKit registers for
// the portal.
const PortalApplication = "Organization admin portal"

// PortalPath is where IAMKit serves the portal.
const PortalPath = "/org-admin"

// Portal is an environment's hosted organization administration portal:
// a public hosted-login OAuth client of its own application, linked to
// the environment's IAM resource, that IAMKit registers and serves.
type Portal struct {
	Enabled     bool                   `json:"enabled"`
	Client      identity.ClientID      `json:"client_id,omitzero"`
	Application identity.ApplicationID `json:"application_id,omitzero"`
	// URL is where organization administrators sign in ("" when off).
	URL string `json:"url,omitempty"`
}

// PortalRedirects are the portal client's registered redirect and
// post-logout redirect URIs for one environment.
type PortalRedirects struct {
	Callback  string
	SignedOut string
}

// NewPortalRedirects derives the portal's URIs from the issuer.
func NewPortalRedirects(issuer string, environment identity.EnvironmentID) (PortalRedirects, error) {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return PortalRedirects{}, errx.Business("the issuer must be an absolute URL to serve the organization admin portal")
	}
	base := strings.TrimRight(issuer, "/") + PortalPath + "/" + environment.String()
	return PortalRedirects{Callback: base + "/callback", SignedOut: base}, nil
}

// PortalMutation is an operator's change to the portal, audited.
type PortalMutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
