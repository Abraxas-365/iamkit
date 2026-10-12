package oauth

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// UpstreamLogout continues an RP-initiated logout at the identity
// provider the ended session signed in with (SAML single logout of an
// organization connection with options.single_logout). Declared here so
// oauth imports no federation package; bootstrap adapts
// federation.LogoutFlows.BeginLogout. /oauth/end_session calls it after
// the session ended: ok true sends the browser to url (a GET) or posts
// fields to url, and the identity provider's LogoutResponse then
// continues to back (the post_logout_redirect_uri with state, or "" for
// the signed-out page). Nil: nothing upstream.
type UpstreamLogout interface {
	BeginLogout(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID, back string) (url string, fields [][2]string, ok bool, err error)
}
