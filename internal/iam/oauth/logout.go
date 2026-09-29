package oauth

import (
	"net/url"
	"slices"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Logout is an RP-initiated logout request (/oauth/end_session). Every
// field is optional; Hint is the raw id_token_hint.
type Logout struct {
	Hint     string
	Client   identity.ClientID
	Redirect string
	State    string
}

// IDTokenHint is what an ID token IAMKit issued says about its session.
// Expired ID tokens are accepted as hints; the signature and issuer are not
// negotiable.
type IDTokenHint struct {
	Environment identity.EnvironmentID
	Subject     identity.UserID
	// Session is the sid claim; zero for ID tokens issued before it existed.
	Session identity.SessionID
	// Clients is the aud claim (the client IDs the token was issued to).
	Clients []string
}

// Names reports whether client is one of the hint's audiences.
func (h IDTokenHint) Names(client identity.ClientID) bool {
	return slices.Contains(h.Clients, client.String())
}

// Client is the hint's only audience, if it has exactly one.
func (h IDTokenHint) Client() identity.ClientID {
	if len(h.Clients) != 1 {
		return identity.ClientID{}
	}
	id, _ := identity.ParseClientID(h.Clients[0])
	return id
}

// Back is where the browser returns after the logout: the registered
// redirect with the state parameter, or empty for IAMKit's signed-out page.
func (l Logout) Back() string {
	if l.Redirect == "" {
		return ""
	}
	u, err := url.Parse(l.Redirect)
	if err != nil {
		return ""
	}
	if l.State != "" {
		q := u.Query()
		q.Set("state", l.State)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// ErrUnregisteredLogoutRedirect refuses a post_logout_redirect_uri the
// client did not register (exact match).
func ErrUnregisteredLogoutRedirect() error {
	return errx.Validation("post_logout_redirect_uri is not registered for the client")
}
