package federation

import (
	"net/url"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// IdP-initiated SAML login, the WorkOS way: an unsolicited response never
// signs anybody in. IAMKit verifies it, spends its assertion ID, and
// redirects the browser to the sign-in endpoint (initiate_login_uri) of an
// OAuth client with the connection named; the client then starts an
// ordinary SP-initiated login (/oauth/authorize?connection_id=…).

// MaxRelayState bounds the RelayState of an unsolicited response.
const MaxRelayState = 1024

// ResponseHint is what a SAML response says before anything is verified:
// only used to find the connection it claims to be for. Nothing in it is
// trusted; the connection's own verification decides.
type ResponseHint struct {
	// Audiences are the audience restrictions of the response's assertions
	// (the service provider entity ID of the connection).
	Audiences []string
	// InResponseTo is set when the response answers a request, which makes
	// it a solicited response (not accepted without its state).
	InResponseTo string
}

// ParseSAMLEntityID reads the environment and connection a service
// provider entity ID of this deployment names (SAMLServiceProvider builds
// it: <issuer>/identity/v1/federation/saml/<environment>/<connection>/metadata).
func ParseSAMLEntityID(issuer, entityID string) (identity.EnvironmentID, identity.ConnectionID, bool) {
	rest, ok := strings.CutPrefix(entityID, issuer+"/identity/v1/federation/saml/")
	if !ok {
		return identity.EnvironmentID{}, identity.ConnectionID{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[2] != "metadata" {
		return identity.EnvironmentID{}, identity.ConnectionID{}, false
	}
	environment, err := identity.ParseEnvironmentID(parts[0])
	if err != nil {
		return identity.EnvironmentID{}, identity.ConnectionID{}, false
	}
	connection, err := identity.ParseConnectionID(parts[1])
	if err != nil {
		return identity.EnvironmentID{}, identity.ConnectionID{}, false
	}
	if SAMLServiceProvider(issuer, environment, connection).EntityID != entityID {
		return identity.EnvironmentID{}, identity.ConnectionID{}, false
	}
	return environment, connection, true
}

// ResponseConnection finds the connection an unsolicited response is for:
// every audience that is a service provider entity ID of this deployment
// must name the same one (none, or two, refuse the response).
func ResponseConnection(issuer string, hint ResponseHint) (identity.EnvironmentID, identity.ConnectionID, error) {
	var (
		environment identity.EnvironmentID
		connection  identity.ConnectionID
	)
	for _, audience := range hint.Audiences {
		e, c, ok := ParseSAMLEntityID(issuer, audience)
		if !ok {
			continue
		}
		if !connection.IsZero() && (c != connection || e != environment) {
			return environment, connection, errx.Unauthorized("invalid SAML response")
		}
		environment, connection = e, c
	}
	if connection.IsZero() {
		return environment, connection, errx.Unauthorized("the SAML response is not addressed to a connection of this service")
	}
	return environment, connection, nil
}

// RelayState is what an identity provider may pass in the RelayState of an
// unsolicited response, as URL query parameters: the OAuth client and the
// redirect URI it wants to land on. Everything else is ignored.
type RelayState struct {
	Client   identity.ClientID
	Redirect string
}

// ParseRelayState reads client_id and redirect_uri from a RelayState
// holding URL query parameters ("client_id=…&redirect_uri=…", with an
// optional leading "?"). An unreadable value or a malformed client ID is
// ignored, not an error: the IdP only suggests, IAMKit decides.
func ParseRelayState(raw string) RelayState {
	var out RelayState
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "?")
	if raw == "" || len(raw) > MaxRelayState {
		return out
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return out
	}
	if id, err := identity.ParseClientID(values.Get("client_id")); err == nil {
		out.Client = id
	}
	out.Redirect = values.Get("redirect_uri")
	return out
}

// LoginClient is an active OAuth client that takes third-party initiated
// logins: it has an initiate_login_uri.
type LoginClient struct {
	ID               identity.ClientID
	InitiateLoginURI string
	Redirects        []string
}

// Target is where the browser goes: the client's sign-in endpoint with the
// connection named (OIDC third-party initiated login: iss, plus
// connection_id and organization_id) and, when the identity provider asked
// for a redirect URI the client registered, target_link_uri. The endpoint's
// own query is kept.
func (c LoginClient) Target(issuer string, connection identity.ConnectionID, organization identity.OrganizationID, relay RelayState) (string, error) {
	params := url.Values{"iss": {issuer}, "connection_id": {connection.String()}, "organization_id": {organization.String()}}
	if relay.Redirect != "" && (oauth.Client{Redirects: c.Redirects}).RedirectRegistered(relay.Redirect) {
		params.Set("target_link_uri", relay.Redirect)
	}
	return oauth.InitiateLoginTarget(c.InitiateLoginURI, params)
}

// ErrIdPInitiatedOff refuses an unsolicited response of a connection that
// names no client for it.
func ErrIdPInitiatedOff() error {
	e := errx.Validation("IdP-initiated sign-in is not enabled for this connection: set options.idp_initiated_client_id, or start sign-in from the application")
	e.Code = "IDP_INITIATED_DISABLED"
	return e
}
