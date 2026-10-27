package oauth

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ValidateAuthorization checks an /oauth/authorize query: a registered
// redirect, the code flow with S256, state and nonce, and well-formed
// connection, interaction and organization hints.
func ValidateAuthorization(issuer string, client *Client, query map[string][]string) error {
	if err := identity.ValidateIssuer(issuer); err != nil {
		return err
	}
	get := func(key string) string {
		v := query[key]
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}
	for key, v := range query {
		// Several resource values are invalid_target, answered at the
		// redirect once it is known to be the client's.
		if (len(v) != 1 && key != "resource") || key == "request" || key == "request_uri" {
			return errx.Validation("invalid authorization request")
		}
	}
	// nonce binds an ID token: a resource server's client that asks for no
	// openid gets none, so it needs no nonce (state still guards the
	// redirect).
	nonce := get("nonce") != "" || (len(query["resource"]) > 0 && !slices.Contains(strings.Fields(get("scope")), "openid"))
	if !client.RedirectRegistered(get("redirect_uri")) || get("response_type") != "code" || get("code_challenge_method") != "S256" || get("code_challenge") == "" || get("state") == "" || !nonce || (get("response_mode") != "" && get("response_mode") != "query") {
		return errx.Validation("code, exact redirect, S256, state and nonce required")
	}
	if _, err := ConnectionHint(query); err != nil {
		return err
	}
	if _, err := ParseInteraction(query); err != nil {
		return err
	}
	_, err := OrganizationHint(query)
	return err
}

// ValidateLogin checks that a sign-in token belongs to the client's
// application and resource and is not an impersonation.
func ValidateLogin(access authentication.Token, client *Client) error {
	if access.Impersonated() || access.Purpose != "application" || access.ApplicationID != client.Application || access.ResourceID != client.Resource {
		return errx.Forbidden("login does not match client")
	}
	return nil
}

// ValidateSession refuses a session past its deadline.
func ValidateSession(deadline time.Time) error {
	if !deadline.After(time.Now()) {
		return errx.Unauthorized("session expired")
	}
	return nil
}
