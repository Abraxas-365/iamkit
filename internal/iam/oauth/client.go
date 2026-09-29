package oauth

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Client struct {
	ID          identity.ClientID
	Environment identity.EnvironmentID
	Application identity.ApplicationID
	Resource    identity.ResourceID
	Audience    string
	Redirects   []string
	Public      bool
	Secret      []byte
	// HostedLogin sends the browser to IAMKit's hosted sign-in pages instead
	// of returning the headless authorization ticket.
	HostedLogin bool
	// PostLogoutRedirects are where /oauth/end_session may send the
	// browser after signing out (exact match).
	PostLogoutRedirects []string
	// Auth is how the client authenticates at the token endpoint.
	Auth identity.ClientAuth
	// AccessTokenFormat is TokenFormatJWT or TokenFormatOpaque.
	AccessTokenFormat string
	// GrantTypes are the grants the client may use (DefaultGrantTypes
	// unless registered otherwise).
	GrantTypes []string
}

// Access token formats of an OAuth client. Opaque tokens are resolved only
// by /oauth/introspect and /oauth/userinfo; /api/v1, /identity/v1 and SDK
// local validation accept JWTs only.
const (
	TokenFormatJWT    = "jwt"
	TokenFormatOpaque = "opaque"
)

// ValidateTokenFormat accepts jwt and opaque.
func ValidateTokenFormat(format string) error {
	if format != TokenFormatJWT && format != TokenFormatOpaque {
		return errx.Validation("access_token_format must be jwt or opaque")
	}
	return nil
}

// Account is a live service account authenticating at the token endpoint
// as an OAuth client (grant client_credentials, client_id = account id).
type Account struct {
	ID          identity.AccountID
	Environment identity.EnvironmentID
	// Secret is the SHA-256 of its ik_svc_ secret.
	Secret []byte
	Auth   identity.ClientAuth
}
