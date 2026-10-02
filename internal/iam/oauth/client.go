package oauth

import (
	"net"
	"net/url"
	"slices"
	"strings"

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

// RedirectRegistered reports whether an authorization request's
// redirect_uri is one the client registered: an exact match, or for a
// registered http://127.0.0.1 or http://[::1] URI the same URI on any port
// (RFC 8252 §7.3: native apps listen on an ephemeral port). http://localhost
// matches exactly only, like fosite.
func (c Client) RedirectRegistered(requested string) bool {
	if slices.Contains(c.Redirects, requested) {
		return true
	}
	r, err := url.Parse(requested)
	if err != nil || r.Scheme != "http" || net.ParseIP(r.Hostname()) == nil || !net.ParseIP(r.Hostname()).IsLoopback() {
		return false
	}
	for _, raw := range c.Redirects {
		u, err := url.Parse(raw)
		if err == nil && u.Scheme == "http" && u.Hostname() == r.Hostname() && u.Path == r.Path && u.RawQuery == r.RawQuery {
			return true
		}
	}
	return false
}

// WarningLoopbackRedirect flags an http loopback redirect URI: accepted for
// development and native apps (RFC 8252), but a deployed web app must use
// https.
const WarningLoopbackRedirect = "loopback_redirect"

// ClientWarning is a registration IAMKit accepts but operators should
// review (Code is stable and translated by the console).
type ClientWarning struct {
	Code  string `json:"code"`
	Field string `json:"field"`
	Value string `json:"value"`
}

// Warnings lists the http loopback URIs among a client's redirect and
// post-logout redirect URIs; never nil.
func Warnings(redirects, postLogout []string) []ClientWarning {
	out := []ClientWarning{}
	for field, values := range map[string][]string{"redirect_uris": redirects, "post_logout_redirect_uris": postLogout} {
		for _, raw := range values {
			if u, err := url.Parse(raw); err == nil && identity.LoopbackHTTP(u) {
				out = append(out, ClientWarning{Code: WarningLoopbackRedirect, Field: field, Value: raw})
			}
		}
	}
	slices.SortFunc(out, func(a, b ClientWarning) int { return strings.Compare(a.Field+" "+a.Value, b.Field+" "+b.Value) })
	return out
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
