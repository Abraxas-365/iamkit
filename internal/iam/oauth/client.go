package oauth

import (
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

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
	// InitiateLoginURI is the client's sign-in endpoint for third-party
	// initiated logins (empty: none).
	InitiateLoginURI string
	// Protected is the protected resource behind the client's resource
	// (nil: none, or inactive): the target of RFC 8707 resource requests.
	Protected *ProtectedTarget
	// Source is SourceRegistered (operator-registered, named by its uuid)
	// or SourceCIMD (a Client ID Metadata Document, named outside IAMKit by
	// ExternalID, its URL). "" reads as registered.
	Source string
	// ExternalID is the client_id URL of an external client ("" otherwise).
	ExternalID string
	// Name is the document's client_name ("" for registered clients).
	Name string
	// ClientURI is the document's client_uri (https, "" for registered
	// clients).
	ClientURI string
	// MetadataFetched is when the document this client holds was read
	// (zero for registered clients).
	MetadataFetched time.Time
	// LogoURI is the document's logo_uri (https; shown only on the
	// client_id's own host, LogoShown).
	LogoURI string
	// Admission and AdmissionExpiresAt gate an external client (Admitted).
	Admission          string
	AdmissionExpiresAt *time.Time
	// Disabled is set at use when the client's protected resource no longer
	// takes clients named by a metadata document (allow_client_metadata off,
	// or the client_metadata_documents feature off in the environment):
	// such a client holds no live token, whatever its row says (M-2).
	Disabled bool
	// LoopbackAnyPort lets registered http://localhost redirect URIs match
	// on any port (external clients always may, RFC 8252 §7.3).
	LoopbackAnyPort bool
	// admitted is the loopback redirect URI AdmitRedirect added for the
	// current request (not part of the stored or published document).
	admitted string
}

// Document is the metadata document an external client was built from, as
// resolved: RequestAccess persists a client not written yet from it without
// reading the document again (M-5).
//
// It is the document as fetched: the loopback redirect URI of the current
// request that AdmitRedirect added is not part of it, so a row written from
// it (a request for access) never keeps a port the client did not publish.
func (c Client) Document() ExternalClient {
	redirects := slices.DeleteFunc(slices.Clone(c.Redirects), func(r string) bool { return c.admitted != "" && r == c.admitted })
	return ExternalClient{ExternalID: c.ExternalID, Name: c.Name, ClientURI: c.ClientURI, LogoURI: c.LogoURI, Redirects: redirects, GrantTypes: slices.Clone(c.GrantTypes), Auth: c.Auth}
}

// External reports whether the client comes from a metadata document.
func (c Client) External() bool { return c.Source != "" && c.Source != SourceRegistered }

// PublicID is the client_id the client uses outside IAMKit: the document
// URL of an external client, else the uuid.
func (c Client) PublicID() string {
	if c.External() {
		return c.ExternalID
	}
	return c.ID.String()
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
// matches on any port too for external clients and clients with
// LoopbackAnyPort, else exactly only, like fosite. A loopback host never
// matches another (localhost ≠ 127.0.0.1, D14).
func (c Client) RedirectRegistered(requested string) bool {
	if slices.Contains(c.Redirects, requested) {
		return true
	}
	r, err := url.Parse(requested)
	if err != nil || r.Scheme != "http" || r.User != nil || r.Fragment != "" {
		return false
	}
	ip := net.ParseIP(r.Hostname())
	switch {
	case ip != nil && ip.IsLoopback():
	case r.Hostname() == "localhost" && (c.External() || c.LoopbackAnyPort):
	default:
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
