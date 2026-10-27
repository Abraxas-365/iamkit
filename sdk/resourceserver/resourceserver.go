// Package resourceserver protects an HTTP resource server (for example a
// remote MCP server over Streamable HTTP) with IAMKit as its OAuth 2.1
// authorization server.
//
// It serves the RFC 9728 protected resource metadata, validates access
// tokens issued for the resource (RFC 8707: aud is the resource's canonical
// URL) and answers like the MCP authorization specification asks: 401 with
// WWW-Authenticate: Bearer resource_metadata="…" when the token is missing
// or invalid, 403 with error="insufficient_scope" when it lacks a scope.
//
// Scopes are IAMKit permissions (prefix:name) of the resource. Only JWT
// access tokens are accepted (OAuth clients with opaque access tokens are
// refused with 401). The token never leaves the middleware: handlers see
// claims only. To call another API on the user's behalf, exchange it with
// a confidential client of the server (authclient.OAuthClient.ExchangeToken)
// instead of forwarding the client's token.
package resourceserver

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/golang-jwt/jwt/v5"
)

// MetadataPath is the RFC 9728 well-known path of protected resource
// metadata.
const MetadataPath = "/.well-known/oauth-protected-resource"

// Config describes the protected resource. Issuer, Resource and
// EnvironmentID are required; the values come from IAMKit (the issuer, the
// protected resource's URI and its environment).
type Config struct {
	// Issuer is IAMKit's issuer URL (the iss of its tokens).
	Issuer string
	// Resource is the server's URL as registered in IAMKit (it is
	// canonicalized: the tokens' aud is its canonical form).
	Resource string
	// EnvironmentID is the IAMKit environment the resource belongs to.
	EnvironmentID string
	// Organizations, when set, admits only tokens of these organizations.
	Organizations []string
	// ScopesSupported are advertised in the metadata (the resource's
	// permissions a client may ask for).
	ScopesSupported []string
	// ResourceName is the human-readable name in the metadata.
	ResourceName string
	// DocumentationURL is advertised as resource_documentation.
	DocumentationURL string
	// Keys verifies signatures; nil fetches Issuer + "/.well-known/jwks.json".
	Keys *authclient.KeySet
	// Leeway tolerates clock skew on exp/nbf/iat (default 30 seconds).
	Leeway time.Duration
	// HTTPClient fetches the JWKS when Keys is nil.
	HTTPClient *http.Client
	// AllowTokensWithoutResource also admits tokens issued without the RFC
	// 8707 resource parameter (no resource claim), such as plain OpenID
	// Connect tokens of a client whose resource is this server. Off by
	// default: such tokens were never consented for this server. Even when
	// admitted, only their granted scopes count, never their permissions
	// claim.
	AllowTokensWithoutResource bool
}

// Claims are a validated access token's claims.
type Claims struct {
	Subject        string
	EnvironmentID  string
	OrganizationID string
	ApplicationID  string
	ResourceID     string
	SessionID      string
	OAuthClientID  string
	// Resource is the protected resource the authorization named (the
	// token's resource claim; empty only with AllowTokensWithoutResource).
	Resource string
	// Scopes are the token's granted scopes (OpenID Connect scopes
	// included); Permissions the granted scopes that are permissions (the
	// token's permissions claim is not read).
	Scopes      []string
	Permissions []string
	AMR         []string
	AuthTime    time.Time
	ExpiresAt   time.Time
}

// HasScope reports whether the token was granted scope.
func (c *Claims) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// protocolScopes are granted scopes that are not permissions.
var protocolScopes = []string{"openid", "profile", "email", "phone", "offline_access"}

// permissionsOf are the granted scopes that are permissions: not OpenID
// Connect scopes nor IAMKit organization hints.
func permissionsOf(scopes []string) []string {
	out := []string{}
	for _, s := range scopes {
		if !slices.Contains(protocolScopes, s) && !strings.HasPrefix(s, "urn:iamkit:") {
			out = append(out, s)
		}
	}
	return out
}

// Errors of Verify.
var (
	// ErrNoToken: the request carries no bearer token.
	ErrNoToken = errors.New("missing bearer token")
	// ErrInvalidToken: the token is malformed, expired, not signed by the
	// issuer or not for this resource.
	ErrInvalidToken = errors.New("invalid access token")
	// ErrUnavailable: the issuer's signing keys could not be fetched; the
	// token was not judged. Answered 503 without a challenge, so clients
	// keep their tokens through an outage.
	ErrUnavailable = errors.New("signing keys unavailable")
)

// errUnavailable marks a key lookup that failed on the JWKS fetch.
type errUnavailable struct{}

func (errUnavailable) Error() string { return ErrUnavailable.Error() }

// InsufficientScopeError is returned by Require when the token lacks some
// of the required scopes. Granted are the token's scopes: the 403 challenge
// asks for Granted ∪ Required, so a client stepping up (which replaces its
// scope with the challenge's) keeps what it had.
type InsufficientScopeError struct{ Required, Granted []string }

func (e *InsufficientScopeError) Error() string {
	return "insufficient scope: " + strings.Join(e.Required, " ")
}

// Scope is the scope a client should ask for: Granted ∪ Required.
func (e *InsufficientScopeError) Scope() []string {
	out := slices.Clone(e.Granted)
	for _, s := range e.Required {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Server validates tokens for one protected resource.
type Server struct {
	cfg         Config
	resource    string
	metadataURL string
	keys        *authclient.KeySet
}

// New checks cfg and canonicalizes the resource.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" || cfg.EnvironmentID == "" {
		return nil, errors.New("resourceserver: Issuer and EnvironmentID are required")
	}
	resource, err := CanonicalResource(cfg.Resource)
	if err != nil {
		return nil, errors.New("resourceserver: " + err.Error())
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	keys := cfg.Keys
	if keys == nil {
		keys = authclient.NewKeySet(strings.TrimRight(cfg.Issuer, "/")+"/.well-known/jwks.json", cfg.HTTPClient)
	}
	return &Server{cfg: cfg, resource: resource, metadataURL: MetadataURL(resource), keys: keys}, nil
}

// Resource is the canonical resource URI (the tokens' aud).
func (s *Server) Resource() string { return s.resource }

// MetadataURL is where the resource's metadata is published.
func (s *Server) MetadataURL() string { return s.metadataURL }

// MetadataURL is the RFC 9728 §3.1 metadata URL of a canonical resource:
// the well-known path inserted between the host and the resource's path.
func MetadataURL(resource string) string {
	scheme, rest, _ := strings.Cut(resource, "://")
	host, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	return scheme + "://" + host + MetadataPath + path
}

// MetadataPaths are the paths a server should answer metadata at: the
// RFC 9728 path for the resource and, for a resource with a path, the root
// well-known path some clients probe first.
func (s *Server) MetadataPaths() []string {
	_, rest, _ := strings.Cut(s.resource, "://")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return []string{MetadataPath + rest[i:], MetadataPath}
	}
	return []string{MetadataPath}
}

// Metadata is the RFC 9728 protected resource metadata document.
type Metadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// Metadata is the server's metadata document.
func (s *Server) Metadata() Metadata {
	return Metadata{Resource: s.resource, AuthorizationServers: []string{s.cfg.Issuer}, ScopesSupported: s.cfg.ScopesSupported,
		BearerMethodsSupported: []string{"header"}, ResourceName: s.cfg.ResourceName, ResourceDocumentation: s.cfg.DocumentationURL}
}

type tokenClaims struct {
	EnvironmentID  string           `json:"environment_id"`
	OrganizationID string           `json:"organization_id"`
	ApplicationID  string           `json:"application_id"`
	ResourceID     string           `json:"resource_id"`
	SessionID      string           `json:"sid"`
	OAuthClientID  string           `json:"oauth_client_id"`
	Purpose        string           `json:"purpose"`
	Resource       string           `json:"resource"`
	Scp            []string         `json:"scp"`
	Scope          string           `json:"scope"`
	AMR            []string         `json:"amr"`
	AuthTime       *jwt.NumericDate `json:"auth_time"`
	jwt.RegisteredClaims
}

// Verify validates a raw access token for this resource: RS256 signature
// by the issuer's keys, iss, aud containing the resource, exp/nbf (with
// leeway), the environment, a user session (purpose application) and the
// organization when Organizations is set.
func (s *Server) Verify(ctx context.Context, raw string) (*Claims, error) {
	if raw == "" {
		return nil, ErrNoToken
	}
	var c tokenClaims
	_, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, err := s.keys.Key(ctx, kid)
		var apiErr *apierror.Error
		if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusServiceUnavailable {
			return nil, errUnavailable{}
		}
		return key, err
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.cfg.Issuer), jwt.WithExpirationRequired(), jwt.WithLeeway(s.cfg.Leeway))
	if errors.As(err, new(errUnavailable)) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, ErrInvalidToken
	}
	audience := false
	for _, aud := range c.Audience {
		if canonical, err := CanonicalResource(aud); err == nil && canonical == s.resource {
			audience = true
		}
	}
	if !audience || c.Subject == "" || c.EnvironmentID != s.cfg.EnvironmentID || c.Purpose != "application" || c.SessionID == "" || c.OrganizationID == "" {
		return nil, ErrInvalidToken
	}
	// Only tokens of an authorization that named this resource (RFC 8707)
	// open it: a plain OpenID Connect token of the same client was never
	// consented for it.
	marked := c.Resource != ""
	if marked {
		canonical, err := CanonicalResource(c.Resource)
		if err != nil || canonical != s.resource {
			return nil, ErrInvalidToken
		}
	} else if !s.cfg.AllowTokensWithoutResource {
		return nil, ErrInvalidToken
	}
	if len(s.cfg.Organizations) > 0 && !slices.Contains(s.cfg.Organizations, c.OrganizationID) {
		return nil, ErrInvalidToken
	}
	scopes := c.Scp
	if len(scopes) == 0 {
		scopes = strings.Fields(c.Scope)
	}
	out := &Claims{Subject: c.Subject, EnvironmentID: c.EnvironmentID, OrganizationID: c.OrganizationID, ApplicationID: c.ApplicationID, ResourceID: c.ResourceID,
		SessionID: c.SessionID, OAuthClientID: c.OAuthClientID, Resource: c.Resource, Scopes: scopes, Permissions: permissionsOf(scopes), AMR: c.AMR}
	if c.AuthTime != nil {
		out.AuthTime = c.AuthTime.Time
	}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}

// Require checks the claims hold every scope.
func Require(c *Claims, scopes ...string) error {
	var missing bool
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			missing = true
		}
	}
	if missing {
		return &InsufficientScopeError{Required: scopes, Granted: c.Scopes}
	}
	return nil
}

// Bearer extracts the bearer token of an Authorization header value ("" if
// there is none).
func Bearer(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// Challenge is the WWW-Authenticate value for err (ErrNoToken,
// ErrInvalidToken or *InsufficientScopeError) and its HTTP status. scopes
// are the scopes the request needs (omitted when empty).
func (s *Server) Challenge(err error, scopes []string) (int, string) {
	params := []string{`resource_metadata="` + s.metadataURL + `"`}
	status := http.StatusUnauthorized
	var insufficient *InsufficientScopeError
	switch {
	case errors.As(err, &insufficient):
		status = http.StatusForbidden
		params = append([]string{`error="insufficient_scope"`}, params...)
		scopes = insufficient.Scope()
	case errors.Is(err, ErrInvalidToken):
		params = append([]string{`error="invalid_token"`, `error_description="The access token is invalid or expired"`}, params...)
	}
	if len(scopes) > 0 {
		params = append(params, `scope="`+strings.Join(scopes, " ")+`"`)
	}
	return status, "Bearer " + strings.Join(params, ", ")
}
