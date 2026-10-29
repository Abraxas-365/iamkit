package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// OAuth 2.0 Dynamic Client Registration (RFC 7591, MCP authorization
// 2025-11-25). POST /oauth/register stores a registration: global (the
// request names no resource, so no environment), public (no secret, auth
// none) and inert. It is materialized as an oauth_clients row (source dcr)
// only at the authorization request of a protected resource whose
// environment has the dynamic_client_registration feature on and that
// allows dynamic registration, and is then admitted like a client of a
// metadata document. Nothing about such a client is verifiable: its name
// is the client's own claim, no allowlist entry ever matches it (entries
// match a URL), so on an allowlist server it always waits for IT.

// dynamicPrefix starts every dynamically registered client_id.
const dynamicPrefix = "dcr_"

// DynamicClientID reports whether a client_id names a dynamic registration:
// dcr_ followed by 32 lowercase hex digits.
func DynamicClientID(raw string) bool {
	if len(raw) != len(dynamicPrefix)+32 || !strings.HasPrefix(raw, dynamicPrefix) {
		return false
	}
	for _, r := range raw[len(dynamicPrefix):] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// NewDynamicClientID is a fresh registration client_id (128 random bits).
func NewDynamicClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errx.Wrap(err, "generate client_id", errx.TypeInternal)
	}
	return dynamicPrefix + hex.EncodeToString(b), nil
}

// RFC 7591 §3.2.2 error codes.
const (
	CodeInvalidRedirectURI    = "invalid_redirect_uri"
	CodeInvalidClientMetadata = "invalid_client_metadata"
)

// RegistrationError is an RFC 7591 error (400, error and
// error_description): code is CodeInvalidRedirectURI or
// CodeInvalidClientMetadata.
func RegistrationError(code, description string) *errx.Error {
	e := errx.Validation(description)
	e.Code = code
	return e
}

// ErrRegistrationNotOffered answers POST /oauth/register while no
// environment takes dynamically registered clients (Offers): 404, as if the
// endpoint did not exist (discovery does not list it either).
func ErrRegistrationNotOffered() *errx.Error {
	return errx.NotFound("not found")
}

// ErrRegistrationsFull refuses a registration while the deployment holds
// config.ClientRegistrationMaxUnused registrations nobody used yet.
func ErrRegistrationsFull() *errx.Error {
	e := errx.TooManyRequests("too many client registrations are waiting to be used; try again later")
	e.Code = "CLIENT_REGISTRATIONS_FULL"
	return e
}

// ClientRegistration is an RFC 7591 registration request. Members IAMKit
// does not keep (scope, contacts, tos_uri, policy_uri, logo_uri, …) are
// ignored; those that would make the client confidential or delegable are
// refused.
type ClientRegistration struct {
	RedirectURIs            []string        `json:"redirect_uris"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	ClientName              string          `json:"client_name"`
	ClientURI               string          `json:"client_uri"`
	SoftwareID              string          `json:"software_id"`
	SoftwareVersion         string          `json:"software_version"`
	JWKSURI                 string          `json:"jwks_uri"`
	JWKS                    json.RawMessage `json:"jwks"`
	SoftwareStatement       string          `json:"software_statement"`
}

// RegistrationTooLarge reports whether a request body exceeds
// config.ClientRegistrationMaxBytes.
func RegistrationTooLarge(body []byte) error {
	if len(body) > config.ClientRegistrationMaxBytes {
		return RegistrationError(CodeInvalidClientMetadata, "the registration request is too large")
	}
	return nil
}

// maxSoftwareField bounds software_id and software_version.
const maxSoftwareField = 255

// Validate reduces a request to what IAMKit registers (D16, D25):
//   - 1–10 redirect URIs of at most 255 characters, each one
//     identity.ValidateClientRedirects accepts (https, http on a loopback
//     host, or a reverse-DNS private-use scheme);
//   - token_endpoint_auth_method none (the default): no secret is issued,
//     no key set is taken, no software statement is trusted;
//   - grant_types and response_types reduced to authorization_code +
//     refresh_token and code, keeping authorization_code;
//   - client_name ≤ 100 printable characters, client_uri https.
func (r ClientRegistration) Validate() (Registered, error) {
	if len(r.RedirectURIs) == 0 || len(r.RedirectURIs) > maxMetadataRedirects {
		return Registered{}, RegistrationError(CodeInvalidRedirectURI, "register between 1 and 10 redirect_uris")
	}
	for _, raw := range r.RedirectURIs {
		if len(raw) > maxClientIDURL {
			return Registered{}, RegistrationError(CodeInvalidRedirectURI, "redirect_uris must be at most 255 characters")
		}
	}
	if err := identity.ValidateClientRedirects(r.RedirectURIs); err != nil {
		return Registered{}, RegistrationError(CodeInvalidRedirectURI, err.Error())
	}
	if r.TokenEndpointAuthMethod != "" && r.TokenEndpointAuthMethod != identity.AuthNone {
		return Registered{}, RegistrationError(CodeInvalidClientMetadata, "token_endpoint_auth_method must be none: dynamically registered clients are public")
	}
	if r.JWKSURI != "" || len(r.JWKS) > 0 {
		return Registered{}, RegistrationError(CodeInvalidClientMetadata, "dynamically registered clients are public and take no keys")
	}
	if r.SoftwareStatement != "" {
		return Registered{}, RegistrationError(CodeInvalidClientMetadata, "software statements are not accepted")
	}
	grants := []string{GrantAuthorizationCode}
	if len(r.GrantTypes) > 0 && !slices.Contains(r.GrantTypes, GrantAuthorizationCode) {
		return Registered{}, RegistrationError(CodeInvalidClientMetadata, "the client must use the authorization_code grant")
	}
	for _, g := range r.GrantTypes {
		if g != GrantAuthorizationCode && g != GrantRefreshToken {
			return Registered{}, RegistrationError(CodeInvalidClientMetadata, "grant_types may only hold authorization_code and refresh_token")
		}
	}
	if len(r.GrantTypes) == 0 || slices.Contains(r.GrantTypes, GrantRefreshToken) {
		grants = append(grants, GrantRefreshToken)
	}
	for _, t := range r.ResponseTypes {
		if t != "code" {
			return Registered{}, RegistrationError(CodeInvalidClientMetadata, "response_types may only hold code")
		}
	}
	name := strings.TrimSpace(r.ClientName)
	if utf8.RuneCountInString(name) > maxClientName || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return Registered{}, RegistrationError(CodeInvalidClientMetadata, "client_name must be at most 100 printable characters")
	}
	if !printable(r.SoftwareID, maxSoftwareField) || !printable(r.SoftwareVersion, maxSoftwareField) {
		return Registered{}, RegistrationError(CodeInvalidClientMetadata, "software_id and software_version must be at most 255 printable characters")
	}
	out := Registered{Name: name, Redirects: slices.Clone(r.RedirectURIs), GrantTypes: grants, SoftwareID: r.SoftwareID, SoftwareVersion: r.SoftwareVersion}
	if u, err := url.Parse(r.ClientURI); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(r.ClientURI) <= maxClientIDURL {
		out.ClientURI = r.ClientURI
	}
	return out, nil
}

func printable(s string, max int) bool {
	return len(s) <= max && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// Registered is a stored dynamic registration.
type Registered struct {
	ClientID        string    `json:"client_id"`
	Name            string    `json:"client_name"`
	ClientURI       string    `json:"client_uri"`
	Redirects       []string  `json:"redirect_uris"`
	GrantTypes      []string  `json:"grant_types"`
	SoftwareID      string    `json:"software_id"`
	SoftwareVersion string    `json:"software_version"`
	CreatedAt       time.Time `json:"-"`
}

// Client is the external client the registration describes (source dcr).
func (r Registered) Client() ExternalClient {
	return ExternalClient{Source: SourceDCR, ExternalID: r.ClientID, Name: r.Name, ClientURI: r.ClientURI, Redirects: slices.Clone(r.Redirects), GrantTypes: slices.Clone(r.GrantTypes), Auth: identity.ClientAuth{Method: identity.AuthNone, SigningAlg: "RS256"}}
}

// RegistrationResponse is the RFC 7591 §3.2.1 answer: the metadata as
// registered, no secret.
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// Response is what POST /oauth/register answers for r.
func (r Registered) Response() RegistrationResponse {
	return RegistrationResponse{ClientID: r.ClientID, ClientIDIssuedAt: r.CreatedAt.Unix(), ClientName: r.Name, ClientURI: r.ClientURI, RedirectURIs: r.Redirects, GrantTypes: r.GrantTypes,
		ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: identity.AuthNone, SoftwareID: r.SoftwareID, SoftwareVersion: r.SoftwareVersion}
}

// Registrations registers clients dynamically (RFC 7591).
type Registrations interface {
	// Register stores a registration; refused with
	// ErrRegistrationNotOffered when no environment takes dynamically
	// registered clients (Offers.DynamicRegistration), ErrRegistrationsFull
	// when too many wait unused.
	Register(ctx context.Context, input ClientRegistration) (Registered, error)
	// PruneRegistrations is the client_registration_prune job.
	PruneRegistrations(ctx context.Context) (bool, error)
}

// RegistrationRepository persists registrations (oauthpg).
type RegistrationRepository interface {
	// SaveRegistration inserts r unless maxUnused registrations nobody
	// used wait already (ErrRegistrationsFull).
	SaveRegistration(ctx context.Context, r Registered, maxUnused int) error
	// PruneRegistrations deletes up to limit registrations never used and
	// created before unusedBefore, or used, held by no client row and idle
	// since idleBefore.
	PruneRegistrations(ctx context.Context, unusedBefore, idleBefore time.Time, limit int) (int, error)
}

// SourceFeature is the environment feature that turns an external source
// on (config.FeatureClientMetadataDocuments for documents,
// config.FeatureDynamicClientRegistration for dynamic registrations).
func SourceFeature(source string) string {
	if source == SourceDCR {
		return config.FeatureDynamicClientRegistration
	}
	return config.FeatureClientMetadataDocuments
}
