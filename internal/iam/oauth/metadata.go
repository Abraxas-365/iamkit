package oauth

import (
	"encoding/json"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-
// document, MCP authorization 2025-11-25): a client whose client_id is an
// https URL publishes its metadata at that URL. IAMKit materializes it as
// an oauth_clients row per protected resource (source cimd) with a uuid of
// its own; outside IAMKit the client is named by the URL.

// Client sources.
const (
	SourceRegistered = "registered"
	SourceCIMD       = "cimd"
)

// Admission states of an external client.
const (
	AdmissionApproved = "approved"
	AdmissionPending  = "pending"
	AdmissionBlocked  = "blocked"
)

// Client admission modes of a protected resource: allowlist (a client no
// allowlist entry matches waits for IT) or open (every valid document is
// admitted).
const (
	ClientAdmissionAllowlist = "allowlist"
	ClientAdmissionOpen      = "open"
)

// maxClientIDURL bounds a client_id URL (and the external_id column).
const maxClientIDURL = 255

// maxMetadataRedirects bounds the redirect URIs of a document.
const maxMetadataRedirects = 10

// maxClientName bounds client_name.
const maxClientName = 100

// ExternalClientID reports whether a client_id names a Client ID Metadata
// Document (an https URL) rather than a registered client (a uuid).
func ExternalClientID(raw string) bool {
	return strings.HasPrefix(raw, "https://")
}

// ParseClientIDURL checks a client_id URL: https, a lowercase DNS host (no
// IP literal, no explicit port), a path other than "/" without dot
// segments, no query, fragment or userinfo, at most 255 characters. It
// returns the URL as sent (client_id comparison is exact).
func ParseClientIDURL(raw string) (*url.URL, error) {
	invalid := errx.Validation("client_id must be an https URL of a client metadata document")
	if len(raw) > maxClientIDURL || !ExternalClientID(raw) {
		return nil, invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, invalid
	}
	host := u.Hostname()
	if host == "" || host != strings.ToLower(host) || net.ParseIP(host) != nil || !strings.Contains(host, ".") || u.Port() != "" {
		return nil, invalid
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return nil, invalid
		}
	}
	if u.Path == "" || u.Path == "/" || u.RawPath != "" && u.RawPath != u.EscapedPath() {
		return nil, invalid
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, invalid
		}
	}
	if u.String() != raw {
		return nil, invalid
	}
	return u, nil
}

// Origin is scheme://host of an absolute URL ("" when it has none).
func Origin(u *url.URL) string {
	if u == nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// ClientMetadata is a Client ID Metadata Document as published (RFC 7591
// names). Unknown members are ignored.
type ClientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	LogoURI                 string   `json:"logo_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	SigningAlg              string   `json:"token_endpoint_auth_signing_alg"`
	JWKSURI                 string   `json:"jwks_uri"`
	JWKS                    any      `json:"jwks"`
	ClientSecret            string   `json:"client_secret"`
	ClientSecretExpiresAt   any      `json:"client_secret_expires_at"`
}

// ParseClientMetadata decodes a document body.
func ParseClientMetadata(body []byte) (ClientMetadata, error) {
	var m ClientMetadata
	if err := json.Unmarshal(body, &m); err != nil {
		return ClientMetadata{}, errx.Validation("the client metadata document is not a JSON object")
	}
	return m, nil
}

// ExternalClient is what IAMKit keeps of a valid document: the fields an
// oauth_clients row of source cimd stores.
type ExternalClient struct {
	ExternalID string
	Name       string
	ClientURI  string
	LogoURI    string
	Redirects  []string
	GrantTypes []string
	Auth       identity.ClientAuth
}

// Public reports whether the client authenticates with none.
func (e ExternalClient) Public() bool { return e.Auth.Method == identity.AuthNone }

// Validate checks a document fetched from clientID and reduces it to what
// IAMKit honours (D16, D18):
//   - client_id equals the URL exactly;
//   - 1–10 redirect URIs, each https or http on a loopback host, without
//     fragment or userinfo;
//   - token_endpoint_auth_method none (default) or private_key_jwt with a
//     jwks_uri on the client_id's origin; no inline jwks, no client secret;
//   - grant_types and response_types are reduced to authorization_code +
//     refresh_token and code, and must keep authorization_code;
//   - client_name ≤ 100 characters, client_uri and logo_uri https.
func (m ClientMetadata) Validate(clientID *url.URL) (ExternalClient, error) {
	if m.ClientID != clientID.String() {
		return ExternalClient{}, errx.Validation("the document's client_id is not its URL")
	}
	if len(m.RedirectURIs) == 0 || len(m.RedirectURIs) > maxMetadataRedirects {
		return ExternalClient{}, errx.Validation("the document must list between 1 and 10 redirect_uris")
	}
	for _, raw := range m.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Fragment != "" || u.User != nil || u.Host == "" || !(u.Scheme == "https" || identity.LoopbackHTTP(u)) {
			return ExternalClient{}, errx.Validation("redirect_uris must be https or http loopback URLs")
		}
	}
	if m.JWKS != nil {
		return ExternalClient{}, errx.Validation("the document may not embed jwks: publish a jwks_uri")
	}
	if m.ClientSecret != "" || m.ClientSecretExpiresAt != nil {
		return ExternalClient{}, errx.Validation("a client metadata document cannot carry a client secret")
	}
	auth := identity.ClientAuth{Method: m.TokenEndpointAuthMethod, SigningAlg: m.SigningAlg, JWKSURI: m.JWKSURI}
	if auth.Method == "" {
		auth.Method = identity.AuthNone
	}
	if auth.SigningAlg == "" {
		auth.SigningAlg = "RS256"
	}
	switch auth.Method {
	case identity.AuthNone:
		auth.JWKSURI = ""
	case identity.AuthPrivateKeyJWT:
		if err := SameOriginJWKS(clientID, auth.JWKSURI); err != nil {
			return ExternalClient{}, err
		}
	default:
		return ExternalClient{}, errx.Validation("token_endpoint_auth_method must be none or private_key_jwt")
	}
	if !slices.Contains(identity.AssertionAlgorithms, auth.SigningAlg) {
		return ExternalClient{}, errx.Validation("token_endpoint_auth_signing_alg is not supported")
	}
	grants := []string{GrantAuthorizationCode}
	if len(m.GrantTypes) > 0 && !slices.Contains(m.GrantTypes, GrantAuthorizationCode) {
		return ExternalClient{}, errx.Validation("the client must use the authorization_code grant")
	}
	if len(m.GrantTypes) == 0 || slices.Contains(m.GrantTypes, GrantRefreshToken) {
		grants = append(grants, GrantRefreshToken)
	}
	if len(m.ResponseTypes) > 0 && !slices.Contains(m.ResponseTypes, "code") {
		return ExternalClient{}, errx.Validation("the client must use the code response type")
	}
	name := strings.TrimSpace(m.ClientName)
	if utf8.RuneCountInString(name) > maxClientName || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ExternalClient{}, errx.Validation("client_name must be at most 100 printable characters")
	}
	out := ExternalClient{ExternalID: clientID.String(), Name: name, Redirects: slices.Clone(m.RedirectURIs), GrantTypes: grants, Auth: auth}
	if u, err := url.Parse(m.ClientURI); err == nil && u.Scheme == "https" && u.Host != "" && len(m.ClientURI) <= maxClientIDURL {
		out.ClientURI = m.ClientURI
	}
	if u, err := url.Parse(m.LogoURI); err == nil && u.Scheme == "https" && u.Host != "" && len(m.LogoURI) <= maxClientIDURL {
		out.LogoURI = m.LogoURI
	}
	return out, nil
}

// SameOriginJWKS checks the jwks_uri of a private_key_jwt document: an
// https URL with a path on the client_id's origin (D18), so whoever
// controls the document controls the keys and nobody else.
func SameOriginJWKS(clientID *url.URL, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Path == "" || Origin(u) != Origin(clientID) || len(raw) > maxClientIDURL {
		return errx.Validation("private_key_jwt needs a jwks_uri on the client_id's origin")
	}
	return nil
}

// Delegable refuses the grants an external client may never use (D16,
// D18): client_credentials, token exchange, jwt-bearer and impersonation.
// Those act without a user at the keyboard or on someone else's behalf;
// a client nobody registered gets only the code flow and refreshes. The
// oauth_clients_external_check constraint holds the same line in the
// database.
func (c Client) Delegable() error {
	if c.External() {
		return ErrUnauthorizedClient("clients identified by a metadata document may only use the authorization code and refresh token grants")
	}
	return nil
}

// CodeUnauthorizedClient is the RFC 6749 error for a grant the client may
// not use.
const CodeUnauthorizedClient = "unauthorized_client"

// ErrUnauthorizedClient refuses a grant to a client.
func ErrUnauthorizedClient(message string) *errx.Error {
	e := errx.Forbidden(message)
	e.Code = CodeUnauthorizedClient
	return e
}

// Admitted reports whether an external client may finish an authorization
// at now: approved and not past its approval's expiry.
func (c Client) Admitted(now time.Time) bool {
	if !c.External() {
		return true
	}
	return c.Admission == AdmissionApproved && (c.AdmissionExpiresAt == nil || now.Before(*c.AdmissionExpiresAt))
}

// AllowlistEntry admits client metadata documents without review: those
// whose URL has exactly Origin and a path under PathPrefix, for one
// protected resource or (nil) every one of the environment.
type AllowlistEntry struct {
	ID          identity.AllowlistEntryID     `json:"id" db:"id"`
	Environment identity.EnvironmentID        `json:"environment_id" db:"environment_id"`
	Protected   *identity.ProtectedResourceID `json:"protected_resource_id" db:"protected_resource_id"`
	Origin      string                        `json:"origin" db:"origin"`
	PathPrefix  string                        `json:"path_prefix" db:"path_prefix"`
	Preset      string                        `json:"preset" db:"preset"`
	CreatedAt   time.Time                     `json:"created_at" db:"created_at"`
}

// AllowlistCreate adds an entry: either a preset (whose document URL
// becomes origin + exact path) or an origin and a path prefix.
type AllowlistCreate struct {
	Protected  *identity.ProtectedResourceID `json:"protected_resource_id"`
	Origin     string                        `json:"origin"`
	PathPrefix string                        `json:"path_prefix"`
	Preset     string                        `json:"preset"`
}

// Resolve validates the input and fills origin and path from the preset.
// Presets are offered only when their availability allows (development
// presets need development, D21).
func (c AllowlistCreate) Resolve(development bool) (AllowlistCreate, error) {
	if c.Preset != "" {
		p, ok := FindPreset(c.Preset)
		if !ok {
			return c, errx.Validation("unknown client preset")
		}
		if p.Mechanism != PresetMetadataDocument || p.MetadataURL == "" {
			return c, errx.Validation("this preset is a fixed client template, not a client metadata document")
		}
		if p.DevelopmentOnly && !development {
			return c, errx.Validation("this preset is offered in development environments only (feature development_clients)")
		}
		if c.Origin != "" || c.PathPrefix != "" {
			return c, errx.Validation("a preset sets origin and path_prefix itself")
		}
		u, _ := url.Parse(p.MetadataURL)
		c.Origin, c.PathPrefix = Origin(u), u.Path
		return c, nil
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" || Origin(u) != c.Origin || c.Origin != strings.ToLower(c.Origin) || u.Port() != "" || len(c.Origin) > maxClientIDURL {
		return c, errx.Validation("origin must be https://host (lowercase, no port, path or query)")
	}
	if !strings.HasPrefix(c.PathPrefix, "/") || len(c.PathPrefix) > maxClientIDURL || strings.ContainsAny(c.PathPrefix, "?#") || strings.Contains(c.PathPrefix, "/../") || strings.HasSuffix(c.PathPrefix, "/..") {
		return c, errx.Validation("path_prefix must be a path starting with /")
	}
	return c, nil
}

// Matches reports whether the entry admits the client_id URL u: same
// origin, and a path equal to the prefix or below it at a segment boundary
// (prefix "/oauth" admits "/oauth" and "/oauth/x", never "/oauthx").
func (e AllowlistEntry) Matches(u *url.URL) bool {
	if Origin(u) != e.Origin {
		return false
	}
	if u.Path == e.PathPrefix || e.PathPrefix == "/" {
		return true
	}
	prefix := e.PathPrefix
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return strings.HasPrefix(u.Path, prefix)
}

// InitialAdmission is the admission of a client seen for the first time:
// approved when the server is open or an entry matches, else pending.
func InitialAdmission(mode string, entries []AllowlistEntry, u *url.URL) string {
	if mode == ClientAdmissionOpen {
		return AdmissionApproved
	}
	for _, e := range entries {
		if e.Matches(u) {
			return AdmissionApproved
		}
	}
	return AdmissionPending
}

// ExternalClientView is an external client as operators see it.
type ExternalClientView struct {
	ID                 identity.ClientID            `json:"id"`
	ClientID           string                       `json:"client_id"`
	Protected          identity.ProtectedResourceID `json:"protected_resource_id"`
	Name               string                       `json:"client_name"`
	ClientURI          string                       `json:"client_uri"`
	LogoURI            string                       `json:"logo_uri"`
	Host               string                       `json:"host"`
	Redirects          []string                     `json:"redirect_uris"`
	AuthMethod         string                       `json:"token_endpoint_auth_method"`
	JWKSURI            string                       `json:"jwks_uri"`
	Admission          string                       `json:"admission"`
	AdmissionExpiresAt *time.Time                   `json:"admission_expires_at"`
	MetadataFetchedAt  *time.Time                   `json:"metadata_fetched_at"`
	LastUsedAt         *time.Time                   `json:"last_used_at"`
	CreatedAt          time.Time                    `json:"created_at"`
}

// ExternalClientFilter narrows the list of a protected resource's external
// clients ("" admission: all).
type ExternalClientFilter struct {
	Admission string
}

// Validate accepts an empty or known admission.
func (f ExternalClientFilter) Validate() error {
	if f.Admission != "" && f.Admission != AdmissionApproved && f.Admission != AdmissionPending && f.Admission != AdmissionBlocked {
		return errx.Validation("admission must be approved, pending or blocked")
	}
	return nil
}

// Approval approves an external client, optionally until ExpiresAt.
type Approval struct {
	ExpiresAt *time.Time `json:"expires_at"`
}

// Validate refuses an expiry in the past.
func (a Approval) Validate(now time.Time) error {
	if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
		return errx.Validation("expires_at must be in the future")
	}
	return nil
}
