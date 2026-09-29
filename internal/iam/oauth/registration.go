package oauth

import (
	"encoding/json"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ClientFilter narrows the client list; zero fields match everything.
type ClientFilter struct {
	Application identity.ApplicationID
}

type ClientView struct {
	ID              identity.ClientID      `json:"id"`
	Application     identity.ApplicationID `json:"application_id"`
	ApplicationName string                 `json:"application_name"`
	Resource        identity.ResourceID    `json:"resource_id"`
	ResourceName    string                 `json:"resource_name"`
	Redirects       []string               `json:"redirect_uris"`
	// PostLogoutRedirects are the registered post_logout_redirect_uri values.
	PostLogoutRedirects []string `json:"post_logout_redirect_uris"`
	Public              bool     `json:"public"`
	HostedLogin         bool     `json:"hosted_login"`
	Active              bool     `json:"active"`
	AccessTokenFormat   string   `json:"access_token_format"`
	// BackchannelLogoutURI receives logout tokens (empty: none).
	BackchannelLogoutURI             string `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required"`
	// GrantTypes are the grants the client may use at the token endpoint.
	GrantTypes []string `json:"grant_types"`
	identity.ClientAuth
}

type Registration struct {
	Application identity.ApplicationID `json:"application_id"`
	Resource    identity.ResourceID    `json:"resource_id"`
	Redirects   []string               `json:"redirect_uris"`
	// PostLogoutRedirects are optional; an empty list allows no redirect
	// after /oauth/end_session (IAMKit shows a signed-out page).
	PostLogoutRedirects []string `json:"post_logout_redirect_uris"`
	Public              bool     `json:"public"`
	HostedLogin         bool     `json:"hosted_login"`
	// AccessTokenFormat is jwt (default) or opaque.
	AccessTokenFormat string `json:"access_token_format"`
	// BackchannelLogoutURI, when set, receives a logout token whenever a
	// session this client was authorized for ends.
	BackchannelLogoutURI             string `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired bool   `json:"backchannel_logout_session_required"`
	// GrantTypes default to authorization_code and refresh_token; the
	// device grant needs hosted_login. A client without authorization_code
	// needs no redirect URIs.
	GrantTypes []string `json:"grant_types"`
	// ClientAuth defaults to none (public) or client_secret_basic.
	identity.ClientAuth
}

// ClientUpdate changes the settings of an existing client; nil fields
// stay unchanged.
type ClientUpdate struct {
	HostedLogin         *bool     `json:"hosted_login"`
	Redirects           *[]string `json:"redirect_uris"`
	PostLogoutRedirects *[]string `json:"post_logout_redirect_uris"`
	AccessTokenFormat   *string   `json:"access_token_format"`
	// BackchannelLogoutURI "" turns back-channel logout off.
	BackchannelLogoutURI             *string `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired *bool   `json:"backchannel_logout_session_required"`
	// GrantTypes replaces the client's grants (checked with its hosted
	// login setting and redirect URIs by the service).
	GrantTypes *[]string `json:"grant_types"`
	// Client authentication: a changed method replaces the keys (jwks and
	// jwks_uri are cleared unless given).
	AuthMethod *string          `json:"token_endpoint_auth_method"`
	SigningAlg *string          `json:"token_endpoint_auth_signing_alg"`
	JWKS       *json.RawMessage `json:"jwks"`
	JWKSURI    *string          `json:"jwks_uri"`
}

// Authentication reports whether the update touches client authentication.
func (u ClientUpdate) Authentication() bool {
	return u.AuthMethod != nil || u.SigningAlg != nil || u.JWKS != nil || u.JWKSURI != nil
}

// Apply merges the authentication fields onto current.
func (u ClientUpdate) Apply(current identity.ClientAuth) identity.ClientAuth {
	next := current
	if u.AuthMethod != nil && *u.AuthMethod != current.Method {
		next.Method, next.JWKS, next.JWKSURI = *u.AuthMethod, nil, ""
	}
	if u.SigningAlg != nil {
		next.SigningAlg = *u.SigningAlg
	}
	if u.JWKS != nil {
		next.JWKS = *u.JWKS
		if string(next.JWKS) == "null" {
			next.JWKS = nil
		}
		if u.JWKSURI == nil {
			next.JWKSURI = ""
		}
	}
	if u.JWKSURI != nil {
		next.JWKSURI = *u.JWKSURI
		if u.JWKS == nil && next.JWKSURI != "" {
			next.JWKS = nil
		}
	}
	return next
}

func (u ClientUpdate) Validate() error {
	if u.HostedLogin == nil && u.Redirects == nil && u.PostLogoutRedirects == nil && u.AccessTokenFormat == nil && u.BackchannelLogoutURI == nil && u.BackchannelLogoutSessionRequired == nil && u.GrantTypes == nil && !u.Authentication() {
		return errx.Validation("hosted_login, redirect_uris, post_logout_redirect_uris, access_token_format, backchannel_logout_uri, grant_types or token_endpoint_auth_method is required")
	}
	if u.BackchannelLogoutURI != nil {
		if err := ValidateBackchannelURI(*u.BackchannelLogoutURI); err != nil {
			return err
		}
	}
	if u.AccessTokenFormat != nil {
		if err := ValidateTokenFormat(*u.AccessTokenFormat); err != nil {
			return err
		}
	}
	return nil
}

// Grants are the registration's grant types, the defaults when none.
func (r Registration) Grants() []string {
	if len(r.GrantTypes) == 0 {
		return DefaultGrantTypes
	}
	return r.GrantTypes
}

// ValidateClientShape checks the settings that depend on each other: the
// grant types against hosted login, and redirect URIs for the
// authorization code grant.
func ValidateClientShape(grants []string, hostedLogin bool, redirects []string) error {
	if err := ValidateGrantTypes(grants, hostedLogin); err != nil {
		return err
	}
	for _, g := range grants {
		if g == GrantAuthorizationCode && len(redirects) == 0 {
			return errx.Validation("at least one redirect URI is required")
		}
	}
	return nil
}

func (r Registration) Validate() error {
	if r.Application.IsZero() {
		return errx.Validation("application_id must be a valid UUID")
	}
	if r.Resource.IsZero() {
		return errx.Validation("resource_id must be a valid UUID")
	}
	if r.GrantTypes != nil && len(r.GrantTypes) == 0 {
		return errx.Validation("grant_types must not be empty")
	}
	if err := ValidateClientShape(r.Grants(), r.HostedLogin, r.Redirects); err != nil {
		return err
	}
	if err := ValidateExchangeClient(r.Grants(), r.Public); err != nil {
		return err
	}
	if r.AccessTokenFormat != "" {
		if err := ValidateTokenFormat(r.AccessTokenFormat); err != nil {
			return err
		}
	}
	if err := ValidateBackchannelURI(r.BackchannelLogoutURI); err != nil {
		return err
	}
	return r.ClientAuth.WithDefaults(r.Public).Validate(r.Public)
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
type Ticket struct {
	Client    identity.ClientID `db:"client_id"`
	Binding   []byte            `db:"binding_hash"`
	Form      string            `db:"request_form"`
	Requested time.Time         `db:"requested_at"`
	// Device is the hash of the device code a device ticket approves (nil
	// for authorize requests).
	Device []byte `db:"device_hash"`
}

// Pending is an unfinished authorization: its active client and the
// original authorize request form.
type Pending struct {
	Client *Client
	Form   string
}

// Login is the session a hosted login completes an authorization with.
type Login struct {
	User         identity.UserID
	Organization identity.OrganizationID
	Session      identity.SessionID
	Permissions  []string
}

// SessionInfo is what tokens take from the end-user session: its lifetime,
// when it was authenticated and how (amr claim).
type SessionInfo struct {
	Expires       time.Time
	Authenticated time.Time
	AMR           []string
}
