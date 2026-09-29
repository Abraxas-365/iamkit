// Package authclient validates application access, never management authority.
package authclient

import (
	"crypto/rsa"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	EnvironmentID  string   `json:"environment_id"`
	OrganizationID string   `json:"organization_id,omitempty"`
	ApplicationID  string   `json:"application_id"`
	ResourceID     string   `json:"resource_id"`
	Permissions    []string `json:"permissions"`
	Purpose        string   `json:"purpose"`
	SessionID      string   `json:"sid,omitempty"`
	ActorID        string   `json:"actor_id,omitempty"`
	// Act (RFC 8693) names the service account impersonating the user
	// (Act.Subject is its ID); nil on ordinary tokens.
	Act           *Actor `json:"act,omitempty"`
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	// AMR is how the session was authenticated: "pwd", "email" or "fed",
	// plus "otp"/"mfa" after a second factor.
	AMR []string `json:"amr,omitempty"`
	// AuthTime is when the user signed in (kept across refreshes); compare
	// it with a maximum age for step-up checks.
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	jwt.RegisteredClaims
}

// Actor is the RFC 8693 act claim.
type Actor struct {
	Subject string `json:"sub"`
}

// Impersonated reports whether someone else acts as the user: an operator
// (ActorID) or a service account (Act).
func (c Claims) Impersonated() bool { return c.ActorID != "" || c.Act != nil }

// HasMFA reports whether the session passed a second factor (amr "mfa");
// use it to require step-up for sensitive actions.
func (c Claims) HasMFA() bool {
	for _, m := range c.AMR {
		if m == "mfa" {
			return true
		}
	}
	return false
}

func (c Claims) HasPermission(required string) bool {
	for _, p := range c.Permissions {
		if p == required {
			return true
		}
	}
	return false
}

// Validate requires all expected boundaries from trusted application config.
// It trusts one key: once an environment rotates its signing keys, use
// NewKeySet and ValidateWithKeySet instead.
// Offline validation cannot observe revocation: use /identity/v1/introspect
// when immediate logout, suspension, or permission removal must take effect.
func Validate(raw string, key *rsa.PublicKey, issuer, audience, environment, application, resource string) (*Claims, error) {
	if key == nil {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "key and expected token boundaries required", HTTPStatus: 400}
	}
	return validate(raw, func(*jwt.Token) (any, error) { return key, nil }, issuer, audience, environment, application, resource)
}

func validate(raw string, key jwt.Keyfunc, issuer, audience, environment, application, resource string) (*Claims, error) {
	if issuer == "" || audience == "" || environment == "" || application == "" || resource == "" {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "key and expected token boundaries required", HTTPStatus: 400}
	}
	c := &Claims{}
	t, err := jwt.ParseWithClaims(raw, c, key, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil {
		return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid or expired token", HTTPStatus: 401}
	}
	if !t.Valid || c.Subject == "" || c.EnvironmentID != environment || c.ApplicationID != application || c.ResourceID != resource {
		return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "token boundary mismatch", HTTPStatus: 401}
	}
	switch c.Purpose {
	case "application":
		if c.OrganizationID == "" || c.SessionID == "" {
			return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "missing user session context", HTTPStatus: 401}
		}
	case "machine":
		if c.OrganizationID != "" || c.SessionID != "" {
			return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid machine context", HTTPStatus: 401}
		}
	default:
		return nil, &apierror.Error{Code: "UNAUTHORIZED", Message: "unsupported token purpose", HTTPStatus: 401}
	}
	return c, nil
}
