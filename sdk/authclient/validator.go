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
	OAuthClientID  string   `json:"oauth_client_id,omitempty"`
	jwt.RegisteredClaims
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
// Offline validation cannot observe revocation: use /identity/v1/introspect
// when immediate logout, suspension, or permission removal must take effect.
func Validate(raw string, key *rsa.PublicKey, issuer, audience, environment, application, resource string) (*Claims, error) {
	if key == nil || issuer == "" || audience == "" || environment == "" || application == "" || resource == "" {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "key and expected token boundaries required", HTTPStatus: 400}
	}
	c := &Claims{}
	t, err := jwt.ParseWithClaims(raw, c, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
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
