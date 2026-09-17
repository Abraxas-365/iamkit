// Package authclient validates application access, never management authority.
package authclient

import (
	"crypto/rsa"
	"fmt"

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
		return nil, fmt.Errorf("key and expected token boundaries required")
	}
	c := &Claims{}
	t, err := jwt.ParseWithClaims(raw, c, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	if !t.Valid || c.Subject == "" || c.EnvironmentID != environment || c.ApplicationID != application || c.ResourceID != resource {
		return nil, fmt.Errorf("token boundary mismatch")
	}
	switch c.Purpose {
	case "application":
		if c.OrganizationID == "" || c.SessionID == "" {
			return nil, fmt.Errorf("missing user session context")
		}
	case "machine":
		if c.OrganizationID != "" || c.SessionID != "" {
			return nil, fmt.Errorf("invalid machine context")
		}
	default:
		return nil, fmt.Errorf("unsupported token purpose")
	}
	return c, nil
}
