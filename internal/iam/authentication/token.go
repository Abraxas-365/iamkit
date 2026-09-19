package authentication

import "github.com/Abraxas-365/iamkit/internal/identity"

type Token struct {
	identity.Access
	Purpose       string   `json:"purpose"`
	SessionID     string   `json:"sid,omitempty"`
	OAuthClientID string   `json:"oauth_client_id,omitempty"`
	ActorID       string   `json:"actor_id,omitempty"`
	Subject       string   `json:"sub"`
	Issuer        string   `json:"iss"`
	Audience      []string `json:"aud"`
	ID            string   `json:"jti"`
	IssuedAt      int64    `json:"iat"`
	NotBefore     int64    `json:"nbf"`
	ExpiresAt     int64    `json:"exp"`
}
type Profile struct {
	ID            string `json:"id" db:"id"`
	Email         string `json:"email" db:"email"`
	Name          string `json:"name" db:"name"`
	EmailVerified bool   `json:"email_verified" db:"email_verified"`
	Environment   string `json:"environment_id" db:"environment_id"`
	Organization  string `json:"organization_id" db:"organization_id"`
	Actor         string `json:"actor_id" db:"actor_id"`
}
type Organization struct {
	ID      string  `json:"id" db:"id"`
	Name    string  `json:"name" db:"name"`
	Unit    *string `json:"org_unit_id" db:"org_unit_id"`
	Manager *string `json:"manager_id" db:"manager_id"`
}
