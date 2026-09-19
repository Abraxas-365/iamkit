package authentication

import "github.com/Abraxas-365/iamkit/internal/identity"

type Token struct {
	identity.Access
	Purpose       string              `json:"purpose"`
	SessionID     identity.SessionID  `json:"sid,omitempty"`
	OAuthClientID identity.ClientID   `json:"oauth_client_id,omitempty"`
	ActorID       identity.OperatorID `json:"actor_id,omitempty"`
	Subject       identity.UserID     `json:"sub"`
	Issuer        string              `json:"iss"`
	Audience      []string            `json:"aud"`
	ID            string              `json:"jti"`
	IssuedAt      int64               `json:"iat"`
	NotBefore     int64               `json:"nbf"`
	ExpiresAt     int64               `json:"exp"`
}
type Profile struct {
	ID            identity.UserID         `json:"id" db:"id"`
	Email         string                  `json:"email" db:"email"`
	Name          string                  `json:"name" db:"name"`
	EmailVerified bool                    `json:"email_verified" db:"email_verified"`
	Environment   identity.EnvironmentID  `json:"environment_id" db:"environment_id"`
	Organization  identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Actor         identity.OperatorID     `json:"actor_id" db:"actor_id"`
}
type Organization struct {
	ID      identity.OrganizationID `json:"id" db:"id"`
	Name    string                  `json:"name" db:"name"`
	Unit    *identity.UnitID        `json:"org_unit_id" db:"org_unit_id"`
	Manager *identity.UserID        `json:"manager_id" db:"manager_id"`
}
