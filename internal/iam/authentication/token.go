package authentication

import "github.com/Abraxas-365/iamkit/internal/identity"

type Token struct {
	identity.Access
	Purpose       string              `json:"purpose"`
	SessionID     identity.SessionID  `json:"sid,omitempty"`
	OAuthClientID identity.ClientID   `json:"oauth_client_id,omitempty"`
	ActorID       identity.OperatorID `json:"actor_id,omitempty"`
	// ActorAccount is the service account impersonating the user (token
	// exchange); the JWT carries it as act.sub.
	ActorAccount identity.AccountID `json:"actor_account_id,omitempty"`
	// AMR lists how the session was authenticated (pwd, email, fed, otp, mfa).
	AMR []string `json:"amr,omitempty"`
	// AuthTime is when the session signed in (unix seconds); refreshes keep
	// it, so it tells how fresh the proof of the user's credentials is.
	AuthTime int64 `json:"auth_time,omitempty"`
	// Scopes are the OAuth scopes granted to an OAuth access token (scp
	// claim); empty for identity-API tokens.
	Scopes    []string        `json:"scp,omitempty"`
	Subject   identity.UserID `json:"sub"`
	Issuer    string          `json:"iss"`
	Audience  []string        `json:"aud"`
	ID        string          `json:"jti"`
	IssuedAt  int64           `json:"iat"`
	NotBefore int64           `json:"nbf"`
	ExpiresAt int64           `json:"exp"`
}

// Impersonated reports whether someone other than the user acts in the
// session (an operator or a service account).
func (t Token) Impersonated() bool { return !t.ActorID.IsZero() || !t.ActorAccount.IsZero() }

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
	// Methods the organization allows (filled for sign-in only).
	Methods `json:"-"`
}
