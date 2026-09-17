package authentication

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

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
	Role    string  `json:"role" db:"role"`
	Unit    *string `json:"org_unit_id" db:"org_unit_id"`
	Manager *string `json:"manager_id" db:"manager_id"`
}
type SessionCommands interface {
	Logout(context.Context, Token) error
	UpdateProfile(context.Context, Token, string) error
	AddMember(context.Context, Token, string) error
}
type SessionQueries interface {
	Profile(context.Context, Token) (Profile, error)
	Organizations(context.Context, Token) ([]Organization, error)
}
type TokenIssuer interface {
	Issue(Token, string) (string, error)
	KeyID() string
	JWKS() any
	Machine(context.Context, string) (string, error)
}
type TokenValidator interface {
	Validate(context.Context, string, string, string) (Token, error)
}

type TokenCodec interface {
	Sign(Token) (string, error)
	Verify(string, string) (Token, error)
	KeyID() string
	JWKS() any
}
type TokenRepository interface {
	Current(context.Context, Token, string) ([]string, error)
	ActorActive(context.Context, Token) (bool, error)
	OAuthActive(context.Context, Token, string) (bool, error)
	Machine(context.Context, []byte) (Token, string, error)
	Revoke(context.Context, string, string) error
	Profile(context.Context, Token) (Profile, error)
	Organizations(context.Context, Token) ([]Organization, error)
	UpdateProfile(context.Context, Token, string) error
	AddMember(context.Context, Token, string) error
}
