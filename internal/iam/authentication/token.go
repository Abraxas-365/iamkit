package authentication

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

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

// Token purposes: a user session, a service account, or a machine user's
// personal access token used directly (no session; the organization is the
// token's).
const (
	PurposeApplication = "application"
	PurposeMachine     = "machine"
	PurposeAccessToken = "pat"
)

// AccessTokenPrefix starts every personal access token.
const AccessTokenPrefix = "ik_pat_"

// PersonalAccessToken is a live personal access token: the token it acts
// as (Purpose pat, the permissions the machine user holds now), the
// audience of its resource and when it expires.
type PersonalAccessToken struct {
	ID       identity.AccessTokenID
	Token    Token
	Audience string
	Expires  time.Time
}

// AMRKey is the amr of a session opened with a machine user key (RFC 8176
// swk: proof of possession of a software-secured key).
const AMRKey = "swk"

// MachineKey is a live machine user key: not expired, its user an active
// machine user.
type MachineKey struct {
	ID          identity.UserKeyID
	Environment identity.EnvironmentID
	User        identity.UserID
	PublicKey   json.RawMessage
	Expires     time.Time
}

// Assertion is a verified JWT-bearer assertion: its single-use jti and
// when it expires.
type Assertion struct {
	JTI     string
	Expires time.Time
}

// KeyGrant is what a verified assertion asks for: a session of the key's
// machine user in the boundary (its environment is the key's).
type KeyGrant struct {
	Key       MachineKey
	Boundary  Context
	Assertion Assertion
}

// KeySession is the session a key grant opened or reused, with the
// audience and permissions of its resource now.
type KeySession struct {
	Session     identity.SessionID
	Audience    string
	Permissions []string
	// Authenticated is when the session was opened (auth_time).
	Authenticated time.Time
}

type Profile struct {
	ID            identity.UserID `json:"id" db:"id"`
	Email         string          `json:"email" db:"email"`
	Name          string          `json:"name" db:"name"`
	Username      string          `json:"username" db:"username"`
	AvatarURL     string          `json:"avatar_url" db:"avatar_url"`
	EmailVerified bool            `json:"email_verified" db:"email_verified"`
	// Phone is changed through /identity/v1/me/phone, not PATCH /me.
	Phone         string                  `json:"phone" db:"phone"`
	PhoneVerified bool                    `json:"phone_verified" db:"phone_verified"`
	Environment   identity.EnvironmentID  `json:"environment_id" db:"environment_id"`
	Organization  identity.OrganizationID `json:"organization_id" db:"organization_id"`
	Actor         identity.OperatorID     `json:"actor_id" db:"actor_id"`
}

// ProfileUpdate is what a user changes about themself (PATCH /me); nil
// fields stay as they are.
type ProfileUpdate struct {
	Name *string `json:"name"`
	// AvatarURL is an https URL ("" removes the picture).
	AvatarURL *string `json:"avatar_url"`
}

// Normalize trims the fields.
func (u ProfileUpdate) Normalize() ProfileUpdate {
	if u.Name != nil {
		name := strings.TrimSpace(*u.Name)
		u.Name = &name
	}
	if u.AvatarURL != nil {
		avatar := strings.TrimSpace(*u.AvatarURL)
		u.AvatarURL = &avatar
	}
	return u
}

func (u ProfileUpdate) Validate() error {
	if u.Name == nil && u.AvatarURL == nil {
		return errx.Validation("name or avatar_url is required")
	}
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		return errx.Validation("name is required")
	}
	if u.AvatarURL != nil {
		if _, err := identity.AvatarURL(*u.AvatarURL); err != nil {
			return err
		}
	}
	return nil
}

type Organization struct {
	ID      identity.OrganizationID `json:"id" db:"id"`
	Name    string                  `json:"name" db:"name"`
	Unit    *identity.UnitID        `json:"org_unit_id" db:"org_unit_id"`
	Manager *identity.UserID        `json:"manager_id" db:"manager_id"`
	// Methods the organization allows (filled for sign-in only).
	Methods `json:"-"`
}
