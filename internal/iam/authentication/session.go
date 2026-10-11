package authentication

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// UserSession is one of a user's live sessions as they see it
// (GET /identity/v1/me/sessions): where it signs in to and where from.
// Sessions opened by token exchange (parent_session_id) are not listed:
// they live and end with their parent, which stands for them.
type UserSession struct {
	ID identity.SessionID `json:"id"`
	// Current marks the session of the token that asked (a token-exchange
	// child stands for its parent).
	Current      bool                `json:"current"`
	Organization SessionOrganization `json:"organization"`
	Application  SessionApplication  `json:"application"`
	// OAuthClient is the OAuth client the session was opened through, when any.
	OAuthClient *identity.ClientID `json:"oauth_client_id"`
	CreatedAt   time.Time          `json:"created_at"`
	// AuthenticatedAt is the sign-in time (auth_time).
	AuthenticatedAt time.Time `json:"authenticated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	AMR             []string  `json:"amr"`
	// IPAddress and UserAgent are what the request that opened the
	// session said (nil when unknown).
	IPAddress *string `json:"ip_address"`
	UserAgent *string `json:"user_agent"`
	// Impersonated marks a session an operator or service account opened
	// on the user's behalf.
	Impersonated bool `json:"impersonated"`
}

// SessionOrganization names the organization a session signs in to.
type SessionOrganization struct {
	ID   identity.OrganizationID `json:"id"`
	Name string                  `json:"name"`
}

// SessionApplication names the application a session signs in to.
type SessionApplication struct {
	ID   identity.ApplicationID `json:"id"`
	Name string                 `json:"name"`
}

// SessionsRevoked is the answer of ending the user's other sessions.
type SessionsRevoked struct {
	Count int `json:"count"`
}
