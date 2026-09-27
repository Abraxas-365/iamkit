package hosted

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Commands manage the branding of the hosted pages.
type Commands interface {
	SaveSettings(ctx context.Context, m Mutation, input Settings) (Settings, error)
}

type Queries interface {
	Settings(ctx context.Context, environment identity.EnvironmentID) (Settings, error)
}

// Flow is the hosted sign-in journey. Every step re-checks the pending
// authorization (ticket, browser binding, active hosted client).
type Flow interface {
	Page(ctx context.Context, r Request) (Page, error)
	Identify(ctx context.Context, r Request, email string) (Route, error)
	Password(ctx context.Context, r Request, email, password string) (Result, error)
	SendCode(ctx context.Context, r Request, email string) (identity.ChallengeID, error)
	VerifyCode(ctx context.Context, r Request, challenge identity.ChallengeID, code string) (Result, error)
	SendReset(ctx context.Context, r Request, email string) (identity.ChallengeID, error)
	Reset(ctx context.Context, r Request, challenge identity.ChallengeID, code, password string) error
	SSO(ctx context.Context, r Request, connection identity.ConnectionID) (federation.Start, error)
	// Federated continues after a hosted single sign-on callback.
	Federated(ctx context.Context, r Request, verified authentication.Verified) (Result, error)
	Choose(ctx context.Context, r Request, organization identity.OrganizationID) (Result, error)
	// SecondFactor checks an authenticator or recovery code (or the first
	// code of a new authenticator) for the parked login.
	SecondFactor(ctx context.Context, r Request, code string) (Result, error)
	// Enrollment returns the authenticator the parked login is adding.
	Enrollment(ctx context.Context, r Request) (authentication.Enrollment, error)
	// Continue finishes after the recovery codes were shown.
	Continue(ctx context.Context, r Request) (Result, error)
}

// SecondFactor is the part of the mfa module the hosted pages use.
type SecondFactor interface {
	Requirement(ctx context.Context, boundary authentication.Context, user identity.UserID, federated bool) (authentication.Requirement, error)
	Verify(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, code string, enroll bool) (mfa.Verification, error)
	Enrolling(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.Enrollment, error)
}

// Invitations is the invitation use cases the hosted accept page uses.
type Invitations interface {
	Preview(ctx context.Context, token string) (invitation.Preview, error)
	Accept(ctx context.Context, input invitation.Acceptance) (invitation.Accepted, error)
}

// Secrets hashes authorization tickets for storage.
type Secrets interface {
	Hash(raw string) []byte
}

// Authorizations is the part of the OAuth flows the hosted pages use.
type Authorizations interface {
	Pending(ctx context.Context, ticket, binding string) (oauth.Pending, error)
}

// Challenges is the part of the authentication commands the hosted pages use.
type Challenges interface {
	InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose string) (identity.ChallengeID, error)
	VerifyChallenge(ctx context.Context, boundary authentication.Context, challenge identity.ChallengeID, code, purpose, password string) (authentication.Result, error)
}

// Federation is the part of the federation flows the hosted pages use.
type Federation interface {
	Discover(ctx context.Context, environment identity.EnvironmentID, email string) (federation.Discovery, error)
	EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]federation.ConnectionSummary, error)
	StartHosted(ctx context.Context, target authentication.Target, connection identity.ConnectionID, continuation string) (federation.Start, error)
}

type Repository interface {
	// Settings returns the environment's branding, or defaults.
	Settings(ctx context.Context, environment identity.EnvironmentID) (Settings, error)
	SaveSettings(ctx context.Context, m Mutation, input Settings) (Settings, error)
	// SaveLogin parks the verified user of an authorization between steps,
	// replacing an earlier one for the ticket (without lowering the attempts
	// the same user already spent).
	SaveLogin(ctx context.Context, ticketHash []byte, environment identity.EnvironmentID, login Login, expires time.Time) error
	// Login returns the unexpired parked login of an authorization.
	Login(ctx context.Context, ticketHash []byte, environment identity.EnvironmentID) (Login, error)
	// Attempt reserves one second-factor try, atomically, while fewer than
	// limit were made; false once they ran out.
	Attempt(ctx context.Context, ticketHash []byte, limit int) (bool, error)
	DeleteLogin(ctx context.Context, ticketHash []byte) error
}
