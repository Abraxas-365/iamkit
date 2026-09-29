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
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands manage the branding of the hosted pages: the environment
// default and optional per-client styles.
type Commands interface {
	SaveSettings(ctx context.Context, m Mutation, input Settings) (Settings, error)
	// SaveClientSettings replaces the style of one OAuth client.
	SaveClientSettings(ctx context.Context, m Mutation, client identity.ClientID, input Settings) (Settings, error)
	// DeleteClientSettings returns the client to the environment default.
	DeleteClientSettings(ctx context.Context, m Mutation, client identity.ClientID) error
	// SaveSignIn replaces which sign-in methods a client offers.
	SaveSignIn(ctx context.Context, m Mutation, client identity.ClientID, input SignIn) (SignIn, error)
	// DeleteSignIn returns the client to offering every method.
	DeleteSignIn(ctx context.Context, m Mutation, client identity.ClientID) error
}

type Queries interface {
	Settings(ctx context.Context, environment identity.EnvironmentID) (Settings, error)
	// ClientSettings is the client's own style; not found when it uses the
	// environment default.
	ClientSettings(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (Settings, error)
	ListClientSettings(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Settings], error)
	// Draft validates and normalizes a style without saving it (previews).
	Draft(ctx context.Context, environment identity.EnvironmentID, input Settings) (Settings, error)
	// SignIn is the sign-in methods the client offers (every method when
	// it has no options of its own).
	SignIn(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (SignIn, error)
	// ListSignIn lists the clients with sign-in options of their own.
	ListSignIn(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[SignIn], error)
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
	// Signup emails a code to confirm the address of a new account.
	Signup(ctx context.Context, r Request, email, name, password string) (identity.ChallengeID, error)
	// CompleteSignup creates the account once the code is right and signs
	// it in like any verified login. A new account without access to the
	// application answers ErrSignedUpNoAccess.
	CompleteSignup(ctx context.Context, r Request, signup identity.ChallengeID, code string) (Result, error)
	SSO(ctx context.Context, r Request, connection identity.ConnectionID) (federation.Start, error)
	// Directory signs in with a password the organization's LDAP directory
	// (Route.Method "ldap") checks; it continues like single sign-on.
	Directory(ctx context.Context, r Request, connection identity.ConnectionID, email, password string) (Result, error)
	// Federated continues after a hosted single sign-on callback.
	Federated(ctx context.Context, r Request, verified authentication.Verified) (Result, error)
	Choose(ctx context.Context, r Request, organization identity.OrganizationID) (Result, error)
	// SecondFactor checks a second-factor or recovery code (or the first
	// code of a new factor) for the parked login.
	SecondFactor(ctx context.Context, r Request, proof authentication.Proof) (Result, error)
	// SecurityKey starts the security key prompt of the parked login.
	SecurityKey(ctx context.Context, r Request) (authentication.WebAuthnOptions, error)
	// PasskeyOptions starts a passkey sign-in when the client offers it.
	PasskeyOptions(ctx context.Context, r Request) (authentication.WebAuthnOptions, error)
	// Passkey signs in with the browser's passkey assertion; a passkey is
	// multi-factor already, so no second factor follows.
	Passkey(ctx context.Context, r Request, session string, credential []byte) (Result, error)
	// SendFactorCode emails or texts a code for the parked login's second
	// factor (factor is email or sms); an enrolling login may email one to
	// add its email address as a factor.
	SendFactorCode(ctx context.Context, r Request, factor string) (Result, error)
	// Enrollment returns what the parked login may add: an authenticator
	// (Result.Enroll) and/or its email address (Result.EnrollEmail).
	Enrollment(ctx context.Context, r Request) (Result, error)
	// Continue finishes after the recovery codes were shown.
	Continue(ctx context.Context, r Request) (Result, error)
	// ChangePassword replaces the parked login's expired password.
	ChangePassword(ctx context.Context, r Request, password string) (Result, error)
}

// SecondFactor is the part of the mfa module the hosted pages use. amr are
// the login's method references so far.
type SecondFactor interface {
	Requirement(ctx context.Context, boundary authentication.Context, user identity.UserID, federated bool, amr []string) (authentication.Requirement, error)
	Verify(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, proof authentication.Proof, enroll bool) (mfa.Verification, error)
	AssertFor(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string) (authentication.WebAuthnOptions, error)
	Send(ctx context.Context, boundary authentication.Context, user identity.UserID, amr []string, factor string, enroll bool) (authentication.CodeSent, error)
	Enrolling(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (authentication.Enrollment, error)
}

// Passkeys start passkey sign-ins (authentication.PasskeyCommands).
type Passkeys interface {
	BeginPasskey(ctx context.Context, environment identity.EnvironmentID) (authentication.WebAuthnOptions, error)
}

// Devices is the user side of the device authorization grant
// (oauth.Devices): /hosted/device looks up a typed user code, then starts
// the ordinary hosted login on a ticket that approves the device.
type Devices interface {
	DeviceRequest(ctx context.Context, userCode string) (oauth.DeviceRequest, error)
	// StartDevice returns the authorization ticket and its browser binding.
	StartDevice(ctx context.Context, userCode string) (string, string, error)
	DenyDevice(ctx context.Context, userCode string) error
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
	InitiateChallenge(ctx context.Context, environment identity.EnvironmentID, email, purpose, locale string) (identity.ChallengeID, error)
	VerifyChallenge(ctx context.Context, boundary authentication.Context, challenge identity.ChallengeID, code, purpose, password string) (authentication.Result, error)
}

// Signups is self-registration (authentication.SignupCommands).
type Signups interface {
	Signup(ctx context.Context, input authentication.Signup) (identity.ChallengeID, error)
	CompleteSignup(ctx context.Context, environment identity.EnvironmentID, signup identity.ChallengeID, code string) (authentication.SignedUp, error)
}

// Federation is the part of the federation flows the hosted pages use.
type Federation interface {
	Discover(ctx context.Context, environment identity.EnvironmentID, email string) (federation.Discovery, error)
	EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]federation.ConnectionSummary, error)
	StartHosted(ctx context.Context, target authentication.Target, connection identity.ConnectionID, continuation string) (federation.Start, error)
	DirectoryHosted(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, email, password string) (authentication.Verified, error)
}

type Repository interface {
	// Settings returns the environment's branding, or defaults.
	Settings(ctx context.Context, environment identity.EnvironmentID) (Settings, error)
	SaveSettings(ctx context.Context, m Mutation, input Settings) (Settings, error)
	// ClientSettings returns a client's own style; not found when it has none.
	ClientSettings(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (Settings, error)
	ListClientSettings(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[Settings], error)
	// SaveClientSettings and DeleteClientSettings audit m in the same
	// transaction; an unknown client of the environment is not found.
	SaveClientSettings(ctx context.Context, m Mutation, client identity.ClientID, input Settings) (Settings, error)
	DeleteClientSettings(ctx context.Context, m Mutation, client identity.ClientID) error
	// SignIn returns a client's sign-in options; ok is false when it has
	// none of its own.
	SignIn(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (SignIn, bool, error)
	ListSignIn(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[SignIn], error)
	// SaveSignIn and DeleteSignIn audit m in the same transaction; an
	// unknown client of the environment is not found.
	SaveSignIn(ctx context.Context, m Mutation, client identity.ClientID, input SignIn) (SignIn, error)
	DeleteSignIn(ctx context.Context, m Mutation, client identity.ClientID) error
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
