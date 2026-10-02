package oauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type ClientRepository interface {
	FindActive(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (*Client, error)
}

// AccountRepository reads service accounts for client_credentials; only
// live ones (not revoked, not expired, application active) are found.
type AccountRepository interface {
	FindAccount(ctx context.Context, account identity.AccountID) (*Account, error)
}

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Registration) (identity.ClientID, string, error)
	Update(ctx context.Context, m Mutation, client identity.ClientID, input ClientUpdate) error
	Disable(ctx context.Context, m Mutation, client identity.ClientID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter ClientFilter, page query.Pagination) (query.Paginated[ClientView], error)
	Find(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (ClientView, error)
	// OriginAllowed reports whether an active client of an active
	// application lists origin (normalized, see Origins) in its
	// allowed_origins.
	OriginAllowed(ctx context.Context, origin string) (bool, error)
}
type Flows interface {
	Client(ctx context.Context, client identity.ClientID) (*Client, error)
	// AccessTokenClient is the live client holding an opaque access token
	// (key: its stored signature hash).
	AccessTokenClient(ctx context.Context, key string) (*Client, error)
	Start(ctx context.Context, client *Client, form string) (string, string, error)
	// Pending checks an unfinished authorization ticket and its browser
	// binding without consuming it (hosted login pages).
	Pending(ctx context.Context, ticket, binding string) (Pending, error)
	Complete(ctx context.Context, ticket, binding string, approve bool, prepare func(Ticket, Authorization) error) error
	Access(ctx context.Context, client *Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error)
	// Logout ends the session an id_token_hint names (RP-initiated logout)
	// and returns where the browser goes next (empty: the signed-out page)
	// and the environment it belongs to, when known.
	Logout(ctx context.Context, input Logout) (string, identity.EnvironmentID, error)
}

// Hints verifies an id_token_hint: an ID token IAMKit signed, expired or
// not (adapter oauthfosite).
type Hints interface {
	Parse(ctx context.Context, raw string) (IDTokenHint, error)
}

type Authorization interface {
	Ticket(ctx context.Context, hash []byte) (Ticket, error)
	// Session is the end-user session an authorization completes with.
	Session(ctx context.Context, session identity.SessionID) (SessionInfo, error)
	// Bind records the client the session was authorized for; a session
	// keeps the first client it was bound to.
	Bind(ctx context.Context, session identity.SessionID, client identity.ClientID) error
	Consume(ctx context.Context, hash []byte) error
	// ApproveDevice marks the pending device authorization of a device
	// ticket approved with login and audits oauth.device_approved.
	ApproveDevice(ctx context.Context, environment identity.EnvironmentID, device []byte, login Login) error
	Commit() error
	Rollback() error
}
type Repository interface {
	ClientRepository
	Environment(ctx context.Context, client identity.ClientID) (identity.EnvironmentID, error)
	// AccessTokenClient finds the environment and client of a live stored
	// access token by its signature hash.
	AccessTokenClient(ctx context.Context, key string) (identity.EnvironmentID, identity.ClientID, error)
	Create(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, input Registration, secretHash []byte) error
	// Update applies input; auth, when not nil, replaces the client's
	// token endpoint authentication.
	Update(ctx context.Context, m Mutation, client identity.ClientID, input ClientUpdate, auth *identity.ClientAuth) error
	Disable(ctx context.Context, m Mutation, client identity.ClientID) error
	List(ctx context.Context, environment identity.EnvironmentID, filter ClientFilter, page query.Pagination) (query.Paginated[ClientView], error)
	Find(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (ClientView, error)
	// OriginAllowed reports whether an active client of an active
	// application lists origin.
	OriginAllowed(ctx context.Context, origin string) (bool, error)
	SaveTicket(ctx context.Context, ticketHash, bindingHash []byte, client *Client, form string) error
	// PendingTicket reads an unconsumed, unexpired ticket without locking it.
	PendingTicket(ctx context.Context, ticketHash []byte) (Ticket, error)
	Begin(ctx context.Context) (Authorization, error)
	Access(ctx context.Context, client *Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error)
	// EndSession revokes the user's session and audits it (m.Action
	// oauth.logout); false when no live session matched.
	EndSession(ctx context.Context, m Mutation, user identity.UserID, session identity.SessionID) (bool, error)
	LogoutRepository
	DeviceRepository
	ExchangeRepository
}

// Devices is the device authorization grant (RFC 8628): the device side
// (/oauth/device_authorization and token polling) and the user side
// (/hosted/device, by user code).
type Devices interface {
	// AuthorizeDevice starts a device authorization for an authenticated
	// client; the answer has no verification URIs (the HTTP adapter adds
	// them).
	AuthorizeDevice(ctx context.Context, client *Client, scope string) (DeviceAuthorization, error)
	DeviceGrants
	// DeviceRequest is the pending device authorization a user code names.
	DeviceRequest(ctx context.Context, userCode string) (DeviceRequest, error)
	// StartDevice opens an authorization ticket (and its browser binding)
	// for the pending device authorization; the hosted login journey
	// completes it.
	StartDevice(ctx context.Context, userCode string) (string, string, error)
	// DenyDevice refuses the pending device authorization.
	DenyDevice(ctx context.Context, userCode string) error
}

// DeviceGrants redeems device codes at the token endpoint: errors carry
// the RFC 8628 error as their Code (DeviceError).
type DeviceGrants interface {
	RedeemDevice(ctx context.Context, client *Client, deviceCode string) (DeviceGrant, error)
}

// Exchanges is OAuth 2.0 Token Exchange (RFC 8693) at /oauth/token.
type Exchanges interface {
	// ExchangeResource turns a live user access token into one for another
	// resource of the same application (a confidential client allowed the
	// token-exchange grant).
	ExchangeResource(ctx context.Context, client *Client, input Exchange) (Exchanged, error)
	// Impersonate issues a user's access token to a service account an
	// owner allowed to impersonate (audited oauth.impersonated).
	Impersonate(ctx context.Context, input Impersonation) (Exchanged, error)
}

// ExchangeRepository opens the sessions exchanged tokens belong to.
type ExchangeRepository interface {
	// ExchangeSession is the live session of the subject token's user for
	// the resource with audience: the root session itself when it is that
	// resource's, else its child session for the resource (created with id
	// when missing, audited oauth.token_exchanged).
	ExchangeSession(ctx context.Context, client *Client, subject authentication.Token, audience string, session identity.SessionID) (ExchangeSession, error)
	// ImpersonationSession creates session for the user acted by the
	// service account until expires, audited oauth.impersonated.
	ImpersonationSession(ctx context.Context, input Impersonation, session identity.SessionID, expires time.Time) (ExchangeSession, error)
}

// DeviceRepository stores device authorizations (codes as hashes).
type DeviceRepository interface {
	// CreateDevice fails with a conflict when the user code is taken.
	CreateDevice(ctx context.Context, client *Client, deviceHash, userHash []byte, scope string, interval, ttl time.Duration) error
	// PendingDevice is the unexpired pending device of a user code.
	PendingDevice(ctx context.Context, userHash []byte) (Device, error)
	SaveDeviceTicket(ctx context.Context, ticketHash, bindingHash []byte, client *Client, deviceHash []byte) error
	// DenyDevice refuses a pending device; not found when none matched.
	DenyDevice(ctx context.Context, userHash []byte) error
	// PollDevice locks the client's device, saves what poll returns and
	// returns it with poll's error (the poll is saved either way).
	PollDevice(ctx context.Context, client *Client, deviceHash []byte, poll func(Device) (Device, error)) (Device, error)
	// SessionInfo is the live session a device was approved with.
	SessionInfo(ctx context.Context, session identity.SessionID) (SessionInfo, error)
}

// LogoutCommands and LogoutQueries are back-channel logout for operators:
// the delivery log and a manual retry of a notification given up on.
type LogoutCommands interface {
	RetryLogout(ctx context.Context, m Mutation, notification int64) error
}
type LogoutQueries interface {
	LogoutDeliveries(ctx context.Context, environment identity.EnvironmentID, filter LogoutFilter, page query.Pagination) (query.Paginated[LogoutDelivery], error)
}

// Dispatcher sends due back-channel logout notifications; it returns how
// many it attempted. Safe to run on every replica at once.
type Dispatcher interface {
	DispatchLogouts(ctx context.Context) (int, error)
}

// LogoutSender signs a logout token for the notification and POSTs it to
// its URI (adapter oauthfosite).
type LogoutSender interface {
	Send(ctx context.Context, notification LogoutNotification) error
}

// LogoutRepository is the logout_notifications outbox (filled by a
// database trigger whenever a session bound to a client ends).
type LogoutRepository interface {
	// ClaimLogouts leases up to limit due notifications for lease,
	// counting an attempt on each.
	ClaimLogouts(ctx context.Context, limit int, lease time.Duration) ([]LogoutNotification, error)
	LogoutDelivered(ctx context.Context, notification int64) error
	// LogoutRetry schedules the next attempt after wait.
	LogoutRetry(ctx context.Context, notification int64, wait time.Duration, reason string) error
	// LogoutFailed gives the notification up and audits m in the same
	// transaction.
	LogoutFailed(ctx context.Context, m Mutation, notification int64, reason string) error
	// PruneLogouts deletes finished notifications older than age.
	PruneLogouts(ctx context.Context, age time.Duration) error
	// LogoutLag is how long the oldest due notification has waited (zero
	// when none is due).
	LogoutLag(ctx context.Context) (time.Duration, error)
	// RetryLogout makes a failed notification due again (audited).
	RetryLogout(ctx context.Context, m Mutation, notification int64) error
	LogoutDeliveries(ctx context.Context, environment identity.EnvironmentID, filter LogoutFilter, page query.Pagination) (query.Paginated[LogoutDelivery], error)
}

type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Passwords interface {
	Hash(password string) (string, error)
}

// ProfileClaims returns a user's claims for the granted scopes beyond name
// and email: with profile picture, preferred_username and the user
// schema's x-iamkit-claim properties; with phone phone_number and
// phone_number_verified. Released in ID tokens and UserInfo. Implemented by
// the user module (user.Queries.Claims).
type ProfileClaims interface {
	Claims(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, scopes []string) (map[string]json.RawMessage, error)
}

// Actions runs the environment's token hooks (action.Runner):
// pre_access_token (also on refresh), pre_id_token and pre_userinfo.
type Actions interface {
	Run(ctx context.Context, environment identity.EnvironmentID, condition string, build func() action.Input) (action.Result, error)
}

// Usage counts access tokens /oauth/token issues through fosite
// (usage.Commands.Count, metric usage.MetricTokens); tokens signed by the
// authentication module count there.
type Usage interface {
	Count(ctx context.Context, environment identity.EnvironmentID, metric string, n int64)
}
