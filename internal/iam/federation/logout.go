package federation

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SAML single logout (SLO) of organization SAML connections, IAMKit being
// the service provider. Opt-in per connection (Options.SingleLogout).
//
// Inbound: the identity provider sends a signed LogoutRequest to the
// connection's SLO endpoint (ServiceProvider.SLO); the sessions opened by
// that connection for the NameID (and SessionIndex, when sent) end, and a
// signed LogoutResponse goes back. Outbound (SP-initiated):
// /oauth/end_session ends a session that has a FederationLink and sends the
// browser to the identity provider with a signed LogoutRequest; its
// LogoutResponse comes back to the same SLO endpoint and the browser
// continues to the post-logout redirect.

// SAML protocol bindings of a SingleLogoutService.
const (
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SAML status codes of a LogoutResponse.
const (
	StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	// StatusPartialLogout (second-level) reports that not every session
	// could be ended.
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
)

// LogoutTTL bounds an SP-initiated logout waiting for the identity
// provider's LogoutResponse (saml_logouts).
const LogoutTTL = 10 * time.Minute

// MaxLogoutMessage bounds an inbound SAMLRequest/SAMLResponse (encoded).
const MaxLogoutMessage = 64 << 10

// Audit actions (events connection.single_logout, connection.logout_sent).
const (
	// ActionSingleLogout: an identity provider's LogoutRequest ended
	// sessions (data.count, actor = the identity provider = system).
	ActionSingleLogout = "connection.single_logout"
)

// LogoutService is the identity provider's SingleLogoutService read from
// its metadata.
type LogoutService struct {
	Location string
	Binding  string
	// ResponseLocation is where LogoutResponses go ("" = Location).
	ResponseLocation string
}

// Response is the location LogoutResponses go to.
func (s LogoutService) Response() string {
	if s.ResponseLocation != "" {
		return s.ResponseLocation
	}
	return s.Location
}

// LogoutMessage is a SAML logout message as the browser brought it to the
// SLO endpoint: HTTP-Redirect (deflated in the query string, signed over
// the raw query: RawQuery keeps it byte for byte) or HTTP-POST (base64 in
// a form, signed in the XML). Exactly one of SAMLRequest and SAMLResponse
// is set.
type LogoutMessage struct {
	Redirect     bool
	SAMLRequest  string
	SAMLResponse string
	RelayState   string
	RawQuery     string
}

// Validate checks the message's shape before any decoding.
func (m LogoutMessage) Validate() error {
	if (m.SAMLRequest == "") == (m.SAMLResponse == "") {
		return errx.Validation("SAMLRequest or SAMLResponse is required")
	}
	if len(m.SAMLRequest) > MaxLogoutMessage || len(m.SAMLResponse) > MaxLogoutMessage || len(m.RawQuery) > 2*MaxLogoutMessage {
		return errx.Validation("SAML message is too large")
	}
	if len(m.RelayState) > 1024 {
		return errx.Validation("RelayState is too long")
	}
	return nil
}

// LogoutRequest is a verified LogoutRequest of an identity provider.
type LogoutRequest struct {
	ID           string
	Issuer       string
	NameID       string
	NameIDFormat string
	// SessionIndexes narrow the logout to these sessions; empty ends every
	// session of the NameID on the connection.
	SessionIndexes []string
	NotOnOrAfter   time.Time
	RelayState     string
}

// Outbound is where the browser goes next: a GET to URL (HTTP-Redirect,
// the message in the query, Fields empty) or an auto-submitted POST of
// Fields to URL (HTTP-POST).
type Outbound struct {
	URL    string
	Fields [][2]string
}

// Post reports whether the browser must post Fields.
func (o Outbound) Post() bool { return len(o.Fields) > 0 }

// PendingLogout is an SP-initiated logout waiting for the identity
// provider's LogoutResponse (saml_logouts): Redirect is where the browser
// continues afterwards ("" = the signed-out page).
type PendingLogout struct {
	RequestID   string
	Environment identity.EnvironmentID
	Connection  identity.ConnectionID
	Redirect    string
	Expires     time.Time
}

// LinkedSession is a session opened by a SAML sign-in with its link
// (federation_sessions).
type LinkedSession struct {
	Session     identity.SessionID
	Environment identity.EnvironmentID
	Link        authentication.FederationLink
}

// LogoutFlows are the SLO browser steps (implemented by fedsvc).
type LogoutFlows interface {
	// SingleLogout handles a message at a connection's SLO endpoint: a
	// LogoutRequest of the identity provider (verified, ends the matching
	// sessions, answers with a signed LogoutResponse) or the
	// LogoutResponse to an SP-initiated logout (verified against the
	// pending saml_logouts row, then the browser continues to its
	// redirect; Outbound.URL "" = the signed-out page). A connection
	// without single logout is 404.
	SingleLogout(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, m LogoutMessage) (Outbound, error)
	// BeginLogout continues the browser logout of an ended session at its
	// identity provider: when the session has a FederationLink on an
	// active connection with single logout, it parks a pending logout
	// (redirect = where the browser goes afterwards) and returns the
	// signed LogoutRequest to send; ok false otherwise (nothing to do).
	BeginLogout(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID, redirect string) (out Outbound, ok bool, err error)
}

// LogoutProtocol reads and writes SAML logout messages for a connection
// (implemented by fedsaml with the environment's signing key and the
// identity provider's certificates from the metadata).
type LogoutProtocol interface {
	// LogoutService is the identity provider's SingleLogoutService
	// (HTTP-Redirect preferred, else HTTP-POST); ok false when the
	// metadata has none.
	LogoutService(c Connection) (LogoutService, bool, error)
	// VerifyLogoutRequest checks an inbound LogoutRequest: signature by the
	// identity provider (required: the query signature of HTTP-Redirect or
	// the XML signature of HTTP-POST), issuer, destination = the
	// connection's SLO URL, version, NotOnOrAfter.
	VerifyLogoutRequest(ctx context.Context, c Connection, m LogoutMessage) (LogoutRequest, error)
	// LogoutResponse signs the answer to request (status StatusSuccess or
	// StatusPartialLogout) for the identity provider's service.
	LogoutResponse(ctx context.Context, c Connection, service LogoutService, request LogoutRequest, status string) (Outbound, error)
	// LogoutRequest signs an SP-initiated LogoutRequest naming link and
	// returns it with its ID.
	LogoutRequest(ctx context.Context, c Connection, service LogoutService, link authentication.FederationLink, relayState string) (Outbound, string, error)
	// VerifyLogoutResponse checks the identity provider's LogoutResponse:
	// signature, issuer, destination, InResponseTo = requestID. A non
	// success status is not an error: success reports it.
	VerifyLogoutResponse(ctx context.Context, c Connection, m LogoutMessage, requestID string) (success bool, err error)
	// LogoutResponseID reads, without verifying anything, the InResponseTo
	// of a LogoutResponse (to find its pending logout first).
	LogoutResponseID(m LogoutMessage) (string, error)
}

// LogoutRepository stores SLO state (implemented by fedpg).
type LogoutRepository interface {
	// LinkedSession returns the session's FederationLink (not found when
	// the session has none), whether or not the session already ended.
	LinkedSession(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID) (LinkedSession, error)
	// EndLinkedSessions spends the LogoutRequest ID (a replay is 401,
	// saml_assertions), ends the live sessions of the connection linked to
	// nameID (only those with one of sessionIndexes when not empty) and
	// records the connection.single_logout event, in one transaction; it
	// returns how many ended.
	EndLinkedSessions(ctx context.Context, c Connection, request LogoutRequest, expires time.Time) (int, error)
	// SaveLogout parks an SP-initiated logout.
	SaveLogout(ctx context.Context, p PendingLogout) error
	// TakeLogout returns and deletes the unexpired pending logout of the
	// request ID on the connection; not found otherwise.
	TakeLogout(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, requestID string) (PendingLogout, error)
	// PruneLogouts deletes expired pending logouts.
	PruneLogouts(ctx context.Context) error
}

// ErrSingleLogoutUnavailable: options.single_logout needs a
// SingleLogoutService in the identity provider's metadata.
func ErrSingleLogoutUnavailable() error {
	e := errx.Validation("options.single_logout needs a SingleLogoutService (HTTP-Redirect or HTTP-POST) in the identity provider's metadata")
	e.Code = "SINGLE_LOGOUT_UNAVAILABLE"
	return e
}
