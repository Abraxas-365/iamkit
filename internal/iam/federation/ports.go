package federation

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, m Mutation, input ConnectionInput) (identity.ConnectionID, error)
	Update(ctx context.Context, m Mutation, connection identity.ConnectionID, input ConnectionUpdate) error
	Link(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID, subject string) error
	Unlink(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID) error
	Disable(ctx context.Context, m Mutation, connection identity.ConnectionID) error
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter ConnectionFilter, page query.Pagination) (query.Paginated[ConnectionView], error)
	Connection(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) (ConnectionDetail, error)
	Identities(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, page query.Pagination) (query.Paginated[ExternalIdentityView], error)
}
type Flows interface {
	Discover(ctx context.Context, environment identity.EnvironmentID, email string) (Discovery, error)
	Start(ctx context.Context, boundary authentication.Context, connection identity.ConnectionID) (Start, error)
	// StartHosted starts a login for the hosted pages: the organization is
	// the connection's own, or chosen after the callback for environment
	// connections. continuation is the authorization ticket to resume.
	StartHosted(ctx context.Context, target authentication.Target, connection identity.ConnectionID, continuation string) (Start, error)
	Callback(ctx context.Context, code, state, binding string) (Outcome, error)
	// Assertion parks a SAML response posted to the assertion consumer
	// service for its pending state (the RelayState) and returns the
	// one-time handle the callback takes as its code.
	Assertion(ctx context.Context, state, response string) (string, error)
	// SAMLMetadata is the service provider metadata of an active SAML
	// connection, to give its identity provider.
	SAMLMetadata(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) ([]byte, error)
	// EnvironmentConnections lists the active connections that serve the
	// whole environment (social and workforce providers shown as buttons).
	EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]ConnectionSummary, error)
	// Directory signs in with a password an organization's LDAP directory
	// checks (headless): a session, or the pending second factor.
	Directory(ctx context.Context, boundary authentication.Context, connection identity.ConnectionID, email, password string) (authentication.Result, error)
	// DirectoryHosted checks a directory password for the hosted pages and
	// returns the verified user; the hosted journey issues the session.
	DirectoryHosted(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, email, password string) (authentication.Verified, error)
}

type Repository interface {
	Create(ctx context.Context, m Mutation, input Connection) error
	Update(ctx context.Context, m Mutation, input Connection) error
	Find(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) (Connection, error)
	FindDetail(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID) (ConnectionDetail, error)
	List(ctx context.Context, environment identity.EnvironmentID, filter ConnectionFilter, page query.Pagination) (query.Paginated[ConnectionView], error)
	Identities(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, page query.Pagination) (query.Paginated[ExternalIdentityView], error)
	// HasVerifiedDomain reports whether the organization has verified any domain.
	HasVerifiedDomain(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error)
	// OperatorGroup reports whether the group exists in the organization and
	// is managed by operators rather than a SCIM directory.
	OperatorGroup(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, group identity.GroupID) (bool, error)
	// Discover returns the SSO route for a verified domain; the zero value
	// when no organization verified it or it has no active connection.
	Discover(ctx context.Context, environment identity.EnvironmentID, domain string) (Discovery, error)
	EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]ConnectionSummary, error)
	SaveState(ctx context.Context, hash []byte, s State) error
	ConsumeState(ctx context.Context, stateHash, bindingHash []byte) (State, error)
	// ParkAssertion keeps a SAML response posted for a pending state of a
	// SAML connection under handleHash until the callback takes it; it fails
	// with 401 when the state is unknown, consumed or expired.
	ParkAssertion(ctx context.Context, stateHash, handleHash []byte, response string) error
	// TakeAssertion returns and deletes the response parked for the state.
	TakeAssertion(ctx context.Context, stateHash, handleHash []byte) (string, error)
	// UseAssertion records a SAML assertion ID until it expires; it fails
	// with 401 when the connection already accepted it (a replay).
	UseAssertion(ctx context.Context, connection identity.ConnectionID, assertion string, expires time.Time) error
	// Refresh updates the user linked to the profile's subject, if any, with
	// the provider's name and email (see Profile), auditing a change as
	// federation.profile_updated.
	Refresh(ctx context.Context, p Profile) error
	// LinkedUser returns an open transaction and the linked active user, or
	// (nil, zero, nil) when the subject is not linked.
	LinkedUser(ctx context.Context, environment identity.EnvironmentID, connection identity.ConnectionID, subject string) (authentication.Transaction, Account, error)
	// Provision links the subject on first login, adopting the active user
	// with the email or creating one, and commits. It fails unless the email's
	// domain is verified by the organization.
	Provision(ctx context.Context, p Provisioning) error
	// Join links the subject of an environment connection on first login:
	// to the active user with the email when j.Link, else by creating one in
	// the organization when j.Signup; it fails with ErrAccountExists when the
	// email's account may not be linked. It commits.
	Join(ctx context.Context, j Joining) error
	// ActiveOrganization reports whether the organization exists and is active.
	ActiveOrganization(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error)
	Link(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID, subject string) error
	Unlink(ctx context.Context, m Mutation, connection identity.ConnectionID, user identity.UserID) error
	Disable(ctx context.Context, m Mutation, connection identity.ConnectionID) error
}

// Provider talks to external identity providers: OIDC and OAuth 2.0
// (fedoidc) and SAML 2.0 (fedsaml), routed by Connection.Provider. It
// resolves the connection's client secret itself: sealed secrets are opened
// with the Cipher, legacy secret_env references must match an approved
// deployment binding.
type Provider interface {
	Approved(c Connection) bool
	// Prepare completes a connection before it is stored: for SAML it
	// fetches the metadata at Options.MetadataURL into Options.MetadataXML
	// and sets the issuer to the identity provider's entity ID and the
	// client ID to the service provider's entity ID.
	Prepare(ctx context.Context, c Connection) (Connection, error)
	Authorize(ctx context.Context, c Connection, state, nonce, verifier string) (string, error)
	// Verify checks the provider's answer: an authorization code, or for
	// SAML the base64 SAML response, which must answer the request made
	// with nonce.
	Verify(ctx context.Context, c Connection, code, nonce, verifier string) (Claims, error)
	// Metadata is the SAML service provider metadata of a SAML connection.
	Metadata(ctx context.Context, c Connection) ([]byte, error)
	Verifier() string
	// Callback is the redirect URI operators register with providers.
	Callback() string
}

// Directory checks a password against an LDAP directory: it finds the
// user the connection's filter names for email and binds as them. A wrong
// password or unknown user is an unauthorized error; the directory owns
// its own lockout.
type Directory interface {
	Authenticate(ctx context.Context, c Connection, email, password string) (Claims, error)
}

// Cipher seals client secrets for storage at rest.
type Cipher interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
type Sessions interface {
	// SignIn finishes a headless single sign-on: a session, or the pending
	// second factor when multi-factor authentication applies. Only
	// organization SSO satisfies SSO enforcement for email and stands in for
	// the organization's second factor.
	SignIn(ctx context.Context, tx authentication.Transaction, boundary authentication.Context, user identity.UserID, email string, organizationSSO bool) (authentication.Result, error)
}
