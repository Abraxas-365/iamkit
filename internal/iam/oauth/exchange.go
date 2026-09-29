package oauth

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Token exchange (RFC 8693).
const (
	// GrantTokenExchange is the grant type of /oauth/token exchanges.
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeAccessToken is the subject token type of a resource
	// exchange and the issued token type of every exchange.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	// TokenTypeUserID names a user by id: a service account allowed to
	// impersonate exchanges it for a token of that user.
	TokenTypeUserID = "urn:iamkit:params:oauth:token-type:user_id"
)

// Token endpoint errors of token exchange (RFC 8693 §2.2.2, RFC 6749
// §5.2); they are the errx Code, sent as the OAuth error. An unusable
// subject token is invalid_request (RFC 8693 §2.2.2).
const (
	ExchangeInvalidRequest     = "invalid_request"
	ExchangeInvalidTarget      = "invalid_target"
	ExchangeInvalidScope       = "invalid_scope"
	ExchangeUnauthorizedClient = "unauthorized_client"
)

// ValidateExchangeClient refuses token exchange to public clients: an
// exchange turns one token into another, so the client must authenticate.
func ValidateExchangeClient(grants []string, public bool) error {
	if public && slices.Contains(grants, GrantTokenExchange) {
		return errx.Validation("token exchange requires a confidential client")
	}
	return nil
}

// ExchangeError is a token exchange error with an OAuth error code.
func ExchangeError(code, message string) *errx.Error {
	e := errx.Validation("token exchange: " + message)
	e.Code = code
	return e
}

// Exchange asks for a token for another resource of the subject token's
// application (audience: the target resource's audience), optionally
// narrowed to some of the user's permissions there (scope).
type Exchange struct {
	Subject  authentication.Token
	Audience string
	Scope    []string
}

// Validate checks the subject is a live user token that may be exchanged:
// a user session, not impersonated, of the client's environment and
// application.
func (e Exchange) Validate(client *Client) error {
	if strings.TrimSpace(e.Audience) == "" {
		return ExchangeError(ExchangeInvalidTarget, "audience is required")
	}
	s := e.Subject
	if s.Purpose != "application" || s.SessionID.IsZero() || s.OrganizationID.IsZero() || s.Subject.IsZero() {
		return ExchangeError(ExchangeInvalidRequest, "subject_token must be a user access token")
	}
	if s.Impersonated() {
		return ExchangeError(ExchangeInvalidRequest, "impersonated tokens cannot be exchanged")
	}
	if s.EnvironmentID != client.Environment || s.ApplicationID != client.Application {
		return ExchangeError(ExchangeInvalidRequest, "subject_token belongs to another application")
	}
	return nil
}

// Impersonation is a service account asking for a token of a user
// (subject_token_type TokenTypeUserID) in one organization.
type Impersonation struct {
	Account      identity.AccountID
	User         identity.UserID
	Organization identity.OrganizationID
	Reason       string
	// Audience, when given, must be the account's resource audience.
	Audience string
}

func (i Impersonation) Validate() error {
	if i.User.IsZero() {
		return ExchangeError(ExchangeInvalidRequest, "subject_token must be a user id")
	}
	if i.Organization.IsZero() {
		return ExchangeError(ExchangeInvalidRequest, "organization_id must be a valid UUID")
	}
	reason := strings.TrimSpace(i.Reason)
	if len(reason) < 10 || len(i.Reason) > 1000 {
		return ExchangeError(ExchangeInvalidRequest, "reason must be 10-1000 characters")
	}
	return nil
}

// ExchangeSession is the session an exchanged token belongs to and what
// the token grants.
type ExchangeSession struct {
	Environment  identity.EnvironmentID
	User         identity.UserID
	ActorAccount identity.AccountID
	Session      identity.SessionID
	Organization identity.OrganizationID
	Application  identity.ApplicationID
	Resource     identity.ResourceID
	Audience     string
	Permissions  []string
	AMR          []string
	// Authenticated is when the user signed in (zero for impersonation).
	Authenticated time.Time
}

// Token is the access token of an exchanged session.
func (s ExchangeSession) Token() authentication.Token {
	t := authentication.Token{
		Access:       identity.Access{EnvironmentID: s.Environment, OrganizationID: s.Organization, ApplicationID: s.Application, ResourceID: s.Resource, Permissions: s.Permissions},
		Purpose:      "application",
		SessionID:    s.Session,
		Subject:      s.User,
		ActorAccount: s.ActorAccount,
		AMR:          s.AMR,
	}
	if !s.Authenticated.IsZero() {
		t.AuthTime = s.Authenticated.Unix()
	}
	return t
}

// Exchanged is the token an exchange issues and its audience.
type Exchanged struct {
	Token    authentication.Token
	Audience string
}
