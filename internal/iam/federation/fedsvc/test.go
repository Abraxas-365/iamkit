package fedsvc

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// IssueTest issues the one-time ticket that opens a test sign-in of the
// connection (active, disabled or a draft with metadata). Only its hash is
// stored; the URL carrying it is shown once to the administrator.
func (s *Service) IssueTest(ctx context.Context, m federation.Mutation, id identity.ConnectionID) (federation.TestTicket, error) {
	if id.IsZero() || m.Environment.IsZero() {
		return federation.TestTicket{}, errx.NotFound("federation connection not found")
	}
	if !strings.HasPrefix(s.issuer, "https://") {
		return federation.TestTicket{}, errx.Validation("federation requires HTTPS issuer")
	}
	c, err := s.repository.FindAny(ctx, m.Environment, id)
	if err != nil {
		return federation.TestTicket{}, err
	}
	if err = testable(c); err != nil {
		return federation.TestTicket{}, err
	}
	ticket, hash, err := s.secrets.Generate(federation.TestPrefix)
	if err != nil {
		return federation.TestTicket{}, err
	}
	expires := time.Now().Add(config.FederationTestTTL)
	if err = s.repository.SaveTest(ctx, m, hash, id, expires); err != nil {
		return federation.TestTicket{}, err
	}
	address := s.issuer + "/identity/v1/federation/test/" + m.Environment.String() + "/" + id.String() + "?ticket=" + url.QueryEscape(ticket)
	return federation.TestTicket{URL: address, ExpiresAt: expires}, nil
}

// testable says whether the connection can be tested in a browser.
func testable(c federation.Connection) error {
	switch {
	case c.Provider == federation.ProviderLDAP:
		return errx.Business("LDAP connections have no browser sign-in to test; check the directory by signing in with a directory account")
	case c.Draft && c.Options.MetadataXML == "":
		return errx.Business("set the identity provider's metadata (options.metadata_url or options.metadata_xml) before testing this draft connection")
	}
	return nil
}

// StartTest spends the ticket and starts the provider sign-in in test mode.
// The ticket is bound to the environment and connection of its URL.
func (s *Service) StartTest(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID, ticket string) (federation.Start, error) {
	if environment.IsZero() || id.IsZero() || !strings.HasPrefix(ticket, federation.TestPrefix) || len(ticket) > 128 {
		return federation.Start{}, errx.Unauthorized("invalid or expired test connection link")
	}
	if !strings.HasPrefix(s.issuer, "https://") {
		return federation.Start{}, errx.Validation("federation requires HTTPS issuer")
	}
	// A wrong or foreign ticket must not reveal whether the connection
	// exists: spend first, read after.
	actor, err := s.repository.UseTest(ctx, s.secrets.Hash(ticket), environment, id)
	if err != nil {
		return federation.Start{}, err
	}
	c, err := s.repository.FindAny(ctx, environment, id)
	if err != nil {
		return federation.Start{}, err
	}
	if err = testable(c); err != nil {
		return federation.Start{}, err
	}
	row := federation.State{Connection: id, Test: true, TestActor: actor}
	row.Boundary.EnvironmentID = environment
	row.Boundary.OrganizationID = c.Organization
	return s.start(ctx, c, row)
}

// callbackTest finishes a test sign-in: it verifies what the provider sent
// exactly like a sign-in would and reports it. It never creates a session,
// user or link, spends no quota and runs no action; a failure is part of
// the result, not an error, so the page can show it.
func (s *Service) callbackTest(ctx context.Context, row federation.State, code, state string) (federation.Outcome, error) {
	var out federation.Outcome
	c, err := s.repository.FindAny(ctx, row.Boundary.EnvironmentID, row.Connection)
	if err != nil {
		return out, err
	}
	result := federation.TestResult{Environment: c.Environment, Connection: c.ID, Organization: c.Organization, ConnectionName: c.Name, Provider: c.Provider}
	claims, err := s.testVerify(ctx, c, row, code, state)
	if err != nil {
		result.Error = message(err)
	} else {
		result.Success = true
		result.Subject, result.Email, result.DisplayName = claims.Subject, claims.Email, claims.Name
		result.EmailVerified = "not sent"
		if claims.EmailVerified != nil {
			result.EmailVerified = "false"
			if *claims.EmailVerified {
				result.EmailVerified = "true"
			}
		}
		result.Groups = claims.Groups
		if len(result.Groups) > federation.MaxTestGroups {
			result.Groups = result.Groups[:federation.MaxTestGroups]
		}
		result.Attributes, result.NameIDFormat = claims.Received, claims.NameIDFormat
	}
	if err = s.repository.RecordTest(ctx, result, row.TestActor); err != nil {
		return out, err
	}
	out.Test = &result
	return out, nil
}

func (s *Service) testVerify(ctx context.Context, c federation.Connection, row federation.State, code, state string) (federation.Claims, error) {
	if c.Provider == federation.ProviderSAML {
		var err error
		if code, err = s.repository.TakeAssertion(ctx, s.secrets.Hash(state), s.secrets.Hash(code)); err != nil {
			return federation.Claims{}, err
		}
	}
	claims, err := s.provider.Verify(ctx, c, code, row.Nonce, row.Verifier)
	if err != nil {
		return claims, err
	}
	if c.Provider == federation.ProviderSAML && claims.Assertion != "" {
		if err = s.repository.UseAssertion(ctx, c.ID, claims.Assertion, claims.AssertionExpires); err != nil {
			return claims, err
		}
	}
	return claims, nil
}

// message is what a failed test shows: the error's own text when it is a
// client-class error, never anything from an internal failure.
func message(err error) string {
	var e *errx.Error
	if errx.As(err, &e) && e.HTTPStatus < 500 {
		return e.Message
	}
	return "the identity provider's answer could not be verified"
}
