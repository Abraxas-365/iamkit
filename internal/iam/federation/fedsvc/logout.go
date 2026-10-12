package fedsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var _ federation.LogoutFlows = (*Service)(nil)

// logoutConnection finds the active SAML connection with single logout
// that an SLO message is addressed to; anything else is 404, so the
// endpoint does not tell connections apart.
func (s *Service) logoutConnection(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, federation.LogoutService, error) {
	notFound := errx.NotFound("SAML connection not found")
	if s.saml == nil || s.logouts == nil || environment.IsZero() || id.IsZero() {
		return federation.Connection{}, federation.LogoutService{}, notFound
	}
	c, err := s.repository.Find(ctx, environment, id)
	if err != nil || c.Provider != federation.ProviderSAML || !c.Options.SingleLogout {
		return federation.Connection{}, federation.LogoutService{}, notFound
	}
	service, ok, err := s.saml.LogoutService(c)
	if err != nil {
		return federation.Connection{}, federation.LogoutService{}, err
	}
	if !ok {
		return federation.Connection{}, federation.LogoutService{}, federation.ErrSingleLogoutUnavailable()
	}
	return c, service, nil
}

// SingleLogout handles a message at the connection's SLO endpoint.
func (s *Service) SingleLogout(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID, m federation.LogoutMessage) (federation.Outbound, error) {
	if err := m.Validate(); err != nil {
		return federation.Outbound{}, err
	}
	c, service, err := s.logoutConnection(ctx, environment, id)
	if err != nil {
		return federation.Outbound{}, err
	}
	if m.SAMLResponse != "" {
		return s.logoutResponse(ctx, c, m)
	}
	return s.logoutRequest(ctx, c, service, m)
}

// logoutRequest ends the sessions an identity provider's LogoutRequest names
// and answers with a signed LogoutResponse. Nothing is ended, and no one is
// answered, before the signature checks out; the request ID is spent with
// the sessions, so a replayed request ends nothing.
func (s *Service) logoutRequest(ctx context.Context, c federation.Connection, service federation.LogoutService, m federation.LogoutMessage) (federation.Outbound, error) {
	request, err := s.saml.VerifyLogoutRequest(ctx, c, m)
	if err != nil {
		return federation.Outbound{}, err
	}
	expires := request.NotOnOrAfter.Add(time.Minute)
	if min := time.Now().Add(federation.LogoutTTL); expires.Before(min) {
		expires = min
	}
	status := federation.StatusSuccess
	if _, err = s.logouts.EndLinkedSessions(ctx, c, request, expires); err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.HTTPStatus == 401 {
			// A replay: nothing is answered to a request seen before.
			return federation.Outbound{}, err
		}
		status = federation.StatusPartialLogout
	}
	return s.saml.LogoutResponse(ctx, c, service, request, status)
}

// logoutResponse continues an SP-initiated logout once the identity
// provider answered: the pending logout of its InResponseTo is spent, the
// response verified, and the browser goes on to where end_session left it.
func (s *Service) logoutResponse(ctx context.Context, c federation.Connection, m federation.LogoutMessage) (federation.Outbound, error) {
	requestID, err := s.saml.LogoutResponseID(m)
	if err != nil {
		return federation.Outbound{}, err
	}
	// The local session ended before the identity provider was asked, so a
	// failed or refused response changes nothing here: the browser goes on.
	// Only a response that verifies spends the pending logout.
	if _, err = s.saml.VerifyLogoutResponse(ctx, c, m, requestID); err != nil {
		return federation.Outbound{}, err
	}
	pending, err := s.logouts.TakeLogout(ctx, c.Environment, c.ID, requestID)
	if err != nil {
		return federation.Outbound{}, errx.Unauthorized("invalid SAML logout message")
	}
	return federation.Outbound{URL: pending.Redirect}, nil
}

// BeginLogout sends the browser of an ended session to its identity
// provider with a signed LogoutRequest, when the session was opened by a
// SAML connection with single logout.
func (s *Service) BeginLogout(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID, redirect string) (federation.Outbound, bool, error) {
	if s.saml == nil || s.logouts == nil || environment.IsZero() || session.IsZero() {
		return federation.Outbound{}, false, nil
	}
	linked, err := s.logouts.LinkedSession(ctx, environment, session)
	if err != nil {
		if isNotFound(err) {
			return federation.Outbound{}, false, nil
		}
		return federation.Outbound{}, false, err
	}
	c, service, err := s.logoutConnection(ctx, environment, linked.Link.Connection)
	if err != nil {
		// The connection was disabled, changed or lost its logout service:
		// the local logout stands.
		return federation.Outbound{}, false, nil
	}
	out, requestID, err := s.saml.LogoutRequest(ctx, c, service, linked.Link, "")
	if err != nil {
		return federation.Outbound{}, false, err
	}
	err = s.logouts.SaveLogout(ctx, federation.PendingLogout{RequestID: requestID, Environment: environment, Connection: c.ID, Redirect: redirect, Expires: time.Now().Add(federation.LogoutTTL)})
	if err != nil {
		return federation.Outbound{}, false, err
	}
	return out, true, nil
}

func isNotFound(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeNotFound
}
