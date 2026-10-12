package fedsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// finder is a federation.Repository that only finds one connection.
type finder struct {
	federation.Repository
	connection federation.Connection
}

func (f finder) Find(_ context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, error) {
	if environment != f.connection.Environment || id != f.connection.ID {
		return federation.Connection{}, errx.NotFound("resource not found")
	}
	return f.connection, nil
}

// protocol is a scripted federation.LogoutProtocol.
type protocol struct {
	service    federation.LogoutService
	hasService bool
	request    federation.LogoutRequest
	verifyErr  error
	responseID string
	responseOK error
	statuses   []string
	requested  []authentication.FederationLink
}

func (p *protocol) LogoutService(federation.Connection) (federation.LogoutService, bool, error) {
	return p.service, p.hasService, nil
}
func (p *protocol) VerifyLogoutRequest(context.Context, federation.Connection, federation.LogoutMessage) (federation.LogoutRequest, error) {
	return p.request, p.verifyErr
}
func (p *protocol) LogoutResponse(_ context.Context, _ federation.Connection, _ federation.LogoutService, _ federation.LogoutRequest, status string) (federation.Outbound, error) {
	p.statuses = append(p.statuses, status)
	return federation.Outbound{URL: "https://idp.example.com/slo?SAMLResponse=x"}, nil
}
func (p *protocol) LogoutRequest(_ context.Context, _ federation.Connection, _ federation.LogoutService, link authentication.FederationLink, _ string) (federation.Outbound, string, error) {
	p.requested = append(p.requested, link)
	return federation.Outbound{URL: "https://idp.example.com/slo?SAMLRequest=x"}, "id-request", nil
}
func (p *protocol) VerifyLogoutResponse(context.Context, federation.Connection, federation.LogoutMessage, string) (bool, error) {
	return p.responseOK == nil, p.responseOK
}
func (p *protocol) LogoutResponseID(federation.LogoutMessage) (string, error) {
	return p.responseID, nil
}

// logouts is an in-memory federation.LogoutRepository.
type logouts struct {
	linked  map[identity.SessionID]federation.LinkedSession
	spent   map[string]bool
	pending map[string]federation.PendingLogout
	ended   int
	fail    error
}

func (l *logouts) LinkedSession(_ context.Context, _ identity.EnvironmentID, session identity.SessionID) (federation.LinkedSession, error) {
	if s, ok := l.linked[session]; ok {
		return s, nil
	}
	return federation.LinkedSession{}, errx.NotFound("resource not found")
}
func (l *logouts) EndLinkedSessions(_ context.Context, _ federation.Connection, r federation.LogoutRequest, _ time.Time) (int, error) {
	if l.fail != nil {
		return 0, l.fail
	}
	if l.spent[r.ID] {
		return 0, errx.Unauthorized("SAML logout request was already used")
	}
	l.spent[r.ID] = true
	l.ended++
	return 1, nil
}
func (l *logouts) SaveLogout(_ context.Context, p federation.PendingLogout) error {
	l.pending[p.RequestID] = p
	return nil
}
func (l *logouts) TakeLogout(_ context.Context, _ identity.EnvironmentID, _ identity.ConnectionID, id string) (federation.PendingLogout, error) {
	p, ok := l.pending[id]
	if !ok || p.Expires.Before(time.Now()) {
		return federation.PendingLogout{}, errx.NotFound("resource not found")
	}
	delete(l.pending, id)
	return p, nil
}
func (l *logouts) PruneLogouts(context.Context) error { return nil }

func logoutSetup(t *testing.T, options federation.Options) (*Service, *protocol, *logouts, federation.Connection) {
	t.Helper()
	c := federation.Connection{ID: identity.NewConnectionID(), Environment: identity.NewEnvironmentID(), Organization: identity.NewOrganizationID(), Provider: federation.ProviderSAML, Options: options}
	p := &protocol{service: federation.LogoutService{Location: "https://idp.example.com/slo", Binding: federation.BindingRedirect}, hasService: true,
		request: federation.LogoutRequest{ID: "req-1", NameID: "u-1", NotOnOrAfter: time.Now().Add(5 * time.Minute)}}
	l := &logouts{linked: map[identity.SessionID]federation.LinkedSession{}, spent: map[string]bool{}, pending: map[string]federation.PendingLogout{}}
	s := &Service{repository: finder{connection: c}}
	s.SetLogout(p, l)
	return s, p, l, c
}

var requestMessage = federation.LogoutMessage{SAMLRequest: "r"}

func TestSingleLogoutRequestEndsSessionsAndAnswers(t *testing.T) {
	s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
	out, err := s.SingleLogout(context.Background(), c.Environment, c.ID, requestMessage)
	if err != nil || out.URL == "" || l.ended != 1 || len(p.statuses) != 1 || p.statuses[0] != federation.StatusSuccess {
		t.Fatalf("%+v %v ended=%d statuses=%v", out, err, l.ended, p.statuses)
	}
	// A replay of the same request ends nothing and is not answered.
	if _, err = s.SingleLogout(context.Background(), c.Environment, c.ID, requestMessage); err == nil || l.ended != 1 || len(p.statuses) != 1 {
		t.Fatalf("replay: %v ended=%d statuses=%v", err, l.ended, p.statuses)
	}
}

func TestSingleLogoutRequestFailureIsPartialLogout(t *testing.T) {
	s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
	l.fail = errors.New("database down")
	if _, err := s.SingleLogout(context.Background(), c.Environment, c.ID, requestMessage); err != nil || len(p.statuses) != 1 || p.statuses[0] != federation.StatusPartialLogout {
		t.Fatalf("%v %v", err, p.statuses)
	}
}

func TestSingleLogoutRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("bad signature answers nothing", func(t *testing.T) {
		s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
		p.verifyErr = errx.Unauthorized("invalid SAML logout message")
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, requestMessage); err == nil || l.ended != 0 || len(p.statuses) != 0 {
			t.Fatalf("%v ended=%d statuses=%v", err, l.ended, p.statuses)
		}
	})
	t.Run("connection without single logout", func(t *testing.T) {
		s, _, l, c := logoutSetup(t, federation.Options{})
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, requestMessage); err == nil || l.ended != 0 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("another environment", func(t *testing.T) {
		s, _, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
		if _, err := s.SingleLogout(ctx, identity.NewEnvironmentID(), c.ID, requestMessage); err == nil || l.ended != 0 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("no logout service in the metadata", func(t *testing.T) {
		s, p, _, c := logoutSetup(t, federation.Options{SingleLogout: true})
		p.hasService = false
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, requestMessage); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("both request and response", func(t *testing.T) {
		s, _, _, c := logoutSetup(t, federation.Options{SingleLogout: true})
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLRequest: "a", SAMLResponse: "b"}); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestBeginLogoutThenResponse(t *testing.T) {
	ctx := context.Background()
	s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
	session := identity.NewSessionID()
	link := authentication.FederationLink{Connection: c.ID, NameID: "u-1", SessionIndex: "idx"}
	l.linked[session] = federation.LinkedSession{Session: session, Environment: c.Environment, Link: link}

	out, ok, err := s.BeginLogout(ctx, c.Environment, session, "https://app.example/bye?state=1")
	if err != nil || !ok || out.URL == "" || len(p.requested) != 1 || p.requested[0] != link {
		t.Fatalf("begin: %+v %v %v", out, ok, err)
	}
	pending := l.pending["id-request"]
	if pending.Connection != c.ID || pending.Redirect != "https://app.example/bye?state=1" || time.Until(pending.Expires) <= 0 {
		t.Fatalf("pending %+v", pending)
	}

	// The identity provider answers: the browser continues to the redirect.
	p.responseID = "id-request"
	next, err := s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLResponse: "x"})
	if err != nil || next.URL != "https://app.example/bye?state=1" || next.Post() {
		t.Fatalf("response: %+v %v", next, err)
	}
	// One use.
	if _, err = s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLResponse: "x"}); err == nil {
		t.Fatal("a response was accepted twice")
	}
}

func TestLogoutResponseRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("unknown request id", func(t *testing.T) {
		s, p, _, c := logoutSetup(t, federation.Options{SingleLogout: true})
		p.responseID = "never-sent"
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLResponse: "x"}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
		l.pending["r"] = federation.PendingLogout{RequestID: "r", Environment: c.Environment, Connection: c.ID, Redirect: "https://app.example/", Expires: time.Now().Add(time.Minute)}
		p.responseID, p.responseOK = "r", errx.Unauthorized("invalid SAML logout message")
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLResponse: "x"}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("expired", func(t *testing.T) {
		s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
		l.pending["r"] = federation.PendingLogout{RequestID: "r", Environment: c.Environment, Connection: c.ID, Expires: time.Now().Add(-time.Minute)}
		p.responseID = "r"
		if _, err := s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLResponse: "x"}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("empty redirect goes to the signed-out page", func(t *testing.T) {
		s, p, l, c := logoutSetup(t, federation.Options{SingleLogout: true})
		l.pending["r"] = federation.PendingLogout{RequestID: "r", Environment: c.Environment, Connection: c.ID, Expires: time.Now().Add(time.Minute)}
		p.responseID = "r"
		out, err := s.SingleLogout(ctx, c.Environment, c.ID, federation.LogoutMessage{SAMLResponse: "x"})
		if err != nil || out.URL != "" {
			t.Fatalf("%+v %v", out, err)
		}
	})
}

func TestBeginLogoutDeclines(t *testing.T) {
	ctx := context.Background()
	t.Run("session without a link", func(t *testing.T) {
		s, p, _, c := logoutSetup(t, federation.Options{SingleLogout: true})
		_, ok, err := s.BeginLogout(ctx, c.Environment, identity.NewSessionID(), "")
		if err != nil || ok || len(p.requested) != 0 {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("single logout switched off since", func(t *testing.T) {
		s, p, l, c := logoutSetup(t, federation.Options{})
		session := identity.NewSessionID()
		l.linked[session] = federation.LinkedSession{Session: session, Environment: c.Environment, Link: authentication.FederationLink{Connection: c.ID, NameID: "u-1"}}
		_, ok, err := s.BeginLogout(ctx, c.Environment, session, "")
		if err != nil || ok || len(p.requested) != 0 {
			t.Fatalf("%v %v", ok, err)
		}
	})
	t.Run("no logout configured", func(t *testing.T) {
		s := &Service{}
		if _, ok, err := s.BeginLogout(ctx, identity.NewEnvironmentID(), identity.NewSessionID(), ""); ok || err != nil {
			t.Fatalf("%v %v", ok, err)
		}
	})
}
