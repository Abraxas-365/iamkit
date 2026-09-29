package samlsvc

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type secrets struct{ n int }

func (s *secrets) Generate(prefix string) (string, []byte, error) {
	s.n++
	raw := prefix + strings.Repeat("x", s.n)
	return raw, s.Hash(raw), nil
}
func (s *secrets) Hash(raw string) []byte { sum := sha256.Sum256([]byte(raw)); return sum[:] }

type request struct {
	pending  samlidp.Pending
	consumed bool
}

type repository struct {
	providers map[identity.ServiceProviderID]samlidp.ServiceProvider
	requests  map[string]*request
	audits    []samlidp.Mutation
}

func (r *repository) Create(ctx context.Context, m samlidp.Mutation, provider samlidp.ServiceProvider) error {
	r.providers[provider.ID] = provider
	r.audits = append(r.audits, m)
	return nil
}
func (r *repository) Update(ctx context.Context, m samlidp.Mutation, provider identity.ServiceProviderID, input samlidp.Update) error {
	r.audits = append(r.audits, m)
	return nil
}
func (r *repository) Delete(ctx context.Context, m samlidp.Mutation, provider identity.ServiceProviderID) error {
	delete(r.providers, provider)
	r.audits = append(r.audits, m)
	return nil
}
func (r *repository) Find(ctx context.Context, environment identity.EnvironmentID, provider identity.ServiceProviderID) (samlidp.ServiceProvider, error) {
	sp, ok := r.providers[provider]
	if !ok || sp.Environment != environment {
		return samlidp.ServiceProvider{}, errx.NotFound("service provider not found")
	}
	return sp, nil
}
func (r *repository) FindEntity(ctx context.Context, environment identity.EnvironmentID, entity string) (samlidp.ServiceProvider, error) {
	for _, sp := range r.providers {
		if sp.Environment == environment && sp.EntityID == entity {
			return sp, nil
		}
	}
	return samlidp.ServiceProvider{}, errx.NotFound("service provider not found")
}
func (r *repository) List(ctx context.Context, environment identity.EnvironmentID, filter samlidp.Filter, page query.Pagination) (query.Paginated[samlidp.ServiceProvider], error) {
	return query.Paginated[samlidp.ServiceProvider]{}, nil
}
func (r *repository) EnvironmentExists(ctx context.Context, environment identity.EnvironmentID) (bool, error) {
	return !environment.IsZero(), nil
}
func (r *repository) SaveRequest(ctx context.Context, ticket, binding []byte, environment identity.EnvironmentID, req samlidp.Request) error {
	r.requests[string(ticket)] = &request{pending: samlidp.Pending{Request: req, Environment: environment, Binding: binding}}
	return nil
}
func (r *repository) PendingRequest(ctx context.Context, ticket []byte) (samlidp.Pending, error) {
	req, ok := r.requests[string(ticket)]
	if !ok || req.consumed {
		return samlidp.Pending{}, errx.Unauthorized("invalid authorization ticket")
	}
	return req.pending, nil
}
func (r *repository) ConsumeRequest(ctx context.Context, m samlidp.Mutation, ticket []byte) error {
	req, ok := r.requests[string(ticket)]
	if !ok || req.consumed {
		return errx.Unauthorized("invalid authorization ticket")
	}
	req.consumed = true
	r.audits = append(r.audits, m)
	return nil
}
func (r *repository) Subject(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (samlidp.Subject, error) {
	return samlidp.Subject{Email: "ada@example.com", Name: "Ada"}, nil
}

type protocol struct {
	decoded   samlidp.AuthnRequest
	responses int
}

const sso = "https://iam.example.com/saml/env/sso"

func (p *protocol) Decode(message samlidp.Message) (samlidp.AuthnRequest, error) {
	out := p.decoded
	out.RelayState = message.RelayState
	return out, nil
}
func (p *protocol) IdentityProvider(ctx context.Context, environment identity.EnvironmentID) (samlidp.IdentityProvider, error) {
	return samlidp.IdentityProvider{SSOURL: sso}, nil
}
func (p *protocol) Metadata(ctx context.Context, environment identity.EnvironmentID) ([]byte, error) {
	return []byte("<md/>"), nil
}
func (p *protocol) Respond(ctx context.Context, environment identity.EnvironmentID, provider samlidp.ServiceProvider, req samlidp.Request, assertion samlidp.Assertion) (samlidp.Response, error) {
	p.responses++
	return samlidp.Response{Environment: environment, ACSURL: req.ACSURL, SAMLResponse: assertion.NameID + "|" + req.ID, RelayState: req.RelayState}, nil
}

func setup(t *testing.T) (*Service, *repository, *protocol, samlidp.ServiceProvider) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	repo := &repository{providers: map[identity.ServiceProviderID]samlidp.ServiceProvider{}, requests: map[string]*request{}}
	proto := &protocol{decoded: samlidp.AuthnRequest{ID: "req-1", Issuer: "https://wiki.example.com", Version: "2.0", IssueInstant: now, Destination: sso}}
	svc := New(repo, proto, &secrets{})
	svc.now = func() time.Time { return now }
	environment := identity.NewEnvironmentID()
	sp, err := svc.Create(context.Background(), samlidp.Mutation{Environment: environment, Actor: "op"}, samlidp.Create{Name: " Wiki ", Application: identity.NewApplicationID(), Resource: identity.NewResourceID(), EntityID: "https://wiki.example.com", ACSURLs: []string{"https://wiki.example.com/acs"}})
	if err != nil {
		t.Fatal(err)
	}
	return svc, repo, proto, sp
}

func TestCreateDefaultsAndAudit(t *testing.T) {
	_, repo, _, sp := setup(t)
	if sp.Name != "Wiki" || sp.NameIDFormat != samlidp.NameIDEmail || sp.Attributes == nil {
		t.Fatalf("defaults: %+v", sp)
	}
	if len(repo.audits) != 1 || repo.audits[0].Action != samlidp.ActionCreate || repo.audits[0].Target != sp.ID.String() {
		t.Fatalf("audit: %+v", repo.audits)
	}
}

func TestSingleSignOn(t *testing.T) {
	svc, repo, proto, sp := setup(t)
	ctx := context.Background()
	ticket, binding, err := svc.Begin(ctx, sp.Environment, samlidp.Message{Redirect: true, SAMLRequest: "x", RelayState: "state"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ticket, samlidp.TicketPrefix) || !strings.HasPrefix(binding, "ik_browser_") {
		t.Fatalf("ticket %q binding %q", ticket, binding)
	}
	target, err := svc.Target(ctx, ticket, binding)
	if err != nil || target.Application != sp.Application || target.Resource != sp.Resource || target.Environment != sp.Environment {
		t.Fatalf("target: %+v %v", target, err)
	}
	if _, err := svc.Target(ctx, ticket, "ik_browser_other"); err == nil {
		t.Fatal("another browser's binding accepted")
	}
	if _, err := svc.Target(ctx, "ik_authorize_x", binding); err == nil {
		t.Fatal("non-SAML ticket accepted")
	}
	login := samlidp.Login{User: identity.NewUserID(), Session: identity.NewSessionID()}
	if _, err := svc.Finish(ctx, ticket, binding, samlidp.Login{}); err == nil {
		t.Fatal("finished without a session")
	}
	response, err := svc.Finish(ctx, ticket, binding, login)
	if err != nil {
		t.Fatal(err)
	}
	if response.ACSURL != "https://wiki.example.com/acs" || response.SAMLResponse != "ada@example.com|req-1" || response.RelayState != "state" {
		t.Fatalf("response: %+v", response)
	}
	last := repo.audits[len(repo.audits)-1]
	if last.Action != samlidp.ActionAssertion || last.Actor != login.User.String() || last.Target != sp.ID.String() {
		t.Fatalf("audit: %+v", last)
	}
	if _, err := svc.Finish(ctx, ticket, binding, login); err == nil {
		t.Fatal("ticket used twice")
	}
	if proto.responses != 1 {
		t.Fatalf("responses signed: %d", proto.responses)
	}
}

func TestBeginRefuses(t *testing.T) {
	svc, _, proto, sp := setup(t)
	ctx := context.Background()
	if _, _, err := svc.Begin(ctx, identity.EnvironmentID{}, samlidp.Message{SAMLRequest: "x"}); err == nil {
		t.Fatal("zero environment accepted")
	}
	if _, _, err := svc.Begin(ctx, identity.NewEnvironmentID(), samlidp.Message{SAMLRequest: "x"}); err == nil {
		t.Fatal("service provider of another environment accepted")
	}
	proto.decoded.ACSURL = "https://evil.example/acs"
	if _, _, err := svc.Begin(ctx, sp.Environment, samlidp.Message{SAMLRequest: "x"}); err == nil {
		t.Fatal("unregistered ACS accepted")
	}
	proto.decoded.ACSURL = ""
	proto.decoded.Issuer = "https://unknown.example.com"
	if _, _, err := svc.Begin(ctx, sp.Environment, samlidp.Message{SAMLRequest: "x"}); err == nil {
		t.Fatal("unknown issuer accepted")
	}
}
