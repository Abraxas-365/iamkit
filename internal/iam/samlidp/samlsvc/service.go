// Package samlsvc implements the SAML identity provider: service provider
// management and the single sign-on flow.
package samlsvc

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository samlidp.Repository
	protocol   samlidp.Protocol
	secrets    samlidp.Secrets
	now        func() time.Time
}

var (
	_ samlidp.Commands = (*Service)(nil)
	_ samlidp.Queries  = (*Service)(nil)
	_ samlidp.Flows    = (*Service)(nil)
)

func New(repository samlidp.Repository, protocol samlidp.Protocol, secrets samlidp.Secrets) *Service {
	return &Service{repository: repository, protocol: protocol, secrets: secrets, now: time.Now}
}

func (s *Service) Create(ctx context.Context, m samlidp.Mutation, input samlidp.Create) (samlidp.ServiceProvider, error) {
	input = input.WithDefaults()
	if err := input.Validate(); err != nil {
		return samlidp.ServiceProvider{}, err
	}
	id := identity.NewServiceProviderID()
	m.Action, m.Target = samlidp.ActionCreate, id.String()
	sp := samlidp.ServiceProvider{ID: id, Environment: m.Environment, Name: input.Name, Application: input.Application, Resource: input.Resource, EntityID: input.EntityID, ACSURLs: input.ACSURLs, NameIDFormat: input.NameIDFormat, Attributes: input.Attributes}
	if err := s.repository.Create(ctx, m, sp); err != nil {
		return samlidp.ServiceProvider{}, err
	}
	return s.repository.Find(ctx, m.Environment, id)
}

func (s *Service) Update(ctx context.Context, m samlidp.Mutation, id identity.ServiceProviderID, input samlidp.Update) (samlidp.ServiceProvider, error) {
	if id.IsZero() {
		return samlidp.ServiceProvider{}, errx.Validation("service_provider_id must be a valid UUID")
	}
	if err := input.Validate(); err != nil {
		return samlidp.ServiceProvider{}, err
	}
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		input.Name = &name
	}
	m.Action, m.Target = samlidp.ActionUpdate, id.String()
	if err := s.repository.Update(ctx, m, id, input); err != nil {
		return samlidp.ServiceProvider{}, err
	}
	return s.repository.Find(ctx, m.Environment, id)
}

func (s *Service) Delete(ctx context.Context, m samlidp.Mutation, id identity.ServiceProviderID) error {
	if id.IsZero() {
		return errx.Validation("service_provider_id must be a valid UUID")
	}
	m.Action, m.Target = samlidp.ActionDelete, id.String()
	return s.repository.Delete(ctx, m, id)
}

func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, filter samlidp.Filter, page query.Pagination) (query.Paginated[samlidp.ServiceProvider], error) {
	return s.repository.List(ctx, environment, filter, page)
}

func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ServiceProviderID) (samlidp.ServiceProvider, error) {
	if id.IsZero() {
		return samlidp.ServiceProvider{}, errx.Validation("service_provider_id must be a valid UUID")
	}
	return s.repository.Find(ctx, environment, id)
}

func (s *Service) IdentityProvider(ctx context.Context, environment identity.EnvironmentID) (samlidp.IdentityProvider, error) {
	if err := s.environment(ctx, environment); err != nil {
		return samlidp.IdentityProvider{}, err
	}
	return s.protocol.IdentityProvider(ctx, environment)
}

func (s *Service) Metadata(ctx context.Context, environment identity.EnvironmentID) ([]byte, error) {
	if err := s.environment(ctx, environment); err != nil {
		return nil, err
	}
	return s.protocol.Metadata(ctx, environment)
}

func (s *Service) environment(ctx context.Context, environment identity.EnvironmentID) error {
	if environment.IsZero() {
		return errx.NotFound("environment not found")
	}
	ok, err := s.repository.EnvironmentExists(ctx, environment)
	if err != nil {
		return err
	}
	if !ok {
		return errx.NotFound("environment not found")
	}
	return nil
}

// Begin checks the AuthnRequest against its registered service provider
// and parks it for the hosted sign-in.
func (s *Service) Begin(ctx context.Context, environment identity.EnvironmentID, message samlidp.Message) (string, string, error) {
	if err := s.environment(ctx, environment); err != nil {
		return "", "", err
	}
	request, err := s.protocol.Decode(message)
	if err != nil {
		return "", "", err
	}
	sp, err := s.repository.FindEntity(ctx, environment, request.Issuer)
	if err != nil {
		return "", "", err
	}
	idp, err := s.protocol.IdentityProvider(ctx, environment)
	if err != nil {
		return "", "", err
	}
	checked, err := request.Check(idp.SSOURL, s.now(), sp)
	if err != nil {
		return "", "", err
	}
	ticket, hash, err := s.secrets.Generate(samlidp.TicketPrefix)
	if err != nil {
		return "", "", err
	}
	binding, bindingHash, err := s.secrets.Generate("ik_browser_")
	if err != nil {
		return "", "", err
	}
	return ticket, binding, s.repository.SaveRequest(ctx, hash, bindingHash, environment, checked)
}

func (s *Service) pending(ctx context.Context, ticket, binding string) (samlidp.Pending, samlidp.ServiceProvider, error) {
	if !strings.HasPrefix(ticket, samlidp.TicketPrefix) || binding == "" {
		return samlidp.Pending{}, samlidp.ServiceProvider{}, invalidTicket()
	}
	p, err := s.repository.PendingRequest(ctx, s.secrets.Hash(ticket))
	if err != nil {
		return samlidp.Pending{}, samlidp.ServiceProvider{}, err
	}
	if subtle.ConstantTimeCompare(p.Binding, s.secrets.Hash(binding)) != 1 {
		return samlidp.Pending{}, samlidp.ServiceProvider{}, invalidTicket()
	}
	sp, err := s.repository.Find(ctx, p.Environment, p.ServiceProvider)
	if err != nil {
		return samlidp.Pending{}, samlidp.ServiceProvider{}, invalidTicket()
	}
	return p, sp, nil
}

func invalidTicket() error {
	return errx.Unauthorized("invalid authorization ticket or browser binding")
}

func (s *Service) Target(ctx context.Context, ticket, binding string) (samlidp.Target, error) {
	p, sp, err := s.pending(ctx, ticket, binding)
	if err != nil {
		return samlidp.Target{}, err
	}
	return samlidp.Target{Environment: p.Environment, Application: sp.Application, Resource: sp.Resource, ServiceProvider: sp.ID, Name: sp.Name}, nil
}

// Finish signs the response first and then uses the ticket (audited), so a
// replayed ticket never produces a second response.
func (s *Service) Finish(ctx context.Context, ticket, binding string, login samlidp.Login) (samlidp.Response, error) {
	p, sp, err := s.pending(ctx, ticket, binding)
	if err != nil {
		return samlidp.Response{}, err
	}
	if login.User.IsZero() || login.Session.IsZero() {
		return samlidp.Response{}, errx.Unauthorized("invalid session context")
	}
	subject, err := s.repository.Subject(ctx, p.Environment, login.User)
	if err != nil {
		return samlidp.Response{}, err
	}
	response, err := s.protocol.Respond(ctx, p.Environment, sp, p.Request, sp.Assert(login, subject))
	if err != nil {
		return samlidp.Response{}, err
	}
	m := samlidp.Mutation{Environment: p.Environment, Actor: login.User.String(), Action: samlidp.ActionAssertion, Target: sp.ID.String()}
	if err := s.repository.ConsumeRequest(ctx, m, s.secrets.Hash(ticket)); err != nil {
		return samlidp.Response{}, err
	}
	return response, nil
}
