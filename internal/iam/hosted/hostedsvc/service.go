// Package hostedsvc implements the hosted sign-in journey and its branding.
package hostedsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository     hosted.Repository
	secrets        hosted.Secrets
	authorizations hosted.Authorizations
	authenticator  authentication.Authenticator
	challenges     hosted.Challenges
	federation     hosted.Federation
	now            func() time.Time
}

func New(repository hosted.Repository, secrets hosted.Secrets, authorizations hosted.Authorizations, authenticator authentication.Authenticator, challenges hosted.Challenges, federation hosted.Federation) *Service {
	return &Service{repository: repository, secrets: secrets, authorizations: authorizations, authenticator: authenticator, challenges: challenges, federation: federation, now: time.Now}
}

var (
	_ hosted.Flow     = (*Service)(nil)
	_ hosted.Commands = (*Service)(nil)
	_ hosted.Queries  = (*Service)(nil)
)

// pending checks the authorization and that its client uses hosted login.
func (s *Service) pending(ctx context.Context, r hosted.Request) (authentication.Target, error) {
	p, err := s.authorizations.Pending(ctx, r.Ticket, r.Binding)
	if err != nil {
		return authentication.Target{}, err
	}
	if !p.Client.HostedLogin {
		return authentication.Target{}, errx.Forbidden("client does not use hosted login")
	}
	return authentication.Target{Environment: p.Client.Environment, Application: p.Client.Application, Resource: p.Client.Resource}, nil
}

func (s *Service) Page(ctx context.Context, r hosted.Request) (hosted.Page, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return hosted.Page{}, err
	}
	settings, err := s.repository.Settings(ctx, target.Environment)
	if err != nil {
		return hosted.Page{}, err
	}
	connections, err := s.federation.EnvironmentConnections(ctx, target.Environment)
	if err != nil {
		return hosted.Page{}, err
	}
	return hosted.Page{Settings: settings, Connections: connections}, nil
}

// Identify routes the email: enforced organization SSO starts at once;
// otherwise password, offering the organization's SSO when it has one.
func (s *Service) Identify(ctx context.Context, r hosted.Request, email string) (hosted.Route, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return hosted.Route{}, err
	}
	d, err := s.federation.Discover(ctx, target.Environment, email)
	if err != nil {
		return hosted.Route{}, err
	}
	if d.Method != federation.MethodSSO || d.Connection == nil {
		return hosted.Route{Method: federation.MethodPassword}, nil
	}
	if !d.Required {
		return hosted.Route{Method: federation.MethodPassword, Connection: d.Connection}, nil
	}
	start, err := s.federation.StartHosted(ctx, target, *d.Connection, r.Ticket)
	if err != nil {
		return hosted.Route{}, err
	}
	return hosted.Route{Method: federation.MethodSSO, Redirect: start.URL, Binding: start.Binding, Connection: d.Connection}, nil
}

func (s *Service) Password(ctx context.Context, r hosted.Request, email, password string) (hosted.Result, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	verified, err := s.authenticator.VerifyPassword(ctx, target.Environment, email, password)
	if err != nil {
		return hosted.Result{}, err
	}
	return s.result(ctx, r, target, verified)
}

func (s *Service) SendCode(ctx context.Context, r hosted.Request, email string) (identity.ChallengeID, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	return s.challenges.InitiateChallenge(ctx, target.Environment, email, "login")
}

func (s *Service) VerifyCode(ctx context.Context, r hosted.Request, challenge identity.ChallengeID, code string) (hosted.Result, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	verified, err := s.authenticator.VerifyCode(ctx, target.Environment, challenge, code)
	if err != nil {
		return hosted.Result{}, err
	}
	return s.result(ctx, r, target, verified)
}

func (s *Service) SendReset(ctx context.Context, r hosted.Request, email string) (identity.ChallengeID, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	return s.challenges.InitiateChallenge(ctx, target.Environment, email, "password_reset")
}

func (s *Service) Reset(ctx context.Context, r hosted.Request, challenge identity.ChallengeID, code, password string) error {
	target, err := s.pending(ctx, r)
	if err != nil {
		return err
	}
	_, err = s.challenges.VerifyChallenge(ctx, authentication.Context{EnvironmentID: target.Environment}, challenge, code, "password_reset", password)
	return err
}

func (s *Service) SSO(ctx context.Context, r hosted.Request, connection identity.ConnectionID) (federation.Start, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return federation.Start{}, err
	}
	return s.federation.StartHosted(ctx, target, connection, r.Ticket)
}

func (s *Service) Federated(ctx context.Context, r hosted.Request, verified authentication.Verified) (hosted.Result, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	return s.result(ctx, r, target, verified)
}

// result signs in to the only possible organization, or keeps the verified
// user until one of several is chosen.
func (s *Service) result(ctx context.Context, r hosted.Request, target authentication.Target, verified authentication.Verified) (hosted.Result, error) {
	organizations, err := s.authenticator.Organizations(ctx, target, verified.User)
	if err != nil {
		return hosted.Result{}, err
	}
	if !verified.Organization.IsZero() {
		// Organization SSO signs in to its own organization only.
		organizations = only(organizations, verified.Organization)
	}
	switch len(organizations) {
	case 0:
		return hosted.Result{}, hosted.ErrNoAccess()
	case 1:
		login, err := s.issue(ctx, target, organizations[0].ID, verified)
		if err != nil {
			return hosted.Result{}, err
		}
		return hosted.Result{Login: &login}, nil
	}
	if err = s.repository.SaveLogin(ctx, s.secrets.Hash(r.Ticket), target.Environment, verified, s.now().Add(config.OAuthAuthorizationTicketTTL)); err != nil {
		return hosted.Result{}, err
	}
	return hosted.Result{Organizations: organizations}, nil
}

func (s *Service) Choose(ctx context.Context, r hosted.Request, organization identity.OrganizationID) (oauth.Login, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return oauth.Login{}, err
	}
	if organization.IsZero() {
		return oauth.Login{}, errx.Validation("choose an organization")
	}
	hash := s.secrets.Hash(r.Ticket)
	verified, err := s.repository.Login(ctx, hash, target.Environment)
	if err != nil {
		return oauth.Login{}, err
	}
	login, err := s.issue(ctx, target, organization, verified)
	if err != nil {
		return oauth.Login{}, err
	}
	return login, s.repository.DeleteLogin(ctx, hash)
}

func (s *Service) issue(ctx context.Context, target authentication.Target, organization identity.OrganizationID, verified authentication.Verified) (oauth.Login, error) {
	issued, err := s.authenticator.Issue(ctx, target.Boundary(organization), verified)
	if err != nil {
		return oauth.Login{}, err
	}
	return oauth.Login{User: issued.User, Organization: issued.Context.OrganizationID, Session: issued.Session, Permissions: issued.Access.Permissions}, nil
}

func only(organizations []authentication.Organization, id identity.OrganizationID) []authentication.Organization {
	for _, o := range organizations {
		if o.ID == id {
			return []authentication.Organization{o}
		}
	}
	return nil
}

func (s *Service) Settings(ctx context.Context, environment identity.EnvironmentID) (hosted.Settings, error) {
	if environment.IsZero() {
		return hosted.Settings{}, errx.Validation("environment_id is required")
	}
	return s.repository.Settings(ctx, environment)
}

func (s *Service) SaveSettings(ctx context.Context, m hosted.Mutation, input hosted.Settings) (hosted.Settings, error) {
	if err := input.Validate(); err != nil {
		return hosted.Settings{}, err
	}
	input.Environment = m.Environment
	return s.repository.SaveSettings(ctx, m, input)
}
