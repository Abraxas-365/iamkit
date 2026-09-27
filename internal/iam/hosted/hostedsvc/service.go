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
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
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
	second         hosted.SecondFactor
	now            func() time.Time
}

// New builds the hosted flow; second may be nil (no multi-factor step).
func New(repository hosted.Repository, secrets hosted.Secrets, authorizations hosted.Authorizations, authenticator authentication.Authenticator, challenges hosted.Challenges, federation hosted.Federation, second hosted.SecondFactor) *Service {
	return &Service{repository: repository, secrets: secrets, authorizations: authorizations, authenticator: authenticator, challenges: challenges, federation: federation, second: second, now: time.Now}
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

// result continues after a first factor.
func (s *Service) result(ctx context.Context, r hosted.Request, target authentication.Target, verified authentication.Verified) (hosted.Result, error) {
	return s.step(ctx, r, target, hosted.Login{Verified: verified})
}

// step moves a verified login forward: a user who has an authenticator
// proves it before choosing among several organizations; once the
// organization is known, its policy may require a second factor (or
// enrollment); then the session is issued. Between steps the login is
// parked under the authorization ticket.
func (s *Service) step(ctx context.Context, r hosted.Request, target authentication.Target, login hosted.Login) (hosted.Result, error) {
	verified := login.Verified
	organizations, err := s.authenticator.Organizations(ctx, target, verified.User)
	if err != nil {
		return hosted.Result{}, err
	}
	if !verified.Organization.IsZero() {
		// Organization SSO signs in to its own organization only.
		organizations = only(organizations, verified.Organization)
	}
	if !login.Chosen.IsZero() {
		organizations = only(organizations, login.Chosen)
	}
	if len(organizations) == 0 {
		return hosted.Result{}, hosted.ErrNoAccess()
	}
	proven := authentication.HasMFA(verified.AMR)
	if len(organizations) > 1 {
		if s.second != nil && !proven && !verified.Federated() {
			// Any organization will do: a user with a factor needs it in all.
			req, err := s.second.Requirement(ctx, target.Boundary(organizations[0].ID), verified.User, false)
			if err != nil {
				return hosted.Result{}, err
			}
			if req.Needed && !req.Enroll {
				return hosted.Result{SecondFactor: true}, s.park(ctx, r, target, login)
			}
		}
		return hosted.Result{Organizations: organizations}, s.park(ctx, r, target, login)
	}
	organization := organizations[0].ID
	login.Chosen = organization
	if s.second != nil && !proven {
		req, err := s.second.Requirement(ctx, target.Boundary(organization), verified.User, verified.Federated())
		if err != nil {
			return hosted.Result{}, err
		}
		if req.Needed {
			if err = s.park(ctx, r, target, login); err != nil {
				return hosted.Result{}, err
			}
			if !req.Enroll {
				return hosted.Result{SecondFactor: true}, nil
			}
			enrollment, err := s.second.Enrolling(ctx, target.Environment, verified.User)
			if err != nil {
				return hosted.Result{}, err
			}
			return hosted.Result{Enroll: &enrollment}, nil
		}
	}
	issued, err := s.authenticator.Issue(ctx, target.Boundary(organization), verified)
	if err != nil {
		return hosted.Result{}, err
	}
	if err = s.repository.DeleteLogin(ctx, s.secrets.Hash(r.Ticket)); err != nil {
		return hosted.Result{}, err
	}
	return hosted.Result{Login: &oauth.Login{User: issued.User, Organization: issued.Context.OrganizationID, Session: issued.Session, Permissions: issued.Access.Permissions}}, nil
}

func (s *Service) park(ctx context.Context, r hosted.Request, target authentication.Target, login hosted.Login) error {
	return s.repository.SaveLogin(ctx, s.secrets.Hash(r.Ticket), target.Environment, login, s.now().Add(config.OAuthAuthorizationTicketTTL))
}

// parked loads the login parked under the authorization.
func (s *Service) parked(ctx context.Context, r hosted.Request) (authentication.Target, hosted.Login, error) {
	target, err := s.pending(ctx, r)
	if err != nil {
		return target, hosted.Login{}, err
	}
	login, err := s.repository.Login(ctx, s.secrets.Hash(r.Ticket), target.Environment)
	return target, login, err
}

func (s *Service) Choose(ctx context.Context, r hosted.Request, organization identity.OrganizationID) (hosted.Result, error) {
	if organization.IsZero() {
		return hosted.Result{}, errx.Validation("choose an organization")
	}
	target, login, err := s.parked(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	if !login.Chosen.IsZero() && login.Chosen != organization {
		return hosted.Result{}, errx.Validation("the organization was already chosen")
	}
	login.Chosen = organization
	return s.step(ctx, r, target, login)
}

// enrolling reports whether the parked login is adding its first factor:
// the chosen organization requires one the user does not have.
func (s *Service) enrolling(ctx context.Context, target authentication.Target, login hosted.Login) (bool, error) {
	if login.Chosen.IsZero() {
		return false, nil
	}
	req, err := s.second.Requirement(ctx, target.Boundary(login.Chosen), login.Verified.User, login.Verified.Federated())
	return req.Enroll, err
}

func (s *Service) SecondFactor(ctx context.Context, r hosted.Request, code string) (hosted.Result, error) {
	if s.second == nil {
		return hosted.Result{}, errx.NotFound("multi-factor authentication is not enabled")
	}
	target, login, err := s.parked(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	hash := s.secrets.Hash(r.Ticket)
	if authentication.HasMFA(login.Verified.AMR) {
		return s.step(ctx, r, target, login)
	}
	enroll, err := s.enrolling(ctx, target, login)
	if err != nil {
		return hosted.Result{}, err
	}
	// The try is reserved before the code is checked so parallel posts
	// cannot share one count.
	allowed, err := s.repository.Attempt(ctx, hash, config.MFAAttempts)
	if err != nil {
		return hosted.Result{}, err
	}
	if !allowed {
		if err = s.repository.DeleteLogin(ctx, hash); err != nil {
			return hosted.Result{}, err
		}
		return hosted.Result{}, hosted.ErrLoginExpired()
	}
	v, err := s.second.Verify(ctx, target.Environment, login.Verified.User, code, enroll)
	if err != nil {
		return hosted.Result{}, err
	}
	login.Verified.AMR = append(login.Verified.AMR, mfa.AMR(v.Proof)...)
	if len(v.RecoveryCodes) > 0 {
		// Shown once; the user continues from that page.
		return hosted.Result{RecoveryCodes: v.RecoveryCodes}, s.park(ctx, r, target, login)
	}
	return s.step(ctx, r, target, login)
}

func (s *Service) Enrollment(ctx context.Context, r hosted.Request) (authentication.Enrollment, error) {
	if s.second == nil {
		return authentication.Enrollment{}, errx.NotFound("multi-factor authentication is not enabled")
	}
	target, login, err := s.parked(ctx, r)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	enroll, err := s.enrolling(ctx, target, login)
	if err != nil {
		return authentication.Enrollment{}, err
	}
	if !enroll {
		return authentication.Enrollment{}, errx.Business("this sign-in does not need an authenticator")
	}
	return s.second.Enrolling(ctx, target.Environment, login.Verified.User)
}

func (s *Service) Continue(ctx context.Context, r hosted.Request) (hosted.Result, error) {
	target, login, err := s.parked(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	return s.step(ctx, r, target, login)
}

func unauthorized(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.HTTPStatus == 401
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
