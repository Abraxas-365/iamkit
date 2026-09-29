// Package hostedsvc implements the hosted sign-in journey and its branding.
package hostedsvc

import (
	"context"
	"net/url"
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/mfa"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
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
	client, err := s.client(ctx, r)
	if err != nil {
		return authentication.Target{}, err
	}
	return authentication.Target{Environment: client.Environment, Application: client.Application, Resource: client.Resource}, nil
}

func (s *Service) client(ctx context.Context, r hosted.Request) (*oauth.Client, error) {
	p, err := s.pendingHosted(ctx, r)
	return p.Client, err
}

// pendingHosted is the pending authorization of a hosted login client.
func (s *Service) pendingHosted(ctx context.Context, r hosted.Request) (oauth.Pending, error) {
	p, err := s.authorizations.Pending(ctx, r.Ticket, r.Binding)
	if err != nil {
		return oauth.Pending{}, err
	}
	if !p.Client.HostedLogin {
		return oauth.Pending{}, errx.Forbidden("client does not use hosted login")
	}
	return p, nil
}

// uiLocales is the ui_locales parameter of the authorization request, the
// languages the application asked for ("" when none).
func uiLocales(p oauth.Pending) string {
	form, err := url.ParseQuery(p.Form)
	if err != nil {
		return ""
	}
	return form.Get("ui_locales")
}

// Page brands the journey with the client's own style, or the
// environment default when it has none.
func (s *Service) Page(ctx context.Context, r hosted.Request) (hosted.Page, error) {
	p, err := s.pendingHosted(ctx, r)
	if err != nil {
		return hosted.Page{}, err
	}
	client := p.Client
	settings, err := s.style(ctx, client.Environment, client.ID)
	if err != nil {
		return hosted.Page{}, err
	}
	options, err := s.SignIn(ctx, client.Environment, client.ID)
	if err != nil {
		return hosted.Page{}, err
	}
	connections, err := s.federation.EnvironmentConnections(ctx, client.Environment)
	if err != nil {
		return hosted.Page{}, err
	}
	language, err := s.language(ctx, p, settings)
	if err != nil {
		return hosted.Page{}, err
	}
	return hosted.Page{Settings: settings, SignIn: options, Connections: options.Offered(connections), Language: language}, nil
}

// language is the page language: the application's ui_locales, else the
// environment language (client styles have none: it is the default's).
func (s *Service) language(ctx context.Context, p oauth.Pending, settings hosted.Settings) (string, error) {
	if code := i18n.Match(uiLocales(p)); code != "" {
		return code, nil
	}
	if settings.Locale == nil {
		environment, err := s.repository.Settings(ctx, p.Client.Environment)
		if err != nil {
			return "", err
		}
		settings.Locale = environment.Locale
	}
	if settings.Locale == nil {
		return "", nil
	}
	return i18n.Match(*settings.Locale), nil
}

// offered checks the pending authorization and that its client offers the
// method.
func (s *Service) offered(ctx context.Context, r hosted.Request, method func(hosted.SignIn) bool) (authentication.Target, hosted.SignIn, error) {
	target, options, _, err := s.offering(ctx, r, method)
	return target, options, err
}

// offering is offered with the pending authorization.
func (s *Service) offering(ctx context.Context, r hosted.Request, method func(hosted.SignIn) bool) (authentication.Target, hosted.SignIn, oauth.Pending, error) {
	p, err := s.pendingHosted(ctx, r)
	if err != nil {
		return authentication.Target{}, hosted.SignIn{}, oauth.Pending{}, err
	}
	client := p.Client
	options, err := s.SignIn(ctx, client.Environment, client.ID)
	if err != nil {
		return authentication.Target{}, hosted.SignIn{}, oauth.Pending{}, err
	}
	if !method(options) {
		return authentication.Target{}, hosted.SignIn{}, oauth.Pending{}, hosted.ErrMethodUnavailable()
	}
	return authentication.Target{Environment: client.Environment, Application: client.Application, Resource: client.Resource}, options, p, nil
}

func password(o hosted.SignIn) bool  { return o.Password }
func emailCode(o hosted.SignIn) bool { return o.EmailCode }
func emailForm(o hosted.SignIn) bool { return o.EmailForm() }

// Identify routes the email: enforced organization SSO starts at once;
// otherwise password, offering the organization's SSO when it has one.
//
// A client that does not offer organization SSO never routes to it: an
// organization that enforces SSO then cannot sign in to it at all, which
// the page says rather than letting a password attempt fail. A client that
// offers only organization SSO accepts only emails that have it.
func (s *Service) Identify(ctx context.Context, r hosted.Request, email string) (hosted.Route, error) {
	target, options, err := s.offered(ctx, r, emailForm)
	if err != nil {
		return hosted.Route{}, err
	}
	d, err := s.federation.Discover(ctx, target.Environment, email)
	if err != nil {
		return hosted.Route{}, err
	}
	sso := d.Method == federation.MethodSSO && d.Connection != nil
	switch {
	case sso && d.Required && !options.OrganizationSSO:
		e := errx.Forbidden("your organization requires single sign-on, which this application does not offer")
		e.Code = "SSO_REQUIRED"
		return hosted.Route{}, e
	case !options.Password && !options.EmailCode && (!sso || !options.OrganizationSSO):
		return hosted.Route{}, errx.Forbidden("this email cannot sign in to this application with single sign-on")
	case !sso || !options.OrganizationSSO:
		return hosted.Route{Method: federation.MethodPassword}, nil
	case !d.Required && (options.Password || options.EmailCode):
		return hosted.Route{Method: federation.MethodPassword, Connection: d.Connection}, nil
	}
	start, err := s.federation.StartHosted(ctx, target, *d.Connection, r.Ticket)
	if err != nil {
		return hosted.Route{}, err
	}
	return hosted.Route{Method: federation.MethodSSO, Redirect: start.URL, Binding: start.Binding, Connection: d.Connection}, nil
}

func (s *Service) Password(ctx context.Context, r hosted.Request, email, secret string) (hosted.Result, error) {
	target, _, err := s.offered(ctx, r, password)
	if err != nil {
		return hosted.Result{}, err
	}
	verified, err := s.authenticator.VerifyPassword(ctx, target.Environment, email, secret)
	if err != nil {
		return hosted.Result{}, err
	}
	return s.result(ctx, r, target, verified)
}

func (s *Service) SendCode(ctx context.Context, r hosted.Request, email string) (identity.ChallengeID, error) {
	target, _, p, err := s.offering(ctx, r, emailCode)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	return s.challenges.InitiateChallenge(ctx, target.Environment, email, "login", uiLocales(p))
}

func (s *Service) VerifyCode(ctx context.Context, r hosted.Request, challenge identity.ChallengeID, code string) (hosted.Result, error) {
	target, _, err := s.offered(ctx, r, emailCode)
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
	target, _, p, err := s.offering(ctx, r, password)
	if err != nil {
		return identity.ChallengeID{}, err
	}
	return s.challenges.InitiateChallenge(ctx, target.Environment, email, "password_reset", uiLocales(p))
}

func (s *Service) Reset(ctx context.Context, r hosted.Request, challenge identity.ChallengeID, code, secret string) error {
	target, _, err := s.offered(ctx, r, password)
	if err != nil {
		return err
	}
	_, err = s.challenges.VerifyChallenge(ctx, authentication.Context{EnvironmentID: target.Environment}, challenge, code, "password_reset", secret)
	return err
}

// SSO starts an offered environment connection, or the organization
// connection the email form routed to when the client offers organization
// SSO (StartHosted checks it is active in the environment).
func (s *Service) SSO(ctx context.Context, r hosted.Request, connection identity.ConnectionID) (federation.Start, error) {
	target, options, err := s.offered(ctx, r, func(hosted.SignIn) bool { return true })
	if err != nil {
		return federation.Start{}, err
	}
	environment, err := s.federation.EnvironmentConnections(ctx, target.Environment)
	if err != nil {
		return federation.Start{}, err
	}
	shared := slices.ContainsFunc(environment, func(c federation.ConnectionSummary) bool { return c.ID == connection })
	if shared && !options.Shows(connection) || !shared && !options.OrganizationSSO {
		return federation.Start{}, hosted.ErrMethodUnavailable()
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
		req, err := s.second.Requirement(ctx, target.Boundary(organization), verified.User, verified.FederatedFor(organization))
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
	if verified.PasswordExpired {
		// Last, after any second factor: a password alone never sets a new one.
		return hosted.Result{PasswordChange: true}, s.park(ctx, r, target, login)
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
	req, err := s.second.Requirement(ctx, target.Boundary(login.Chosen), login.Verified.User, login.Verified.FederatedFor(login.Chosen))
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

// ChangePassword replaces the parked login's expired password. step only
// asks once the organization is chosen and any second factor passed; a
// direct post is held to the same.
func (s *Service) ChangePassword(ctx context.Context, r hosted.Request, secret string) (hosted.Result, error) {
	target, login, err := s.parked(ctx, r)
	if err != nil {
		return hosted.Result{}, err
	}
	if !login.Verified.PasswordExpired || login.Chosen.IsZero() {
		return hosted.Result{}, errx.Validation("no password change is pending")
	}
	if s.second != nil && !authentication.HasMFA(login.Verified.AMR) {
		req, err := s.second.Requirement(ctx, target.Boundary(login.Chosen), login.Verified.User, login.Verified.FederatedFor(login.Chosen))
		if err != nil {
			return hosted.Result{}, err
		}
		if req.Needed {
			return hosted.Result{}, errx.Forbidden("a second factor is required")
		}
	}
	login.Verified, err = s.authenticator.ChangePassword(ctx, target.Environment, login.Verified, secret)
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
	out, err := s.repository.Settings(ctx, environment)
	if err != nil {
		return hosted.Settings{}, err
	}
	return out, filled(&out)
}

func (s *Service) SaveSettings(ctx context.Context, m hosted.Mutation, input hosted.Settings) (hosted.Settings, error) {
	if err := input.Validate(); err != nil {
		return hosted.Settings{}, err
	}
	input.Environment, input.Client = m.Environment, nil
	out, err := s.repository.SaveSettings(ctx, m, input)
	if err != nil {
		return hosted.Settings{}, err
	}
	return out, filled(&out)
}

func (s *Service) ClientSettings(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (hosted.Settings, error) {
	if environment.IsZero() || client.IsZero() {
		return hosted.Settings{}, errx.Validation("environment_id and client_id are required")
	}
	out, err := s.repository.ClientSettings(ctx, environment, client)
	if err != nil {
		return hosted.Settings{}, err
	}
	return out, filled(&out)
}

func (s *Service) ListClientSettings(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[hosted.Settings], error) {
	if environment.IsZero() {
		return query.Paginated[hosted.Settings]{}, errx.Validation("environment_id is required")
	}
	out, err := s.repository.ListClientSettings(ctx, environment, page)
	if err != nil {
		return query.Paginated[hosted.Settings]{}, err
	}
	for i := range out.Items {
		if err = filled(&out.Items[i]); err != nil {
			return query.Paginated[hosted.Settings]{}, err
		}
	}
	return out, nil
}

func (s *Service) SaveClientSettings(ctx context.Context, m hosted.Mutation, client identity.ClientID, input hosted.Settings) (hosted.Settings, error) {
	if client.IsZero() {
		return hosted.Settings{}, errx.Validation("client_id is required")
	}
	if err := input.Validate(); err != nil {
		return hosted.Settings{}, err
	}
	// Email language is the environment's; a client style has none.
	input.Environment, input.Client, input.Locale = m.Environment, &client, nil
	out, err := s.repository.SaveClientSettings(ctx, m, client, input)
	if err != nil {
		return hosted.Settings{}, err
	}
	return out, filled(&out)
}

func (s *Service) DeleteClientSettings(ctx context.Context, m hosted.Mutation, client identity.ClientID) error {
	if client.IsZero() {
		return errx.Validation("client_id is required")
	}
	return s.repository.DeleteClientSettings(ctx, m, client)
}

// Draft normalizes an unsaved style for a preview.
func (s *Service) Draft(_ context.Context, environment identity.EnvironmentID, input hosted.Settings) (hosted.Settings, error) {
	if err := input.Validate(); err != nil {
		return hosted.Settings{}, err
	}
	input.Environment = environment
	return input, nil
}

// SignIn is the client's sign-in options, or every method.
func (s *Service) SignIn(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (hosted.SignIn, error) {
	if environment.IsZero() || client.IsZero() {
		return hosted.SignIn{}, errx.Validation("environment_id and client_id are required")
	}
	out, ok, err := s.repository.SignIn(ctx, environment, client)
	if err != nil || !ok {
		return hosted.DefaultSignIn(environment, client), err
	}
	return out, nil
}

func (s *Service) ListSignIn(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[hosted.SignIn], error) {
	if environment.IsZero() {
		return query.Paginated[hosted.SignIn]{}, errx.Validation("environment_id is required")
	}
	return s.repository.ListSignIn(ctx, environment, page)
}

// SaveSignIn stores a client's sign-in options. Listed connections must be
// active environment connections; one disabled later simply stops showing.
func (s *Service) SaveSignIn(ctx context.Context, m hosted.Mutation, client identity.ClientID, input hosted.SignIn) (hosted.SignIn, error) {
	if client.IsZero() {
		return hosted.SignIn{}, errx.Validation("client_id is required")
	}
	input.Normalize()
	if err := input.Validate(); err != nil {
		return hosted.SignIn{}, err
	}
	if len(input.Connections) > 0 {
		environment, err := s.federation.EnvironmentConnections(ctx, m.Environment)
		if err != nil {
			return hosted.SignIn{}, err
		}
		for _, id := range input.Connections {
			if !slices.ContainsFunc(environment, func(c federation.ConnectionSummary) bool { return c.ID == id }) {
				return hosted.SignIn{}, errx.Validation("connection_ids must be active environment connections")
			}
		}
	}
	input.Environment, input.Client = m.Environment, client
	return s.repository.SaveSignIn(ctx, m, client, input)
}

func (s *Service) DeleteSignIn(ctx context.Context, m hosted.Mutation, client identity.ClientID) error {
	if client.IsZero() {
		return errx.Validation("client_id is required")
	}
	return s.repository.DeleteSignIn(ctx, m, client)
}

// style is the client's own style, or the environment default.
func (s *Service) style(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID) (hosted.Settings, error) {
	out, err := s.repository.ClientSettings(ctx, environment, client)
	var e *errx.Error
	if errx.As(err, &e) && e.Type == errx.TypeNotFound {
		out, err = s.repository.Settings(ctx, environment)
	}
	if err != nil {
		return hosted.Settings{}, err
	}
	return out, filled(&out)
}

// filled completes stored branding with the defaults of unset values
// (rows saved before the theme existed have an empty one). A stored email
// language no longer available is kept as is: readers resolve it with
// i18n.Match (the default applies) and the console asks for another.
func filled(s *hosted.Settings) error {
	locale := s.Locale
	s.Locale = nil
	err := s.Validate()
	s.Locale = locale
	if err != nil {
		return errx.Wrap(err, "stored hosted branding is invalid", errx.TypeInternal)
	}
	return nil
}
