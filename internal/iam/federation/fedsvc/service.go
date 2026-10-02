package fedsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository federation.Repository
	provider   federation.Provider
	cipher     federation.Cipher
	secrets    federation.Secrets
	sessions   federation.Sessions
	directory  federation.Directory
	issuer     string
	actions    federation.Actions
	quota      federation.Quota
}

// SetActions runs the environment's federation hooks.
func (s *Service) SetActions(actions federation.Actions) { s.actions = actions }

// SetQuota enforces the environment's users limit on first sign-ins that
// create accounts.
func (s *Service) SetQuota(q federation.Quota) { s.quota = q }

func New(r federation.Repository, p federation.Provider, directory federation.Directory, cipher federation.Cipher, secrets federation.Secrets, sessions federation.Sessions, issuer string) *Service {
	return &Service{repository: r, provider: p, directory: directory, cipher: cipher, secrets: secrets, sessions: sessions, issuer: issuer}
}

func (s *Service) Create(ctx context.Context, m federation.Mutation, input federation.ConnectionInput) (identity.ConnectionID, error) {
	if err := input.Validate(); err != nil {
		return identity.ConnectionID{}, err
	}
	c := input.Connection(m.Environment)
	c.ID = identity.NewConnectionID()
	c, err := s.prepare(ctx, c)
	if err != nil {
		return identity.ConnectionID{}, err
	}
	if err := s.check(ctx, c); err != nil {
		return identity.ConnectionID{}, err
	}
	if c.SecretEnv != "" && !s.provider.Approved(c) {
		return identity.ConnectionID{}, errx.Forbidden("provider credential is not approved for this environment, issuer and client")
	}
	if input.ClientSecret != "" {
		sealed, err := s.cipher.Seal([]byte(input.ClientSecret))
		if err != nil {
			return identity.ConnectionID{}, err
		}
		c.Sealed = sealed
	}
	return c.ID, s.repository.Create(ctx, m, c)
}

// prepare lets the provider complete a connection (SAML metadata) and
// requires HTTPS for SAML, whose endpoints live under the issuer.
func (s *Service) prepare(ctx context.Context, c federation.Connection) (federation.Connection, error) {
	if c.Provider != federation.ProviderSAML {
		return c, nil
	}
	if !strings.HasPrefix(s.issuer, "https://") {
		return c, errx.Validation("SAML connections require an HTTPS issuer")
	}
	return s.provider.Prepare(ctx, c)
}

func (s *Service) Update(ctx context.Context, m federation.Mutation, id identity.ConnectionID, input federation.ConnectionUpdate) error {
	if id.IsZero() {
		return errx.NotFound("federation connection not found")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	current, err := s.repository.Find(ctx, m.Environment, id)
	if err != nil {
		return err
	}
	c, err := input.Apply(current)
	if err != nil {
		return err
	}
	if c.Provider == federation.ProviderSAML && input.Options != nil {
		// Refetch or reparse the metadata; the identity provider's entity
		// ID is what linked subjects belong to, so it cannot change.
		if input.Options.MetadataURL != "" && input.Options.MetadataXML == "" {
			c.Options.MetadataXML = ""
		}
		if c, err = s.prepare(ctx, c); err != nil {
			return err
		}
		if c.Issuer != current.Issuer {
			return errx.Validation("the metadata names another identity provider entity ID; create another connection")
		}
	}
	if c.Provider == federation.ProviderApple && input.ClientSecret != nil {
		if _, err = federation.ParseAppleKey(*input.ClientSecret); err != nil {
			return err
		}
	}
	if err = s.check(ctx, c); err != nil {
		return err
	}
	if input.ClientSecret != nil {
		if c.Sealed, err = s.cipher.Seal([]byte(*input.ClientSecret)); err != nil {
			return err
		}
		c.SecretEnv = ""
	}
	return s.repository.Update(ctx, m, c)
}

// check enforces the rules shared by create and update: organization-only
// settings, a JIT group the directory cannot overwrite, and enforcement only
// once the organization has verified a domain (enforcement applies to
// verified-domain emails, so without one it would silently do nothing).
func (s *Service) check(ctx context.Context, c federation.Connection) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if !c.JITGroup.IsZero() {
		ok, err := s.repository.OperatorGroup(ctx, c.Environment, c.Organization, c.JITGroup)
		if err != nil {
			return err
		}
		if !ok {
			return errx.Validation("jit_group_id must be an operator-managed group of the organization")
		}
	}
	if c.Signup {
		ok, err := s.repository.ActiveOrganization(ctx, c.Environment, c.SignupOrganization)
		if err != nil {
			return err
		}
		if !ok {
			return errx.Validation("signup_organization_id must be an active organization")
		}
	}
	if !c.SignupGroup.IsZero() {
		ok, err := s.repository.OperatorGroup(ctx, c.Environment, c.SignupOrganization, c.SignupGroup)
		if err != nil {
			return err
		}
		if !ok {
			return errx.Validation("signup_group_id must be an operator-managed group of the signup organization")
		}
	}
	if c.Enforcement != federation.EnforcementEnforced {
		return nil
	}
	verified, err := s.repository.HasVerifiedDomain(ctx, c.Environment, c.Organization)
	if err != nil {
		return err
	}
	if !verified {
		return errx.Business("enforcing SSO requires the organization to have a verified domain")
	}
	return nil
}

func (s *Service) Link(ctx context.Context, m federation.Mutation, connectionID identity.ConnectionID, userID identity.UserID, subject string) error {
	if connectionID.IsZero() || userID.IsZero() || subject == "" || len(subject) > 512 {
		return errx.Validation("invalid external identity")
	}
	return s.repository.Link(ctx, m, connectionID, userID, subject)
}
func (s *Service) Disable(ctx context.Context, m federation.Mutation, id identity.ConnectionID) error {
	if id.IsZero() {
		return errx.Validation("invalid connection")
	}
	return s.repository.Disable(ctx, m, id)
}
func (s *Service) Unlink(ctx context.Context, m federation.Mutation, connectionID identity.ConnectionID, userID identity.UserID) error {
	if connectionID.IsZero() || userID.IsZero() {
		return errx.Validation("invalid external identity")
	}
	return s.repository.Unlink(ctx, m, connectionID, userID)
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, filter federation.ConnectionFilter, page query.Pagination) (query.Paginated[federation.ConnectionView], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[federation.ConnectionView]{}, err
	}
	return s.repository.List(ctx, environment, filter, page)
}
func (s *Service) Connection(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) (federation.ConnectionDetail, error) {
	if connectionID.IsZero() {
		return federation.ConnectionDetail{}, errx.NotFound("federation connection not found")
	}
	out, err := s.repository.FindDetail(ctx, environment, connectionID)
	out.Callback = s.provider.Callback()
	if out.Provider == federation.ProviderSAML {
		sp := federation.SAMLServiceProvider(s.issuer, environment, connectionID)
		out.SAML, out.Callback = &sp, sp.ACS
	}
	if out.Provider == federation.ProviderLDAP {
		out.Callback = ""
	}
	return out, err
}
func (s *Service) Identities(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID, page query.Pagination) (query.Paginated[federation.ExternalIdentityView], error) {
	if connectionID.IsZero() {
		return query.Paginated[federation.ExternalIdentityView]{}, errx.NotFound("federation connection not found")
	}
	return s.repository.Identities(ctx, environment, connectionID, page)
}

// Discover routes an email by its domain alone, never by whether an account
// exists, so it cannot be used to enumerate users.
func (s *Service) Discover(ctx context.Context, environment identity.EnvironmentID, email string) (federation.Discovery, error) {
	email, err := identity.Email(email)
	if err != nil || environment.IsZero() {
		return federation.Discovery{}, errx.Validation("environment_id and a valid email are required")
	}
	out, err := s.repository.Discover(ctx, environment, identity.EmailDomain(email))
	if err != nil {
		return federation.Discovery{}, err
	}
	if out.Method == "" {
		out = federation.Discovery{Method: federation.MethodPassword}
	}
	return out, nil
}

func (s *Service) EnvironmentConnections(ctx context.Context, environment identity.EnvironmentID) ([]federation.ConnectionSummary, error) {
	if environment.IsZero() {
		return nil, errx.Validation("environment_id is required")
	}
	return s.repository.EnvironmentConnections(ctx, environment)
}

func (s *Service) Start(ctx context.Context, b authentication.Context, id identity.ConnectionID, back federation.Return) (federation.Start, error) {
	if err := b.Validate(); err != nil {
		return federation.Start{}, err
	}
	if back.Set() {
		if err := s.returnable(ctx, b, back); err != nil {
			return federation.Start{}, err
		}
	}
	connection, err := s.connection(ctx, b.EnvironmentID, id)
	if err != nil {
		return federation.Start{}, err
	}
	// An organization connection only signs users in to its organization.
	if connection.Scoped() && connection.Organization != b.OrganizationID {
		return federation.Start{}, errx.Validation("connection belongs to another organization")
	}
	return s.start(ctx, connection, federation.State{Connection: id, Boundary: b, Return: back})
}

// returnable checks that a custom sign-in UI may receive the callback:
// return_to's origin is allowed by an OAuth client of the application.
func (s *Service) returnable(ctx context.Context, b authentication.Context, back federation.Return) error {
	if err := back.Validate(); err != nil {
		return err
	}
	origin, _ := back.Origin()
	ok, err := s.repository.ReturnAllowed(ctx, b.EnvironmentID, b.ApplicationID, origin)
	if err != nil {
		return err
	}
	if !ok {
		return errx.Validation("return_to must be on an origin an OAuth client of the application allows (allowed_origins)")
	}
	return nil
}

func (s *Service) StartHosted(ctx context.Context, target authentication.Target, id identity.ConnectionID, continuation string) (federation.Start, error) {
	if target.Environment.IsZero() || target.Application.IsZero() || target.Resource.IsZero() || continuation == "" {
		return federation.Start{}, errx.Validation("invalid federation context")
	}
	connection, err := s.connection(ctx, target.Environment, id)
	if err != nil {
		return federation.Start{}, err
	}
	// Organization connections fix the organization now; environment
	// connections leave it to the hosted organization choice.
	return s.start(ctx, connection, federation.State{Connection: id, Boundary: target.Boundary(connection.Organization), Continuation: continuation})
}

func (s *Service) connection(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, error) {
	if id.IsZero() {
		return federation.Connection{}, errx.Validation("invalid federation context")
	}
	if !strings.HasPrefix(s.issuer, "https://") {
		return federation.Connection{}, errx.Validation("federation requires HTTPS issuer")
	}
	return s.repository.Find(ctx, environment, id)
}

func (s *Service) start(ctx context.Context, connection federation.Connection, row federation.State) (federation.Start, error) {
	var out federation.Start
	if connection.Provider == federation.ProviderLDAP {
		return out, errx.Validation("LDAP connections sign in with a password: POST /identity/v1/federation/ldap/login")
	}
	state, hash, err := s.secrets.Generate("ik_state_")
	if err != nil {
		return out, err
	}
	binding, bindingHash, err := s.secrets.Generate("ik_binding_")
	if err != nil {
		return out, err
	}
	nonce, _, err := s.secrets.Generate("ik_nonce_")
	if err != nil {
		return out, err
	}
	verifier := s.provider.Verifier()
	address, err := s.provider.Authorize(ctx, connection, state, nonce, verifier)
	if err != nil {
		return out, err
	}
	row.Binding, row.Nonce, row.Verifier = bindingHash, nonce, verifier
	if err = s.repository.SaveState(ctx, hash, row); err != nil {
		return out, err
	}
	return federation.Start{URL: address, Binding: binding}, nil
}

func (s *Service) Callback(ctx context.Context, code, state, binding string) (federation.Outcome, error) {
	var out federation.Outcome
	if code == "" || state == "" {
		return out, errx.Unauthorized("invalid federation callback")
	}
	row, err := s.repository.ConsumeState(ctx, s.secrets.Hash(state), s.secrets.Hash(binding))
	if err != nil {
		return out, err
	}
	out.Continuation = row.Continuation
	out.ReturnTo = row.Return.To
	connection, err := s.repository.Find(ctx, row.Boundary.EnvironmentID, row.Connection)
	if err != nil {
		return out, err
	}
	if connection.Provider == federation.ProviderSAML {
		// The code is the handle the assertion consumer service parked the
		// response under, for this state only.
		if code, err = s.repository.TakeAssertion(ctx, s.secrets.Hash(state), s.secrets.Hash(code)); err != nil {
			return out, err
		}
	}
	claims, err := s.provider.Verify(ctx, connection, code, row.Nonce, row.Verifier)
	if err != nil {
		return out, err
	}
	if claims.Assertion != "" {
		if err = s.repository.UseAssertion(ctx, connection.ID, claims.Assertion, claims.AssertionExpires); err != nil {
			return out, err
		}
	}
	tx, user, err := s.account(ctx, connection, claims)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	// Enforcement is checked for the account's own email: the provider's
	// may differ for an operator-linked identity.
	if out.Hosted() {
		// The hosted pages choose the organization and issue the session.
		out.Verified = authentication.Verified{User: user.ID, Email: user.Email, Method: authentication.MethodSSO, Organization: connection.Organization}
		return out, nil
	}
	// Only the organization's own identity provider stands in for its
	// second factor; social providers do not.
	if row.Return.Set() {
		// A custom sign-in UI redeems the identity with its verifier; the
		// session is issued then, in its own transaction. Release the user
		// lock first: the parked row's foreign key needs it.
		tx.Rollback()
		handle, hash, err := s.secrets.Generate(federation.ResultPrefix)
		if err != nil {
			return out, err
		}
		if err = s.repository.ParkResult(ctx, hash, federation.Result{Boundary: row.Boundary, User: user.ID, Email: user.Email, OrganizationSSO: connection.Scoped(), NoAccess: connection.Scoped() || connection.Social(), Challenge: row.Return.Challenge}); err != nil {
			return out, err
		}
		out.Result = handle
		return out, nil
	}
	result, err := s.sessions.SignIn(ctx, tx, row.Boundary, user.ID, user.Email, connection.Scoped())
	out.Issued, out.MFA = result.Issued, result.MFA
	if (connection.Scoped() || connection.Social()) && unauthorized(err) {
		// The provider proved the identity; what is missing is access
		// (inactive membership, or no roles for a just-provisioned user).
		return out, errx.Forbidden("signed in, but the user has no access to this application")
	}
	return out, err
}

// Redeem signs in with a parked result; a wrong verifier spends it.
func (s *Service) Redeem(ctx context.Context, handle, verifier string) (authentication.Result, error) {
	if !strings.HasPrefix(handle, federation.ResultPrefix) || len(handle) > 128 {
		return authentication.Result{}, errx.Unauthorized("invalid or expired federation result")
	}
	r, err := s.repository.TakeResult(ctx, s.secrets.Hash(handle))
	if err != nil {
		return authentication.Result{}, err
	}
	if !r.Verifies(verifier) {
		return authentication.Result{}, errx.Unauthorized("invalid or expired federation result")
	}
	tx, user, err := s.repository.ActiveUser(ctx, r.Boundary.EnvironmentID, r.User)
	if err != nil {
		return authentication.Result{}, err
	}
	defer tx.Rollback()
	result, err := s.sessions.SignIn(ctx, tx, r.Boundary, user.ID, user.Email, r.OrganizationSSO)
	if r.NoAccess && unauthorized(err) {
		return result, errx.Forbidden("signed in, but the user has no access to this application")
	}
	return result, err
}

// account refreshes the profile when the connection asks for it, then
// returns the user linked to the claims' subject, linking it first when the
// connection allows (join), with the open transaction to sign in with.
func (s *Service) account(ctx context.Context, connection federation.Connection, claims federation.Claims) (authentication.Transaction, federation.Account, error) {
	claims, err := s.postFederation(ctx, connection, claims)
	if err != nil {
		return nil, federation.Account{}, err
	}
	if connection.UpdateProfile {
		// Before the lookup, so the session carries the refreshed email.
		if err := s.repository.Refresh(ctx, connection.Profile(claims)); err != nil {
			return nil, federation.Account{}, err
		}
	}
	tx, user, err := s.repository.LinkedUser(ctx, connection.Environment, connection.ID, claims.Subject)
	if err != nil || tx != nil {
		return tx, user, err
	}
	if err = s.preRegistration(ctx, connection, claims); err != nil {
		return nil, federation.Account{}, err
	}
	if err = s.join(ctx, connection, claims); err != nil {
		return nil, federation.Account{}, err
	}
	if tx, user, err = s.repository.LinkedUser(ctx, connection.Environment, connection.ID, claims.Subject); err != nil {
		return nil, federation.Account{}, err
	}
	if tx == nil {
		return nil, federation.Account{}, errx.Unauthorized("external identity is not linked")
	}
	return tx, user, nil
}

// Directory signs in headlessly with a password the organization's LDAP
// directory checks. Like the organization's other single sign-on, it
// satisfies SSO enforcement and its MFA policy for federated logins.
func (s *Service) Directory(ctx context.Context, b authentication.Context, id identity.ConnectionID, email, password string) (authentication.Result, error) {
	if err := b.Validate(); err != nil {
		return authentication.Result{}, err
	}
	connection, claims, err := s.bind(ctx, b.EnvironmentID, id, email, password)
	if err != nil {
		return authentication.Result{}, err
	}
	if connection.Organization != b.OrganizationID {
		return authentication.Result{}, errx.Validation("connection belongs to another organization")
	}
	tx, user, err := s.account(ctx, connection, claims)
	if err != nil {
		return authentication.Result{}, err
	}
	defer tx.Rollback()
	result, err := s.sessions.SignIn(ctx, tx, b, user.ID, user.Email, true)
	if unauthorized(err) {
		return result, errx.Forbidden("signed in, but the user has no access to this application")
	}
	return result, err
}

// DirectoryHosted checks a directory password for the hosted pages.
func (s *Service) DirectoryHosted(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID, email, password string) (authentication.Verified, error) {
	connection, claims, err := s.bind(ctx, environment, id, email, password)
	if err != nil {
		return authentication.Verified{}, err
	}
	tx, user, err := s.account(ctx, connection, claims)
	if err != nil {
		return authentication.Verified{}, err
	}
	defer tx.Rollback()
	return authentication.Verified{User: user.ID, Email: user.Email, Method: authentication.MethodSSO, Organization: connection.Organization}, nil
}

// bind checks the password with the directory of an active LDAP
// connection. The email must be on a domain the organization verified, so
// a directory cannot sign in addresses its organization does not own.
func (s *Service) bind(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID, email, password string) (federation.Connection, federation.Claims, error) {
	var claims federation.Claims
	email, err := identity.Email(email)
	if err != nil || environment.IsZero() || id.IsZero() {
		return federation.Connection{}, claims, errx.Validation("environment_id, connection_id and a valid email are required")
	}
	if password == "" || len(password) > 1024 {
		return federation.Connection{}, claims, errx.Unauthorized("invalid credentials")
	}
	connection, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return connection, claims, err
	}
	if connection.Provider != federation.ProviderLDAP {
		return connection, claims, errx.NotFound("LDAP connection not found")
	}
	d, err := s.repository.Discover(ctx, environment, identity.EmailDomain(email))
	if err != nil {
		return connection, claims, err
	}
	if d.Organization == nil || *d.Organization != connection.Organization {
		return connection, claims, errx.Unauthorized("invalid credentials")
	}
	claims, err = s.directory.Authenticate(ctx, connection, email, password)
	return connection, claims, err
}

// join links an unlinked subject on first login when the connection allows
// it: organization JIT provisioning, or sign-up and email linking of an
// environment connection.
func (s *Service) join(ctx context.Context, c federation.Connection, claims federation.Claims) error {
	if c.Scoped() {
		return s.provision(ctx, c, claims)
	}
	email, err := c.Joining(claims)
	if err != nil {
		return err
	}
	return s.repository.Join(ctx, federation.Joining{
		Connection: c.ID, Environment: c.Environment, Organization: c.SignupOrganization, Group: c.SignupGroup,
		User: identity.NewUserID(), Subject: claims.Subject, Email: email, Name: claims.DisplayName(email), AvatarURL: claims.Avatar(), Link: c.LinkEmail, Signup: c.Signup,
	})
}

// provision links an unlinked subject on first login when the connection
// allows it (JIT, or linking by email to an existing account): the provider email must be verified (or unreported) and its
// domain verified by the connection's organization, which the repository
// checks in its transaction. The account persists even when the user has no
// access yet, so operators can find it and grant roles.
func (s *Service) provision(ctx context.Context, c federation.Connection, claims federation.Claims) error {
	email, err := c.Admit(claims)
	if err != nil {
		return err
	}
	return s.repository.Provision(ctx, federation.Provisioning{
		Create:     c.JIT,
		Connection: c.ID, Environment: c.Environment, Organization: c.Organization, Group: c.JITGroup,
		User: identity.NewUserID(), Subject: claims.Subject, Email: email, Domain: identity.EmailDomain(email), Name: claims.DisplayName(email), AvatarURL: claims.Avatar(),
	})
}

func unauthorized(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeAuthorization && e.HTTPStatus == 401
}

func identityInput(c federation.Connection, claims federation.Claims) *action.IdentityInput {
	return &action.IdentityInput{Connection: c.ID, Provider: c.Provider, Subject: claims.Subject, Email: claims.Email, Name: claims.Name}
}

// postFederation runs function:post_federation, which may refuse the
// identity or replace its name.
func (s *Service) postFederation(ctx context.Context, c federation.Connection, claims federation.Claims) (federation.Claims, error) {
	if s.actions == nil {
		return claims, nil
	}
	result, err := s.actions.Run(ctx, c.Environment, action.PostFederation, func() action.Input {
		in := action.Input{Identity: identityInput(c, claims)}
		if c.Scoped() {
			in.Organization = &c.Organization
		}
		return in
	})
	if err != nil {
		return claims, err
	}
	if name, ok := result.Patch["name"]; ok {
		claims.Name = name
	}
	return claims, nil
}

// preRegistration runs function:pre_registration and checks the users
// limit before a first sign-in that would create a user (sign-up or JIT
// connections, and no account has the email yet — linking an existing
// account is not a registration).
func (s *Service) preRegistration(ctx context.Context, c federation.Connection, claims federation.Claims) error {
	if (s.actions == nil && s.quota == nil) || !(c.Signup || (c.Scoped() && c.JIT)) {
		return nil
	}
	email, err := identity.Email(claims.Email)
	if err != nil {
		return nil // join refuses it
	}
	if exists, err := s.repository.HasUser(ctx, c.Environment, email); err != nil || exists {
		return err
	}
	if s.quota != nil {
		if err = s.quota.Admit(ctx, c.Environment, usage.LimitUsers); err != nil {
			return err
		}
	}
	if s.actions == nil {
		return nil
	}
	_, err = s.actions.Run(ctx, c.Environment, action.PreRegistration, func() action.Input {
		in := action.Input{Method: []string{"fed"}, Identity: identityInput(c, claims), User: &action.UserInput{Email: email, Name: claims.Name}}
		organization := c.SignupOrganization
		if c.Scoped() {
			organization = c.Organization
		}
		if !organization.IsZero() {
			in.Organization = &organization
		}
		return in
	})
	return err
}

// Assertion parks a SAML response for its RelayState. The state and the
// response are only checked here for shape; the callback (in the browser
// that holds the binding cookie) verifies both.
func (s *Service) Assertion(ctx context.Context, state, response string) (string, error) {
	if !strings.HasPrefix(state, "ik_state_") || len(state) > 128 || response == "" {
		return "", errx.Unauthorized("invalid SAML response or RelayState")
	}
	if len(response) > config.SAMLResponseMax {
		return "", errx.Validation("SAML response too large")
	}
	handle, hash, err := s.secrets.Generate("ik_saml_")
	if err != nil {
		return "", err
	}
	if err = s.repository.ParkAssertion(ctx, s.secrets.Hash(state), hash, response); err != nil {
		return "", err
	}
	return handle, nil
}

func (s *Service) SAMLMetadata(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID) ([]byte, error) {
	if environment.IsZero() || id.IsZero() {
		return nil, errx.NotFound("SAML connection not found")
	}
	c, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	if c.Provider != federation.ProviderSAML {
		return nil, errx.NotFound("SAML connection not found")
	}
	return s.provider.Metadata(ctx, c)
}

var _ federation.Commands = (*Service)(nil)
var _ federation.Queries = (*Service)(nil)
var _ federation.Flows = (*Service)(nil)
