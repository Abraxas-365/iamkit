package fedsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository federation.Repository
	provider   federation.Provider
	cipher     federation.Cipher
	secrets    federation.Secrets
	sessions   federation.Sessions
	issuer     string
}

func New(r federation.Repository, p federation.Provider, cipher federation.Cipher, secrets federation.Secrets, sessions federation.Sessions, issuer string) *Service {
	return &Service{r, p, cipher, secrets, sessions, issuer}
}

func (s *Service) Create(ctx context.Context, m federation.Mutation, input federation.ConnectionInput) (identity.ConnectionID, error) {
	if err := input.Validate(); err != nil {
		return identity.ConnectionID{}, err
	}
	c := input.Connection(m.Environment)
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
	c.ID = identity.NewConnectionID()
	return c.ID, s.repository.Create(ctx, m, c)
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
	c := input.Apply(current)
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
	return s.repository.List(ctx, environment, filter, page)
}
func (s *Service) Connection(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) (federation.ConnectionDetail, error) {
	if connectionID.IsZero() {
		return federation.ConnectionDetail{}, errx.NotFound("federation connection not found")
	}
	return s.repository.FindDetail(ctx, environment, connectionID)
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

func (s *Service) Start(ctx context.Context, b authentication.Context, id identity.ConnectionID) (federation.Start, error) {
	if err := b.Validate(); err != nil {
		return federation.Start{}, err
	}
	connection, err := s.connection(ctx, b.EnvironmentID, id)
	if err != nil {
		return federation.Start{}, err
	}
	// An organization connection only signs users in to its organization.
	if connection.Scoped() && connection.Organization != b.OrganizationID {
		return federation.Start{}, errx.Validation("connection belongs to another organization")
	}
	return s.start(ctx, connection, federation.State{Connection: id, Boundary: b})
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
	connection, err := s.repository.Find(ctx, row.Boundary.EnvironmentID, row.Connection)
	if err != nil {
		return out, err
	}
	claims, err := s.provider.Verify(ctx, connection, code, row.Nonce, row.Verifier)
	if err != nil {
		return out, err
	}
	tx, user, err := s.repository.LinkedUser(ctx, row.Boundary.EnvironmentID, row.Connection, claims.Subject)
	if err != nil {
		return out, err
	}
	if tx == nil {
		if err = s.provision(ctx, connection, claims); err != nil {
			return out, err
		}
		if tx, user, err = s.repository.LinkedUser(ctx, row.Boundary.EnvironmentID, row.Connection, claims.Subject); err != nil {
			return out, err
		}
		if tx == nil {
			return out, errx.Unauthorized("external identity is not linked")
		}
	}
	defer tx.Rollback()
	if out.Hosted() {
		// The hosted pages choose the organization and issue the session.
		out.Verified = authentication.Verified{User: user, Email: claims.Email, Method: authentication.MethodSSO, Organization: connection.Organization}
		return out, nil
	}
	out.Issued, err = s.sessions.NewSession(ctx, tx, row.Boundary, user)
	if connection.Scoped() && unauthorized(err) {
		// The provider proved the identity; what is missing is access
		// (inactive membership, or no roles for a just-provisioned user).
		return out, errx.Forbidden("signed in, but the user has no access to this application")
	}
	return out, err
}

// provision links an unlinked subject on first login when the connection
// allows it: the provider email must be verified (or unreported) and its
// domain verified by the connection's organization, which the repository
// checks in its transaction. The account persists even when the user has no
// access yet, so operators can find it and grant roles.
func (s *Service) provision(ctx context.Context, c federation.Connection, claims federation.Claims) error {
	email, err := c.Admit(claims)
	if err != nil {
		return err
	}
	return s.repository.Provision(ctx, federation.Provisioning{
		Connection: c.ID, Environment: c.Environment, Organization: c.Organization, Group: c.JITGroup,
		User: identity.NewUserID(), Subject: claims.Subject, Email: email, Domain: identity.EmailDomain(email), Name: claims.DisplayName(email),
	})
}

func unauthorized(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Type == errx.TypeAuthorization && e.HTTPStatus == 401
}

var _ federation.Commands = (*Service)(nil)
var _ federation.Queries = (*Service)(nil)
var _ federation.Flows = (*Service)(nil)
