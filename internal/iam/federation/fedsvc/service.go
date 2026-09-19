package fedsvc

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct {
	repository federation.Repository
	provider   federation.Provider
	secrets    federation.Secrets
	sessions   federation.Sessions
	issuer     string
}

func New(r federation.Repository, p federation.Provider, secrets federation.Secrets, sessions federation.Sessions, issuer string) *Service {
	return &Service{r, p, secrets, sessions, issuer}
}

var secretName = regexp.MustCompile(`^IAMKIT_PROVIDER_[A-Z0-9_]+$`)

func (s *Service) Create(ctx context.Context, input federation.Connection) (identity.ConnectionID, error) {
	u, err := url.Parse(input.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || input.Name == "" || input.Client == "" || !secretName.MatchString(input.SecretEnv) {
		return identity.ConnectionID{}, errx.Validation("HTTPS issuer, client ID and IAMKIT_PROVIDER_ secret variable required")
	}
	if !s.provider.Approved(input) {
		return identity.ConnectionID{}, errx.Forbidden("provider credential is not approved for this environment, issuer and client")
	}
	input.ID = identity.NewConnectionID()
	return input.ID, s.repository.Create(ctx, input)
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
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID) ([]federation.ConnectionView, error) {
	return s.repository.List(ctx, environment)
}
func (s *Service) Connection(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) (federation.ConnectionDetail, error) {
	if connectionID.IsZero() {
		return federation.ConnectionDetail{}, errx.NotFound("federation connection not found")
	}
	return s.repository.FindDetail(ctx, environment, connectionID)
}
func (s *Service) Identities(ctx context.Context, environment identity.EnvironmentID, connectionID identity.ConnectionID) ([]federation.ExternalIdentityView, error) {
	if connectionID.IsZero() {
		return nil, errx.NotFound("federation connection not found")
	}
	return s.repository.Identities(ctx, environment, connectionID)
}
func (s *Service) Start(ctx context.Context, b authentication.Context, id identity.ConnectionID) (federation.Start, error) {
	var out federation.Start
	if err := b.Validate(); err != nil {
		return out, err
	}
	if id.IsZero() {
		return out, errx.Validation("invalid federation context")
	}
	if !strings.HasPrefix(s.issuer, "https://") {
		return out, errx.Validation("federation requires HTTPS issuer")
	}
	connection, err := s.repository.Find(ctx, b.EnvironmentID, id)
	if err != nil {
		return out, err
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
	if err = s.repository.SaveState(ctx, hash, federation.State{Connection: id, Boundary: b, Binding: bindingHash, Nonce: nonce, Verifier: verifier}); err != nil {
		return out, err
	}
	return federation.Start{URL: address, Binding: binding}, nil
}
func (s *Service) Callback(ctx context.Context, code, state, binding string) (authentication.Issued, error) {
	var out authentication.Issued
	if code == "" || state == "" {
		return out, errx.Unauthorized("invalid federation callback")
	}
	row, err := s.repository.ConsumeState(ctx, s.secrets.Hash(state), s.secrets.Hash(binding))
	if err != nil {
		return out, err
	}
	connection, err := s.repository.Find(ctx, row.Boundary.EnvironmentID, row.Connection)
	if err != nil {
		return out, err
	}
	subject, err := s.provider.Verify(ctx, connection, code, row.Nonce, row.Verifier)
	if err != nil {
		return out, err
	}
	tx, user, err := s.repository.LinkedUser(ctx, row.Boundary.EnvironmentID, row.Connection, subject)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	return s.sessions.NewSession(ctx, tx, row.Boundary, user)
}
