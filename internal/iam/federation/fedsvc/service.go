package fedsvc

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/google/uuid"
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
func validID(id string) bool { _, err := uuid.Parse(id); return err == nil }

var secretName = regexp.MustCompile(`^IAMKIT_PROVIDER_[A-Z0-9_]+$`)

func (s *Service) Create(ctx context.Context, input federation.Connection) (string, error) {
	u, err := url.Parse(input.Issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || input.Name == "" || input.Client == "" || !secretName.MatchString(input.SecretEnv) {
		return "", errx.Validation("HTTPS issuer, client ID and IAMKIT_PROVIDER_ secret variable required")
	}
	if !s.provider.Approved(input) {
		return "", errx.Forbidden("provider credential is not approved for this environment, issuer and client")
	}
	input.ID = uuid.NewString()
	return input.ID, s.repository.Create(ctx, input)
}
func (s *Service) Link(ctx context.Context, m federation.Mutation, connection, user, subject string) error {
	if !validID(connection) || !validID(user) || subject == "" || len(subject) > 512 {
		return errx.Validation("invalid external identity")
	}
	return s.repository.Link(ctx, m, connection, user, subject)
}
func (s *Service) Disable(ctx context.Context, m federation.Mutation, id string) error {
	if !validID(id) {
		return errx.Validation("invalid connection")
	}
	return s.repository.Disable(ctx, m, id)
}
func (s *Service) Start(ctx context.Context, b authentication.Context, id string) (federation.Start, error) {
	var out federation.Start
	if !validID(b.EnvironmentID) || !validID(b.OrganizationID) || !validID(b.ApplicationID) || !validID(b.ResourceID) || !validID(id) {
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
