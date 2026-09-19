package mgmtsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Control struct {
	repository management.ControlRepository
	secrets    management.Secrets
}

func NewControl(r management.ControlRepository, s management.Secrets) *Control { return &Control{r, s} }
func (s *Control) CreateKey(ctx context.Context, p management.Principal, expiresIn *string) (management.Credential, error) {
	ttl, err := identity.ParseTTL(expiresIn)
	if err != nil {
		return management.Credential{}, err
	}
	out := management.Credential{ID: identity.NewKeyID(), Expires: time.Now().Add(ttl)}
	raw, hash, err := s.secrets.Generate("ik_mgmt_")
	if err != nil {
		return out, err
	}
	out.Secret = raw
	return out, s.repository.CreateKey(ctx, p, out.ID, hash, out.Expires)
}
func (s *Control) Keys(ctx context.Context, p management.Principal) ([]management.Key, error) {
	return s.repository.Keys(ctx, p)
}
func (s *Control) RevokeKey(ctx context.Context, p management.Principal, id identity.KeyID) error {
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.RevokeKey(ctx, p, id)
}
func (s *Control) Delegate(ctx context.Context, p management.Principal, email, role string, expiresIn *string) (management.Delegated, error) {
	var out management.Delegated
	if p.Role != "owner" {
		return out, errx.Forbidden("insufficient permissions")
	}
	email, err := identity.Email(email)
	if err != nil || (role != "admin" && role != "viewer") {
		return out, errx.Validation("invalid request")
	}
	ttl, err := identity.ParseTTL(expiresIn)
	if err != nil {
		return out, err
	}
	raw, hash, err := s.secrets.Generate("ik_mgmt_")
	if err != nil {
		return out, err
	}
	out = management.Delegated{Key: identity.NewKeyID(), Secret: raw, Expires: time.Now().Add(ttl)}
	out.Operator, err = s.repository.Delegate(ctx, p, email, role, out.Key, hash, out.Expires)
	return out, err
}
func (s *Control) DisableOperator(ctx context.Context, p management.Principal, id identity.OperatorID) error {
	if p.Role != "owner" {
		return errx.Forbidden("insufficient permissions")
	}
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.DisableOperator(ctx, p, id)
}
func (s *Control) CreateProject(ctx context.Context, p management.Principal, name string) (identity.ProjectID, error) {
	if strings.TrimSpace(name) == "" {
		return identity.ProjectID{}, errx.Validation("invalid request")
	}
	id := identity.NewProjectID()
	return id, s.repository.CreateProject(ctx, p.WorkspaceID, id, name)
}
func (s *Control) Projects(ctx context.Context, p management.Principal) ([]management.Named, error) {
	return s.repository.Projects(ctx, p.WorkspaceID)
}
func (s *Control) CreateEnvironment(ctx context.Context, p management.Principal, project identity.ProjectID, name string) (identity.EnvironmentID, error) {
	if project.IsZero() || strings.TrimSpace(name) == "" {
		return identity.EnvironmentID{}, errx.Validation("invalid request")
	}
	id := identity.NewEnvironmentID()
	return id, s.repository.CreateEnvironment(ctx, p.WorkspaceID, project, id, name)
}
func (s *Control) Environments(ctx context.Context, p management.Principal, project identity.ProjectID) ([]management.Named, error) {
	if project.IsZero() {
		return nil, errx.NotFound("resource not found")
	}
	return s.repository.Environments(ctx, p.WorkspaceID, project)
}
func (s *Control) Operators(ctx context.Context, p management.Principal) ([]management.Operator, error) {
	return s.repository.Operators(ctx, p.WorkspaceID)
}
