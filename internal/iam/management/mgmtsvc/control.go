package mgmtsvc

import (
	"context"
	"log/slog"
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
	if err != nil {
		return out, errx.Validation("email is invalid")
	}
	if role != management.RoleAdmin && role != management.RoleViewer {
		return out, errx.Validation("role must be admin or viewer")
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
	out.Operator, out.Reactivated, err = s.repository.Delegate(ctx, p, email, role, out.Key, hash, out.Expires)
	if err == nil && out.Reactivated {
		slog.InfoContext(ctx, "operator.reactivated", "operator", out.Operator.String(), "workspace", p.WorkspaceID.String(), "by", p.OperatorID.String(), "role", role)
	}
	return out, err
}

// SetOperatorRole changes a member's role. Only owners do it, and a
// workspace always keeps one active owner; an owner may demote themselves
// while another remains.
func (s *Control) SetOperatorRole(ctx context.Context, p management.Principal, id identity.OperatorID, role string) error {
	if p.Role != management.RoleOwner {
		return errx.Forbidden("insufficient permissions")
	}
	if !management.ValidRole(role) {
		return errx.Validation("role must be owner, admin or viewer")
	}
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	previous, err := s.repository.SetOperatorRole(ctx, p, id, role)
	if err != nil {
		return err
	}
	if previous != role {
		slog.InfoContext(ctx, "operator.role_changed", "operator", id.String(), "workspace", p.WorkspaceID.String(), "by", p.OperatorID.String(), "from", previous, "to", role)
	}
	return nil
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
func (s *Control) SetPasswordAccess(ctx context.Context, p management.Principal, id identity.OperatorID, allowed bool) error {
	if p.Role != "owner" {
		return errx.Forbidden("insufficient permissions")
	}
	if id.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.SetPasswordAccess(ctx, p.WorkspaceID, id, allowed)
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
