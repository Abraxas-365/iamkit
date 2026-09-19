package provsvc

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
	"time"
)

type Control struct {
	repository provisioning.ControlRepository
	secrets    provisioning.Generator
}

func NewControl(r provisioning.ControlRepository, s provisioning.Generator) *Control {
	return &Control{r, s}
}
func (s *Control) Issue(ctx context.Context, environment string, input provisioning.CredentialInput) (provisioning.Credential, error) {
	var out provisioning.Credential
	if err := input.Validate(); err != nil {
		return out, err
	}
	ttl, err := identity.ParseTTL(input.ExpiresIn)
	if err != nil {
		return out, err
	}
	create := input.Connection == ""
	if create {
		input.Connection = uuid.NewString()
	}
	raw, hash, err := s.secrets.Generate("ik_scim_")
	if err != nil {
		return out, err
	}
	out = provisioning.Credential{ID: uuid.NewString(), Secret: raw, Expires: time.Now().Add(ttl), Connection: input.Connection}
	return out, s.repository.IssueCredential(ctx, environment, input, out, hash, create)
}
func (s *Control) Revoke(ctx context.Context, m provisioning.Mutation, id string) error {
	if !identity.ValidID(id) {
		return errx.Validation("invalid credential")
	}
	return s.repository.RevokeCredential(ctx, m, id)
}
func (s *Control) Link(ctx context.Context, m provisioning.Mutation, input provisioning.Link) error {
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.Link(ctx, m, input)
}
func (s *Control) Credentials(ctx context.Context, environment string) ([]provisioning.CredentialView, error) {
	return s.repository.Credentials(ctx, environment)
}
