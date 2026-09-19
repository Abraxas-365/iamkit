package provsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Control struct {
	repository provisioning.ControlRepository
	secrets    provisioning.Generator
}

func NewControl(r provisioning.ControlRepository, s provisioning.Generator) *Control {
	return &Control{r, s}
}
func (s *Control) Issue(ctx context.Context, environment identity.EnvironmentID, input provisioning.CredentialInput) (provisioning.Credential, error) {
	var out provisioning.Credential
	if err := input.Validate(); err != nil {
		return out, err
	}
	ttl, err := identity.ParseTTL(input.ExpiresIn)
	if err != nil {
		return out, err
	}
	create := input.Connection.IsZero()
	if create {
		input.Connection = identity.NewConnectionID()
	}
	raw, hash, err := s.secrets.Generate("ik_scim_")
	if err != nil {
		return out, err
	}
	out = provisioning.Credential{ID: identity.NewCredentialID(), Secret: raw, Expires: time.Now().Add(ttl), Connection: input.Connection}
	return out, s.repository.IssueCredential(ctx, environment, input, out, hash, create)
}
func (s *Control) Revoke(ctx context.Context, m provisioning.Mutation, id identity.CredentialID) error {
	if id.IsZero() {
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
func (s *Control) Credentials(ctx context.Context, environment identity.EnvironmentID) ([]provisioning.CredentialView, error) {
	return s.repository.Credentials(ctx, environment)
}
