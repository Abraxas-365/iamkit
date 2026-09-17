package provsvc

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/google/uuid"
	"strings"
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
	if !validID(input.Organization) || strings.TrimSpace(input.Name) == "" {
		return out, errx.Validation("name and organization required")
	}
	create := input.Connection == ""
	if create {
		input.Connection = uuid.NewString()
	} else if !validID(input.Connection) {
		return out, errx.Validation("invalid connection")
	}
	raw, hash, err := s.secrets.Generate("ik_scim_")
	if err != nil {
		return out, err
	}
	out = provisioning.Credential{ID: uuid.NewString(), Secret: raw, Expires: time.Now().Add(24 * time.Hour), Connection: input.Connection}
	return out, s.repository.IssueCredential(ctx, environment, input, out, hash, create)
}
func (s *Control) Revoke(ctx context.Context, m provisioning.Mutation, id string) error {
	if !validID(id) {
		return errx.Validation("invalid credential")
	}
	return s.repository.RevokeCredential(ctx, m, id)
}
func (s *Control) Link(ctx context.Context, m provisioning.Mutation, input provisioning.Link) error {
	if !validID(input.Connection) || !validID(input.User) || input.External == "" {
		return errx.Validation("connection, user and external ID required")
	}
	return s.repository.Link(ctx, m, input)
}
