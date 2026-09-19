package impsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Service struct{ repository impersonation.Repository }

func New(r impersonation.Repository) *Service { return &Service{r} }
func (s *Service) Create(ctx context.Context, actor management.Principal, environment identity.EnvironmentID, input impersonation.Request) (authentication.Token, string, error) {
	var token authentication.Token
	if actor.Role != "owner" {
		return token, "", errx.Forbidden("only workspace owners may impersonate")
	}
	if environment.IsZero() {
		return token, "", errx.Validation("valid target context and 10-1000 character reason required")
	}
	if err := input.Validate(); err != nil {
		return token, "", err
	}
	sessionID := identity.NewSessionID()
	target := impersonation.Target{
		Context: authentication.Context{
			EnvironmentID:  environment,
			OrganizationID: input.Organization,
			ApplicationID:  input.Application,
			ResourceID:     input.Resource,
		},
		User:    input.User,
		Reason:  strings.TrimSpace(input.Reason),
		Actor:   actor.OperatorID,
		Session: sessionID,
		Expires: time.Now().Add(config.ImpersonationTokenTTL),
	}
	access, err := s.repository.Create(ctx, target)
	if err != nil {
		return token, "", err
	}
	token = authentication.Token{
		Access: identity.Access{
			EnvironmentID:  environment,
			OrganizationID: input.Organization,
			ApplicationID:  input.Application,
			ResourceID:     input.Resource,
			Permissions:    access.Permissions,
		},
		Subject:   input.User,
		SessionID: sessionID,
		ActorID:   actor.OperatorID,
		Purpose:   "application",
	}
	return token, access.Audience, nil
}
